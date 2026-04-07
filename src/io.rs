use std::{
    cell::RefCell,
    ffi::{c_void, CStr},
    io,
    pin::Pin,
};

use bitflags::bitflags;
use io_uring::{squeue, types::Fd, IoUring};
use libc;

/// Our internal abstraction around IOUring.
pub struct IO {
    uring: RefCell<IoUring>,
}

enum Operation<'io_op> {
    Uninitialized,
    Open {
        pathname: Pin<&'io_op CStr>,
        flags: OpenFlags,
    },
    Read {
        fd: Fd,
        buf: Pin<&'io_op mut [u8]>,
        offset: u64,
    },
    Close {
        fd: Fd,
    },
}

/// The opaque memory needed for the operation. The caller should have this allocated and manage the
/// memory, but should not need to know the contents.
pub struct Completion<'io_op> {
    operation: Operation<'io_op>,
    context: *const c_void,
    callback: *const c_void,
    trampoline: unsafe fn(*const c_void, *const c_void, io::Result<i32>),
}

impl<'a> Default for Completion<'a> {
    fn default() -> Self {
        Self {
            operation: Operation::Uninitialized,
            context: Default::default(),
            callback: Default::default(),
            trampoline: |_, _, _| panic!("uninitialized"),
        }
    }
}

impl<'io_op> Completion<'io_op> {
    fn prep(&mut self) -> squeue::Entry {
        use io_uring::opcode;
        let mut entry = match &mut self.operation {
            Operation::Uninitialized => unreachable!(),
            Operation::Open { pathname, flags } => {
                opcode::OpenAt::new(io_uring::types::Fd(libc::AT_FDCWD), pathname.as_ptr())
                    .flags(flags.bits())
                    .mode(0o644)
                    .file_index(None)
                    .build()
            }
            Operation::Read { fd, buf, offset } => {
                opcode::Read::new(fd.clone(), buf.as_mut_ptr(), buf.len() as u32)
                    .offset(*offset)
                    .build()
            }
            Operation::Close { fd } => opcode::Close::new(fd.clone()).build(),
        };
        entry.set_user_data(self as *const _ as u64);
        entry
    }

    fn complete(&mut self, result: i32) -> bool {
        let res = if result < 0 {
            let errno = -result;
            if errno == libc::EINTR {
                return false;
            }
            Err(io::Error::from_raw_os_error(errno))
        } else {
            Ok(result)
        };
        unsafe { (self.trampoline)(self.context, self.callback, res) }
        true
    }
}

bitflags! {
    /// Flags to pass to `openat`.
    pub struct OpenFlags: i32 {
        /// Open for reading only.
        const RDONLY = libc::O_RDONLY;
        /// Open for writing only.
        const WRONLY = libc::O_WRONLY;
        /// Open for reading and writing.
        const RDWR = libc::O_RDWR;
        /// Create file if it does not exist.
        const CREAT  = libc::O_CREAT;
        /// Truncate size to 0.
        const TRUNC  = libc::O_TRUNC;
        /// Append on each write.
        const APPEND  = libc::O_APPEND;
        /// Direct I/O.
        const DIRECT  = libc::O_DIRECT;
        /// Error if O_CREAT and the file exists.
        const EXCL  = libc::O_EXCL;
        /// Restrict open to a directory.
        const DIRECTORY  = libc::O_DIRECTORY;
    }
}

pub trait ContextPtr {
    fn into_raw(self) -> *const c_void;
    unsafe fn from_raw(ptr: *const c_void) -> Self;
}

impl<'a, T> ContextPtr for &'a mut T {
    fn into_raw(self) -> *const c_void {
        self as *mut T as *const c_void
    }

    unsafe fn from_raw(ptr: *const c_void) -> Self {
        unsafe { &mut *(ptr as *mut T) }
    }
}

impl<'a, T> ContextPtr for &'a T {
    fn into_raw(self) -> *const c_void {
        self as *const T as *const c_void
    }

    unsafe fn from_raw(ptr: *const c_void) -> Self {
        unsafe { &*(ptr as *const T) }
    }
}

impl IO {
    /// Creates a new `IO` instance with a new `io_uring` ring.
    pub fn new() -> Self {
        Self {
            uring: RefCell::new(IoUring::new(128).expect("iouring must be available")),
        }
    }

    pub fn drain(&self) -> io::Result<()> {
        let mut uring = self.uring.borrow_mut();
        let (submitter, mut sq, mut cq) = uring.split();
        while !sq.is_empty() {
            submitter.submit_and_wait(sq.len())?;
            cq.sync();
            while let Some(cqe) = cq.next() {
                let user_data = cqe.user_data();
                let comp = unsafe { &mut *(user_data as *mut Completion) };
                let ok = comp.complete(cqe.result());
                if !ok {
                    let mut entry = comp.prep();
                    unsafe {
                        sq.push(&mut entry).expect("TODO: handle full");
                    }
                }
            }
            sq.sync();
        }
        Ok(())
    }

    /// Submits an asynchronous `open` operation.
    pub fn open<'io_op, C: ContextPtr>(
        &self,
        context: C,
        pathname: Pin<&'io_op CStr>,
        flags: OpenFlags,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<Fd>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(
            ctx: *const c_void,
            cb: *const c_void,
            result: io::Result<i32>,
        ) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<Fd>) = std::mem::transmute(cb);
                (C::from_raw(ctx), cb)
            };
            callback(context, result.map(|fd| Fd(fd)))
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Open { pathname, flags };
        completion.callback = callback as *const c_void;
        completion.trampoline = trampoline::<C>;
        let mut entry = comp.prep();
        unsafe {
            self.uring
                .borrow_mut()
                .submission()
                .push(&mut entry)
                .expect("TODO: handle full")
        }
    }

    /// Submits an asynchronous `read` operation.
    ///
    /// Reads up to `buf.len()` bytes from the file descriptor `fd` at the specified `offset`.
    pub fn read<'io_op, C: ContextPtr>(
        &self,
        context: C,
        fd: Fd,
        buf: Pin<&'io_op mut [u8]>,
        offset: u64,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<u64>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(
            ctx: *const c_void,
            cb: *const c_void,
            result: io::Result<i32>,
        ) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<u64>) = std::mem::transmute(cb);
                (C::from_raw(ctx), cb)
            };
            callback(context, result.map(|amt| amt as u32 as u64))
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Read { fd, buf, offset };
        completion.callback = callback as *const c_void;
        completion.trampoline = trampoline::<C>;
        let mut entry = comp.prep();
        unsafe {
            self.uring
                .borrow_mut()
                .submission()
                .push(&mut entry)
                .expect("TODO: handle full")
        }
    }

    /// Submits an asynchronous `close` operation.
    ///
    /// Deletes the descriptor from the per-process object reference table.
    pub fn close<'io_op, C: ContextPtr>(
        &self,
        context: C,
        fd: Fd,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<()>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(
            ctx: *const c_void,
            cb: *const c_void,
            result: io::Result<i32>,
        ) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<()>) = std::mem::transmute(cb);
                (C::from_raw(ctx), cb)
            };
            callback(context, result.map(|r| assert_eq!(r, 0)))
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Close { fd };
        completion.callback = callback as *const c_void;
        completion.trampoline = trampoline::<C>;
        let mut entry = comp.prep();
        unsafe {
            self.uring
                .borrow_mut()
                .submission()
                .push(&mut entry)
                .expect("TODO: handle full")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::{pin, Pin};

    use super::*;

    fn open(io: &IO, filename: Pin<&CStr>, flags: OpenFlags) -> io::Result<Fd> {
        let comp = pin!(Default::default());
        let mut fd: Option<io::Result<Fd>> = None;
        io.open(&mut fd, filename, flags, comp, |store, fd| {
            *store = Some(fd);
        });
        io.drain()?;
        fd.expect("io should have finished")
    }

    fn read(io: &IO, fd: Fd, buf: Pin<&mut [u8]>, offset: u64) -> io::Result<u64> {
        let comp = pin!(Default::default());
        let mut result: Option<io::Result<u64>> = None;
        io.read(&mut result, fd, buf, offset, comp, |store, result| {
            *store = Some(result);
        });
        io.drain()?;
        result.expect("io should have finished")
    }

    fn close(io: &IO, fd: Fd) -> io::Result<()> {
        let comp = pin!(Default::default());
        let mut result: Option<io::Result<()>> = None;
        io.close(&mut result, fd, comp, |holder, r| {
            *holder = Some(r);
        });
        io.drain()?;
        result.expect("io should have finished")
    }

    #[test]
    fn read_file() {
        let io = IO::new();
        let fd = open(&io, pin!(c"./src/testdata/foo.txt"), OpenFlags::RDONLY)
            .expect("open should succeed");
        let mut buf: [u8; 4096] = [0; 4096];
        let pinned_buf = Pin::new(&mut buf[..]);
        let amt = read(&io, fd, pinned_buf, 0).expect("read should succeed");
        let expected = "Hello, world!\n";
        assert_eq!(amt, expected.len() as u64);
        assert_eq!(&buf[0..amt as usize], expected.as_bytes());
        close(&io, fd).expect("close should succeed");
    }
}
