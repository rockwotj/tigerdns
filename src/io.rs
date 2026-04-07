use std::{
    cell::RefCell,
    ffi::{CStr, c_void},
    io,
    pin::Pin,
};

use bitflags::bitflags;
use io_uring::{IoUring, squeue, types::Fd};
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
    Socket {
        domain: SocketDomain,
        socket_type: SocketType,
        // We always set protocol to 0 for teh sockets we support
        // protocol: i32,
    },
    Bind {
        fd: Fd,
        raw_socket_data: [u8; 28],
        raw_socket_len: libc::socklen_t,
    },
    Listen {
        fd: Fd,
        backlog: i32,
    },
    Accept {
        fd: Fd,
        raw_socket_data: [u8; 28],
        raw_socket_length: libc::socklen_t,
    },
}

#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketDomain {
    INet = libc::PF_INET,
    INet6 = libc::PF_INET6,
}

#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketType {
    Stream = libc::SOCK_STREAM,
    DGram = libc::SOCK_DGRAM,
    Raw = libc::SOCK_RAW,
}

/// The opaque memory needed for the operation. The caller should have this allocated and manage the
/// memory, but should not need to know the contents.
pub struct Completion<'io_op> {
    operation: Operation<'io_op>,
    context: *const c_void,
    callback: *const c_void,
    trampoline: unsafe fn(&mut Completion<'io_op>, io::Result<i32>),
    prev: *mut Completion<'io_op>,
    next: *mut Completion<'io_op>,
}

impl<'a> Default for Completion<'a> {
    fn default() -> Self {
        Self {
            operation: Operation::Uninitialized,
            context: Default::default(),
            callback: Default::default(),
            trampoline: |_, _| panic!("uninitialized"),
            prev: Default::default(),
            next: Default::default(),
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
            Operation::Socket {
                domain,
                socket_type,
            } => opcode::Socket::new(*domain as i32, *socket_type as i32, 0).build(),
            Operation::Bind {
                fd,
                raw_socket_data,
                raw_socket_len,
            } => opcode::Bind::new(
                fd.clone(),
                raw_socket_data.as_ptr() as *const libc::sockaddr,
                *raw_socket_len,
            )
            .build(),
            Operation::Listen { fd, backlog } => opcode::Listen::new(fd.clone(), *backlog).build(),
            Operation::Accept {
                fd,
                raw_socket_data,
                raw_socket_length,
            } => opcode::Accept::new(
                fd.clone(),
                raw_socket_data.as_mut_ptr() as *mut libc::sockaddr,
                raw_socket_length as *mut libc::socklen_t,
            )
            .build(),
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
        unsafe { (self.trampoline)(self, res) }
        true
    }
}

bitflags! {
    /// Flags to pass to `openat`.
    pub struct OpenFlags: i32 {
        /// Open for reading only.
        const Readonly = libc::O_RDONLY;
        /// Open for writing only.
        const WriteOnly = libc::O_WRONLY;
        /// Open for reading and writing.
        const ReadWrite = libc::O_RDWR;
        /// Create file if it does not exist.
        const Create  = libc::O_CREAT;
        /// Truncate size to 0.
        const Truncate  = libc::O_TRUNC;
        /// Append on each write.
        const Append  = libc::O_APPEND;
        /// Direct I/O.
        const Direct  = libc::O_DIRECT;
        /// Error if O_CREAT and the file exists.
        const Exclusive  = libc::O_EXCL;
        /// Restrict open to a directory.
        const Directory  = libc::O_DIRECTORY;
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
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<Fd>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
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
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<u64>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
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
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<()>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
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

    pub fn socket<'io_op, C: ContextPtr>(
        &self,
        context: C,
        domain: SocketDomain,
        socket_type: SocketType,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<Fd>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<Fd>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
            };
            callback(context, result.map(|fd| Fd(fd)))
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Socket {
            domain,
            socket_type,
        };
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

    pub fn bind<'io_op, C: ContextPtr>(
        &self,
        context: C,
        fd: Fd,
        addr: std::net::SocketAddr,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<()>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<Fd>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
            };
            callback(context, result.map(|fd| Fd(fd)))
        }
        completion.context = context.into_raw();
        // Wow this is really verbose to do a C memcpy :P
        let mut raw: [u8; 28] = [0; 28];
        fn copy_into<T: Sized>(src: &T, dst: &mut [u8; 28]) -> u32 {
            let raw = unsafe {
                std::slice::from_raw_parts((src as *const T) as *const u8, std::mem::size_of::<T>())
            };
            assert!(raw.len() <= dst.len(), "src must be smaller than dst");
            for (i, &b) in raw.iter().enumerate() {
                dst[i] = b;
            }
            raw.len() as u32
        }
        let raw_len: u32;
        match addr {
            std::net::SocketAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: v4.ip().to_bits(),
                    },
                    sin_zero: [0; 8],
                };
                raw_len = copy_into(&sa, &mut raw);
            }
            std::net::SocketAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u16,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    sin6_scope_id: v6.scope_id(),
                };
                raw_len = copy_into(&sa, &mut raw);
            }
        };
        completion.operation = Operation::Bind {
            fd,
            raw_socket_data: raw,
            raw_socket_len: raw_len,
        };
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

    pub fn listen<'io_op, C: ContextPtr>(
        &self,
        context: C,
        fd: Fd,
        backlog_length: i32,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<()>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<()>) = std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
            };
            callback(context, result.map(|r| assert_eq!(r, 0)))
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Listen {
            fd,
            backlog: backlog_length,
        };
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

    pub fn accept<'io_op, C: ContextPtr>(
        &self,
        context: C,
        fd: Fd,
        mut comp: Pin<&mut Completion<'io_op>>,
        callback: fn(C, io::Result<(Fd, std::net::SocketAddr)>),
    ) {
        let completion = &mut *comp;
        unsafe fn trampoline<C: ContextPtr>(comp: &mut Completion, result: io::Result<i32>) {
            let (context, callback) = unsafe {
                let cb: fn(C, io::Result<(Fd, std::net::SocketAddr)>) =
                    std::mem::transmute(comp.callback);
                (C::from_raw(comp.context), cb)
            };
            match comp.operation {
                Operation::Accept {
                    fd: _,
                    raw_socket_data,
                    raw_socket_length,
                } => {
                    fn from_slice_unsafe<T: Sized>(bytes: &[u8]) -> &T {
                        assert!(
                            bytes.len() >= std::mem::size_of::<T>(),
                            "expected to have at least {} for {} got: {}",
                            std::mem::size_of::<T>(),
                            std::any::type_name::<T>(),
                            bytes.len(),
                        );
                        unsafe {
                            // Cast the slice pointer to a struct pointer
                            let ptr = bytes.as_ptr() as *const T;
                            &*ptr // Dereference to get the reference
                        }
                    }
                    let raw = raw_socket_data
                        .get(..raw_socket_length as usize)
                        .expect("to be less than our socket data struct");
                    let family = from_slice_unsafe::<libc::sockaddr>(raw);
                    let addr = match family.sa_family as i32 {
                        libc::AF_INET => {
                            let addr = from_slice_unsafe::<libc::sockaddr_in>(raw);
                            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                                std::net::Ipv4Addr::from_bits(addr.sin_addr.s_addr),
                                addr.sin_port,
                            ))
                        }
                        libc::AF_INET6 => {
                            let addr = from_slice_unsafe::<libc::sockaddr_in6>(raw);
                            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                std::net::Ipv6Addr::from_octets(addr.sin6_addr.s6_addr),
                                addr.sin6_port,
                                addr.sin6_flowinfo,
                                addr.sin6_scope_id,
                            ))
                        }
                        _ => panic!("unknown sock type {}", family.sa_family),
                    };
                    callback(context, result.map(|fd| (Fd(fd), addr)));
                }
                _ => panic!("incorrect operation type"),
            };
        }
        completion.context = context.into_raw();
        completion.operation = Operation::Accept {
            fd,
            raw_socket_data: Default::default(),
            raw_socket_length: Default::default(),
        };
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
    use std::pin::{Pin, pin};

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
        let fd = open(&io, pin!(c"./src/testdata/foo.txt"), OpenFlags::Readonly)
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
