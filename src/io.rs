use core::{
    cell::RefCell,
    ffi::CStr,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{io, pin::pin};

use bitflags::bitflags;
use io_uring::{IoUring, squeue, types::Fd};
use libc;

/// Our internal abstraction around IOUring.
pub struct IO {
    uring: RefCell<IoUring>,
}

pub enum Operation<'io_op> {
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
    Write {
        fd: Fd,
        buf: Pin<&'io_op [u8]>,
        offset: u64,
    },
    Close {
        fd: Fd,
    },
    Socket {
        domain: SocketDomain,
        socket_type: SocketType,
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
    Connect {
        fd: Fd,
        raw_socket_data: [u8; 28],
        raw_socket_length: libc::socklen_t,
    },
    SetSocketOption {
        fd: Fd,
        opt: SocketOption,
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

#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketOptionFlag {
    Enable = 1,
    Disable = 0,
}

#[derive(Copy, Clone)]
pub enum SocketOption {
    RecvBufferSize(i32),
    SendBufferSize(i32),
    ReuseAddress(SocketOptionFlag),
    ReusePort(SocketOptionFlag),
    KeepAlive(SocketOptionFlag),
    Linger(libc::linger),
    TCPNoDelay(SocketOptionFlag),
    TCPCork(SocketOptionFlag),
    TCPKeepIdle(i32),
    TCPKeepInterval(i32),
    TCPKeepCount(i32),
}

impl SocketOption {
    fn name(&self) -> i32 {
        match *self {
            SocketOption::RecvBufferSize(_) => libc::SO_RCVBUF,
            SocketOption::SendBufferSize(_) => libc::SO_SNDBUF,
            SocketOption::ReuseAddress(_) => libc::SO_REUSEADDR,
            SocketOption::ReusePort(_) => libc::SO_REUSEPORT,
            SocketOption::KeepAlive(_) => libc::SO_KEEPALIVE,
            SocketOption::Linger(_) => libc::SO_LINGER,
            SocketOption::TCPNoDelay(_) => libc::TCP_NODELAY,
            SocketOption::TCPCork(_) => libc::TCP_CORK,
            SocketOption::TCPKeepIdle(_) => libc::TCP_KEEPIDLE,
            SocketOption::TCPKeepInterval(_) => libc::TCP_KEEPINTVL,
            SocketOption::TCPKeepCount(_) => libc::TCP_KEEPCNT,
        }
    }
    fn level(&self) -> i32 {
        match *self {
            SocketOption::RecvBufferSize(_)
            | SocketOption::SendBufferSize(_)
            | SocketOption::ReuseAddress(_)
            | SocketOption::ReusePort(_)
            | SocketOption::KeepAlive(_)
            | SocketOption::Linger(_) => libc::SOL_SOCKET,
            SocketOption::TCPNoDelay(_)
            | SocketOption::TCPCork(_)
            | SocketOption::TCPKeepIdle(_)
            | SocketOption::TCPKeepInterval(_)
            | SocketOption::TCPKeepCount(_) => libc::IPPROTO_TCP,
        }
    }
    fn value(&self) -> *const libc::c_void {
        match self {
            SocketOption::RecvBufferSize(v) => v as *const _ as *const libc::c_void,
            SocketOption::SendBufferSize(v) => v as *const _ as *const libc::c_void,
            SocketOption::ReuseAddress(v) => v as *const _ as *const libc::c_void,
            SocketOption::ReusePort(v) => v as *const _ as *const libc::c_void,
            SocketOption::KeepAlive(v) => v as *const _ as *const libc::c_void,
            SocketOption::Linger(linger) => linger as *const _ as *const libc::c_void,
            SocketOption::TCPNoDelay(v) => v as *const _ as *const libc::c_void,
            SocketOption::TCPCork(v) => v as *const _ as *const libc::c_void,
            SocketOption::TCPKeepIdle(v) => v as *const _ as *const libc::c_void,
            SocketOption::TCPKeepInterval(v) => v as *const _ as *const libc::c_void,
            SocketOption::TCPKeepCount(v) => v as *const _ as *const libc::c_void,
        }
    }
    fn value_len(&self) -> libc::socklen_t {
        match *self {
            SocketOption::Linger(_) => core::mem::size_of::<libc::linger>() as libc::socklen_t,
            _ => core::mem::size_of::<i32>() as libc::socklen_t,
        }
    }
}

/// The opaque memory needed for the operation. No allocations needed.
/// Holds the async state and the waker.
pub struct Completion<'io_op> {
    operation: Operation<'io_op>,
    waker: Option<Waker>,
    result: Option<io::Result<i32>>,
}

impl<'a> Default for Completion<'a> {
    fn default() -> Self {
        Self {
            operation: Operation::Uninitialized,
            waker: None,
            result: None,
        }
    }
}

fn buffer_limit(buf_len: usize) -> u32 {
    const LIMIT: usize = 0x7ffff000;
    core::cmp::min(LIMIT, buf_len) as u32
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
                opcode::Read::new(*fd, buf.as_mut_ptr(), buffer_limit(buf.len()))
                    .offset(*offset)
                    .build()
            }
            Operation::Write { fd, buf, offset } => {
                opcode::Write::new(*fd, buf.as_ptr(), buffer_limit(buf.len()))
                    .offset(*offset)
                    .build()
            }
            Operation::Close { fd } => opcode::Close::new(*fd).build(),
            Operation::Socket {
                domain,
                socket_type,
            } => opcode::Socket::new(*domain as i32, *socket_type as i32, 0).build(),
            Operation::Bind {
                fd,
                raw_socket_data,
                raw_socket_len,
            } => opcode::Bind::new(
                *fd,
                raw_socket_data.as_ptr() as *const libc::sockaddr,
                *raw_socket_len,
            )
            .build(),
            Operation::Listen { fd, backlog } => opcode::Listen::new(*fd, *backlog).build(),
            Operation::Accept {
                fd,
                raw_socket_data,
                raw_socket_length,
            } => opcode::Accept::new(
                *fd,
                raw_socket_data.as_mut_ptr() as *mut libc::sockaddr,
                raw_socket_length as *mut libc::socklen_t,
            )
            .build(),
            Operation::Connect {
                fd,
                raw_socket_data,
                raw_socket_length,
            } => opcode::Connect::new(
                *fd,
                raw_socket_data.as_mut_ptr() as *const libc::sockaddr,
                *raw_socket_length,
            )
            .build(),
            Operation::SetSocketOption { fd, opt } => opcode::SetSockOpt::new(
                *fd,
                opt.level() as u32,
                opt.name() as u32,
                opt.value(),
                opt.value_len(),
            )
            .build(),
        };
        entry.set_user_data(self as *const _ as u64);
        entry
    }
}

bitflags! {
    pub struct OpenFlags: i32 {
        const Readonly = libc::O_RDONLY;
        const WriteOnly = libc::O_WRONLY;
        const ReadWrite = libc::O_RDWR;
        const Create  = libc::O_CREAT;
        const Truncate  = libc::O_TRUNC;
        const Append  = libc::O_APPEND;
        const Direct  = libc::O_DIRECT;
        const Exclusive  = libc::O_EXCL;
        const Directory  = libc::O_DIRECTORY;
    }
}

/// An inline Future that handles submission and waking.
struct OpFuture<'a, 'io_op> {
    io: &'a IO,
    comp: Pin<&'a mut Completion<'io_op>>,
    submitted: bool,
}

impl<'a, 'io_op> Future for OpFuture<'a, 'io_op> {
    type Output = io::Result<i32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        // 1. Check if background reactor updated the result
        if let Some(res) = this.comp.result.take() {
            return Poll::Ready(res);
        }

        // 2. Submit to IO uring if first poll
        if !this.submitted {
            let mut entry = this.comp.prep();
            unsafe {
                this.io
                    .uring
                    .borrow_mut()
                    .submission()
                    .push(&mut entry)
                    .expect("SQ full; add submitter loop handling if needed");
            }
            this.submitted = true;
        }

        // 3. Register the waker for the reactor to hit when the CQE is reaped
        // Using unchecked mut because setting waker doesn't move the pinned structure memory.
        unsafe {
            let comp_mut = this.comp.as_mut().get_unchecked_mut();
            comp_mut.waker = Some(cx.waker().clone());
        }

        Poll::Pending
    }
}

impl IO {
    pub fn new() -> Self {
        Self {
            uring: RefCell::new(IoUring::new(128).expect("iouring must be available")),
        }
    }

    /// The reactor step. You'd call this after polling futures or inside your `epoll`/blocking loop.
    pub fn drain(&self) -> io::Result<()> {
        let mut uring = self.uring.borrow_mut();
        let (submitter, mut sq, mut cq) = uring.split();

        while !sq.is_empty() {
            submitter.submit_and_wait(sq.len())?;
            cq.sync();

            while let Some(cqe) = cq.next() {
                let user_data = cqe.user_data();
                let comp = unsafe { &mut *(user_data as *mut Completion) };

                let result = cqe.result();

                // Fast-path EINTR retry without bothering the Future/Executor
                if result < 0 && -result == libc::EINTR {
                    let mut entry = comp.prep();
                    unsafe {
                        sq.push(&mut entry).expect("SQ is full on retry");
                    }
                    continue;
                }

                let parsed_res = if result < 0 {
                    Err(io::Error::from_raw_os_error(-result))
                } else {
                    Ok(result)
                };

                comp.result = Some(parsed_res);
                if let Some(waker) = comp.waker.take() {
                    waker.wake();
                }
            }
            sq.sync();
        }
        Ok(())
    }

    pub async fn open<'io_op>(
        &self,
        pathname: Pin<&'io_op CStr>,
        flags: OpenFlags,
    ) -> io::Result<Fd> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Open { pathname, flags };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|fd| Fd(fd))
    }

    pub async fn read<'io_op>(
        &self,
        fd: Fd,
        buf: Pin<&'io_op mut [u8]>,
        offset: u64,
    ) -> io::Result<usize> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Read { fd, buf, offset };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|amt| amt as usize)
    }

    pub async fn write<'io_op>(
        &self,
        fd: Fd,
        buf: Pin<&'io_op [u8]>,
        offset: u64,
    ) -> io::Result<usize> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Write { fd, buf, offset };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|amt| amt as usize)
    }

    pub async fn close<'io_op>(&self, fd: Fd) -> io::Result<()> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Close { fd };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|_| ())
    }

    pub async fn socket<'io_op>(
        &self,
        domain: SocketDomain,
        socket_type: SocketType,
    ) -> io::Result<Fd> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Socket {
            domain,
            socket_type,
        };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|fd| Fd(fd))
    }

    pub async fn bind<'io_op>(&self, fd: Fd, addr: std::net::SocketAddr) -> io::Result<()> {
        let (raw, raw_len) = create_socket_addr(addr);
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Bind {
            fd,
            raw_socket_data: raw,
            raw_socket_len: raw_len,
        };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|_| ())
    }

    pub async fn listen<'io_op>(&self, fd: Fd, backlog_length: i32) -> io::Result<()> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Listen {
            fd,
            backlog: backlog_length,
        };
        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|_| ())
    }

    pub async fn accept<'io_op>(&self, fd: Fd) -> io::Result<(Fd, std::net::SocketAddr)> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::Accept {
            fd,
            raw_socket_data: [0; 28],
            raw_socket_length: 28, // Max size to ensure no truncation from kernel
        };

        // We re-borrow `comp` cleanly so we can inspect it after resolving.
        let result = OpFuture {
            io: self,
            comp: pin!(&mut comp),
            submitted: false,
        }
        .await?;
        let fd_out = Fd(result);

        let (raw_data, raw_len) = match &comp.operation {
            Operation::Accept {
                raw_socket_data,
                raw_socket_length,
                ..
            } => (raw_socket_data, *raw_socket_length),
            _ => unreachable!(),
        };

        fn from_slice_unsafe<T: Sized>(bytes: &[u8]) -> &T {
            assert!(bytes.len() >= core::mem::size_of::<T>());
            unsafe { &*(bytes.as_ptr() as *const T) }
        }

        let raw = raw_data.get(..raw_len as usize).unwrap();
        let family = from_slice_unsafe::<libc::sockaddr>(raw);
        let addr = match family.sa_family as i32 {
            libc::AF_INET => {
                let addr = from_slice_unsafe::<libc::sockaddr_in>(raw);
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from_bits(u32::from_be(addr.sin_addr.s_addr)),
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

        Ok((fd_out, addr))
    }

    pub async fn connect<'io_op>(&self, fd: Fd, addr: std::net::SocketAddr) -> io::Result<()> {
        let mut comp = Completion::<'io_op>::default();
        let (raw, raw_len) = create_socket_addr(addr);
        comp.operation = Operation::Connect {
            fd,
            raw_socket_data: raw,
            raw_socket_length: raw_len,
        };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|_| ())
    }

    pub async fn set_sock_opt<'io_op>(&self, fd: Fd, opt: SocketOption) -> io::Result<()> {
        let mut comp = Completion::<'io_op>::default();
        comp.operation = Operation::SetSocketOption { fd, opt };

        OpFuture {
            io: self,
            comp: pin!(comp),
            submitted: false,
        }
        .await
        .map(|_| ())
    }
}

fn create_socket_addr(addr: std::net::SocketAddr) -> ([u8; 28], u32) {
    let mut raw: [u8; 28] = [0; 28];
    fn copy_into<T: Sized>(src: &T, dst: &mut [u8; 28]) -> u32 {
        let raw = unsafe {
            core::slice::from_raw_parts((src as *const T) as *const u8, core::mem::size_of::<T>())
        };
        dst[..raw.len()].copy_from_slice(raw);
        raw.len() as u32
    }
    let raw_len: u32;
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: v4.ip().to_bits().to_be(),
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
    (raw, raw_len)
}

#[cfg(test)]
mod tests {
    use futures::task::noop_waker;

    use crate::allocator;

    use super::*;
    use core::pin::{Pin, pin};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        task::{Context, Poll},
    };

    /// A simple no_std compatible event loop for our tests.
    fn block_on<F: Future>(io: &IO, mut fut: Pin<&mut F>) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        loop {
            if let Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
                return val;
            }
            io.drain().expect("drain failed");
        }
    }

    #[test]
    fn read_file() {
        let _guard = allocator::GLOBAL.lock();
        let io = IO::new();

        // Use an async block and pin it locally
        let test_fut = pin!(async {
            let fd = io
                .open(pin!(c"./src/testdata/foo.txt"), OpenFlags::Readonly)
                .await
                .expect("open should succeed");

            let mut buf: [u8; 4096] = [0; 4096];

            let amt = io
                .read(fd, Pin::new(&mut buf[..]), 0)
                .await
                .expect("read should succeed");

            let expected = "Hello, world!\n";
            assert_eq!(amt, expected.len());
            assert_eq!(&buf[0..amt as usize], expected.as_bytes());

            io.close(fd).await.expect("close should succeed");
        });

        block_on(&io, test_fut);
    }

    #[test]
    fn write_file() {
        let _guard = allocator::GLOBAL.lock();
        let io = IO::new();

        let test_fut = pin!(async {
            let fd = io
                .open(
                    pin!(c"./src/testdata/bar.txt"),
                    OpenFlags::Create
                        | OpenFlags::Truncate
                        | OpenFlags::ReadWrite
                        | OpenFlags::Direct,
                )
                .await
                .expect("open should succeed");

            let mut buf: [u8; 4096] = [0; 4096];
            let expected = "Hello, world!\n";
            buf[..expected.len()].copy_from_slice(expected.as_bytes());

            let amt = io
                .write(fd, Pin::new(&buf[..expected.len()]), 0)
                .await
                .expect("write should succeed");

            assert_eq!(amt, expected.len());

            let mut read_buf = [0; 4096];
            let amt = io
                .read(fd, Pin::new(&mut read_buf[..]), 0)
                .await
                .expect("read should succeed");

            assert_eq!(&read_buf[0..amt as usize], expected.as_bytes());

            io.close(fd).await.expect("close should succeed");
        });

        block_on(&io, test_fut);
    }

    #[test]
    fn test_socket_configuration() {
        let _guard = allocator::GLOBAL.lock();
        let io = IO::new();

        let test_fut = pin!(async {
            // 1. Create a TCP Socket
            let fd = io
                .socket(SocketDomain::INet, SocketType::Stream)
                .await
                .expect("socket creation failed");

            // 2. Set Socket Options (TCP_NODELAY)
            io.set_sock_opt(fd, SocketOption::TCPNoDelay(SocketOptionFlag::Enable))
                .await
                .expect("set_sock_opt failed");

            // 3. Set Reuse Address
            io.set_sock_opt(fd, SocketOption::ReuseAddress(SocketOptionFlag::Enable))
                .await
                .expect("set_reuse_addr failed");

            // 4. Close
            io.close(fd).await.expect("close failed");
        });

        block_on(&io, test_fut);
    }

    #[test]
    fn test_tcp_bind_and_listen() {
        let _guard = allocator::GLOBAL.lock();
        let io = IO::new();

        let test_fut = pin!(async {
            let fd = io
                .socket(SocketDomain::INet, SocketType::Stream)
                .await
                .expect("socket failed");

            // Bind to an ephemeral port on localhost
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            io.bind(fd, addr).await.expect("bind failed");

            // Start listening
            io.listen(fd, 128).await.expect("listen failed");

            io.close(fd).await.expect("close failed");
        });

        block_on(&io, test_fut);
    }

    #[test]
    fn test_tcp_full_handshake() {
        let _guard = allocator::GLOBAL.lock();
        let io = IO::new();

        let test_fut = pin!(async {
            // --- SERVER SETUP ---
            let l_fd = io
                .socket(SocketDomain::INet, SocketType::Stream)
                .await
                .expect("server socket failed");

            io.set_sock_opt(l_fd, SocketOption::ReuseAddress(SocketOptionFlag::Enable))
                .await
                .unwrap();

            // Bind to a specific local port
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
            io.bind(l_fd, srv_addr).await.expect("bind failed");

            io.listen(l_fd, 5).await.expect("listen failed");

            // --- CLIENT CONNECT ---
            // Note: In a real app, you'd spawn a task. Here we just chain the logic.
            // Since io_uring is async, the 'accept' can be pending while we 'connect'.

            let c_fd = io
                .socket(SocketDomain::INet, SocketType::Stream)
                .await
                .expect("client socket failed");

            // Since we are single-threaded, we have to be careful with the order.
            // We initiate the connect.

            // We use a manual poll-loop for the handshake to avoid blocking on one.
            let connect_fut = io.connect(c_fd, srv_addr);
            let accept_fut = io.accept(l_fd);

            // Logic: The connect will complete once the kernel processes the SYN/ACK.
            // The accept will complete once the handshake is done.

            // To keep the test simple without a full 'select!', we just await them sequentially.
            // io_uring will queue the accept, then the connect will trigger it.
            let (conn_res, accept_res) = futures::join!(connect_fut, accept_fut);

            conn_res.expect("client connect failed");
            let (connected_fd, _client_addr) = accept_res.expect("server accept failed");

            // Clean up
            io.close(c_fd).await.unwrap();
            io.close(connected_fd).await.unwrap();
            io.close(l_fd).await.unwrap();
        });

        block_on(&io, test_fut);
    }
}
