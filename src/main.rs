use io_uring::types::Fd;

use crate::io::{IO, OpenFlags};
use std::{
    io::Result,
    pin::{Pin, pin},
    task::{Context, Poll},
};

mod allocator;
mod io;

extern "C" fn handle_sigint(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _data: *mut libc::c_void,
) {
    const MSG: &[u8] = b"Caught SIGINT\n";
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG.as_ptr() as *const _, MSG.len());
    }
}

fn main() {
    unsafe {
        let mut handler: libc::sigaction = std::mem::zeroed();
        handler.sa_sigaction = handle_sigint as *const () as usize;
        libc::sigemptyset(&mut handler.sa_mask);
        handler.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        let r = libc::sigaction(libc::SIGINT, &handler as *const _, std::ptr::null_mut());
        if r == -1 {
            let err = std::io::Error::last_os_error();
            panic!("failed to setup signal handler: {}", err);
        }
    }

    // Startup
    let io = IO::new();

    // Freeze allocations
    let _guard = allocator::GLOBAL.lock();

    let main_fut = async_main(&io);
    let result = block_on(&io, pin!(main_fut));

    drop(_guard); // Drop so we can allocate to print the unwrap and abort

    result.unwrap();
}

fn block_on<F: Future>(io: &IO, mut fut: Pin<&mut F>) -> F::Output {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    loop {
        if let Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
            return val;
        }
        io.drain().expect("drain failed");
    }
}

async fn async_main(io: &IO) -> Result<()> {
    let socket_fd = io
        .socket(io::SocketDomain::INet, io::SocketType::DGram)
        .await?;
    let stdout_fd = match io
        .open(
            pin!(c"/dev/stdout"),
            OpenFlags::WriteOnly | OpenFlags::Append,
        )
        .await
    {
        Ok(fd) => fd,
        Err(err) => {
            let _ = io.close(socket_fd).await;
            return Err(err);
        }
    };
    let run_result = run_server(io, socket_fd, stdout_fd).await;
    let socket_close_result = io.close(socket_fd).await;
    let stdout_close_result = io.close(stdout_fd).await;
    run_result.and(socket_close_result).and(stdout_close_result)
}

async fn run_server(io: &IO, socket_fd: Fd, stdout_fd: Fd) -> Result<()> {
    io.bind(
        socket_fd,
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            10053,
        )),
    )
    .await?;
    let mut buf = [0u8; 5000];
    loop {
        let amt = io.read(socket_fd, pin!(&mut buf[..4096]), 0).await?;
        buf[amt] = b'\n'; // Add a newline
        let mut recv_buf = &buf[..amt + 1];
        loop {
            let amt = io.write(stdout_fd, pin!(recv_buf), 0).await?;
            recv_buf = &recv_buf[amt..];
            if recv_buf.is_empty() {
                break;
            }
        }
    }
}
