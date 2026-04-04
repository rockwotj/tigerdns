use core::ptr;

use rustix_uring::{self as uring, Errno};

pub(crate) fn run() -> Result<(), Errno> {
    use rustix::net;
    let mut ring = uring::IoUring::new(128)?;
    let sockfd = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        Some(net::ipproto::UDP),
    )?;
    net::bind(
        sockfd,
        &net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 1053),
    )?;
    let (submitter, mut sq, mut cq) = ring.split();

    let accept =
        uring::opcode::Accept::new(sockfd.into(), ptr::null_mut(), ptr::null_mut()).build();
    unsafe {
        sq.push(&accept).expect("to not be full");
    }
    Ok(())
}
