#![no_std]
#![no_main]

use core::fmt;
use rustix::io::Errno;
use rustix::stdio::stderr;
use syscalls::syscall;

use core::fmt::Write;

mod udp;

struct PanicWriter;

impl Write for PanicWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // rustix::io::write takes a file descriptor and a byte slice.
        // It returns a Result, but in a panic handler, we ignore errors
        // because there's nothing we can do if stderr is broken.
        // SAFETY: stderr is not closed, don't do that please
        let mut b = s.as_bytes();
        while !b.is_empty() {
            match unsafe { rustix::io::write(stderr(), b) } {
                Ok(amt) => b = &b[amt..],
                Err(Errno::INTR) => continue,
                _ => break,
            }
        }
        Ok(())
    }
}

#[panic_handler]
pub(crate) fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut writer = PanicWriter;
    if let Some(location) = info.location() {
        let _ = write!(&mut writer, "panic: {} @ {}\n", info.message(), location);
    } else {
        let _ = write!(&mut writer, "panic: {}\n", info.message());
    }
    exit(101);
}

// With panic=abort this is never called, but the linker still needs the symbol.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

fn exit(code: i32) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        syscall!(syscalls::x86_64::Sysno::exit, code).expect("must exit");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        syscall!(syscalls::aarch64::Sysno::exit, code).expect("must exit");
    }
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    match udp::run() {
        Ok(_) => 0,
        Err(errno) => {
            let mut w = PanicWriter;
            let _ = write!(&mut w, "{}", errno);
            1
        }
    }
}
