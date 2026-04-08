use crate::io::IO;

mod allocator;
mod io;

fn main() {
    // Startup
    let io = IO::new();

    // Freeze allocations
    let _guard = allocator::GLOBAL.lock();

    // Run!
    io.drain().expect("io failure");
}
