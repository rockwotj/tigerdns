use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::io::IO;

mod io;

struct StartupAllocator {
    locked: AtomicBool,
}

impl StartupAllocator {
    const fn new() -> Self {
        StartupAllocator {
            locked: AtomicBool::new(false),
        }
    }
    /// Lock memory such that no more maybe allocated
    fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst)
    }
}

unsafe impl GlobalAlloc for StartupAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.locked.load(Ordering::Relaxed) {
            std::process::abort();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if self.locked.load(Ordering::Relaxed) {
            std::process::abort();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if self.locked.load(Ordering::Relaxed) {
            std::process::abort();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: StartupAllocator = StartupAllocator::new();

fn main() {
    // Startup
    let io = IO::new();

    // Free allocations
    GLOBAL.lock();

    // Run!
    io.tick().expect("io failure");
}
