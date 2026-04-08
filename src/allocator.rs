use std::alloc::{GlobalAlloc, Layout, System};

pub struct StartupAllocator {
    // TODO: Thread local might be cleaner
    alloc_mu: std::sync::Mutex<()>,
    crash_mu: std::sync::Mutex<()>,
}

impl StartupAllocator {
    pub const fn new() -> Self {
        StartupAllocator {
            alloc_mu: std::sync::Mutex::new(()),
            crash_mu: std::sync::Mutex::new(()),
        }
    }
    /// Lock memory such that no more maybe allocated
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.alloc_mu.lock().unwrap()
    }
    fn crash_with_backtrace(&self) -> ! {
        eprintln!(
            "allocation at: {}",
            std::backtrace::Backtrace::force_capture()
        );
        std::process::abort();
    }
}

unsafe impl GlobalAlloc for StartupAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match self.alloc_mu.try_lock() {
            Ok(_) => unsafe { System.alloc(layout) },
            Err(_) => match self.crash_mu.try_lock() {
                Ok(_) => self.crash_with_backtrace(),
                Err(_) => unsafe { System.alloc(layout) },
            },
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match self.alloc_mu.try_lock() {
            Ok(_) => unsafe { System.alloc_zeroed(layout) },
            Err(_) => match self.crash_mu.try_lock() {
                Ok(_) => self.crash_with_backtrace(),
                Err(_) => unsafe { System.alloc_zeroed(layout) },
            },
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        match self.alloc_mu.try_lock() {
            Ok(_) => unsafe { System.realloc(ptr, layout, new_size) },
            Err(_) => match self.crash_mu.try_lock() {
                Ok(_) => self.crash_with_backtrace(),
                Err(_) => unsafe { System.realloc(ptr, layout, new_size) },
            },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
pub static GLOBAL: StartupAllocator = StartupAllocator::new();
