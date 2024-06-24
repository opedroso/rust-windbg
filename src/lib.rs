use std::thread;
use std::thread::ThreadId;
use std::sync::{Once, Arc};
use windows::Win32::System::Threading::GetCurrentThreadStackLimits;
use windows::Win32::System::Threading::GetCurrentThread;
use windows::Win32::Foundation::CloseHandle;

pub struct ThreadInfo {
    main_thread_id: ThreadId,
}

impl ThreadInfo {
    pub fn get_thread_name() -> String { // No arguments
        let thread_info = get_thread_info();
        let current_thread = thread::current();
        let thread_id = current_thread.id();
        if current_thread.name().is_none() && thread_id == thread_info.main_thread_id {
            "main".to_string()
        } else {
            current_thread.name().unwrap_or("<unnamed>").to_string()
        }
    }

    pub fn print_thread_id() { // No arguments
        let thread_name = ThreadInfo::get_thread_name(); 
        let thread_id = thread::current().id();

        println!("Running on thread_id {:?} named '{}'", thread_id, thread_name);
    }

    pub fn init_from_main_thread() {  // No arguments
        // getting it creates and sets the caller thread_id as the main thread id
        let _thread_info = get_thread_info(); 
    }

    pub fn print_stack_extents_win() {
        unsafe {
            // Get the current thread handle
            let _thread_handle = GetCurrentThread();
    
            // Initialize variables to store stack limits
            let mut stack_base: usize = 0;
            let mut stack_limit: usize = 0;
    
            // Retrieve the stack limits
            GetCurrentThreadStackLimits(&mut stack_base, &mut stack_limit);
            let _result = CloseHandle(_thread_handle);
    
            // Print the stack addresses
            println!("print_stack_extents_win: Stack base address : 0x{:016x}", stack_base);
            println!("print_stack_extents_win: Stack limit address: 0x{:016x}", stack_limit);
            let stack_extent = stack_limit - stack_base;
            println!("print_stack_extents_win: Stack extent       : {}  (0x{:x})", stack_extent, stack_extent);
        }
    }

    pub fn get_stack_size() -> Result<usize, &'static str> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                // Get the current thread handle
                let _thread_handle = GetCurrentThread();
        
                // Initialize variables to store stack limits
                let mut stack_base: usize = 0;
                let mut stack_limit: usize = 0;
        
                // Retrieve the stack limits
                GetCurrentThreadStackLimits(&mut stack_base, &mut stack_limit);
                // let _result = CloseHandle(_thread_handle);

                Ok((stack_limit - stack_base) + 1)
            }
        }

        #[cfg(target_os = "linux")]
        {
            let mut attr: libc::pthread_attr_t = std::mem::zeroed();
            let err = unsafe { libc::pthread_getattr_np(libc::pthread_self(), &mut attr) };

            if err == 0 {
                let mut stack_size: libc::size_t = 0;
                let err = unsafe { libc::pthread_attr_getstacksize(&attr, &mut stack_size) };

                if err == 0 {
                    unsafe { libc::pthread_attr_destroy(&mut attr) };
                    Ok(stack_size)
                } else {
                    Err("Error getting stack size")
                }
            } else {
                Err("Error getting thread attributes")
            }
        }

        #[cfg(target_os = "macos")]
        {
            let stack_bottom = unsafe { libc::pthread_get_stackaddr_np(libc::pthread_self()) };
            let stack_size = unsafe { libc::pthread_get_stacksize_np(libc::pthread_self()) };
            Ok(stack_size)
        }
    }
}

// Singleton instance - instantiate on first usage
static mut THREAD_INFO: Option<Arc<ThreadInfo>> = None;
static ONCE: Once = Once::new();

pub fn get_thread_info() -> Arc<ThreadInfo> {
    unsafe {
        ONCE.call_once(|| {
            // first caller is assumed/required to be from main thread
            THREAD_INFO = Some(Arc::new(ThreadInfo { main_thread_id: thread::current().id() }));
        });
        THREAD_INFO.clone().unwrap()
    }
}

#[cfg(test)]
pub mod test {
    use crate::ThreadInfo;

    #[test]
    fn test_thread_info() {
        ThreadInfo::init_from_main_thread();
    
        let expected_thread_stack_size = 8 * 1024;
        let new_named_thread = std::thread::Builder::new()
            .name("My awesome thread".into())
            .stack_size(expected_thread_stack_size)  // set for a small stack
            .spawn(move || {
                ThreadInfo::print_thread_id();
                ThreadInfo::print_stack_extents_win();

                let expected_thread_name = "My awesome thread".to_string();
                let thread_name = ThreadInfo::get_thread_name();
                assert_eq!(expected_thread_name, thread_name);

                let thread_stack_size = ThreadInfo::get_stack_size().unwrap();
                assert_eq!(expected_thread_stack_size, thread_stack_size);

            })
            .unwrap();
    
        let exit_code = new_named_thread.join().unwrap();
        assert_eq!((), exit_code);

        let expected_thread_stack_size = 1024 * 1024;
        let new_unnamed_thread = std::thread::Builder::new()
            // .name("My awesome thread".into()) // skip naming it
            .stack_size(expected_thread_stack_size)  // set for a 1 MiB stack
            .spawn(move || {
                ThreadInfo::print_thread_id();
                ThreadInfo::print_stack_extents_win();

                let expected_thread_name = "<unnamed>".to_string();
                let thread_name = ThreadInfo::get_thread_name();
                assert_eq!(expected_thread_name, thread_name);

                let thread_stack_size = ThreadInfo::get_stack_size().unwrap();
                assert_eq!(expected_thread_stack_size, thread_stack_size);
            })
            .unwrap();
    
        let exit_code = new_unnamed_thread.join().unwrap();
        assert_eq!((), exit_code);
    
        ThreadInfo::print_thread_id(); 
        ThreadInfo::print_stack_extents_win();

        // interesting find: test threads are named!
        let expected_thread_name = "test::test_thread_info".to_string();
        let thread_name = ThreadInfo::get_thread_name();
        assert_eq!(expected_thread_name, thread_name);

        let expected_thread_stack_size = 2 * 1024 * 1024; // empirical: 2 MiB stack size
        let thread_stack_size = ThreadInfo::get_stack_size().unwrap();
        assert_eq!(expected_thread_stack_size, thread_stack_size);
}
}