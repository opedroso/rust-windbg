//
// Illustrates different behaviors of panic and exception handlers
//  - panic_hook
//  - signalhandler
//  - stack overflow
//
use std::env;
use std::panic;
use std::thread;
use std::io::Write;
//use libc::{SIGSEGV, c_void, siginfo_t};
use libc::{sigaction, SA_ONSTACK, SA_SIGINFO, SIGBUS, SIGSEGV, c_void, siginfo_t};
use rust_windbg::ThreadInfo;

#[cfg(target_os = "windows")]
compile_error!("This code is targeted for non-Windows platform only.");


fn main() {
    // remembers main thread id
    ThreadInfo::init_from_main_thread();

    println!("main: Setting up SISSEGV signal handler ...");
    // Register the signal handler (unsafe operation)
    unsafe {
        let mut sigaction_mut = sigaction::SigAction::new(handler_sigsegv, None, sigaction::SA_SIGINFO|sigaction::SA_ONSTACK);
        unsafe {
            sigaction(SIGSEGV, &mut sigaction_mut, None);
        }
    }
    let thread_id = thread::current().id();
    println!("main(tid={:?}): Declare panic hook...", thread_id);
    panic::set_hook(Box::new(panic_hook_sample)); // separate function, so easier to set breakpoint in debugger
    println!("main: Panic hook set up!");

    let args: Vec<String> = env::args().collect();

    // Check if there's at least one command-line argument (besides the program name)
    if args.len() > 1 {
        // force an access violation (null dereferencing)
        eprint!("main: With argument - forcing an access violation\n");
        std::io::stderr().flush().unwrap(); // Flush after printing

        if args.len() == 2 { // cargo run 1
            unsafe { // only works for x64 architecture!
                std::arch::asm!("mov rax, 0; mov rax, [rax]"); // Assembly to dereference a null pointer   causes  Access violation - code c0000005 (first chance)
            }
        } else if args.len() == 3 { // cargo run 1 2
            let ptr: *mut i32 = std::ptr::null_mut(); // Mutable null pointer
            unsafe { // Wanted to: Trigger access violation through volatile write    but instead causes ...
                std::ptr::write_volatile(ptr, 42); // Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
            }
        } else if args.len() == 4 { // cargo run 1 2 3
            let ptr: *mut i32 = 0xC0000000 as *mut i32; // make ptr non-null and aligned if you really want to bypass write_volatile() pointer checks; then causes  Access violation - code c0000005 (first chance)
            unsafe { // Wanted to: Trigger access violation through volatile write    but instead causes ...
                std::ptr::write_volatile(ptr, 42); // Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
            }
        }
    } else { // cargo run
        eprint!("main(tid={:?}): No argument - calling Panic\n", thread_id);
        std::io::stderr().flush().unwrap(); // Flush after printing
        panic!("main: No argument - calling straight Panic!"); // Original panic message
    }
}


#[inline(never)]
fn panic_hook_sample(info: &panic::PanicInfo) {
    // Instead of println!/eprintln!, use a function that is safe to call from within a panic hook.
    let thread_id = thread::current().id();
    eprint!("panic_hook_sample(tid={:?}): from panic_hook_sample\n", thread_id);
    eprint!("panic_hook_sample: {:?}\n", info);
    std::io::stderr().flush().unwrap(); // Flush after printing
    // Avoid calling `std::process::exit` from within the panic hook. Let the panic unwind naturally.
}

#[inline(never)]
fn handler_sigsegv(sig: i32, info: *mut siginfo_t, _: *mut c_void)  {
    // Limited Operations: Signal handlers run in a restricted environment. Avoid complex logic, heap allocations, or using most of the Rust standard library within the handler.
    // Re-entrant Signals: Signal handlers can be interrupted by other signals. Be cautious if your handler needs to be re-entrant.

    let thread_id = thread::current().id();
    eprintln!("handler_sigsegv(tid={:?}): Segmentation fault (SIGSEGV={}) detected.", thread_id, SIGSEGV);

    // Perform additional actions (e.g., logging, cleanup)
    eprint!("handler_sigsegv: signum= {:?}\n", SIGSEGV);
    std::io::stderr().flush().unwrap(); // Flush after printing

    std::process::exit(1); // Terminate the process with an error code
}
