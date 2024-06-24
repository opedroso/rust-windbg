use std::thread;
use std::io::{self, Write};
use rust_windbg::ThreadInfo;

// design our "argument" to be 1 KiB in size
const FACTORIAL_ARGUMENT_DESIRED_SIZE_IN_BYTES: usize = 3 * 1_024;
const COUNT_ENTRIES: usize = (FACTORIAL_ARGUMENT_DESIRED_SIZE_IN_BYTES - core::mem::size_of::<usize>()) / core::mem::size_of::<usize>(); // works for x86 or x64
struct FactorialArgument {
    array: [usize; COUNT_ENTRIES],
    idx: usize,
}



fn main() {
    // Set a custom panic hook for stack overflow
    std::panic::set_hook(Box::new(hook_handles_stack_overflow_v0));

    // validate some assumptions
    assert_eq!(std::mem::size_of::<FactorialArgument>(), FACTORIAL_ARGUMENT_DESIRED_SIZE_IN_BYTES);

    println!("Hello from main!");
    ThreadInfo::print_stack_extents_win();

    // Create a builder for the thread
    let builder = thread::Builder::new()
        .name("thread1".to_string()) // Set thread name
        .stack_size(8 * 1024);  // set for a small stack (default for Windows processes is 1 MiB, minimum is 4 KiB)

    // Spawn the thread with my closure
    let handle = builder.spawn(move || {
        println!("Hello from thread1!");
        ThreadInfo::print_stack_extents_win();

        // test the panic hook
        unsafe {
            core::arch::asm!("mov rax, 0; mov [rax], rax"); // Assembly to dereference a null pointer
        }
        
        let number = read_usize();
        let mut arg = FactorialArgument { idx: number, array: [0; COUNT_ENTRIES]};
        arg.array[0] = number;
        let result = factorial(arg);
        println!("The factorial of {} is: {}", number, result);
    }).unwrap(); // Handle potential errors during spawning

    // Wait for the thread to finish
    handle.join().unwrap(); 
}

#[inline(never)]
fn factorial(arg: FactorialArgument) -> u64 {
    if arg.idx == 0 {
        1 // Base case: Factorial of 0 is 1
    } else {
        let mut new_arg = FactorialArgument { idx: arg.idx-1, array: [0;COUNT_ENTRIES]}; // wastes stack space on every call
        new_arg.array[new_arg.idx] = arg.idx;
        arg.idx as u64 * factorial(new_arg) // Recursive case: n! = n * (n-1)!
    }
}

fn read_usize() -> usize {
    let mut input = String::new();

    loop {
        print!("Enter a non-negative integer: ");
        // Ensure the prompt is displayed before reading
        io::stdout().flush().expect("Failed to flush stdout"); 

        input.clear(); // Clear the input buffer before reading a new line
        io::stdin().read_line(&mut input).expect("Failed to read line");

        match input.trim().parse::<usize>() {
            Ok(number) => return number,
            Err(_) => println!("Invalid input. Please enter a valid non-negative integer."),
        }
    }
}

// We now rewrite the handle for stack overflow using only memory that is static/pre-defined prior to the stack overflow event
// This should reduce our stack usage and allow the hook to run and print an appropriate message in the event of an stack overflow

// Win32 API declaration
extern "system" {
    fn OutputDebugStringA(lpOutputString: *const std::os::raw::c_char);
    fn DebugBreak();
}

// Pre-allocated buffer for the message
static mut DEBUG_MESSAGE_BUFFER: [u8; 1024] = [0; 1024]; // 128 bytes should be enough for most panic messages


#[inline(never)]
fn hook_handles_stack_overflow_v0(_info: &std::panic::PanicInfo) {
    //unsafe { DebugBreak(); };
    let _ = io::stderr().write(b"Panic hook called!\n"); // Write to stderr
    std::process::exit(-1);
    //println!("Panic hook called! Message: {:?}", info.payload());
}

#[allow(unused)]
#[inline(never)]
fn hook_handles_stack_overflow_v1(info: &std::panic::PanicInfo) {
    unsafe { DebugBreak(); };
    let payload = match info.payload().downcast_ref::<&str>() {
        Some(s) => s,
        None => "Unknown panic payload",
    };

    let msg = format!("Panic occurred: {}", payload);
    let msg_len = msg.len();

    // Safely write to the static buffer
    unsafe {
        let buffer_ptr = DEBUG_MESSAGE_BUFFER.as_mut_ptr() as *mut u8;

        if msg_len < DEBUG_MESSAGE_BUFFER.len() {
            std::ptr::copy_nonoverlapping(msg.as_ptr(), buffer_ptr, msg_len);
            *buffer_ptr.add(msg_len) = 0; // Null-terminate the string
            OutputDebugStringA(buffer_ptr as *mut std::os::raw::c_char);
        }
    }
}