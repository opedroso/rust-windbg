use std::thread;
use std::io::{self, Write};
use rust_windbg::ThreadInfo;

// design our "argument" to be 1 KiB in size
const FACTORIAL_ARGUMENT_DESIRED_SIZE_IN_BYTES: usize = 1_024;
const COUNT_ENTRIES: usize = (FACTORIAL_ARGUMENT_DESIRED_SIZE_IN_BYTES - core::mem::size_of::<usize>()) / core::mem::size_of::<usize>(); // works for x86 or x64
struct FactorialArgument {
    array: [usize; COUNT_ENTRIES],
    idx: usize,
}



fn main() {
    // validate some assumptions
    assert_eq!(std::mem::size_of::<FactorialArgument>(), 1024);

    println!("Hello from main!");
    ThreadInfo::print_stack_extents_win();

    // Set a custom panic hook for stack overflow
    std::panic::set_hook(Box::new(hook_handles_stack_overflow));

    // Create a builder for the thread
    let builder = thread::Builder::new()
        .name("thread1".to_string()) // Set thread name
        .stack_size(8 * 1024);  // set for a small stack (default for Windows processes is 1 MiB)
        // Note: even though the source asks for 8 Kib, we will get 64 Kib during runtime.
        // Maybe related to how windows reserves memory blocks. E.g. any DLL will also have at least 64 Kib reserved.

    // Spawn the thread with my closure
    let handle = builder.spawn(move || {
        println!("Hello from thread1!");
        ThreadInfo::print_stack_extents_win();
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

#[inline(never)]
fn hook_handles_stack_overflow(info: &std::panic::PanicInfo) {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        if *s == "stack overflow" {
            eprintln!("Error: Stack overflow detected. Please use a smaller input argument.");
            std::process::exit(1);
        }
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
