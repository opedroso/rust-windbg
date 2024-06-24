use std::process;

use microseh::Exception;

fn main() {
    // Set a custom panic hook to catch access violation but it will never be called
    let _original_hook = std::panic::set_hook(Box::new(|info| {
        eprintln!("Access violation occurred! Details:");
        eprintln!("{:?}", info);
        process::exit(1);  // Or perform alternative actions (logging, cleanup)
    }));

    // proof: only enter if exception happens
    if let Err(ex) = microseh::try_seh(|| do_nothing() ) {
        eprintln!("microseh: Caught something !?!?");
        eprintln!("address: {:x?}", ex.address());
        eprintln!("rax: {:x}", ex.registers().rax());
    }

    // proof: enters if when exception happens
    if let Err(ex) = microseh::try_seh(|| force_access_violation() ) {
        print_exception(ex);
    }

    // let's check if panic hook gets called
    force_access_violation();
}

#[inline(never)]
fn force_access_violation() {
    // Code that causes an access violation (a.k.a. SIGSEGV) but does not call panic hook

    eprintln!("forcing access violation through assembly");
    // force an access violation
    unsafe {
        // causes in DEBUG or RELEASE a (exit code: 0xc0000005, STATUS_ACCESS_VIOLATION)
        std::arch::asm!("mov rax, 0; mov rax, [rax]"); // Assembly to dereference a null pointer
    }

    eprintln!("forcing access violation through std::prt::null_mut() de-reference");
    #[allow(unused_mut)]
    let mut x: *mut i32 = std::ptr::null_mut();
    unsafe {
        // causes a (exit code: 0xc0000005, STATUS_ACCESS_VIOLATION) in DEBUG but in RELEASE a (exit code: 0xc000001d, STATUS_ILLEGAL_INSTRUCTION)
        *x = 10; // This will cause an access violation (a.k.a. SIGSEGV)
    }

}

#[inline(never)]
fn do_nothing() {
    // nothing to be done
}

#[inline(never)]
fn print_exception(ex: Exception) {
    eprintln!("microseh: Caught an {:?}", ex.code());
    eprintln!("address: {:x?}", ex.address());
    eprintln!("rip: {} ({:x})", ex.registers().rip(), ex.registers().rip());
    eprintln!("rsp: {} ({:x})", ex.registers().rsp(), ex.registers().rsp());
    eprintln!("rax: {} ({:x})", ex.registers().rax(), ex.registers().rax());
    eprintln!("rbx: {} ({:x})", ex.registers().rbx(), ex.registers().rbx());
    eprintln!("rcx: {} ({:x})", ex.registers().rcx(), ex.registers().rcx());
    eprintln!("rdx: {} ({:x})", ex.registers().rdx(), ex.registers().rdx());
    eprintln!("full record: {:?}", ex);
}
