# How to Capture Runtime Exceptions

Altough Rust offers an aura of error free runtime, reality frequently enters the picture without an invitation.
In this Readme we will show:
    - how to use the SysInternal's tool ProcDump to capture these uninvited events and make a record of them using minidumps in Windows
    - how to use Windows debuggers to extract useful information from minidumps

## What is a Minidump?

A minidump is a smart core dump of your process. It records the context of your process when an event is detected.
Events can be exceptions or thresholds being crossed such as a specific percentage of CPU usage reached or a specific memory usage reached.
They can be created with various types of information which will control their size on disk.
The Windows debuggers can be used to report on the information stored.
A minidump can also be opened (as an *.exe) in Visual Studio and then click on Debug => Run to setup a process that the Visual Studio debugger can analyze, allowing the developer to walk through the stack and inspect local variables at the various functions captured on the context of the event captured. You can not continue its execution, but the process context in the minidump can be analyzed.

Minidumps have pre-defined sections but it also allows for a developer to implement a function that can add exta information when a minidump is created. This function is called a callback.

### What is ProcDump?

ProcDump is an executable part of the SysInternals Suite.

ProcDump can create minidumps of multiple types:

```
Dump Types:
   -mm     Write a 'Mini' dump file. (default)
           - Includes directly and indirectly referenced memory (stacks and what they reference).
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -ma     Write a 'Full' dump file.
           - Includes all memory (Image, Mapped and Private).
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -mt     Write a 'Triage' dump file.
           - Includes directly referenced memory (stacks).
           - Includes limited metadata (Process, Thread, Module and Handle).
           - Removal of sensitive information is attempted but not guaranteed.
   -mp     Write a 'MiniPlus' dump file.
           - Includes all Private memory and all Read/Write Image or Mapped memory.
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
           - To minimize size, the largest Private memory area over 512MB is excluded.
             A memory area is defined as the sum of same-sized memory allocations.
             The dump is as detailed as a Full dump but 10%-75% the size.
           - Note: CLR processes are dumped as Full (-ma) due to debugging limitations.
   -mc     Write a 'Custom' dump file.
           - Includes the memory and metadata defined by the specified MINIDUMP_TYPE mask (Hex).
   -md     Write a 'Callback' dump file.
           - Includes the memory defined by the MiniDumpWriteDump callback routine
             named MiniDumpCallbackRoutine of the specified DLL.
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -mk     Also write a 'Kernel' dump file.
           - Includes the kernel stacks of the threads in the process.
           - OS doesn't support a kernel dump (-mk) when using a clone (-r).
           - When using multiple dump sizes, a kernel dump is taken for each dump size.
```

### How to get information from a minidump

Some of the Windows debuggers like WinDBG and CDB can be scripted. CDB is a CLI version of WinDBG, which lends itself better for scripting.
CBD and WinDBG share most command line options and commands.

When a minidump is open with the debugger, the skeleton of a process is created and the minidump information is used to fill it in.
When the minidump is a full dump (-ma was used with ProcDump), all the data structures plus the heap is available to fill the skeleton in.
When the minidump is a triage dump (-mt), Process, Thread, Module and Handle information is available.

For example, these commands ".ecxr;k;q" would:
- .excr - load the exception context recorded in the minidump into process skeleton
- k - print the process stack at time of exception
- q - quit the debugger
```
cdb -c ".ecxr;kb;q" -z Dumps\two_senders_and_two_receiver_handlers_tokio_1_C0000005_241117_083308.dmp
...
0:007> cdb: Reading initial command '.ecxr;k;q'
*** Output for '.excr' command
rax=000001275a8e07c0 rbx=0000012759854740 rcx=0000012759854740
rdx=0000000000000000 rsi=0000012759854740 rdi=00000009bf8fec90
rip=00007ff66107c030 rsp=00000009bf8fe6b8 rbp=00000009bf8fe7d0
 r8=0000000000000001  r9=00000009bf8fe698 r10=0000000000000012
r11=00000009bf8fe6a0 r12=0000000059a01801 r13=00000000097a6d44
r14=00000009bf8feb6d r15=00000009bf8fec90
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010200
core_messaging_4b9cbd3c8bffceb0!zmq::ctx_t::check_tag:
00007ff6`6107c030 817960fecaadab  cmp     dword ptr [rcx+60h],0ABADCAFEh ds:00000127`598547a0=????????
*** Output for 'k'
  *** Stack trace for last set context - .thread/.cxr resets it
Child-SP          RetAddr               Call Site
00000009`bf8fe6b8 00007ff6`61077393     core_messaging_4b9cbd3c8bffceb0!zmq::ctx_t::check_tag
00000009`bf8fe6c0 00007ff6`60fbdaa0     core_messaging_4b9cbd3c8bffceb0!zmq_ctx_term+0x13
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!zmq::RawContext::term+0x8
00000009`bf8fe6f0 00007ff6`60e8fe91     core_messaging_4b9cbd3c8bffceb0!zmq::impl$10::drop+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ptr::drop_in_place+0x5
00000009`bf8fe720 00007ff6`60ea0b25     core_messaging_4b9cbd3c8bffceb0!alloc::sync::Arc::drop_slow<zmq::RawContext,alloc::alloc::Global>+0x11
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!alloc::sync::impl$34::drop+0x19
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ptr::drop_in_place+0x19
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ptr::drop_in_place+0x19
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ptr::drop_in_place+0x19
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core_messaging::que::zmq::impl$2::close+0x2d
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core_messaging::tests::zmq::two_senders_and_one_receiver_handler_tokio::async_block$0::_two_senders_and_one_receiver_handler_tokio_internal::async_fn$0+0x851
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!serial_test::serial_code_lock::local_async_serial_core::async_fn$0+0x9fa
00000009`bf8fe750 00007ff6`60eb076d     core_messaging_4b9cbd3c8bffceb0!core_messaging::tests::zmq::two_senders_and_one_receiver_handler_tokio::async_block$0+0xab5
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::future::future::impl$1::poll+0x9
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::park::impl$4::block_on::closure$0+0x9
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::coop::with_budget+0x4d
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::coop::budget+0x4d
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::park::CachedParkThread::block_on+0x8f
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::context::blocking::BlockingRegionGuard::block_on+0x8f
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::scheduler::multi_thread::impl$0::block_on::closure$0+0x8f
00000009`bf8feaa0 00007ff6`60e938e5     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::context::runtime::enter_runtime<tokio::runtime::scheduler::multi_thread::impl$0::block_on::closure_env$0<core::pin::Pin<ref_mut$<dyn$<core::future::...
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::scheduler::multi_thread::MultiThread::block_on+0x1c
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::runtime::Runtime::block_on_inner+0x2e
00000009`bf8febc0 00007ff6`60e9ff41     core_messaging_4b9cbd3c8bffceb0!tokio::runtime::runtime::Runtime::block_on<core::pin::Pin<ref_mut$<dyn$<core::future::future::Future<assoc$<Output,tuple$<> > > > > > >+0x55
00000009`bf8fec60 00007ff6`60e95b1d     core_messaging_4b9cbd3c8bffceb0!core_messaging::tests::zmq::two_senders_and_one_receiver_handler_tokio+0xd1
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core_messaging::tests::zmq::two_senders_and_one_receiver_handler_tokio::closure$0+0x5
00000009`bf8ff080 00007ff6`610010d0     core_messaging_4b9cbd3c8bffceb0!core::ops::function::FnOnce::call_once<core_messaging::tests::zmq::two_senders_and_one_receiver_handler_tokio::closure_env$0,tuple$<> >+0xd
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ops::function::FnOnce::call_once+0x2
00000009`bf8ff0b0 00007ff6`60fffff2     core_messaging_4b9cbd3c8bffceb0!test::__rust_begin_short_backtrace<enum2$<core::result::Result<tuple$<>,alloc::string::String> >,enum2$<core::result::Result<tuple$<>,...
00000009`bf8ff0f0 00007ff6`60fc01fb     core_messaging_4b9cbd3c8bffceb0!test::run_test::closure$0+0x252
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!test::run_test::closure$1+0x83
00000009`bf8ff6e0 00007ff6`60fc5b8d     core_messaging_4b9cbd3c8bffceb0!std::sys_common::backtrace::__rust_begin_short_backtrace<test::run_test::closure_env$1,tuple$<> >+0xab
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!std::thread::impl$0::spawn_unchecked_::closure$2::closure$0+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::panic::unwind_safe::impl$25::call_once+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!std::panicking::try::do_call+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!std::panicking::try+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!std::panic::catch_unwind+0x10
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!std::thread::impl$0::spawn_unchecked_::closure$2+0x9e
00000009`bf8ff870 00007ff6`61052a4d     core_messaging_4b9cbd3c8bffceb0!core::ops::function::FnOnce::call_once<std::thread::impl$0::spawn_unchecked_::closure_env$2<test::run_test::closure_env$1,tuple$<> >,tuple$<> >+0xbd
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!alloc::boxed::impl$48::call_once+0xb
(Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!alloc::boxed::impl$48::call_once+0x16
00000009`bf8ff920 00007ff8`04c07374     core_messaging_4b9cbd3c8bffceb0!std::sys::pal::windows::thread::impl$0::new::thread_start+0x3d
00000009`bf8ff980 00007ff8`0515cc91     kernel32!BaseThreadInitThunk+0x14
00000009`bf8ff9b0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
...
```

Notice on the stack above that even the inline functions are represented. That is only possible if:
- the Rust project was compiled with the correct settings for generating a valid (PDB) symbol file
- the location of this PDB is in the symbols path when the debugger runs

This project above had these settings in its `Cargo.toml` to create the PDB file when the command "cargo test --no-run --release" was used to build the executable containing this project tests:
```
[workspace]
resolver = "2"
members = [ "benchmarks/zmq_proxy_av",
...
]

[profile.release]
debug = "line-tables-only"  # info for backtraces and profilers
split-debuginfo = "packed"  # generate PDB on Windows, DWP on Linux, .dSYM on MacOS
strip = "none"              # strip symbols and lineinfo from the executable itself during linking is possible; off for now; TODO: re-evaluate setting prior end user deployment
```

### Installing SysInternals ProcDump (and friends)

The best way to install and keep SysInternals update is to use the script [Install-SysInternasSuite.ps1](https://powershellisfun.com/2023/01/27/install-or-update-your-sysinternals-suite-using-powershell/).
It allows for a smooth installation to a chosen directory, then it will remember it and only update the necessary tools that get updated since the last run.

### Capturing Access Violation Events

ProcDump has two main being executed:
1. starting an executable by name and its associated arguments
2. attaching to a running process

The first method is simple but has the disadvantage of using ProcDump's default minidump naming.  
The second method allows one to specify some pre-defined strings that will be part of the minidump filename but requires that the target process already exists or is started after the ProcDump command executes.  

I prefer the second method, which allows my minidumps to have  the exception code that caused the exception event as part of its filename.  
It is a nice way to find an interesting exception in the middle of sometimes thousands of minidump files recorded during an overnight testing marathon.  

This is the command used to generate the minidump above:
```batch
:: create Dumps directory on first run; must exist of ProcDump fails when attempting to create the minidumps
if not exist ".\Dumps" mkdir %CD%\Dumps

:: delete all dump files currently in Dumps subdirectory
if exist "%CD%\Dumps\*.dmp" del "%CD%\Dumps\*.dmp"

:: run the ProcDump and tests 100 times because my test failure is intermittent
for /L %i in (1,1,100) do  (
    :: delete all set thread name exceptions recorded (latest ProcDump version seems buggy that is not filtering out requested exception)
    del "%CD%\Dumps\*_406D1388_*.dmp"

    :: start ProcDump minimized, generating triage size minidumps, interested in access violation (C0000005) and not interested in set thread name exception (406D1388)
    :: also specify that ProcDump should wait for the process named "core_messaging-4b9cbd3c8bffceb0.exe" and
    :: in case there is an event, it should use the following filename to save it: "%CD%\Dumps\two_senders_and_two_receiver_handlers_tokio_%i_EXCEPTIONCODE_YYMMDD_HHMMSS.dmp"
    :: EXCEPTION_CODE will be replaced with the actual exception code (32bit hexadecimal), YYMMDD replaced with the date, HHMMSS replaced with the time
    :: notice that I also use the shell variable expansion both for the path (%CD%\...) and also expanding the run count as part of the filename created (..._%i_EXC...)
    start /MIN procdump -mt -n 100 -e 1 -l -accepteula -f C0000005 -fx 406d1388 -w "core_messaging-4b9cbd3c8bffceb0.exe"  "%CD%\Dumps\two_senders_and_two_receiver_handlers_tokio_%i_EXCEPTIONCODE_YYMMDD_HHMMSS.dmp"

    :: here we start the process that ProcDump will attach
    "r:\repo\messaging\target\release\deps\core_messaging-4b9cbd3c8bffceb0.exe" zmq --test-threads 1 --nocapture

    :: here we display the dumps that have been captured so far
    dir "%CD%\Dumps\*.dmp"
)
```

The reason I am running it multiple times is because the problem I am tracking down does not happen every time I run a single test.  
It happens intermitently and only if I run all tests in my project.

### Analysing the Minidumps

Once a minidump gets created, you can open it usinga Windows debugger and type ".excr" to set the skeleton process with its data.  
Once that is done, you can then use regular like "~*kb" (show the stack with arguments for all threads in the process).  
The active thread is the one that caused the exception event. The instruction pointer of this thread is the instruction that caused the event.  
When you have symbols set correctly, these stacks will have their function names and the debugger will even show the source (if available) that caused the exception event recorded.  

Notice that we run "rwindbg.bat -z path\to\file.dmp":
```batch
r:\repo\myproject\messaging\core_messaging> r:\repo\rust-windbg\rwindbg -z Dumps\two_senders_and_two_receiver_handlers_tokio_1_C0000005_241117_083308.dmp
start windbg -W Default -c "$><T:\SYSTEM\Temp\rwindbg.windbg" -z Dumps\two_senders_and_two_receiver_handlers_tokio_1_C0000005_241117_083308.dmp
```
Details from the WinDBG window opened.

1. First few lines, procdump records as a comment the command line used to create this minidump followed by the reason (event type):
   ```text
   Microsoft (R) Windows Debugger Version 10.0.22621.2428 AMD64
   Copyright (c) Microsoft Corporation. All rights reserved.

   Loading Dump File [r:\repo\myproject\messaging\core_messaging\Dumps\two_senders_and_two_receiver_handlers_tokio_1_C0000005_241117_083308.dmp]
   Comment: '
   *** procdump  -mt -n 100 -e 1 -l -accepteula -f C0000005 -fx 406d1388 -w "core_messaging-4b9cbd3c8bffceb0.exe"  "r:\repo\myproject\messaging\core_messaging\Dumps\two_senders_and_two_receiver_handlers_tokio_1_EXCEPTIONCODE_YYMMDD_HHMMSS.dmp"
   *** Unhandled exception: C0000005.ACCESS_VIOLATION'
   ```

2. WinDBG shows the effective symbol path used for this run. Later on, you may want to set your _NT_SYMBOL_PATH environment variable to this value.
   ```text
   Symbol search path is: cache*T:\SYSTEM\Temp\rwindbg\symbols\ms;srv*https://msdl.microsoft.com/download/symbols;R:\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\;R:\repo\myproject\messaging\target\release\deps\;SRV*c:\pdb_cache\my-company*\\NUE-DEVVM-018.my-company.com\Symbols
   ```

3. WinDBG shows the effective source path used for this run.
   ```text
   Source search path is: srv*;r:\repo\myproject\messaging\core_messaging\examples\;r:\repo\myproject\messaging\core_messaging\src\;r:\repo\myproject\messaging\core_messaging\src\que\;r:\repo\myproject\messaging\core_messaging\src\tests\;R:\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\src\rust\library\alloc\benches\;R:\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\src\rust\library\alloc\benches\btree\;...
   ```

4. The output of the "lm" (show modules) shows the the modules loaded and their load addresses.  
Notice that the executable has "(private pdb symbols)" after its name, indicating that the PDB for it was found and it has been loaded.
   ```text
   ========== lm - show the modules currently loaded to our process
   start             end                 module name
   00007ff6`60e60000 00007ff6`61208000   core_messaging_4b9cbd3c8bffceb0 C (private pdb symbols)  t:\system\temp\rwindbg\symbols\ms\core_messaging-4b9cbd3c8bffceb0.pdb\6FC820A0DE6C45A7B1B20FC03F5348F98\core_messaging-4b9cbd3c8bffceb0.pdb
   00007ff8`002c0000 00007ff8`002d2000   kernel_appcore # (deferred)             
   ```

5. You can ask WinDBG to load the minidump data into the skeleton process it created by using the ".excr" command.  
Notice that the last line shows the instructions that caused the event and the line above, the "module_name!function_name" where it happened:  
   ```text
   0:007> .excr
   rax=000001275a8e07c0 rbx=0000012759854740 rcx=0000012759854740
   rdx=0000000000000000 rsi=0000012759854740 rdi=00000009bf8fec90
   rip=00007ff66107c030 rsp=00000009bf8fe6b8 rbp=00000009bf8fe7d0
    r8=0000000000000001  r9=00000009bf8fe698 r10=0000000000000012
   r11=00000009bf8fe6a0 r12=0000000059a01801 r13=00000000097a6d44
   r14=00000009bf8feb6d r15=00000009bf8fec90
   iopl=0         nv up ei pl nz na pe nc
   cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010200
   core_messaging_4b9cbd3c8bffceb0!zmq::ctx_t::check_tag:
   00007ff6`6107c030 817960fecaadab  cmp     dword ptr [rcx+60h],0ABADCAFEh ds:00000127`598547a0=????????
   ```

6. You can use the "~k" command to see the stack causing the event. The ".excr" command made it the current stack in the skeleton process.  
WinDBG will open the source file for you on a window if you click on its path on the stack command.  
If you click on the frame number (00, 01, 02 at the left of each stack entry line), the registers will be loaded with the values at the time that call was made, values which are saved on the stack.  
   ```text
   0:007> ~k
    # Child-SP          RetAddr               Call Site
   00 00000009`bf8fe6b8 00007ff6`61077393     core_messaging_4b9cbd3c8bffceb0!zmq::ctx_t::check_tag [r:\.cargo\registry\src\artifactory.my-company.com-207c04f103d33362\zeromq-src-0.2.6+4.3.4\vendor\src\ctx.cpp @ 109] 
   01 00000009`bf8fe6c0 00007ff6`60fbdaa0     core_messaging_4b9cbd3c8bffceb0!zmq_ctx_term+0x13 [r:\.cargo\registry\src\artifactory.my-company.com-207c04f103d33362\zeromq-src-0.2.6+4.3.4\vendor\src\zmq.cpp @ 152] 
   02 (Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!zmq::RawContext::term+0x8 [r:\.cargo\registry\src\artifactory.my-company.com-207c04f103d33362\zmq-0.10.0\src\lib.rs @ 383] 
   03 00000009`bf8fe6f0 00007ff6`60e8fe91     core_messaging_4b9cbd3c8bffceb0!zmq::impl$10::drop+0x10 [r:\.cargo\registry\src\artifactory.my-company.com-207c04f103d33362\zmq-0.10.0\src\lib.rs @ 0] 
   04 (Inline Function) --------`--------     core_messaging_4b9cbd3c8bffceb0!core::ptr::drop_in_place+0x5 [/rustc/129f3b9964af4d4a709d1383930ade12dfe7c081\library\core\src\ptr\mod.rs @ 514] 
   ```

7. If you have system APIs on the stack trace, you may want to force the load of those PDBs with the ".reload /f /i" command.  
Notice that after this command executes, the kernel_appcore module now says "(pdb symbols)" where it used to show "(deferred)".  
   ```text
   0:007> .reload /f /i
   .*** WARNING: Unable to verify checksum for core_messaging-4b9cbd3c8bffceb0.exe
   ...................
   0:007> lm
   start             end                 module name
   00007ff6`60e60000 00007ff6`61208000   core_messaging_4b9cbd3c8bffceb0 C (private pdb symbols)  t:\system\temp\rwindbg\symbols\ms\core_messaging-4b9cbd3c8bffceb0.pdb\6FC820A0DE6C45A7B1B20FC03F5348F98\core_messaging-4b9cbd3c8bffceb0.pdb
   00007ff8`002c0000 00007ff8`002d2000   kernel_appcore # (pdb symbols)          t:\system\temp\rwindbg\symbols\ms\Kernel.Appcore.pdb\FF8898495A82A37624B4A1FDF19E2A5D1\Kernel.Appcore.pdb
   ```
