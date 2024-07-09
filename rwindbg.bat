@echo off
:: rwindbg.bat
::
:: executes WinDBG with settings to help debug Rust projects
::
:: Source: https://github.com/opedroso/rust-windbg
::

:: Arguments to this script are expected (stuff after the ... in lines below):
:: run windbg with all arguments given to this script:                                          windbg ... executable_name arg1 arg2 ... argN
:: you can attach to a running process by specifying it process_id:                             windbg ... -p [PID]
:: you can attach to a running process by specifying it process name (as seen on TaskMgr):      windbg ... -pn [process_name.exe]
:: you can freeze a running process (-pv) when attaching to it (-p PID or -pn name),
:: inspect all its current stacks for all threads "~*k" and
:: then resume running it "qd" command for quit and detach:                                     windbg ... -pv -p PID



::
:: this script assumes we are executed from base of Rust project (where target directory gets created by cargo build)
::
@if NOT exist "Cargo.toml" @echo "Current directory expected to be at rust project directory!"


::
:: all environment variable changes beyond this point only valid during script execution
::
@setlocal EnableExtensions
@setlocal EnableDelayedExpansion


::
:: find the default toolchain we are using and load it's source
::
@for /f "delims=" %%i in ('rustc --print=sysroot') do set rustc_sysroot=%%i
@set rust_etc_for_natvis=%rustc_sysroot%\lib\rustlib\etc
@set rust_bin_for_pdb=%rustc_sysroot%\bin
@set rust_src_for_rs=%rustc_sysroot%\lib\rustlib\src\rust
@rustup component add rust-src > c:\NUL 2>&1


::
:: where downloaded PDB (symbol files) will be cached
::
set PDB_CACHE=%TEMP%\rwindbg\symbols
@if NOT exist "%PDB_CACHE%\ms" mkdir "%PDB_CACHE%\ms"


::
:: where source files (referenced in the symbol files) will be downloaded
::
set DBGHELP_HOMEDIR=%TEMP%\rwindbg\source
@if NOT exist "%DBGHELP_HOMEDIR%" mkdir "%DBGHELP_HOMEDIR%"


::
:: show our environment variables related to windbg symbols and source paths and rust that will be used in our session
::
:: (if you want to see the arguments to WinDBG and Rust that are active, comment the next line by adding :: as first two characters)
goto :skip_over_show_env
@echo === These are the environment settings that WinDBG uses:
@set _NT
@set DBGHELP
@echo ==== RUST environment will also affect our commands:
@set RU 2>c:\NUL
:skip_over_show_env


::
:: create a initialization script for windbg (necessary when some commands require double-quote usage)
::
@set WINDBG_INIT_SCRIPT=%TEMP%\rwindbg.windbg
:: the reload will force symbols referenced in your process to be downloaded now (normally demand loaded)
@echo .echo ========== .reload /f - forces loading of the symbols associated with our currently loaded modules> %WINDBG_INIT_SCRIPT%
@echo .reload /f>> %WINDBG_INIT_SCRIPT%
:: 'sxe *' tells the debugger to stop when any of the known exceptions happen at the instruction where it happens on the ipc (instruction pointer register)
::@echo sxe *>> %WINDBG_INIT_SCRIPT%
:: an example how to load a WinDBG extension
::@echo .load uext>> %WINDBG_INIT_SCRIPT%
:: most extensions will list their commands when you execute their help command
::@echo !uext.help>> %WINDBG_INIT_SCRIPT%
:: add new exceptions that is not on WinDBG original list; e06d7363 is a C++ exception to indicate unhandled exception
::@echo sxn -c2 ^"k;.echo First Chance Exception at this stack above^" e06d7363>> %WINDBG_INIT_SCRIPT%
:: add a new exception that is not on WinDBG original list; 406D1388 (MS_VC_EXCEPTION) is a special exception used by MS VC++ that the debugger process and uses its argument to set the name of the thread to aid debugging
::@echo sxe -c ^"k;.echo First Chance Exception setting a thread name;.echo type GN when done looking at the stack^" 406D1388>> %WINDBG_INIT_SCRIPT%
:: add some commands to execute on STACK_OVERFLOW; c00000fd (STAUTS_STACK_OVERFLOW)
::@echo sxe -c ^".echo Show stacks for all existing threads;~*k;.echo Show current thread (where stack overflow event happened) with more details, showing first 4 args to each call on the stack;.echo type GN when done looking at the stack^" c00000fd>> %WINDBG_INIT_SCRIPT%
@echo sxe -c ^".echo Show current thread (where stack overflow event happened) with more details, showing first 4 args to each call on the stack;~#k;.echo type GN when done looking at the stack^" sov>> %WINDBG_INIT_SCRIPT%
:: find the address of a Win32 API function: CreateFileW (uncomment if desired; left as an example)
::@echo x *!CreateFileW>> %WINDBG_INIT_SCRIPT%
:: The following lines were output on my laptop when I executed the command above; as OS versions change, you might get different results
:: 00007fff`6e6149f0 KERNELBASE!CreateFileW (CreateFileW)
:: 00007fff`6fdd0460 KERNEL32!CreateFileW (CreateFileW)
::@echo .echo This is an example of a reference to the Win32 API being exported by other OS DLLs>> %WINDBG_INIT_SCRIPT%
::@echo uf KERNEL32!CreateFileW>> %WINDBG_INIT_SCRIPT%
::@echo .echo You can disassemble the actual Win32API by typing: uf KERNELBASE!CreateFileW>> %WINDBG_INIT_SCRIPT%
:: finally we find the real CreateFileW() Win32 API function (uncomment next line if you want to see the disassembly of it; left as example)
::@echo uf KERNELBASE!CreateFileW>> %WINDBG_INIT_SCRIPT%
:: sets a beakpoint on a Win32 API: CreateFileW() which is used to open and/or create files (uncomment next line if desired; left as example)
::@echo bp KERNELBASE!CreateFileW>> %WINDBG_INIT_SCRIPT%
:: tell WinDBG to start running the process once it stops on the initial break point, at which point all modules are loaded into the process memory
::@echo g>> %WINDBG_INIT_SCRIPT%
:: load formatters to printout rust data structures in WinDBG
@pushd %rust_etc_for_natvis%
@for /f "delims=" %%i in ('dir/s/b *.natvis') do @echo .nvload %%i>> %WINDBG_INIT_SCRIPT%
@popd
:: load location of PDBs delivered/built with Rust
@set PDBPATH_INIT_SCRIPT=%WINDBG_INIT_SCRIPT%_PDBpath
@echo .sympath cache*%PDB_CACHE%\ms;srv*https://msdl.microsoft.com/download/symbols> %PDBPATH_INIT_SCRIPT%
@pushd %rust_bin_for_pdb%
@for /f "delims=" %%i in ('dir/s/b *.pdb')  do @if NOT "%%~dpi" == "!PREV!" @set "PREV=%%~dpi"&(@echo !PREV!>> %PDBPATH_INIT_SCRIPT%)
@popd
@echo ^$^$^>^<%PDBPATH_INIT_SCRIPT%>> %WINDBG_INIT_SCRIPT%
:: load location of src files
@set SRCPATH_INIT_SCRIPT=%WINDBG_INIT_SCRIPT%_SRCpath
@echo .srcpath srv*> %SRCPATH_INIT_SCRIPT%
@pushd %rust_src_for_rs%
@for /f "delims=" %%i in ('dir/s/b/ad src') do @if NOT "%%~dpi" == "!PREV!" @set "PREV=%%~dpi"&(@echo !PREV!>> %SRCPATH_INIT_SCRIPT%)
@popd
@echo ^$^$^>^<%SRCPATH_INIT_SCRIPT%>> %WINDBG_INIT_SCRIPT%
:: lists the modules (DLLs) that are loaded and their associated symbol files, if it was able to find and download them
@echo .echo ========== lm - show the modules currently loaded to our process>> %WINDBG_INIT_SCRIPT%
@echo lm>> %WINDBG_INIT_SCRIPT%
@echo .echo ========== type "k<ENTER>" to see our current stack>> %WINDBG_INIT_SCRIPT%
@echo .echo ========== type "~<ENTER>" to see our current threads>> %WINDBG_INIT_SCRIPT%
@echo .echo ========== type "g<ENTER>" to resume running the program>> %WINDBG_INIT_SCRIPT%


::
:: prints the windbg command that wil be executed (for informational purposes)
::
goto :skip_debug
@set RUSTUP_
@set _NT
@set DBG
pause
@type "%SRCPATH_INIT_SCRIPT%"
@echo =========================================================
pause
@type "%PDBPATH_INIT_SCRIPT%"
@echo =========================================================
pause
@type "%WINDBG_INIT_SCRIPT%"
@echo =========================================================
:skip_debug
@echo start windbg -W Default -c "$><%WINDBG_INIT_SCRIPT%" %*


::
:: then runs WinDBG passing it all arguments given to this script
::
start windbg -W Default -c "$><%WINDBG_INIT_SCRIPT%" %*

::
:: any environment setting beyond these lines will affect the environment settings
::
@endlocal
@endlocal

exit /b 0
