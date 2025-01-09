@echo off
REM This is the main script for launching a fuzzing session under WinFuzz.
REM Command line parameters:
REM benchmark_winfuzz.bat <benchmark name> <# of seconds to run fuzzer for> <# of fuzzing iterations before restarting process completely>
mkdir ..\results\%1\
call %1\env.bat
set WINFUZZ_TIMEOUT=%2
..\Win32\Release\afl-fuzz.exe -i %1\in -o ..\results\%1\winfuzz -t %RUN_TIMEOUT% -I %INITIAL_TIMEOUT% -- -bbfile %1\bblist_%1.bb -- -harness %1\%1_harness.dll -no_minidumps -nofork -persistent_iterations %3 -- %1\%1.exe %BENCH_ARGS%
taskkill /im %1.exe
