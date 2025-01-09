REM The timeout for the initial fuzzing setup (milliseconds)
set INITIAL_TIMEOUT=10000

REM The timeout for each fuzzing execution (milliseconds)
set RUN_TIMEOUT=1000

REM The arguments to pass to the benchmark, where @@ is the placeholder for input filename.
REM This binary just takes the input filename, but a more complicated example (ffmpeg) might look like:
REM set BENCH_ARGS=-i @@ out\output.avi -y
set BENCH_ARGS=@@

REM The number of command line args, including the binary name.
set N_ARGS=2
