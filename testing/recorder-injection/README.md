On a Mac use `env DYLD_INSERT_LIBRARIES=target/debug/libbalboa_recorder_injection.dylib`

On Linux, use `env LD_PRELOAD=target/debug/libbalboa_recorder_injection.so` 

`rm -f /tmp/stallone-master; cargo run --bin stallone-tools -- run-master-streaming --socket-path /tmp/stallone-master target/debug/libbalboa_recorder_injection.so`

`env TRANSCRIPT_FILE=test_transcript RUST_BACKTRACE=1 DYLD_INSERT_LIBRARIES=target/debug/libbalboa_recorder_injection.dylib STALLONE_MASTER=/tmp/stallone-master nc -l -p 12345`

`env TRANSCRIPT_FILE=test_transcript RUST_BACKTRACE=1 LD_PRELOAD=target/debug/libbalboa_recorder_injection.so STALLONE_MASTER=/tmp/stallone-master nc -l -p 12345`

`echo hello world | nc localhost 12345`
