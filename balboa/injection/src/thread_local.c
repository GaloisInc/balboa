#include <stdint.h>

// See ../build.rs for the rationale for this C file.

static _Thread_local uint8_t balboa_injection_already_entered = 0;

// This is signal-safe. See build.rs for the tls-model argument that makes accessing this
// thread-local signal-safe.
uint8_t* balboa_injection_already_entered_thread_local() {
    return &balboa_injection_already_entered;
}
