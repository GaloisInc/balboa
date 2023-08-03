#include <stdint.h>

// See ../build.rs for the rationale for this C file.

#define PAYLOAD_SIZE 120

// Keep this entire header in sync with thread_local.rs
struct StalloneThreadLocal {
    uint64_t state;
    uint8_t payload[PAYLOAD_SIZE];
};

static _Thread_local struct StalloneThreadLocal stallone_thread_local = {0};

// This is signal-safe. See build.rs for the tls-model argument that makes accessing this
// thread-local signal-safe.
struct StalloneThreadLocal* stallone_thread_local_access() {
    return &stallone_thread_local;
}
