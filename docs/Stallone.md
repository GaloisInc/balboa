---
title: "Stallone"
...
Stallone is a high-performance logging library for Rust.
# Why does Balboa need a new logging library?
Balboa has a number of unique considerations which other systems do not have.

* **Performance Requirements.** Balboa's security _depends_ on its ability to rewrite network traffic _quickly_. Its rewrite performance cannot be impacted by a slow disk or other considerations. As a result, we need a library which will _drop_ log events if its buffers get full, rather than blocking the logging process (which would cause security issues).
* **Embedded in Another Process.** Balboa runs injected into other processes. These other processes frequently `fork()`. Balboa's logging system must be resilient to forking, as well as being amenable to running inside a process that we've been dynamically injected into.

# High-Level Stallone Overview
Stallone is a low-latency logging library for Rust. It achieves its high-performance by optimizing, as much as possible, the write-side of the logger. To that end, Stallone implemented [structured logging](https://sematext.com/glossary/structured-logging/)--not just because it makes the logs more useful, but because it makes logging faster. A lot of time is spent 