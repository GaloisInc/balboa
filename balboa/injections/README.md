To use these injections, you'll want to run the target binary with special environment variables set:
  * Set `LD_PRELOAD` (`DYLD_INSERT_LIBRARIES` on a Mac) to the path of the compiled `.so` (`.dylib` on a Mac)
  * Set `STALLONE_MASTER` to the path of a stallone master's socket
  * Set `ROCKY_MASTER_SOCKET` to the path of the rocky master's socket.

Individual injections may require additional environment variables, as well.
