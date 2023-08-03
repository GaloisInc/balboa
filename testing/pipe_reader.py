import io
import os
from threading import Lock, Thread
from typing import BinaryIO

from rocky.etc.machine import Machine
from rocky.testing.logfiles import logfiles_path


class PipeReader:
    """
    Spawn a background thread to read continuously from a stream, allowing the
    main thread to sample from it.

    NOTE: unless you need to read output from a process while it's still running,
    prefer redirecting to a file, since that doesn't require a Python thread.

    In addition, closing the PipeReader will close the reciever side of the stream.
    If PipeReader is attached to process, this may trigger a SIGPIPE on that process,
    which may kill it. If this is undesierable, make sure to close the process first.

    The stream _must_ support fileno(). PipeReader will read directly from the file
    descriptor, and avoid any buffering.
    """

    def __init__(self, machine: Machine, log_out: str, stream: BinaryIO) -> None:
        self._closed = False
        self._stream = stream
        self._log_file_dst = (logfiles_path(machine) / log_out).open("wb")
        self._buffer = bytearray()
        self._lock = Lock()
        self._thread = Thread(
            target=self._background_thread,
            daemon=True,
            name=f"write stream into {log_out}",
        )
        self._thread.start()
        machine.add_cleanup_handler(self.close)

    def _background_thread(self) -> None:
        try:
            while True:
                try:
                    # If self._stream is buffered, read takes a lock. If the
                    # main thread tries to close the stream, it'd also need to
                    # take the lock, which would cause deadlock! As a result,
                    # we instead read from the file descriptor directly.
                    extra = os.read(self._stream.fileno(), 1024 * 1024)
                    if len(extra) == 0:
                        break
                except:
                    break
                self._log_file_dst.write(extra)
                with self._lock:
                    self._buffer += extra
        finally:
            self._log_file_dst.close()

    def sample(self) -> bytes:
        with self._lock:
            return bytes(self._buffer)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stream.close()
        # DO NOT self._thread.join()
        # Making that thread exit when the PipeReader is closed is hard.
        # Closing self._stream isn't sufficient.
        # See "Multithreaded processes and close()" in
        # https://man7.org/linux/man-pages/man2/close.2.html
        # Instead, we just give up. That thread should die once the
        # subprocess exits.
