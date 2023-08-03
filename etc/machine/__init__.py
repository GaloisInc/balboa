import os
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass
from datetime import timedelta
from io import BufferedReader, BufferedWriter
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock, Thread
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import rocky
from rocky.etc.nix import PkgSet


class MachineSubprocess(ABC):
    """
    A running subprocess in a Machine (similar to `subprocess.Popen`). This subprocess will be
    automatically `close()` when the Machine is closed.
    """

    stdin: Optional[BufferedWriter]
    "The stdin pipe, only if `stdin=PIPE` was passed to `popen()`"
    stdout: Optional[BufferedReader]
    "The stdout pipe, only if `stdout=PIPE` was passed to `popen()`"
    stderr: Optional[BufferedReader]
    "The stderr pipe, only if `stderr=PIPE` was passed to `popen()`"
    close_timeout: timedelta = timedelta(seconds=5)
    "Wait `close_timeout` for the process to exit before killing it (on `close()`)"

    def __init__(
        self,
        stdin: Optional[BufferedWriter],
        stdout: Optional[BufferedReader],
        stderr: Optional[BufferedReader],
    ) -> None:
        self._closed = False
        self.stdout = stdout
        self.stdin = stdin
        self.stderr = stderr

    @abstractmethod
    def poll(self) -> Optional[int]:
        """
        Return `None` if the process is still running. If the process has exited, return its exit
        code.
        """
        ...

    @abstractmethod
    def wait(self, timeout: Optional[timedelta] = None) -> int:
        """
        If the process has not yet exited, wait for it to finish, and return the return code.
        If a `timeout` is specified, then raise an exception if the subprocess doesn't finish in
        time.
        """
        ...

    @abstractmethod
    def terminate(self) -> None:
        """SIGTERM the subprocess."""
        ...

    @abstractmethod
    def kill(self) -> None:
        """SIGKILL the subprocess."""
        ...

    def communicate(
        self, input: Optional[bytes], timeout: Optional[timedelta]
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Run the process to completion, writing `input` to stdin (asuming that the process was
        launched with `stdin=PIPE`), and returning `(stdout, stderr)` if they were set as `PIPE`
        when the process was launched.

        This function should be called at most once.
        """
        deadline = (
            time.monotonic() + timeout.total_seconds() if timeout is not None else None
        )
        remaining_timeout: Callable[[], Optional[float]] = (
            lambda: max(0.0, deadline - time.monotonic())
            if deadline is not None
            else None
        )
        threads: List[Thread] = []
        stdout: Optional[bytes] = None
        stderr: Optional[bytes] = None
        if input is not None:
            if self.stdin is None:
                raise Exception("You can't provide input if stdin is None!")
            else:

                def _stdin_thread() -> None:
                    # Mypy's flow-sensitive typing doesn't track state across a closure boundary, so
                    # we need to manually assert to appease the type checker.
                    assert self.stdin is not None
                    assert input is not None
                    self.stdin.write(input)
                    self.stdin.close()

                threads.append(Thread(target=_stdin_thread))
        if self.stdout is not None:

            def _stdout_thread() -> None:
                nonlocal stdout
                assert self.stdout is not None
                stdout = self.stdout.read()

            threads.append(Thread(target=_stdout_thread))
        if self.stderr is not None:

            def _stderr_thread() -> None:
                nonlocal stderr
                assert self.stderr is not None
                stderr = self.stderr.read()

            threads.append(Thread(target=_stderr_thread))
        for thread in threads:
            thread.daemon = True
            thread.start()
        # TODO: timeouts here should become subprocess timeout errors.
        for thread in threads:
            thread.join(remaining_timeout())
        rt = remaining_timeout()
        self.wait(timedelta(seconds=rt) if rt is not None else None)
        self.close()
        return stdout, stderr

    def close(self) -> None:
        """
        This idempotent method will clean up and completely dispose of the
        process.
        """
        if self._closed:
            return
        self._closed = True
        try:
            # Flushing a buffered stream might raise an exception
            # It might also block indefinitely.
            if self.stdin:
                # To avoid deadlock, we close the underlying file descriptor, without flushing the
                # buffer. This will cause any data in the stdin buffer to be lost. We document this
                # fact in the popen documentation, saying that users should flush stdin if they care
                # about the data there.
                try:
                    self.stdin.raw.close()
                except (BrokenPipeError, BlockingIOError):
                    pass
        finally:
            if self.poll() is None:
                # The process is not dead.
                self.terminate()
                try:
                    self.wait(timeout=self.close_timeout)
                except subprocess.TimeoutExpired:
                    self.kill()
                    self.wait()
                assert self.poll() != -int(signal.SIGSEGV)
                assert self.poll() != -int(signal.SIGBUS)
                assert self.poll() != -int(signal.SIGILL)
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()


_Pipe = NamedTuple("_Pipe", [])
PIPE = _Pipe()
"""A sentinel object to denote that a stream to a process ought to be a pipe."""

_DevNull = NamedTuple("_DevNull", [])
DEV_NULL = _DevNull()
"""A sentinel object to denote that a stream to a process ought to be `/dev/null`."""

ProcessIOArgument = Union[BinaryIO, Path, _Pipe, _DevNull]

_T = TypeVar("_T")
_dev_null_fd = os.open("/dev/null", os.O_RDWR)


@dataclass
class _ProcessFdOutput:
    close_fd: bool
    """
    If `True`, then close `fd` immediately after the fork. This should be set only when `fd` was
    opened by `_process_fd`.
    """
    fd_to_popen: int
    stream_for_subprocess_object: Optional[BinaryIO]
    "This is the File object that is created for `PIPE` FDs."


def _process_fd(
    f: Optional[ProcessIOArgument], default_fileno: int, is_output: bool
) -> _ProcessFdOutput:
    """
    `is_output` is `True` if the *subprocess* will be *writing*, while the current process will be
    reading.
    """
    if f is None:
        return _ProcessFdOutput(
            close_fd=False,
            fd_to_popen=default_fileno,
            stream_for_subprocess_object=None,
        )
    elif isinstance(f, _Pipe):
        r, w = os.pipe()
        if is_output:
            theirs, ours = (w, r)
        else:
            theirs, ours = (r, w)
        return _ProcessFdOutput(
            # We close the "theirs" pipe.
            close_fd=True,
            fd_to_popen=theirs,
            stream_for_subprocess_object=cast(
                BinaryIO, os.fdopen(ours, "rb" if is_output else "wb")
            ),
        )
    elif isinstance(f, _DevNull):
        return _ProcessFdOutput(
            close_fd=False, fd_to_popen=_dev_null_fd, stream_for_subprocess_object=None
        )
    elif isinstance(f, Path):
        return _ProcessFdOutput(
            # We shouldn't keep the FD for the file around, after the fork.
            close_fd=True,
            fd_to_popen=os.open(
                f, os.O_WRONLY | os.O_CREAT if is_output else os.O_RDONLY
            ),
            stream_for_subprocess_object=None,
        )
    elif isinstance(f, int):
        raise Exception(f"{f} is not an IO object.")
    else:
        # Assume it's BinaryIO
        return _ProcessFdOutput(
            close_fd=False,
            fd_to_popen=cast(Any, f).fileno(),
            stream_for_subprocess_object=None,
        )


class Machine(ABC):
    """
    A machine on which commands can be run and files can be manipulated.

    # Paths
    This machine will (at least) have *Read Only* access to `rocky.ROOT` and its subdirectories, and
    *Read/Write* access to `self.tmp_dir`.

    # Platform
    This machine must be able to run Rust binaries compiled (under Nix) for the host machine.

    # Cleaning Up
    Rather than putting the burden on consumers of your API to ensure that a `close()` method is
    called for every resource that you allocate, it's preferable to use the `add_cleanup_handler()`
    functionality to ensure that resources are cleaned up when the machine is closed. This can help
    avoid verbose clean-up code, and make it harder to accidentally forget to clean-up a resource.
    """

    def __init__(self) -> None:
        self._cleanup_handlers: List[Callable[[], None]] = []

        self._closing_on_thread_id: Optional[int] = None
        self._closing_lock = Lock()
        # Cargo will try to invoke, for example, cargo-fmt in ~/.cargo/bin/cargo-fmt, before it
        # checks the PATH environment variable. If we set the homedir to be a folder inside of
        # rocky, this problem can't happen.
        home = rocky.ROOT / "target/home"
        home.mkdir(exist_ok=True, parents=True)
        self.default_env: Dict[str, str] = {"HOME": str(home)}
        if rocky.IS_IN_CI:
            self.default_env["ROCKY_IS_IN_CI"] = "1"

    @property
    @abstractmethod
    def is_darwin(self) -> bool:
        ...

    @property
    @abstractmethod
    def hostname(self) -> str:
        ...

    @property
    @abstractmethod
    def tmp_dir(self) -> Path:
        """
        The path to a fresh temporary directory on the machine.
        """
        ...

    @property
    @abstractmethod
    def bind(self) -> IPv4Address:
        """
        The address to which servers on this machine should bind to.
        """
        ...

    def add_cleanup_handler(self, cleanup: Callable[[], None]) -> None:
        """
        Add a handler to run when `Machine` gets closed. Cleanup handlers will
        be run in the reverse of the order in which they were added.

        This is thread-safe.

        It is valid to add clean up handlers from a cleanup handler. They will be run as part of
        the cleanup process.
        """
        with self._closing_lock:
            if (
                self._closing_on_thread_id is not None
                and self._closing_on_thread_id != threading.get_ident()
            ):
                raise Exception(
                    f"Machine {self} is closing on a different thread, while we're trying to register a callback on it."
                )
            self._cleanup_handlers.append(cleanup)

    def _close(self, lst: Iterator[Callable[[], None]]) -> None:
        try:
            callback = next(lst)
        except StopIteration:
            return
        try:
            with self._closing_lock:
                self._cleanup_handlers = []
            callback()
        finally:
            # TODO: don't use finally in case this stack overflows.
            # If the callback registered some cleanup handlers, call them, too!
            with self._closing_lock:
                cleanup_handlers = list(self._cleanup_handlers)
                self._cleanup_handlers = []
            self._close(reversed(cleanup_handlers))
            self._close(lst)

    def close(self) -> None:
        "Close the machine by running all of its cleanup handlers."
        with self._closing_lock:
            if self._closing_on_thread_id is not None:
                return
            self._closing_on_thread_id = threading.get_ident()
            cleanup_handlers = list(self._cleanup_handlers)
            self._cleanup_handlers = []
        self._close(reversed(cleanup_handlers))
        with self._closing_lock:
            # Avoid race condition.
            self._closing_on_thread_id = 0

    def __enter__(self: _T) -> _T:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        if self._closing_on_thread_id is None:
            print("Machine %r was not closed" % self)

    @abstractmethod
    def which(self, pkg_set: PkgSet, cmd: str) -> Path:
        """
        Find the path of `cmd` in `pkg_set`. Raise an Exception if it's not found.
        """
        ...

    @abstractmethod
    def _popen(
        self,
        pkg_set: PkgSet,
        args: Sequence[str],
        stdin_fd: int,
        stdout_fd: int,
        stderr_fd: int,
        stdin: Optional[BufferedWriter],
        stdout: Optional[BufferedReader],
        stderr: Optional[BufferedReader],
        cwd: str,
        env: Dict[str, str],
    ) -> MachineSubprocess:
        """
        An internal-only method to spawn a subprocess for the machine.

        The `_fd` arguments are file descriptors which should become the standard streams for the
        subprocess.

        The `std` arguments should be passed to the `MachineSubprocess` constructor. They are
        non-`None` only if the corresponding argument to `popen` was `PIPE`.

        The `env` will already have `self._default.env` added in.
        """

    def popen(
        self,
        pkg_set: PkgSet,
        args: Sequence[Union[str, Path]],
        *,
        stdin: Optional[ProcessIOArgument] = DEV_NULL,
        stdout: Optional[ProcessIOArgument] = None,
        stderr: Optional[ProcessIOArgument] = None,
        cwd: Optional[Union[Path, str]] = None,
        env: Dict[str, str] = dict(),
    ) -> MachineSubprocess:
        """
        Run a subprocess. This behaves just like `subprocess.popen`, except that
        it requires a package set as input, `check` defaults to `True`, and
        `env` adds to the environment, instead of replacing all of its contents

        It is valid to set the std{io,out,err} arguments to a path, instead of
        a stream The path can be either be valid for the local machine, or for
        the remote machine. Files passed into these arguments will not be
        closed by this function.

        Rather than using `subprocess.PIPE` and friends, this module defines type-safe alternatives.

        If you use `stdin=PIPE`, and you care to make sure that all its contents get delivered, make
        sure to manually call `flush()` on the `stdin` pipe.

        The default cwd is `self.tmp_path`.

        This function is thread-safe.
        """
        fds: List[_ProcessFdOutput] = []
        try:
            # 0, 1, and 2 are the standard fileno's for stdin, stdout, and stderr, respectively.
            fds.append(_process_fd(f=stdin, default_fileno=0, is_output=False))
            fds.append(_process_fd(f=stdout, default_fileno=1, is_output=True))
            fds.append(_process_fd(f=stderr, default_fileno=2, is_output=True))
            proc = self._popen(
                pkg_set,
                [str(arg) for arg in args],
                cwd=str(cwd or self.tmp_dir),
                env=self.default_env | env,
                # These three types are correct, but they're determined by is_output above and, even
                # though we could technically properly type this by using overloads and literal
                # types on _process_fd, it's really not worth it, as _process_fd is only invoked
                # here, anyway.
                stdin=fds[0].stream_for_subprocess_object,  # type: ignore
                stdout=fds[1].stream_for_subprocess_object,  # type: ignore
                stderr=fds[2].stream_for_subprocess_object,  # type: ignore
                stdin_fd=fds[0].fd_to_popen,
                stdout_fd=fds[1].fd_to_popen,
                stderr_fd=fds[2].fd_to_popen,
            )
            self.add_cleanup_handler(proc.close)
            for fd in fds:
                # Don't close the subprocess object below.
                fd.stream_for_subprocess_object = None
        finally:
            for fd in fds:
                if fd.close_fd:
                    os.close(fd.fd_to_popen)
                if fd.stream_for_subprocess_object:
                    fd.stream_for_subprocess_object.close()
        return proc

    def run(
        self,
        pkg_set: PkgSet,
        args: Sequence[Union[str, Path]],
        *,
        input: Optional[bytes] = None,
        stdin: Optional[ProcessIOArgument] = DEV_NULL,
        stdout: Optional[ProcessIOArgument] = None,
        stderr: Optional[ProcessIOArgument] = None,
        capture_output: bool = False,
        cwd: Optional[Union[Path, str]] = None,
        timeout: Optional[timedelta] = None,
        check: bool = True,
        env: Dict[str, str] = dict(),
    ) -> subprocess.CompletedProcess[bytes]:
        """
        Run a subprocess. This behaves just like `subprocess.run`, except that
        it requires a package set as input, `check` defaults to `True`, and
        `env` adds to the environment, instead of replacing all of its contents

        capture_output just sets stdout and stderr to PIPE.

        Rather than using `subprocess.PIPE` and friends, this module defines type-safe alternatives.

        It is valid to set the std{io,out,err} arguments to a path, instead of
        a stream The path can be either be valid for the local machine, or for
        the remote machine. Files passed into these arguments will not be
        closed by this function.

        The default cwd is `self.tmp_dir`

        This function is thread-safe.
        """
        if stdin is PIPE:
            raise ValueError(
                "It doesn't make sense to have stdin=PIPE as an argument to run."
            )
        if input is not None:
            if stdin is not None:
                raise ValueError("You can't set both input AND stdin")
            stdin = PIPE
        if capture_output:
            if stdout is not None or stderr is not None:
                raise ValueError(
                    "You can't set both capture_output AND (stdout OR stderr)"
                )
            stdout = PIPE
            stderr = PIPE
        final_args = [str(x) for x in args]
        with closing(
            self.popen(
                pkg_set,
                args,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=env,
            )
        ) as cmd:
            out, err = cmd.communicate(input, timeout=timeout)
            rc = cmd.poll()
            assert rc is not None
            cp = subprocess.CompletedProcess(
                returncode=rc, args=final_args, stdout=out, stderr=err
            )
            if check:
                cp.check_returncode()
            return cp
