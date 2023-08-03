import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import tempfile
from datetime import timedelta
from io import BufferedReader, BufferedWriter
from ipaddress import IPv4Address
from itertools import chain
from pathlib import Path
from threading import Lock
from typing import (
    BinaryIO,
    Dict,
    FrozenSet,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import rocky
from rocky.etc.machine import (
    DEV_NULL,
    PIPE,
    Machine,
    MachineSubprocess,
    ProcessIOArgument,
)
from rocky.etc.nix import PkgSet, to_nix_literal

_logger = logging.getLogger(__name__)


_cache_lock = Lock()
_env_cache: Dict[str, Dict[str, str]] = dict()


def local_pkgset_env(pkgset: PkgSet) -> Dict[str, str]:
    """
    Return the environment variables that need to be set to (locally) enter the context of the
    given package set.
    """
    global _cache_lock
    global _env_cache
    cache_key = pkgset.cache_key
    with _cache_lock:
        if cache_key not in _env_cache:
            # Extract the environment for pkgset. This allows us to only need to invoke `nix-shell`
            # once. This is more efficient than invoking it multiple times.
            _logger.debug(
                "Getting local environment for Nix pkgset: %r%s",
                str(pkgset.path.relative_to(rocky.ROOT)),
                " " + repr(pkgset.args) if len(pkgset.args) > 0 else "",
            )
            env_bytes = subprocess.run(
                ["nix-shell", "--pure"]
                + list(
                    chain(
                        *[
                            ["--arg", k, to_nix_literal(v)]
                            for k, v in pkgset.args.items()
                        ]
                    )
                )
                + [str(pkgset.path), "--run", "exec env --null"],
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            env: Dict[str, str] = dict()
            for entry in env_bytes.split(b"\x00"):
                if len(entry) == 0:
                    continue
                equals = entry.index(b"=")
                env[entry[0:equals].decode("utf-8")] = entry[equals + 1 :].decode(
                    "utf-8"
                )
            if "PWD" in env:
                del env["PWD"]
            _env_cache[cache_key] = env
        return _env_cache[cache_key]


class _LocalMachineSubprocess(MachineSubprocess):
    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        stdin: Optional[BufferedWriter],
        stdout: Optional[BufferedReader],
        stderr: Optional[BufferedReader],
    ) -> None:
        super().__init__(stdout=stdout, stdin=stdin, stderr=stderr)
        self._proc = proc

    def poll(self) -> Optional[int]:
        return self._proc.poll()

    def wait(self, timeout: Optional[timedelta] = None) -> int:
        return self._proc.wait(
            timeout=timeout.total_seconds() if timeout is not None else None
        )

    def terminate(self) -> None:
        self._proc.terminate()

    def kill(self) -> None:
        self._proc.kill()


def _process_fd(
    f: Optional[ProcessIOArgument], is_output: bool
) -> Tuple[bool, Optional[Union[BinaryIO, int]]]:
    if f is None:
        return False, None
    elif f is PIPE:
        return True, subprocess.PIPE
    elif f is DEV_NULL:
        return False, subprocess.DEVNULL
    elif isinstance(f, Path):
        if is_output:
            return True, f.open("wb")
        else:
            return True, f.open("rb")
    elif isinstance(f, int):
        raise Exception(f"{f} is not an IO object.")
    else:
        # Assume it's BinaryIO
        return False, cast(BinaryIO, f)


_hostnames_checked: Set[IPv4Address] = set()
_hostnames_checked_lock = Lock()

_NORMAL_LOCALHOST_BINDS = frozenset([IPv4Address("0.0.0.0"), IPv4Address("127.0.0.1")])


class LocalMachine(Machine):
    def __init__(self, tmp_dir: Path, bind: IPv4Address) -> None:
        """
        This machine will have full R/W access to both `rocky.ROOT` and `self.tmp_dir`.
        # Args
        * `tmp_dir`: the base temporary directory for the machine
        * `bind`: what IP address should processes on this local machine bind to (if they need) to
          bind. If `bind` is anothing other than `127.0.0.1` or `0.0.0.0` then processes spawned
          under this machine will set the `BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT` environment
          variable.
        """
        # TODO: at the moment we're assuming that the bind IP is a valid IP for the given local
        # machine. That's not true for 0.0.0.0, so we should clarify that.
        super().__init__()
        if "TMPDIR" in os.environ:
            self.default_env["TMPDIR"] = os.environ["TMPDIR"]
        self._tmp_dir = tmp_dir
        self._bind = bind
        if bind not in _NORMAL_LOCALHOST_BINDS:
            self.default_env["BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT"] = str(self._bind)
            # Let's also make sure that we can bind to this IP address.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            try:
                try:
                    sock.bind((str(bind), 0))
                except OSError as e:
                    # NOTE: this error should only occur on macOS.
                    # For 127.42.42.{1, 2, ..., 8}, which we commonly use in tests, let's try to
                    # give the user just one command to run, as opposed to making them run one
                    # command for each IP.
                    if bind in [
                        IPv4Address(x) for x in [f"127.42.42.{i+1}" for i in range(8)]
                    ]:
                        suggested_command = f"sudo bash -c 'for i in $(seq 1 8); do ifconfig lo0 alias 127.42.42.$i up; done'"
                    else:
                        suggested_command = (
                            f"sudo bash -c 'ifconfig lo0 alias {bind} up'"
                        )
                    raise Exception(
                        "\n".join(
                            [
                                "You probably need to run the command:",
                                f"    {suggested_command}",
                            ]
                        )
                    ) from e
            finally:
                sock.close()

    @property
    def hostname(self) -> str:
        global _hostnames_checked
        global _hostnames_checked_lock
        if self._bind in _NORMAL_LOCALHOST_BINDS:
            return "localhost"
        else:
            # If this stops working xip.io and nip.io are identical alternatives
            BASE = "sslip.io"
            out = f"test-machine.{self._bind}.{BASE}"
            with _hostnames_checked_lock:
                if self._bind in _hostnames_checked:
                    return out
            actual = IPv4Address(socket.gethostbyname(out))
            if actual != self._bind:
                raise Exception(
                    f"hostname {repr(out)} resolved to {actual} not {self._bind}"
                )
            with _hostnames_checked_lock:
                _hostnames_checked.add(self._bind)
            return out

    @property
    def tmp_dir(self) -> Path:
        return self._tmp_dir

    @property
    def bind(self) -> IPv4Address:
        return self._bind

    @property
    def is_darwin(self) -> bool:
        return platform.system() == "Darwin"

    def which(self, pkg_set: PkgSet, cmd: str) -> Path:
        env = local_pkgset_env(pkg_set)
        out = shutil.which(cmd, path=env["PATH"])
        if out is None:
            raise Exception("Unable to find cmd %r in PATH %r" % (cmd, env["PATH"]))
        return Path(out).resolve()

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
        return _LocalMachineSubprocess(
            subprocess.Popen[bytes](
                args,
                stdin=stdin_fd,
                stdout=stdout_fd,
                stderr=stderr_fd,
                cwd=cwd,
                env=local_pkgset_env(pkg_set) | env,
            ),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )


def local_machine() -> LocalMachine:
    """
    Create a new local machine with reasonable defaults.
    """
    tmp_dir = tempfile.TemporaryDirectory()
    machine = LocalMachine(
        tmp_dir=Path(tmp_dir.name).resolve(),
        bind=IPv4Address("127.0.0.1"),
    )
    machine.add_cleanup_handler(tmp_dir.cleanup)
    return machine
