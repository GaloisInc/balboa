import logging
import socket
from datetime import timedelta
from pathlib import Path

from rocky.etc.machine import Machine
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, all_built_artifacts, executable_target
from rocky.testing import UNIX_SOCKET_MAX_PATH_LEN
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.logfiles import logfiles_path

_logger = logging.getLogger(__name__)

_SOCKET_FILE_NAME = "2s"


class StalloneMaster:
    def __init__(
        self,
        machine: Machine,
        name: str,
        add_to_default_env: bool,
        check_returncode: bool = False,
    ) -> None:
        """
        Start up a new stallone master. This constructor won't exit until the stallone master is up
        and running.

        The stallone master will be automatically closed when `machine` closes (if it wasn't
        manually closed already).

        Args:
            name: the name of this stallone master. This name should be kept short
                so that the resulting unix socket doesn't have too long a path. This
                function will raise an exception if the name is too long.
            add_to_default_env: register this stallone master in the default environment of the
                machine, so subprocesses will automatically log to it.
        """
        self._machine = machine
        self._stallone_tools = executable_target("stallone-tools").build(
            BuildMode.RELEASE
        )
        self._key = name
        self._out_path = logfiles_path(machine) / f"stallone_{self._key}"
        if self._out_path.exists():
            raise Exception(f"Stallone master name {repr(name)} already used!")
        self._out_path.mkdir()
        self.master_path = machine.tmp_dir / ("STALLONE_" + self._key)
        sock_path = (self.master_path / _SOCKET_FILE_NAME).resolve()
        assert len(str(sock_path)) < UNIX_SOCKET_MAX_PATH_LEN
        self.binary_log_out_path = self._out_path / "raw.bin"
        # Use the systemd readyness protocol to wait for stallone to have started.
        notify_socket_path = self.master_path.with_suffix(".readyness")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify_sock:
            notify_sock.bind(str(notify_socket_path))
            notify_sock.settimeout(5)
            self._proc = machine.popen(
                pkgset("empty"),
                [
                    self._stallone_tools.path,
                    "collect-logs",
                    self.master_path,
                    "--timeout-after-exit-request",
                    str(60 * 2),
                ],
                stdout=self.binary_log_out_path,
                stderr=self._out_path / "collect-logs.stderr.log",
                env={"NOTIFY_SOCKET": str(notify_socket_path)},
            )
            self._proc.close_timeout = timedelta(seconds=60)
            assert notify_sock.recv(256) == b"READY=1"
        assert sock_path.exists
        self._closed = False
        machine.add_cleanup_handler(self.close)
        if add_to_default_env:
            machine.default_env["STALLONE_MASTER"] = str(self.master_path)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._proc.close()
        rc = self._proc.poll()
        assert rc == 0, f"Unexpected stallone returncode {rc}"


def write_stallone_metadata(dst: Path) -> None:
    """
    Write the stallone metadata for all targets built so far to `dst`.

    Since `stallone-tools parse-binary-metadata` emits the Stallone metadata as YAML, it is
    advisable for `dst` to have a `.yml` extension.
    """
    artifacts = all_built_artifacts()
    if len(artifacts) == 0:
        return
    _logger.debug("Writing stallone binary metadata to %s", dst)
    # We'll arbitrarily pick the DEBUG build mode here. It probably shouldn't matter.
    stallone_tools = executable_target("stallone-tools").build(BuildMode.DEBUG)
    with local_machine() as machine:
        machine.run(
            pkgset("empty"),
            [str(stallone_tools.path), "parse-binary-metadata", "-o", str(dst)]
            + [str(ba.path) for ba in artifacts],
        )
