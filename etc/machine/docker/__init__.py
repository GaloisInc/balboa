import json
import logging
import os
import platform
import random
import shutil
import socket
import string
import subprocess
from dataclasses import dataclass
from datetime import timedelta
from io import BufferedReader, BufferedWriter
from ipaddress import IPv4Address
from math import e
from pathlib import Path
from threading import Lock
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
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
from rocky.etc.machine.docker.netem import NetEmSettings
from rocky.etc.machine.local import LocalMachine, local_machine
from rocky.etc.nix import PkgSet, pkgset, to_nix_literal
from rocky.testing.busy_wait import busy_wait_assert

_logger = logging.getLogger(__name__)

_DOCKER_IMAGES: Dict[FrozenSet[str], str] = dict()
"The key is a frozen set of pkgset cache keys."
_DOCKER_IMAGES_LOCK = Lock()


def _docker_image(pkgsets: List[PkgSet]) -> str:
    """
    Turn a list of docker images into a `image-name:image-tag` string, building it if needed.

    The image build process is completely deterministic.
    """
    if len(pkgsets) == 0:
        pkgsets = [pkgset("empty")]
    cache_key = frozenset(ps.cache_key for ps in pkgsets)
    with _DOCKER_IMAGES_LOCK:
        if cache_key in _DOCKER_IMAGES:
            return _DOCKER_IMAGES[cache_key]
        _logger.info("Building docker image with pkgsets %r", pkgsets)
        # Use nix to make a file containing two lines. The first line is the image name, and the
        # second line is the path to a command which, when run, will dump the docker image to
        # stdout.
        output = subprocess.run(
            [
                "nix-build",
                "etc/nix/docker-image.nix",
                "--no-out-link",
                "--argstr",
                "name",
                "rocky-pkgsets",
                "--arg",
                "rocky_uid",
                # We want the rocky user inside the container to be able to read rocky.ROOT. We want
                # to be able to write to (and importantly, delete) the temporary directory from the
                # host. As a result, we need to make sure that the UID of the rocky user inside the
                # container matches the UID of the host user. Because this UID will be included in
                # the nix hash used in the tag of the container, this won't cause conflicts on a
                # multi-user machine like forge.
                str(os.getuid()),
                "--arg",
                "pkgsets",
                "["
                + " ".join(
                    f"((import {ps.path}) {to_nix_literal(ps.args)})"
                    for ps in sorted(list(pkgsets), key=lambda ps: ps.cache_key)
                )
                + "]",
            ],
            stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            check=True,
            cwd=rocky.ROOT,
        )
        lines = (
            Path(output.stdout.decode("ascii").strip()).read_text().strip().split("\n")
        )
        if len(lines) != 2:
            raise Exception("Malformed docker image build script output")
        img_name = lines[0]
        img_build_cmd = lines[1]
        with local_machine() as m:
            img_check_out = m.run(
                pkgset("docker"), ["docker", "images", "-q", img_name], stdout=PIPE
            )
            if img_check_out.stdout.strip() == b"":
                # We haven't build this image before.
                build_popen = m.popen(pkgset("empty"), [img_build_cmd], stdout=PIPE)
                m.run(pkgset("docker"), ["docker", "load"], stdin=build_popen.stdout)
        _DOCKER_IMAGES[cache_key] = img_name
        return img_name


@dataclass(frozen=True)
class DockerImage:
    pkgsets: List[PkgSet]
    image_identifier: str
    "The `image name:image tag` string."

    @classmethod
    def build(cls, pkgsets: List[PkgSet]) -> "DockerImage":
        return cls(pkgsets, _docker_image(pkgsets))


class _DockerSubprocess(MachineSubprocess):
    def __init__(
        self,
        proc_id: int,
        container: "DockerContainer",
        cmd: List[str],
        stdin: Optional[BufferedWriter],
        stdout: Optional[BufferedReader],
        stderr: Optional[BufferedReader],
    ) -> None:
        super().__init__(stdout=stdout, stdin=stdin, stderr=stderr)
        self._proc_id = proc_id
        self._container = container
        self._cmd = cmd

    def poll(self) -> Optional[int]:
        rc = self._container._send_to_sock(
            dict(which="wait", timeout_seconds=0, proc=self._proc_id), []
        )
        if rc is None:
            return None
        else:
            assert isinstance(rc, int)
            return rc

    def wait(self, timeout: Optional[timedelta] = None) -> int:
        rc = self._container._send_to_sock(
            dict(
                which="wait",
                timeout_seconds=timeout.total_seconds() if timeout else None,
                proc=self._proc_id,
            ),
            [],
        )
        if rc is None:
            assert timeout is not None
            raise subprocess.TimeoutExpired(self._cmd, timeout=timeout.total_seconds())
        else:
            assert isinstance(rc, int)
            return rc

    def terminate(self) -> None:
        self._container._send_to_sock(dict(which="terminate", proc=self._proc_id), [])

    def kill(self) -> None:
        self._container._send_to_sock(dict(which="kill", proc=self._proc_id), [])


class DockerContainer(Machine):
    def __init__(self, parent: "DockerCluster", name: str, image: DockerImage) -> None:
        "This constructor should only be called from the main thread."
        super().__init__()
        assert (
            platform.system() != "Darwin"
        ), "We only support running Docker on native Linux."
        self._image = image
        container_name = f"{parent._name}-{name}-{parent._next_container_id}"
        parent._next_container_id += 1
        tmp_dir = parent._base_path / container_name
        tmp_dir.mkdir()
        self._tmp_dir = tmp_dir
        self._container_name = container_name
        container_id = (
            parent._machine.run(
                pkgset("docker"),
                [
                    "docker",
                    "run",
                    "--rm",
                    "--cap-add",
                    "NET_ADMIN",
                    "--network",
                    parent._network_id,
                    "-v",
                    f"{rocky.ROOT}:{rocky.ROOT}:ro",
                    "-v",
                    f"{tmp_dir}:{tmp_dir}",
                    "--name",
                    container_name,
                    "--detach",
                    "--pull",
                    "never",
                    image.image_identifier,
                ],
                stdout=PIPE,
                timeout=timedelta(seconds=10),
            )
            .stdout.decode("ascii")
            .strip()
        )
        assert len(container_id) > 0
        self._container_id = container_id

        def _kill_docker_container() -> None:
            parent._machine.run(
                pkgset("docker"), ["docker", "kill", container_id], stdout=DEV_NULL
            )

        self.add_cleanup_handler(_kill_docker_container)
        parent._machine.add_cleanup_handler(self.close)
        parent._machine.run(
            pkgset("docker"),
            ["docker", "exec", self._container_id] + parent._netem.netem_command(),
        )
        self._server_sock_path = self._tmp_dir / "rocky-docker.sock"
        parent._machine.popen(
            pkgset("docker"),
            [
                "docker",
                "exec",
                "--user",
                "rocky",
                self._container_id,
                "rocky-docker-server",
                self._server_sock_path,
            ],
            stdout=tmp_dir / "docker-server.stdout",
            stderr=tmp_dir / "docker-server.stderr",
        )

        def assert_server_sock_path_exists() -> None:
            assert self._server_sock_path.exists()

        busy_wait_assert(assert_server_sock_path_exists)

        try:
            self._bind = IPv4Address(
                list(
                    json.loads(
                        parent._machine.run(
                            pkgset("docker"),
                            ["docker", "inspect", self._container_id],
                            stdout=PIPE,
                        ).stdout
                    )[0]["NetworkSettings"]["Networks"].values()
                )[0]["IPAddress"]
            )
        except Exception as e:
            raise Exception("Unable to get container IP") from e

    def _send_to_sock(self, cmd: Any, fds: List[int]) -> Any:
        cmd_json = memoryview(json.dumps(cmd).encode("ascii"))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self._server_sock_path))
            # We send the FDs, if any, along with the first command byte.
            if len(fds) > 0:
                socket.send_fds(sock, [cmd_json[0:1]], fds)
                cmd_json = cmd_json[1:]
            sock.sendall(cmd_json)
            sock.shutdown(socket.SHUT_WR)
            response_bytes = bytearray()
            while True:
                new_data = sock.recv(1024)
                if len(new_data) == 0:
                    break
                else:
                    response_bytes.extend(new_data)
            response = json.loads(response_bytes)
            if "Exception" in response:
                raise Exception(
                    "Received exception from command '%s': %s"
                    % (cmd, response["Exception"])
                )
            elif "ok" in response:
                return response["ok"]
            else:
                raise Exception("Malformed docker server response")
        finally:
            sock.close()

    @property
    def is_darwin(self) -> bool:
        return False

    @property
    def tmp_dir(self) -> Path:
        return self._tmp_dir

    @property
    def hostname(self) -> str:
        return self._container_name

    @property
    def bind(self) -> IPv4Address:
        return self._bind

    def which(self, pkg_set: PkgSet, cmd: str) -> Path:
        if pkg_set not in self._image.pkgsets and pkg_set != pkgset("empty"):
            raise Exception(
                f"Package set {pkg_set} is not present in {self._container_name}"
            )
        return Path(self._send_to_sock(dict(which="which", cmd=cmd), fds=[]))

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
        if pkg_set not in self._image.pkgsets and pkg_set != pkgset("empty"):
            raise Exception(
                f"Package set {pkg_set} is not present in {self._container_name}"
            )
        proc_id = self._send_to_sock(
            dict(
                which="popen",
                args=args,
                cwd=cwd,
                env=env,
            ),
            [stdin_fd, stdout_fd, stderr_fd],
        )
        return _DockerSubprocess(
            proc_id, self, list(args), stdin=stdin, stdout=stdout, stderr=stderr
        )


class DockerCluster:
    "A `DockerCluster` is a collection of containers which can communicate with each other."

    def __init__(
        self, netem: NetEmSettings = NetEmSettings.no_effect(), save_logs: bool = False
    ) -> None:
        """
        Create a new `DockerCluster` with the specified network emulation settings.

        `save_logs` when `True` saves any logs created in this process.
        """
        if not docker_supported():
            raise Exception(
                "We don't think your machine supports docker. "
                + "Is your host machine linux? "
                + "Does the `docker info` command complete successfully?"
            )
        self._tcpdump_started = False
        self._netem = netem
        self._name = "rocky-" + "".join(
            random.choices(string.ascii_letters + string.digits, k=8)
        )
        base_path = f"/tmp/{self._name}"
        self._base_path = Path(base_path)
        self._base_path.mkdir()
        self._machine = LocalMachine(self._base_path, IPv4Address("127.0.0.1"))

        def remove_base_path() -> None:
            if save_logs:
                _logger.info("Logs saved to %s" % base_path)
            else:
                shutil.rmtree(base_path, ignore_errors=True)

        self._machine.add_cleanup_handler(remove_base_path)
        self._next_container_id = 1
        self._containers: List[DockerContainer] = []
        try:
            self._network_id = (
                self._machine.run(
                    pkgset("docker"),
                    ["docker", "network", "create", self._name],
                    stdout=PIPE,
                )
                .stdout.decode("ascii")
                .strip()
            )

            def _cleanup_network() -> None:
                self._machine.run(
                    pkgset("docker"),
                    ["docker", "network", "rm", self._network_id],
                    stdout=DEV_NULL,
                )

            self._machine.add_cleanup_handler(_cleanup_network)
        except:
            # If there are any exceptions during initialization, close() before returning.
            self.close()
            raise

    def new_container(self, name: str, image: DockerImage) -> DockerContainer:
        "This is **NOT** thread-safe. Please only call this from the main thread."
        return DockerContainer(self, name, image)

    def tcpdump(self, dst: Path) -> None:
        """
        Record all of the network packets in the cluster to `dst`.
        This function can only be called once per cluster.
        """
        if self._tcpdump_started:
            raise Exception("tcpdump() can only be called once on a cluster.")
        self._tcpdump_started = True
        # We use docker to get NET_ADMIN rights to dump the network interface, without requiring the
        # user to enter their root password.
        # TODO: does attaching stdout force docker to copy the pcaps through its RPC interface
        # (which could be slow). Consider using the docker server with SCM_RIGHTS to avoid this.
        self._machine.popen(
            pkgset("docker"),
            [
                "docker",
                "run",
                "--rm",
                "-a",
                "stdout",
                "-a",
                "stderr",
                "--net=host",
                "--cap-add",
                "NET_ADMIN",
                "--pull",
                "never",
                "--name",
                f"tcpdump-{self._name}",
                DockerImage.build([pkgset("tcpdump")]).image_identifier,
                "tcpdump",
                "-w",
                "-",
                "-i",
                f"br-{self._network_id[0:12]}",
            ],
            stdout=dst,
        )

    @property
    def name(self) -> str:
        return self._name

    def close(self) -> None:
        _logger.debug("Gracefully closing docker cluster %r", self._name)
        self._machine.close()

    def __enter__(self) -> "DockerCluster":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def docker_supported() -> bool:
    "Return `True` if we detect docker support."
    if platform.system() == "Darwin":
        return False
    try:
        # if we're running under pdoc, then popen won't work properly.
        # TODO: this is a bit of a coarse trick
        import pdoc  # type: ignore

        return False
    except ImportError:
        pass
    with local_machine() as m:
        return (
            m.run(
                pkgset("docker"),
                ["docker", "info"],
                check=False,
                stdout=DEV_NULL,
                stderr=DEV_NULL,
                stdin=DEV_NULL,
            ).returncode
            == 0
        )
