import json
import logging
import os
import random
import selectors
import shlex
import shutil
import socket
import string
import struct
import textwrap
from abc import ABC
from dataclasses import dataclass
from datetime import timedelta
from functools import cache, partial
from hashlib import blake2b, sha512
from ipaddress import IPv4Address
from itertools import product
from pathlib import Path
from threading import Lock, Thread
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    cast,
)

import pytest

import rocky
from rocky.etc.machine import DEV_NULL, Machine
from rocky.etc.machine.local import LocalMachine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target, executable_target
from rocky.testing import UNIX_SOCKET_MAX_PATH_LEN
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import MediaPlayer, Vlc
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.certs import der_pubkey_file
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path
from rocky.testing.stallone import StalloneMaster

_logger = logging.getLogger(__name__)


def rocky_key(ip0: IPv4Address, ip1: IPv4Address) -> bytes:
    a, b = sorted([ip0, ip1])
    return sha512(b"rocky mickey test key" + a.packed + b.packed).digest()


class MickeyServer:
    def __init__(self, machine: Machine, master_sock: socket.socket) -> None:
        "Do not manually call this constructor."
        self._machine = machine
        self._master_sock = master_sock

    def _make_and_send_stream(self, ip: IPv4Address, cmd: int) -> socket.socket:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        # TODO: a might leak on error
        try:
            buf = bytes([cmd]) + ip.packed
            self._master_sock.sendmsg(
                [buf],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", b.fileno()))],
            )
            # For testing purposes
            a.settimeout(30)
            return a
        finally:
            b.close()

    def receiver(self, src: "MickeyServer") -> "MickeyReceiver":
        return MickeyReceiver(
            self._machine, self._make_and_send_stream(src._machine.bind, 1)
        )

    def sender(self, dst: "MickeyServer") -> "MickeySender":
        return MickeySender(
            self._machine, self._make_and_send_stream(dst._machine.bind, 2)
        )


def _recvall(sock: socket.socket, size: int) -> bytes:
    assert size >= 0
    buf = bytearray()
    while size > 0:
        partial = sock.recv(size)
        if len(partial) == 0:
            raise EOFError(f"Unexpected EOF with {size} bytes remaining")
        buf += partial
        size -= len(partial)
    return bytes(buf)


class MickeyReceiver:
    def __init__(self, machine: Machine, sock: socket.socket) -> None:
        "Do not manually call this constructor."
        self._sock = sock
        machine.add_cleanup_handler(lambda: self.close())

    def __enter__(self) -> "MickeyReceiver":
        return self

    def __exit__(self, *arg: object) -> None:
        self.close()

    def recv(self) -> bytes:
        size_buf = _recvall(self._sock, 4)
        size = struct.unpack("<I", size_buf)[0]
        return _recvall(self._sock, size)

    def close(self) -> None:
        self._sock.close()


class MickeySender:
    def __init__(self, machine: Machine, sock: socket.socket) -> None:
        "Do not manually call this constructor."
        self._sock = sock
        machine.add_cleanup_handler(lambda: self.close())

    def __enter__(self) -> "MickeySender":
        return self

    def __exit__(self, *arg: object) -> None:
        self.close()

    def send(self, buf: bytes) -> None:
        self._sock.sendall(struct.pack("<I", len(buf)))
        self._sock.sendall(buf)

    def close(self) -> None:
        self._sock.close()


_T = TypeVar("_T")


@dataclass(frozen=True)
class _MickeyMachineInfo(Generic[_T]):
    machine: Machine
    spawn_socket: socket.socket
    mickey_master_socket: socket.socket
    rocky_secret_dir: Path
    mickey_balboa_ipc_path: Path
    server: _T


class MickeyCluster:
    base_path: Path

    def __init__(
        self,
        base_path: Path,
        build_mode: BuildMode,
        count: int,
        spawn_server: Callable[[Machine, EnvBuilder], _T],
        spawn_client: Callable[[Machine, EnvBuilder, _T], None],
    ) -> None:
        "`spawn_client` must be thread-safe."
        assert count >= 1
        assert count <= 254
        ips = [IPv4Address(f"127.42.42.{i + 1}") for i in range(count)]
        close_background_thread_s, close_background_thread_r = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_DGRAM
        )
        self._close_background_thread = close_background_thread_s
        self._closed = False
        self._machines = []
        self.base_path = base_path
        self._spawn_client = spawn_client
        self._build_mode = build_mode
        do_the_close = True
        # Intermediate errors will cause the machines to get torn down, once they're added to the
        # finally.
        try:
            for i, ip in enumerate(ips):
                tmp_dir = base_path / f"m{i+1}"
                tmp_dir.mkdir()
                self._machines.append(
                    LocalMachine(
                        tmp_dir=tmp_dir,
                        bind=ip,
                    )
                )
            # Map from both hostname and IP to machine info
            self._machine_infos: Dict[str, _MickeyMachineInfo[_T]] = dict()
            self._ordered_machine_infos: List[_MickeyMachineInfo[_T]] = []

            for m in self._machines:
                info = self._setup_machine(m, spawn_server=spawn_server)
                self._machine_infos[str(m.bind)] = info
                self._machine_infos[m.hostname] = info
                self._ordered_machine_infos.append(info)
            Thread(
                target=lambda: self._client_spawning_thread(close_background_thread_r),
                daemon=True,
            ).start()
            do_the_close = False
        finally:
            # In case there are any errors during init, we want to cleanly close down the machines
            if do_the_close:
                close_background_thread_r.close()
                self.close()

    def _client_spawning_thread(self, close_background_thread: socket.socket) -> None:
        s = selectors.DefaultSelector()
        try:
            s.register(close_background_thread, selectors.EVENT_READ)
            for m in self._ordered_machine_infos:
                m.spawn_socket.setblocking(False)
                s.register(m.spawn_socket, selectors.EVENT_READ, m)
            while not self._closed:
                events = s.select()
                for key, _ in events:
                    if key.fileobj is close_background_thread:
                        return
                    m = key.data
                    sock = cast(socket.socket, key.fileobj)
                    try:
                        data = sock.recv(4096)
                    except BlockingIOError:
                        continue
                    target_name = data.decode("ascii").strip()
                    if target_name not in self._machine_infos:
                        _logger.warn(
                            "Machine %r/%r wants to spawn a client to non-existant target %r",
                            m.machine.hostname,
                            m.machine.bind,
                            target_name,
                        )
                        continue
                    target = self._machine_infos[target_name]
                    _logger.debug(
                        "Machine %r/%r spawning client to %r/%r",
                        m.machine.hostname,
                        m.machine.bind,
                        target.machine.hostname,
                        target.machine.bind,
                    )
                    self._spawn_client(
                        m.machine,
                        EnvBuilder(m.machine)
                        .add_custom("ROCKY_BASE_SECRETS_PATH", str(m.rocky_secret_dir))
                        .add_custom(
                            "MICKEY_BALBOA_IPC_SOCKET", str(m.mickey_balboa_ipc_path)
                        ),
                        target.server,
                    )
        finally:
            s.close()

    def _setup_machine(
        self, m: Machine, spawn_server: Callable[[Machine, EnvBuilder], _T]
    ) -> _MickeyMachineInfo[_T]:
        StalloneMaster(m, "stlne", add_to_default_env=True)
        state_directory = m.tmp_dir / "mickey_state"
        mickey_socket = state_directory / "mickey_master.sock"
        assert len(str(mickey_socket)) < UNIX_SOCKET_MAX_PATH_LEN
        mickey_balboa_ipc_socket = state_directory / "balboa_mickey_ipc.sock"
        assert len(str(mickey_balboa_ipc_socket)) < UNIX_SOCKET_MAX_PATH_LEN
        ip_hostname_map = m.tmp_dir / "ip-hostname-map.json"
        ip_hostname_map.write_text(
            json.dumps({str(x.bind): x.hostname for x in self._machines})
        )
        rocky_secrets = m.tmp_dir / "mickey-rocky-secrets"
        rocky_secrets.mkdir()
        for x in self._machines:
            (rocky_secrets / f"{x.bind}.der").symlink_to(der_pubkey_file(x.hostname))
            (rocky_secrets / f"{x.bind}.rocky-key").write_bytes(
                rocky_key(m.bind, x.bind)
            )
        spawn_socket_path = m.tmp_dir / "spwn"
        assert len(str(spawn_socket_path)) < UNIX_SOCKET_MAX_PATH_LEN
        spawner = m.tmp_dir / "spawner.sh"
        spawner.write_text(
            textwrap.dedent(
                f"""
                #!/usr/bin/env bash
                set -euo pipefail
                dst={shlex.quote(str(spawn_socket_path))}
                echo -n "$@" | socat - "UNIX-SENDTO:$dst"
                """.strip()
            )
        )
        spawner.chmod(0o555)
        spawn_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        m.add_cleanup_handler(spawn_socket.close)
        spawn_socket.bind(str(spawn_socket_path))
        m.popen(
            pkgset("socat"),
            [
                executable_target("mickey-server").build(self._build_mode).path,
                "--state-directory",
                state_directory,
                "--vlc-launcher",
                spawner,
                "--ip-hostname-map",
                ip_hostname_map,
                "--address",
                str(m.bind),
                "--hostname",
                m.hostname,
                "--pinned-server-key",
                str(rocky_secrets / f"{m.bind}.der"),
            ],
            stdin=DEV_NULL,
            stdout=logfiles_path(m) / "mickey.stdout",
            stderr=logfiles_path(m) / "mickey.stderr",
            env=EnvBuilder(m)
            .add_custom("ROCKY_BASE_SECRETS_PATH", str(rocky_secrets))
            .build(),
        )

        def try_connecting_to_sock(sock_path: str) -> None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(sock_path)

        busy_wait_assert(lambda: try_connecting_to_sock(str(mickey_socket)))
        busy_wait_assert(lambda: try_connecting_to_sock(str(mickey_balboa_ipc_socket)))

        server = spawn_server(
            m,
            EnvBuilder(m)
            .add_custom("ROCKY_BASE_SECRETS_PATH", str(rocky_secrets))
            .add_custom("MICKEY_BALBOA_IPC_SOCKET", str(mickey_balboa_ipc_socket)),
        )
        mickey_master_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        m.add_cleanup_handler(mickey_master_socket.close)
        mickey_master_socket.connect(str(mickey_socket))
        return _MickeyMachineInfo(
            machine=m,
            spawn_socket=spawn_socket,
            rocky_secret_dir=rocky_secrets,
            mickey_balboa_ipc_path=mickey_balboa_ipc_socket,
            mickey_master_socket=mickey_master_socket,
            server=server,
        )

    def __enter__(self) -> "MickeyCluster":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __len__(self) -> int:
        return len(self._ordered_machine_infos)

    def __getitem__(self, index: int) -> MickeyServer:
        return self.mickey_server(index)

    def __iter__(self) -> Iterator[MickeyServer]:
        for i in range(len(self._ordered_machine_infos)):
            yield self.mickey_server(i)

    def mickey_server(self, index: int) -> MickeyServer:
        info = self._ordered_machine_infos[index]
        return MickeyServer(info.machine, info.mickey_master_socket)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            # This send should never block since this is the first time we're writing any data to it
            self._close_background_thread.send(b"close")
        except (ConnectionRefusedError, ConnectionResetError):
            pass
        close_activities = [
            self._close_background_thread.close,
        ] + [m.close for m in self._machines]

        def close_all() -> None:
            nonlocal close_activities
            if len(close_activities) > 0:
                try:
                    close_activities.pop()()
                finally:
                    close_all()

        close_all()
