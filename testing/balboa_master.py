from __future__ import annotations

import logging
import os
import random
from hashlib import blake2b, sha256, sha512
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import Dict, Iterator, List, Optional, Union

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, executable_target
from rocky.testing import UNIX_SOCKET_MAX_PATH_LEN
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.capabilities import generate_capability
from rocky.testing.certs import der_pubkey_file
from rocky.testing.logfiles import logfiles_path

_logger = logging.getLogger(__name__)


class BalboaMaster:
    def __init__(
        self,
        name: str,
        machine: Machine,
    ) -> None:
        self.machine = machine
        prefix = machine.tmp_dir / name

        self.data_path = prefix / "rocky-data"
        self.base_secrets_path = prefix / "rocky-secrets"
        self.capabilities_path = prefix / "rocky-capabilities"

        self.data_path.mkdir(parents=True, exist_ok=True)
        self.base_secrets_path.mkdir(parents=True, exist_ok=True)
        self.capabilities_path.mkdir(parents=True, exist_ok=True)

        self.generator = random.Random()
        self.generator.seed("name")

        self.server_secret = self.generator.randbytes(16).hex()
        self.pre_shared_secret = self.generator.randbytes(32).hex()

    def incoming_streams(self) -> Iterator[Path]:
        return self.data_path.glob("incoming-*")

    def outgoing_streams(self) -> Iterator[Path]:
        return self.data_path.glob("outgoing-*")

    def generate_capability_for(
        self, identity: int, other: BalboaMaster, *, spoil_pubkey: bool
    ) -> None:
        generate_capability(
            self.machine,
            self.capabilities_path / f"{other.machine.bind}.capability",
            identity,
            other.server_secret,
            other.pre_shared_secret,
            der_pubkey_file(
                other.machine.hostname
                if not spoil_pubkey
                else other.machine.hostname + ".non-existent"
            ),
            other.machine.bind,
        )


class BalboaMasters:
    """Environment controls for two ends of a Balboa Connection.

    In a previous iteration, BalboaMasters were physically represented
    by a pair of processes, which communicated with Balboa over a
    socket. The current iteration no longer requires these processes,
    and instead provides the information previously sent over that
    socket via environment variables directly to the balboa process.
    This class maintains those environment variables, and provides
    methods to interact with the results.
    """

    def __init__(
        self,
        server_machine: Machine,
        client_machine: Machine,
        assert_min_transmitted_data: Optional[int] = None,
    ) -> None:
        """Generate a pair of balboa masters.
        `server_machine` and `client_machine` can be the same.
        """
        self._assert_min_transmitted_data = assert_min_transmitted_data

        self.server = BalboaMaster("server", server_machine)
        self.client = BalboaMaster("client", client_machine)

        server_machine.add_cleanup_handler(self.validate)
        client_machine.add_cleanup_handler(self.validate)

    @property
    def client_received_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.client.incoming_streams())

    @property
    def server_received_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.server.incoming_streams())

    def validate(self) -> None:
        """Validate the state of data transmission for the balboa
        masters. Should be called after transmission has completed.

        1. **Validity.** the data recieved by both parties should be a
           prefix of the datat that was sent.
        2. **Utility.** if `assert_min_transmitted_data` is specified,
           assert that the amount of transmitted data (in bytes)
           exceeds this size.
        """

        recv_bytes = 0
        for s, r in [(self.server, self.client), (self.client, self.server)]:

            def extract(streams: Iterator[Path]) -> Dict[bytes, bytes]:
                out = dict()
                for stream in streams:
                    data = stream.read_bytes()
                    if len(data) >= 16:
                        out[data[0:16]] = data
                return out

            sent = extract(s.outgoing_streams())
            recv = extract(r.incoming_streams())
            recv_bytes = max(recv_bytes, sum(len(data) for _, data in recv.items()))
            for k, v in recv.items():
                assert k in sent, "%r %r" % (k, sent.keys())
                assert sent[k].startswith(v)
        _logger.info(
            f"Received {self.server_received_bytes} bytes on the server and {self.client_received_bytes} bytes on the client"
        )
        if self._assert_min_transmitted_data is not None:
            assert (
                recv_bytes >= self._assert_min_transmitted_data
            ), f"Got {recv_bytes}. Expected at least {self._assert_min_transmitted_data}"
