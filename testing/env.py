from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Dict, Optional

import rocky
from rocky.etc.machine import Machine
from rocky.etc.rust import BuildArtifact, CDylibTarget
from rocky.testing.balboa_master import BalboaMaster
from rocky.testing.certs import ssl_cert_file
from rocky.testing.stallone import StalloneMaster


class EnvBuilder:
    """A builder to construct an environment variable mapping."""

    def __init__(self, machine: Machine) -> None:
        """
        Create a new `EnvBuilder`. By default it includes envrionment variables to override the
        list of root certificate authorities to include the Rocky test CA.
        """
        self._machine = machine
        self._env: Dict[str, str] = dict()
        self.add_custom("SSL_CERT_FILE", str(ssl_cert_file(machine)))
        self.add_custom("NIX_SSL_CERT_FILE", str(ssl_cert_file(machine)))
        self.add_custom("RUST_BACKTRACE", "1")

    def add_stallone(self, stallone_master: StalloneMaster) -> EnvBuilder:
        """
        Explicitly add a StalloneMaster to this environment builder. It's preferable to use the
        `stallone_master` fixture, which will add `STALLONE_MASTER` as a default enviornment var.
        """
        assert "STALLONE_MASTER" not in self._env
        self._env["STALLONE_MASTER"] = str(stallone_master.master_path)
        return self

    def add_injection(
        self, preload_injection: BuildArtifact[CDylibTarget]
    ) -> EnvBuilder:
        "Tell the dynamic linker to inject a dynamic library."
        assert "DYLD_INSERT_LIBRARIES" not in self._env
        assert "LD_PRELOAD" not in self._env
        if self._machine.is_darwin:
            self._env["DYLD_INSERT_LIBRARIES"] = str(preload_injection.path)
        else:
            self._env["LD_PRELOAD"] = str(preload_injection.path)
        return self

    def add_non_existent_sslkeylogfile(self) -> EnvBuilder:
        self._env["SSLKEYLOGFILE"] = str(
            self._machine.tmp_dir / f"sslkeylogfile-{secrets.token_urlsafe()}"
        )
        return self

    def add_balboa_master(self, master: BalboaMaster) -> EnvBuilder:
        self.add_custom("ROCKY_DATA_PATH", master.data_path)
        self.add_custom("ROCKY_CAPABILITIES_PATH", master.capabilities_path)
        self.add_custom("ROCKY_BASE_SECRETS_PATH", master.base_secrets_path)
        self.add_custom("ROCKY_PRE_SHARED_SECRET", master.pre_shared_secret)

        self.add_custom("ROCKY_SERVER_SECRET", master.server_secret)

        return self

    def add_custom(self, key: str, value: str | Path) -> EnvBuilder:
        """Add a custom environment variable to the map."""
        self._env[key] = str(value)
        return self

    def build(self) -> Dict[str, str]:
        return dict(self._env)
