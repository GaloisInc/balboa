from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

from rocky.etc.machine import PIPE, Machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, executable_target


def generate_capability(
    machine: Machine,
    out_path: Path,
    covert_signaling_identity: int,
    server_secret: str,
    rocky_key: str,
    pinned_server_pub_key: Path,
    address: IPv4Address,
) -> None:
    generator_target = executable_target("generate-capability").build(BuildMode.DEBUG)

    result = machine.run(
        pkgset("empty"),
        [
            generator_target.path,
            "--covert-signaling-identity",
            str(covert_signaling_identity),
            "--server-secret",
            server_secret,
            "--rocky-secret",
            rocky_key,
            "--pinned-server-pub-key",
            pinned_server_pub_key,
            "--address",
            str(address),
        ],
        stdout=out_path,
    )
