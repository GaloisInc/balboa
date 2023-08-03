import logging
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, ContextManager, Iterator

import pytest

from rocky.etc.machine import Machine
from rocky.etc.machine.local import LocalMachine
from rocky.etc.rust import BuildMode
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.stallone import StalloneMaster

"""
These fixtures will be automatically available to any integration test.
"""


@pytest.fixture(
    scope="function",
    params=[x for x in list(CipherSuite) if x != CipherSuite.Aes128CBC],
)
def cipher_suite(request: Any) -> Iterator[CipherSuite]:
    yield request.param


@pytest.fixture(scope="function", params=list(CipherSuite))
def cipher_suite_including_cbc(request: Any) -> Iterator[CipherSuite]:
    yield request.param


@pytest.fixture(
    scope="function",
    params=[
        pytest.param(BuildMode.DEBUG, marks=pytest.mark.debugbuild),
        pytest.param(BuildMode.RELEASE, marks=pytest.mark.releasebuild),
    ],
)
def build_mode(request: Any) -> Iterator[BuildMode]:
    yield request.param


@pytest.fixture(scope="function")
def machine(tmp_path: Path) -> Iterator[Machine]:
    "Provide, via a fixture, a `LocalMachine` with reasonable defaults for pytest."
    # TODO: come back to the bind to enable parallelism?
    with LocalMachine(tmp_dir=tmp_path, bind=IPv4Address("127.0.0.1")) as machine:
        yield machine


@pytest.fixture(scope="function")
def stallone_master(machine: Machine) -> StalloneMaster:
    """
    Adding this fixture adds this STALLONE_MASTER to the default environment of the machine (for
    future spawned processes).
    """
    return StalloneMaster(machine, name="stallone", add_to_default_env=True)


# The type of the https://github.com/bjoluc/pytest-reraise fixture.
ReraiseFixture = ContextManager[None]
