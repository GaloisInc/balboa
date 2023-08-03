# This module tests the Docker machine functionality which is used for benchmarking.

import logging
import time
from datetime import timedelta

import pytest

import rocky
from rocky.etc.machine import PIPE
from rocky.etc.machine.docker import DockerCluster, DockerImage, docker_supported
from rocky.etc.machine.docker.netem import NetEmNormalDelay, NetEmSettings
from rocky.etc.nix import pkgset
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.env import EnvBuilder

# This will apply to all tests in this module.
pytestmark = pytest.mark.skipif(
    not docker_supported(), reason="docker is not supported"
)

_logger = logging.getLogger(__name__)


CUTOFF_DURATION = timedelta(seconds=1)


def icecast_docker_curl(netem: NetEmSettings) -> timedelta:
    with DockerCluster(netem) as cluster:
        server = cluster.new_container(
            "server", DockerImage.build([pkgset("apps/icecast")])
        )
        client = cluster.new_container(
            "client", DockerImage.build([pkgset("apps/icecast")])
        )
        icecast = IcecastServer(
            server,
            EnvBuilder(server),
            rocky.ROOT / "testing/assets/large.ogg",
            loop_song=True,
            cipher_suite=None,
        )
        # Curl the homepage
        homepage_url = icecast.music_url.replace("vorbis.ogg", "")
        start = time.perf_counter_ns()
        homepage_contents = (
            client.run(
                pkgset("apps/icecast"),
                ["curl", homepage_url],
                stdout=PIPE,
                env=EnvBuilder(client).build(),
            )
            .stdout.decode("ascii")
            .lower()
        )
        end = time.perf_counter_ns()
        assert "icecast" in homepage_contents
    return timedelta(microseconds=(end - start) / 1000)


def test_icecast_docker() -> None:
    duration = icecast_docker_curl(NetEmSettings.no_effect())
    _logger.info("Duration=%s", duration)
    assert duration < CUTOFF_DURATION


def test_icecast_docker_delayed() -> None:
    duration = icecast_docker_curl(
        NetEmSettings(
            delay=NetEmNormalDelay(
                timedelta(milliseconds=250), timedelta(milliseconds=1)
            )
        )
    )
    _logger.info("Duration=%s", duration)
    assert duration > CUTOFF_DURATION
