from ipaddress import IPv4Address
from pathlib import Path

import rocky
from rocky.etc.machine.local import LocalMachine
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import Vlc
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.env import EnvBuilder

_TEST_SONG = rocky.ROOT / "testing/assets/short.ogg"


def test_balboa_bind_pre_connect(tmp_path: Path, build_mode: BuildMode) -> None:
    """
    Test that setting BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT for local machines works.
    """
    bind = IPv4Address("127.42.42.1")
    with LocalMachine(tmp_path, bind) as machine:
        icecast = IcecastServer(
            machine, EnvBuilder(machine), _TEST_SONG, False, cipher_suite=None
        )
        injection = cdylib_target("balboa-recorder-injection").build(build_mode)
        Vlc(
            machine,
            icecast,
            EnvBuilder(machine)
            # We need to pick _some_ injection to check that the pre-connect bind works.
            # The actual injection doesn't even need to do TLS manipulation.
            .add_injection(injection).add_custom("TRANSCRIPT_FILE", "/dev/null"),
        )

        def check() -> None:
            assert str(bind) in icecast.stderr_log.read_text()

        busy_wait_assert(check)
