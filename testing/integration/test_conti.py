import json
import os
import platform
import time
from datetime import timedelta
from typing import Type

import pytest

import rocky
from rocky.etc.machine import Machine
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps import media_players
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import MediaPlayer
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.certs import der_pubkey_file
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.env import EnvBuilder
from rocky.testing.integration.parameterize_utils import Marked, parameterize_test
from rocky.testing.stallone import StalloneMaster

_TEST_SONG = rocky.ROOT / "testing/assets/short.ogg"
_MUSIC_PLAYER_SHOULD_LIVE_AT_LEAST_SECONDS = 5
_MUSIC_PLAYER_TIMEOUT = 30  # mplayer is slow to exit

# TODO: if we want to continue to support the "NO_REWRITE" option in conti, we should test it here.
# Especially since we don't know how it interacts with the other media players.
@parameterize_test(
    media_player=[
        media_players.Vlc,
        media_players.Mpv,
        Marked(media_players.Mplayer, [pytest.mark.skip("Mplayer is flakey")]),
        Marked(
            media_players.Ffmpeg,
            [
                pytest.mark.nightlyonly(),
                pytest.mark.skipif(
                    platform.system() == "Darwin",
                    reason="ffmpeg does not work on darwin",
                ),
            ],
        ),
        Marked(media_players.Ffplay, [pytest.mark.skip("Needs audio device in CI")]),
        Marked(
            media_players.Audacious,
            [pytest.mark.skip("Audacious seems to segfault on True-True")],
        ),
    ],
    rocky_on_server=[True, False],
    rocky_on_client=[True, False],
)
def test_conti(
    machine: Machine,
    stallone_master: StalloneMaster,
    media_player: Type[MediaPlayer],
    cipher_suite: CipherSuite,
    rocky_on_server: bool,
    rocky_on_client: bool,
    build_mode: BuildMode,
) -> None:
    server_env = EnvBuilder(machine)
    client_env = EnvBuilder(machine)

    masters = BalboaMasters(machine, machine)

    server_env.add_balboa_master(masters.server)
    client_env.add_balboa_master(masters.client)

    masters.client.generate_capability_for(
        21, masters.server, spoil_pubkey=not rocky_on_server
    )

    if rocky_on_server:
        server_env.add_injection(
            cdylib_target("balboa-injection-icecast").build(build_mode)
        )
    if rocky_on_client:
        client_env.add_injection(
            cdylib_target("balboa-injection-vlc").build(build_mode)
        )
    client_env.add_non_existent_sslkeylogfile()
    icecast = IcecastServer(
        machine,
        server_env,
        _TEST_SONG,
        loop_song=False,
        cipher_suite=cipher_suite,
    )
    start = time.perf_counter_ns()
    mp = media_player(machine, icecast, client_env)
    result = mp.wait(timeout=timedelta(seconds=_MUSIC_PLAYER_TIMEOUT))
    end = time.perf_counter_ns()
    assert result == 0
    assert (end - start) / (10**9) >= _MUSIC_PLAYER_SHOULD_LIVE_AT_LEAST_SECONDS
    icecast.close()
