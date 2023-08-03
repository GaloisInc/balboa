import enum
import logging
import random
from functools import wraps
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Sequence, Type

import click

import rocky
from rocky.etc.machine.docker import DockerCluster, DockerImage
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import (
    Audacious,
    Ffmpeg,
    Ffplay,
    MediaPlayer,
    Mplayer,
    Mpv,
    Vlc,
)
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.certs import der_pubkey_file
from rocky.testing.detectability.scenario_lib import scenario
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path
from rocky.testing.stallone import StalloneMaster

_logger = logging.getLogger(__name__)

_MEDIA_PLAYERS: Dict[str, Type[MediaPlayer]] = {
    "vlc": Vlc,
    "mpv": Mpv,
    "mplayer": Mplayer,
    "ffmpeg": Ffmpeg,
    # TODO: not yet working in docker: do we need pulseaudio?
    # "ffplay": Ffplay,
    # TODO: not yet working in docker: do we need pulseaudio?
    # "audacious": Audacious,
}

# We probably don't care about running the classifer on Debug mode.
_BUILD_MODE = BuildMode.RELEASE
_ROCKY_ENABLED = "ROCKY_ENABLED"


@scenario(variants=[_ROCKY_ENABLED, "ROCKY_DISABLED"])
@click.option(
    "--media-player",
    type=click.Choice(sorted(list(_MEDIA_PLAYERS.keys())), case_sensitive=False),
    help="Which media player should be run as the client",
    show_default=True,
    default="vlc",
)
@click.option(
    "--song",
    help="What should be streamed by icecast. (A shorter song will mean a shorter test run.)",
    show_default=True,
    type=click.types.Path(exists=True, file_okay=True, readable=True),
    default=str(rocky.ROOT / "testing/assets/short.ogg"),
)
@click.option(
    "--no-stallone",
    is_flag=True,
    help=(
        "if set, then don't launch the stallone master or provide a `STALLONE_MASTER` environment "
        "variable to services."
    ),
)
def balboa_icecast(
    variant: str,
    cluster: DockerCluster,
    media_player: str,
    song: str,
    no_stallone: bool,
) -> None:
    """
    Run Icecast with a media player both with and without balboa enabled, capturing the packets
    between them.
    """
    the_media_player = _MEDIA_PLAYERS[media_player]
    the_song = Path(song)
    server_image = DockerImage.build([pkgset("apps/icecast")])
    client_image = DockerImage.build([the_media_player.PKG_SET])
    icecast_injection = cdylib_target("balboa-injection-icecast").build(_BUILD_MODE)
    vlc_injection = cdylib_target("balboa-injection-vlc").build(_BUILD_MODE)
    server = cluster.new_container("server", server_image)
    client = cluster.new_container("client", client_image)
    if not no_stallone:
        StalloneMaster(server, "stallone", add_to_default_env=True)
        StalloneMaster(client, "stallone", add_to_default_env=True)
    balboa_masters = BalboaMasters(
        server,
        client,
    )
    server_env = EnvBuilder(server).add_balboa_master(balboa_masters.server)
    if variant == _ROCKY_ENABLED:
        server_env.add_injection(icecast_injection)
    client_env = (
        EnvBuilder(client)
        .add_balboa_master(balboa_masters.client)
        .add_non_existent_sslkeylogfile()
    )
    if variant == _ROCKY_ENABLED:
        client_env.add_injection(vlc_injection)
    icecast = IcecastServer(
        server,
        server_env,
        the_song,
        loop_song=False,
        cipher_suite=None,
    )
    mp = the_media_player(
        client,
        icecast,
        client_env,
    )
    result = mp.wait(timeout=None)
    if result != 0:
        _logger.error("Machine failed with result %d", result)
        raise Exception(
            "Scenario failed. See %s for details (Note that the logs are only saved if the --save-logs flag is used)."
            % logfiles_path(client)
        )


@scenario(variants=["left", "right"])
@click.option(
    "--media-player-left",
    type=click.Choice(sorted(list(_MEDIA_PLAYERS.keys())), case_sensitive=False),
    help="The 'left' media player",
    required=True,
)
@click.option(
    "--media-player-right",
    type=click.Choice(sorted(list(_MEDIA_PLAYERS.keys())), case_sensitive=False),
    help="The 'right' media player",
    required=True,
)
@click.option(
    "--song",
    help="What should be streamed by icecast. (A shorter song will mean a shorter test run.)",
    show_default=True,
    type=click.types.Path(exists=True, file_okay=True, readable=True),
    default=str(rocky.ROOT / "testing/assets/short.ogg"),
)
def icecast_media_players(
    variant: str,
    cluster: DockerCluster,
    media_player_left: str,
    media_player_right: str,
    song: str,
) -> None:
    "Compare the network footprints of two media players. (DOES NOT RUN BALBOA!)"
    media_player = _MEDIA_PLAYERS[
        media_player_left if variant == "left" else media_player_right
    ]
    the_song = Path(song)
    server_image = DockerImage.build([pkgset("apps/icecast")])
    client_image = DockerImage.build([media_player.PKG_SET])
    server = cluster.new_container("server", server_image)
    client = cluster.new_container("client", client_image)
    icecast = IcecastServer(
        server,
        EnvBuilder(server),
        the_song,
        loop_song=False,
        cipher_suite=None,
    )
    mp = media_player(
        client,
        icecast,
        EnvBuilder(client),
    )
    mp.wait(timeout=None)


SCENARIOS = [balboa_icecast, icecast_media_players]
