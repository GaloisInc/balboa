import re
import shlex
from abc import ABC, abstractmethod
from datetime import timedelta
from secrets import token_urlsafe
from typing import Callable, List, NamedTuple, Optional

from rocky.etc.machine import DEV_NULL, Machine
from rocky.etc.nix import PkgSet, pkgset
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.certs import ssl_cert_file
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path


class MediaPlayer(ABC):
    """A media player which can stream music from an icecast server."""

    SUPPORTS_DARWIN: bool
    PKG_SET: PkgSet

    @abstractmethod
    def _args(self, machine: Machine, url: str) -> List[str]:
        ...

    def __init__(
        self, machine: Machine, icecast: IcecastServer, env: EnvBuilder
    ) -> None:
        """
        Spawn a media player on the given `machine` which connects to `icecast`. The media player
        will have its environment variables set according to `env`. If it's not manually closed,
        the media player will be closed when the machine closes.
        """
        if machine.is_darwin:
            assert self.SUPPORTS_DARWIN
        args = self._args(machine, icecast.music_url)
        player = args[0]
        name = f"{player}-{token_urlsafe(8)}"
        remote_song_path = machine.tmp_dir / f"{name}-song.ogg"
        remote_song_path.symlink_to(icecast.song_path.resolve())
        # If we do any injection, we want to make sure that our library is directly
        # injected into the target executable. For a number of our media players, nix
        # has wrapper bash scripts set-up around the actual executable. If we naively
        # inject, then we end up injecting into bash, instead of the target executable.

        player_path = machine.which(self.PKG_SET, player)

        # First, let's see if there's a wrapper script.
        with player_path.open("rb") as f:
            uses_bash_wrapper = f.read(2) == b"#!"

        # We'll write our own wrapper script which will, if there is a bash wrapper,
        # set environment variables, and then source the original wrapper. Otherwise,
        # our outer wrapper script will just set environment variables, and then exec
        # the binary.

        runner_script = machine.tmp_dir / f"{name}.run.sh"
        export_env = "\n".join(
            f"export {k}={shlex.quote(v)}"
            for k, v in (env.build() | {"OGG_FILE": str(remote_song_path)}).items()
        )
        runner_script.write_text(
            f"""set -e
{export_env}
set -- {' '.join(shlex.quote(str(x)) for x in args[1:])}
source {player_path}"""
            if uses_bash_wrapper
            else f"""set -e
{export_env}
exec {player_path} {' '.join(shlex.quote(str(x)) for x in args[1:])}"""
        )
        self._proc = machine.popen(
            self.PKG_SET,
            ["bash", runner_script],
            stdin=DEV_NULL,
            stdout=logfiles_path(machine) / f"{name}.stdout",
            stderr=logfiles_path(machine) / f"{name}.stderr",
        )

    def wait(self, timeout: Optional[timedelta]) -> int:
        """Wait for the media player to exit and return the exit status."""
        return self._proc.wait(timeout)

    def close(self) -> None:
        self._proc.close()


class Audacious(MediaPlayer):
    SUPPORTS_DARWIN: bool = False
    PKG_SET: PkgSet = pkgset("apps/audacious")

    def _args(self, machine: Machine, url: str) -> List[str]:
        return ["audacious", "-H", "-VV", "-q", url]


class Ffmpeg(MediaPlayer):
    SUPPORTS_DARWIN: bool = False  # XXX Not yet tested on Darwin
    PKG_SET: PkgSet = pkgset("apps/ffmpeg")

    def _args(self, machine: Machine, url: str) -> List[str]:
        return ["ffmpeg", "-v", "debug", "-f", "null", "-", "-i", url]


class Ffplay(MediaPlayer):
    SUPPORTS_DARWIN: bool = False  # XXX Not yet tested on Darwin
    PKG_SET: PkgSet = pkgset("apps/ffmpeg")

    def _args(self, machine: Machine, url: str) -> List[str]:
        return ["ffplay", "-v", "debug", "-nodisp", "-autoexit", "-volume", "0", url]


class Mpv(MediaPlayer):
    SUPPORTS_DARWIN: bool = True
    PKG_SET: PkgSet = pkgset("apps/mpv")

    def _args(self, machine: Machine, url: str) -> List[str]:
        return ["mpv", "--ao=null", url]


class Mplayer(MediaPlayer):
    SUPPORTS_DARWIN: bool = True
    PKG_SET: PkgSet = pkgset("apps/mplayer")

    def _args(self, machine: Machine, url: str) -> List[str]:
        return ["mplayer", "-ao", "null", url]


class Vlc(MediaPlayer):
    SUPPORTS_DARWIN: bool = True
    PKG_SET: PkgSet = pkgset("apps/vlc")

    def _args(self, machine: Machine, url: str) -> List[str]:
        args = [
            "vlc",
            "--verbose",
            "2",
            "-I",
            "dummy",
            "--aout",
            "dummy",
            url,
            "vlc://quit",
        ]
        if machine.is_darwin:
            # On Darwin, we use a custom build of VLC with GnuTLS enabled,
            # instead of using something Nix built. As a result, our standard
            # environment variables won't actually affect this VLC. To get around this
            # we pass some extra flags for macOS.
            gnutls_dir_trust = machine.tmp_dir / "vlc-gnutls-mac-dir-trust"
            if not gnutls_dir_trust.exists():
                gnutls_dir_trust.mkdir()
                for i, entry in enumerate(
                    re.findall(
                        r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
                        ssl_cert_file(machine).read_text(),
                        re.DOTALL,
                    )
                ):
                    (gnutls_dir_trust / f"cert_{i}.pem").write_text(entry)
            args += [
                "--no-gnutls-system-trust",
                "--gnutls-dir-trust",
                str(gnutls_dir_trust),
            ]
        return args
