#
# Functions for launching the balboa server outside of the test environment.
#
# To run the server, run the following within `./rocky repl`:
#
# > import rocky.testing.local as local
# > server = local.<server-application>(...)
# ...
# > server.close()
#
# To connect a client to a running server, run the following:
#
# > STALLONE_MASTER=/tmp/rocky-local/STALLONE_local ROCKY_MASTER_SOCKET=/tmp/rocky-local/blbamstr-client SSLKEYLOGFILE=/tmp/sslkeylogfile.$(head -c 16 /dev/urandom | xxd -p) LD_PRELOAD=<path-to-injection-library> <client-application> <client-application-arguments>
#
# All logs are dumped to `/tmp/rocky-local`.
#

import shutil
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Dict

from rocky.etc.machine.local import LocalMachine
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps import media_players
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.web import NginxServer
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.certs import der_pubkey_file
from rocky.testing.env import EnvBuilder
from rocky.testing.stallone import StalloneMaster

_build_mode = BuildMode.RELEASE


class LocalServer:
    def __init__(
        self,
        server: Any,
        injection: str,
        args: Dict[str, Any],
        tmp_dir: Path = Path("/tmp/rocky-local"),
        rmdir: bool = False,
    ):
        if rmdir:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            tmp_dir.mkdir()
        self.machine = LocalMachine(tmp_dir, IPv4Address("127.0.0.1"))
        _ = StalloneMaster(self.machine, "local", True)
        env = EnvBuilder(self.machine)
        balboa_masters = BalboaMasters(
            self.machine,
            self.machine,
        )
        env.add_balboa_master(balboa_masters.server)
        env.add_injection(cdylib_target(injection).build(_build_mode))
        self.client_sock = balboa_masters.client
        self.server = server(self.machine, env, **args)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        self.server.close()
        self.machine.close()


# def socat() -> LocalServer:
#     args = {"cipher_suite": None}
#     return LocalServer(SocatServer, "balboa-injection-socatrtsp", args, rmdir=True)


def nginx(static_root: Path) -> LocalServer:
    args = {"static_root": static_root, "cipher_suite": None}
    return LocalServer(NginxServer, "balboa-injection-nginx", args, rmdir=True)


def icecast(song_path: Path, loop_song: bool = False) -> LocalServer:
    args = {"song_path": song_path, "loop_song": loop_song, "cipher_suite": None}
    return LocalServer(IcecastServer, "balboa-injection-icecast", args, rmdir=True)
