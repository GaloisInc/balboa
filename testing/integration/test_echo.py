import itertools
import json
import os
import time
from secrets import token_urlsafe
from typing import Optional, Tuple

import pytest

from rocky.etc.machine import PIPE, Machine, MachineSubprocess
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.certs import der_pubkey_file, key_crt_combined_pem_file
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path
from rocky.testing.pipe_reader import PipeReader
from rocky.testing.stallone import StalloneMaster

PORT = 4433


def spawn_openssl_server(
    machine: Machine,
    env: EnvBuilder,
    cipher_suite: CipherSuite,
) -> Tuple[MachineSubprocess, PipeReader]:
    no_tls13_flag = []
    if not cipher_suite.is_tls13():
        no_tls13_flag.append("-no_tls1_3")

    cmd = machine.popen(
        pkgset("apps/openssl"),
        [
            "openssl",
            "s_server",
        ]
        + no_tls13_flag
        + [
            "-cert",
            str(key_crt_combined_pem_file(machine.hostname)),
            "-4",
            "-accept",
            f"{machine.bind}:{PORT}",
        ],
        stdin=PIPE,
        stdout=PIPE,
        stderr=logfiles_path(machine) / "openssl-server.stderr.txt",
        env=env.build(),
    )
    assert cmd.stdout is not None
    out = PipeReader(machine, "openssl-server.stdout.txt", cmd.stdout)

    def wait_for_server() -> None:
        machine.run(
            pkgset("apps/openssl"),
            ["nc", "--zero", "--wait=1", machine.hostname, str(PORT)],
            capture_output=True,
        )

    busy_wait_assert(wait_for_server)
    return cmd, out


def spawn_openssl_client(
    machine: Machine,
    env: EnvBuilder,
    cipher_suite: CipherSuite,
    target: str,
) -> Tuple[MachineSubprocess, PipeReader]:
    # openssl uses a different flag to specify the cipher string for TLS 1.2
    # ("-cipher") and 1.3 ("-ciphersuites").
    if cipher_suite.is_tls13():
        cipher_flags = ["-ciphersuites"]
    else:
        cipher_flags = ["-no_tls1_3", "-cipher"]
    cipher_flags.append(cipher_suite.openssl_cipher_string)

    cmd = machine.popen(
        pkgset("apps/openssl"),
        [
            "openssl",
            "s_client",
            "-showcerts",
        ]
        + cipher_flags
        + [
            f"{target}:{PORT}",
        ],
        stdin=PIPE,
        stdout=PIPE,
        stderr=logfiles_path(machine) / "openssl-client.stderr.txt",
        env=env.build(),
    )
    assert cmd.stdout is not None
    out = PipeReader(machine, "openssl-client.stdout.txt", cmd.stdout)
    return cmd, out


def spawn_gnutls_client(
    machine: Machine,
    env: EnvBuilder,
    cipher_suite: CipherSuite,
    target: str,
) -> Tuple[MachineSubprocess, PipeReader]:
    cmd = machine.popen(
        pkgset("apps/gnutls"),
        [
            "gnutls-cli",
            "--insecure",
            "--priority",
            cipher_suite.gnutls_cipher_string,
            f"{target}:{PORT}",
            "-VVVVVVVV",
            "-d",
            "9999",
        ],
        stdin=PIPE,
        stdout=PIPE,
        stderr=logfiles_path(machine) / "gnutls-client.stderr.txt",
        env=env.build()
        | {
            "SSLKEYLOGFILE": str(
                machine.tmp_dir / f"gnutls-client-sslkeylogfile-{token_urlsafe(8)}"
            ),
        },
    )
    assert cmd.stdout is not None
    out = PipeReader(machine, "gnutls-client.stdout.txt", cmd.stdout)
    return cmd, out


COMMUNICATION_SCRIPTS = {
    # These shouldn't be so long that they are bigger than the buffers, since
    # we're doing everything synchronously.
    # we just grep for the bodies in stdout. They should be unique enough for
    # that to not give false positives.
    # (sender, body)
    "SCRIPT1": [
        ("Server", b"hello i am the server\n"),
        ("Client", b"well hello there, i am the client\n"),
        ("Client", b"here is another client message\n"),
        ("Server", b"well, here is another server message, then.\n"),
    ],
    "SCRIPT2": [
        ("Client", b"hello server, i am the client, and this is the first message\n"),
        ("Server", b"hello client"),
        ("Client", b"goodbye server"),
        ("Server", b"goodbye client"),
    ],
}


@pytest.mark.parametrize(
    "server,client,communication_script,rocky_enable_server,rocky_enable_client",
    list(
        itertools.product(
            # See the note in ssl_cli.py about why there isn't a gnutls server here
            ["openssl"],
            ["openssl", "gnutls"],
            sorted(list(COMMUNICATION_SCRIPTS.keys())),
            [True, False],
            [True, False],
        )
    ),
)
def test_simple_echo(
    server: str,
    client: str,
    communication_script: str,
    rocky_enable_server: bool,
    rocky_enable_client: bool,
    machine: Machine,
    cipher_suite_including_cbc: CipherSuite,
    stallone_master: StalloneMaster,
    build_mode: BuildMode,
) -> None:
    server_env = EnvBuilder(machine)
    client_env = EnvBuilder(machine)

    masters = BalboaMasters(machine, machine)

    server_env.add_balboa_master(masters.server)
    client_env.add_balboa_master(masters.client)

    masters.client.generate_capability_for(
        21, masters.server, spoil_pubkey=not rocky_enable_server
    )

    if rocky_enable_server:
        server_env.add_injection(
            cdylib_target("balboa-injection-openssl-echo").build(build_mode)
        )

    if rocky_enable_client:
        client_env.add_injection(
            cdylib_target(
                "balboa-injection-openssl-echo"
                if client == "openssl"
                else "balboa-injection-gnutls-echo"
            ).build(build_mode),
        )

    cipher_suite = cipher_suite_including_cbc
    assert server == "openssl"
    server_proc, server_out = spawn_openssl_server(machine, server_env, cipher_suite)
    assert client in ["openssl", "gnutls"]
    # spawn_server waits for the server to start up.
    client_proc, client_out = (
        spawn_openssl_client if client == "openssl" else spawn_gnutls_client
    )(machine, client_env, cipher_suite, machine.hostname)

    def check_for_connection_is_accepted() -> None:
        assert b"-----END SSL SESSION PARAMETERS-----" in server_out.sample()

    busy_wait_assert(check_for_connection_is_accepted)
    # There's a little bit more processing before the accept() is finished.
    # So we sleep, to make sure data isn't lost. I blame the openssl code!
    time.sleep(0.2)
    for sender, msg in COMMUNICATION_SCRIPTS[communication_script]:
        assert sender in ["Server", "Client"]
        if sender == "Server":
            s = server_proc
            r = client_proc
            r_out = client_out
        elif sender == "Client":
            s = client_proc
            r = server_proc
            r_out = server_out
        assert s.stdin is not None
        s.stdin.write(msg)
        s.stdin.flush()

        def _wait_for_msg() -> None:
            assert msg in r_out.sample()

        busy_wait_assert(_wait_for_msg)
