import json
import logging
import os
import random
import shlex
import socket
import string
import struct
import textwrap
from dataclasses import dataclass
from datetime import timedelta
from functools import cache, partial
from hashlib import blake2b, sha512
from ipaddress import IPv4Address
from itertools import product
from pathlib import Path
from secrets import token_urlsafe
from threading import Lock, Thread
from typing import Any, Callable, Dict, Generic, Iterator, List, Optional, Type, TypeVar

import pytest

import rocky
from rocky.etc.machine import DEV_NULL, Machine
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import PkgSet, pkgset
from rocky.etc.rust import BuildMode, cdylib_target, executable_target
from rocky.testing import UNIX_SOCKET_MAX_PATH_LEN
from rocky.testing.apps import media_players
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import MediaPlayer
from rocky.testing.apps.web import NginxServer
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.certs import der_pubkey_file
from rocky.testing.env import EnvBuilder
from rocky.testing.integration.fixtures import ReraiseFixture
from rocky.testing.logfiles import logfiles_path
from rocky.testing.mickey import MickeyCluster, MickeyReceiver, MickeySender
from rocky.testing.stallone import StalloneMaster

_logger = logging.getLogger(__name__)


def test_python_mickey_client(machine: Machine) -> None:
    MSGS = [b"hello there", b"", b"general kenobi"]
    recv_sock, send_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def run_sender() -> None:
        with MickeySender(machine, send_sock) as sender:
            for msg in MSGS:
                sender.send(msg)

    Thread(target=run_sender, daemon=True).start()
    with MickeyReceiver(machine, recv_sock) as recv:
        for msg in MSGS:
            assert recv.recv() == msg


DeployMickeyCluster = Callable[[int], MickeyCluster]

_T = TypeVar("_T")


@dataclass(frozen=True)
class Spawners(Generic[_T]):
    spawn_server: Callable[[Machine, EnvBuilder], _T]
    spawn_client: Callable[[Machine, EnvBuilder, _T], None]


def icecast_spawners(
    media_player: Type[MediaPlayer],
) -> Callable[[BuildMode], Spawners[IcecastServer]]:
    def swallow(x: Any) -> None:
        "Make mypy happy!"

    def out(build_mode: BuildMode) -> Spawners[IcecastServer]:
        # We'll build/download everything _now_, before we start any servers, to avoid timeouts.
        server_injection = cdylib_target("balboa-injection-icecast").build(build_mode)
        client_injection = cdylib_target("balboa-injection-vlc").build(build_mode)
        with local_machine() as m:
            # Set up the package sets we need.
            m.run(media_player.PKG_SET, ["true"])
            m.run(IcecastServer.PKG_SET, ["true"])
        return Spawners(
            spawn_server=lambda m, env: IcecastServer(
                machine=m,
                env=env.add_injection(server_injection),
                song_path=rocky.ROOT / "testing/assets/large.ogg",
                loop_song=True,
                cipher_suite=None,
            ),
            spawn_client=lambda m, env, icecast: swallow(
                media_player(
                    m,
                    icecast,
                    env.add_injection(
                        client_injection
                    ).add_non_existent_sslkeylogfile(),
                )
            ),
        )

    return out


def curl_spawners(build_mode: BuildMode) -> Spawners[NginxServer]:
    # We'll build/download everything _now_, before we start any servers, to avoid timeouts.
    server_injection = cdylib_target("balboa-injection-nginx").build(build_mode)
    client_injection = cdylib_target("balboa-injection-firefox").build(build_mode)
    with local_machine() as m:
        # Set up the package sets we need.
        for ps in NginxServer.PKG_SETS:
            m.run(ps, ["true"])
    STATIC_ROOT = rocky.ROOT / "testing/assets"

    def spawn_client(m: Machine, env: EnvBuilder, nginx: NginxServer) -> None:
        name = f"curl-{token_urlsafe(8)}"
        m.popen(
            pkgset("apps/curl"),
            [
                "bash",
                "-c",
                textwrap.dedent(
                    f"""
                    while true; do
                        LD_PRELOAD={shlex.quote(str(client_injection.path))} DYLD_INSERT_LIBRARIES={shlex.quote(str(client_injection.path))} curl --verbose {shlex.quote(nginx.base_url + '/large.ogg')} > /dev/null
                        sleep 0.1
                    done
                    """.strip()
                ),
            ],
            env=env.add_custom("STATIC_FILE_DIRECTORY", str(STATIC_ROOT))
            .add_custom("UPLOAD_FILE_DIRECTORY", str(STATIC_ROOT))
            .add_non_existent_sslkeylogfile()
            .build(),
            stdout=logfiles_path(m) / f"{name}.stdout",
            stderr=logfiles_path(m) / f"{name}.stderr",
        )

    return Spawners(
        spawn_server=lambda m, env: NginxServer(
            m,
            env.add_injection(server_injection),
            static_root=STATIC_ROOT,
            upload_root=STATIC_ROOT,
        ),
        spawn_client=spawn_client,
    )


@pytest.fixture(
    scope="function",
    params=[
        pytest.param(icecast_spawners(media_players.Vlc), id="vlc"),
        pytest.param(curl_spawners, marks=pytest.mark.nightlyonly(), id="curl"),
        pytest.param(
            icecast_spawners(media_players.Mpv),
            marks=pytest.mark.nightlyonly(),
            id="mpv",
        ),
    ],
)
def deploy_mickey_cluster(
    tmp_path: Path, build_mode: BuildMode, request: Any
) -> Iterator[DeployMickeyCluster]:
    clusters: List[MickeyCluster] = []
    spawners = request.param(build_mode)

    def build(count: int) -> MickeyCluster:
        nonlocal clusters
        cluster = MickeyCluster(
            base_path=tmp_path,
            build_mode=build_mode,
            count=count,
            spawn_client=spawners.spawn_client,
            spawn_server=spawners.spawn_server,
        )
        clusters.append(cluster)
        return cluster

    try:
        yield build
    finally:
        for cluster in clusters:
            cluster.close()


CHUNK_SIZE = 1024


def pad_message_to_full_chunk(msg: bytes) -> bytes:
    # For improved performance, mickey tries to pack multiple messages into a
    # single chunk, if possible. In some of our tests, this is undesirable.
    # We get around this behavior by padding our messages.
    #
    # The first chunk is only 1020 bytes.
    # If we want, we could support padding for even bigger messages, but that
    # won't matter for these tests.
    assert len(msg) < CHUNK_SIZE - 4
    return msg + b"." * (CHUNK_SIZE - 4 - len(msg))


####################################################################################################
######################################## MICKEY TEST SUITE #########################################
####################################################################################################


def test_one_msg_mickey(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    "single short message from one source to one dest"
    a, b = deploy_mickey_cluster(2)
    a_sends_to_b = a.sender(b)
    a_recv_from_b = b.receiver(a)
    msg = b"This is message of the utmost importance. It is also an incredibly exciting message."
    a_sends_to_b.send(msg)
    assert a_recv_from_b.recv() == msg


def test_several_msgs_mickey(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    "send a group of 15 messages from one source to one dest. Waiting for each one to arrive."
    a, b = deploy_mickey_cluster(2)
    send = a.sender(b)
    recv = b.receiver(a)
    for i in range(15):
        msg = pad_message_to_full_chunk(f"HELLO {i}".encode("ascii"))
        _logger.debug("Sent message %d", i)
        send.send(msg)
        _logger.debug("Recving message %d", i)
        assert recv.recv() == msg
        _logger.debug("Got message %d", i)


def test_one_big_msg_mickey(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    "send a single message of 4kB from one source to one dest"
    a, b = deploy_mickey_cluster(2)
    send = a.sender(b)
    recv = b.receiver(a)
    DIGEST_SIZE = 64
    rng = blake2b(b"my fun seed", digest_size=DIGEST_SIZE)
    msg = b""
    for _ in range(4096 // DIGEST_SIZE):
        rng.update(b"abc")
        msg += rng.digest()
    send.send(msg)
    assert recv.recv() == msg


@pytest.mark.nightlyonly
def test_mickey_blast(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    "send full-chunk sized messages, 256 unique, from one source to one dest"
    a, b = deploy_mickey_cluster(2)
    send = a.sender(b)
    recv = b.receiver(a)
    N = 256

    def msg(i: int) -> bytes:
        return pad_message_to_full_chunk(
            f"exciting and surprising message #{i}".encode("ascii")
        )

    def background() -> None:
        for i in range(N):
            send.send(msg(i))

    Thread(target=background, daemon=True).start()
    for i in range(N):
        assert recv.recv() == msg(i)


def test_mickey_backpressure(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    """
    create back-pressure to make sure that queueing works correctly, and that delivery resumes as
    expected when pressure is released
    """
    _logger.debug("Starting")
    a, b = deploy_mickey_cluster(2)
    send = a.sender(b)
    recv = b.receiver(a)
    # Make sure that there is a point at which the buffers get filled.
    # Don't want to use the stream timeout since that we won't be able to resume
    # the sendall() call where it left off during the timeout.
    send._sock.settimeout(None)
    lock = Lock()
    last_sent_message = -1
    stop_at: Optional[int] = None

    def msg(i: int) -> bytes:
        return pad_message_to_full_chunk(f"message {i}".encode("ascii"))

    def background() -> None:
        nonlocal last_sent_message
        i = 0
        while True:
            with lock:
                if stop_at is not None and i >= stop_at:
                    break
            _logger.debug("Sending message %d", i)
            send.send(msg(i))
            _logger.debug("Sent message %d", i)
            with lock:
                last_sent_message = i
            i += 1

    Thread(target=background, daemon=True).start()
    last_sample = -2

    def check_backpressure() -> None:
        nonlocal last_sample
        with lock:
            current_sample = last_sent_message
        old = last_sample
        last_sample = current_sample
        _logger.debug("old=%d, current=%d", old, current_sample)
        assert old == current_sample

    # If delay is too low, then it'll appear that we have backpressure before
    # we actually do.
    busy_wait_assert(check_backpressure, delay=timedelta(seconds=4), max_times=200)
    with lock:
        n = last_sent_message
        stop_at = n + 10
    # n + 10 shows that it got unblocked.
    for i in range(n + 10):
        assert recv.recv() == msg(i)
        _logger.debug("Read message %d", i)


def test_mickey_send_message_to_self(
    deploy_mickey_cluster: DeployMickeyCluster,
) -> None:
    "send and recv of message at same agent"
    [m] = deploy_mickey_cluster(1)
    m.sender(m).send(b"self message!")
    assert m.receiver(m).recv() == b"self message!"


@pytest.mark.nightlyonly
def test_mickey_circle(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    "sending in a circle"
    mickeys = deploy_mickey_cluster(4)

    @cache
    def sender(src: int, dst: int) -> MickeySender:
        return mickeys[src].sender(mickeys[dst])

    @cache
    def receiver(src: int, dst: int) -> MickeyReceiver:
        return mickeys[dst].receiver(mickeys[src])

    for i in range(10):
        for s, r in [
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 0),
        ]:
            msg = f"this devastatingly chic message #{i} is being sent: {s} => {r}".encode(
                "ascii"
            )
            _logger.debug("Sending message #%d from %d to %d.", i, s, r)
            sender(s, r).send(msg)
            _logger.debug("Sent message #%d from %d to %d.", i, s, r)
            assert receiver(s, r).recv() == msg
            _logger.debug("Received message #%d from %d to %d.", i, s, r)


@pytest.mark.nightlyonly
def test_mickey_send_before_recv(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    """
    post the send before the recv is initiated, to make sure that waiting message is received
    correctly later
    """
    [one] = deploy_mickey_cluster(1)
    recv = None
    for i in range(3):
        msg = ("Hello! I am message %d" % i).encode("ascii")
        with one.sender(one) as send:
            send.send(msg)
        if recv is None:
            recv = one.receiver(one)
        assert recv.recv() == msg


@pytest.mark.releasebuild
def test_mickey_product(
    deploy_mickey_cluster: DeployMickeyCluster, reraise: ReraiseFixture
) -> None:
    "all-to-all communications"
    mickeys = deploy_mickey_cluster(4)
    NUM_MSGS = 20
    # construct a message to be sent from src to dst, with index i, that is unique
    def msg(src: int, dst: int, i: int) -> bytes:
        base = "Message from %r to %r number %d: " % (src, dst, i)
        base = base.encode("ascii")
        return base + b"".join(
            blake2b(base, salt=str(j).encode("ascii"), digest_size=64).digest()
            for j in range(2048 // 64)
        )

    # send 20 unique messages from src to dst, and print a message on successful send
    def send(src: int, dst: int, s: MickeySender) -> None:
        with reraise:
            _logger.debug("Just spawned sender from %r to %r" % (src, dst))
            for i in range(NUM_MSGS):
                s.send(msg(src, dst, i))
                _logger.debug("Sent message %d from %r to %r" % (i, src, dst))

    # receive 20 messages, check that the right message was received, and print a message on successful receipt
    def recv(src: int, dst: int, r: MickeyReceiver) -> None:
        with reraise:
            _logger.debug("Just spawned receiver at %r to receive from %r" % (dst, src))
            for i in range(NUM_MSGS):
                assert r.recv() == msg(src, dst, i)
                _logger.debug("Read message %d sent by %r to %r" % (i, src, dst))

    threads = []
    # for all possible combinations of sender and receiver
    for src, dst in product(list(range(len(mickeys))), list(range(len(mickeys)))):
        # print debug message to make sure all threads spawn correctly
        _logger.debug("Spawning threads to send from %r to %r", src, dst)
        # spawn a thread named 'Send from <src> to <dst>' to send messages between the two
        thr = Thread(
            target=send,
            args=(src, dst, mickeys[src].sender(mickeys[dst])),
            name="Send from %r to %r" % (src, dst),
            daemon=True,
        )
        thr.start()
        threads.append(thr)
        # spawn a thread named 'Recv messages sent to <dst> from <src>'
        thr = Thread(
            target=recv,
            args=(src, dst, mickeys[dst].receiver(mickeys[src])),
            daemon=True,
            name="Recv messages sent to %r from %r" % (dst, src),
        )
        thr.start()
        threads.append(thr)
        _logger.info("Spawning complete...")

    # wait until all threads finish
    for thr in threads:
        _logger.debug("Waiting on %r", thr.name)
        thr.join()


# TODO: fix this flakey test (and reproduce flakeyness in the new test environment)
@pytest.mark.skip(reason="Flakey")
def test_mickey_packing(deploy_mickey_cluster: DeployMickeyCluster) -> None:
    """
    Stress test for message packing
        Send 10,000 messages of length 0
        Next, send 200 messages, alternating length 0 with length 'full buffer'
    """
    ROUND1_MSGS = 10_000
    ROUND2_MSGS = 200
    BIG_MSG = b"Message for you, Sir...@@$"
    # NOTE: this test SHOULD NOT trigger backpressure.
    one, two = deploy_mickey_cluster(2)
    sender = one.sender(two)
    receiver = two.receiver(one)
    # First send 10,000 messages of length 0.
    for _ in range(ROUND1_MSGS):
        sender.send(b"")
    _logger.debug("Sent 10K msgs of length 0")
    # And recieve them
    for _ in range(ROUND1_MSGS):
        assert receiver.recv() == b""
    _logger.debug("Received 10K msgs of length 0")
    # Then we send 200 messages alternating between empty and whole chunk.
    for i in range(ROUND2_MSGS):
        if i % 2 == 0:
            sender.send(pad_message_to_full_chunk(BIG_MSG))
        else:
            sender.send(b"")
    _logger.debug("Sent the 200 messages of alternating size")
    # and recieve them
    for i in range(ROUND2_MSGS):
        if i % 2 == 0:
            assert receiver.recv() == pad_message_to_full_chunk(BIG_MSG)
        else:
            assert receiver.recv() == b""


def _rand_str(magnitude: int, allowed_chars: str = string.punctuation) -> bytes:
    "Return a string of length 3^`magnitude` consisting of the elements of `allowed_chars`"
    N = 3**magnitude
    #   print('Generating string of length %r' % N)
    return "".join(random.choice(allowed_chars) for _ in range(N)).encode("ascii")


@pytest.mark.nightlyonly
def test_varying_sized_msgs_separately_mickey(
    deploy_mickey_cluster: DeployMickeyCluster,
) -> None:
    "test single messages in lengths from 1B to 100kB, receive one at a time"
    one, two = deploy_mickey_cluster(2)
    send = one.sender(two)
    recv = two.receiver(one)
    for msgpass in range(32):
        _logger.info("Starting trial %d", msgpass)
        for exponent in range(6):
            msg = _rand_str(exponent)
            _logger.debug("Sending message of length %d bytes", len(msg))
            send.send(msg)
            assert recv.recv() == msg


@pytest.mark.nightlyonly
def test_varying_sized_msgs_all_at_once_mickey(
    deploy_mickey_cluster: DeployMickeyCluster,
) -> None:
    "test messages from 0B to 10,000 B, receive all at once"
    # NOTE: this test SHOULD NOT trigger backpressure, since the mickey sender
    # queues are based on the number of messages, not on the message size.
    msglist = []
    maxexponent = 4
    one, two = deploy_mickey_cluster(2)
    send = one.sender(two)
    recv = two.receiver(one)
    msglist.append(b"")
    send.send(b"")
    for exponent in range(maxexponent):
        msg = _rand_str(exponent)
        _logger.debug("Sending message of length %d", len(msg))
        msglist.append(msg)
        send.send(msg)
    for msg in msglist:
        assert recv.recv() == msg


@pytest.mark.nightlyonly
@pytest.mark.releasebuild
def test_mickey_1_for_all(
    deploy_mickey_cluster: DeployMickeyCluster, reraise: ReraiseFixture
) -> None:
    "many threads on one sender sending to one thread on each of many receivers"
    mickeys = deploy_mickey_cluster(5)
    NUM_MSGS = 100

    def msg(src: int, dst: int, i: int) -> bytes:
        base = "Message from %r to %r number %d: " % (src, dst, i)
        base = base.encode("ascii")
        return base + b"".join(
            blake2b(base, salt=str(j).encode("ascii"), digest_size=64).digest()
            for j in range(2048 // 64)
        )

    def send(src: int, dst: int, s: MickeySender) -> None:
        "send NUM_MSGS unique messages from src to dst, and print a message on successful send"
        with reraise:
            _logger.info("Just spawned sender from %r to %r", src, dst)
            for i in range(NUM_MSGS):
                s.send(msg(src, dst, i))
                _logger.debug("Sent message %d from %r to %r", i, src, dst)

    def recv(src: int, dst: int, r: MickeyReceiver) -> None:
        "receive 20 messages, check that the right message was received"
        with reraise:
            _logger.info("Just spawned receiver at %r to receive from %r", dst, src)
            for i in range(NUM_MSGS):
                assert r.recv() == msg(src, dst, i)
                _logger.debug("Read message %d sent by %r to %r", i, src, dst)

    threads: List[Thread] = []
    src = 0
    for dst in range(len(mickeys)):
        threads.append(
            Thread(
                target=send,
                args=(src, dst, mickeys[src].sender(mickeys[dst])),
                name="Send from %r to %r" % (src, dst),
                daemon=True,
            )
        )
        threads.append(
            Thread(
                target=recv,
                args=(src, dst, mickeys[dst].receiver(mickeys[src])),
                daemon=True,
                name="Recv messages sent to %r from %r" % (dst, src),
            )
        )
    for thr in threads:
        thr.start()
    for thr in threads:
        _logger.debug("Waiting for %r", thr.name)
        thr.join()
