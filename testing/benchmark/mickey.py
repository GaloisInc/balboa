import json
import logging
import shlex
import shutil
import textwrap
from collections import defaultdict
from pathlib import Path
from secrets import token_urlsafe
from statistics import mean, median, stdev
from threading import Thread
from time import perf_counter_ns, sleep
from typing import Callable, DefaultDict, Iterator, List, Union
from uuid import uuid4

import click

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target, executable_target
from rocky.testing.apps.web import NginxServer
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path
from rocky.testing.mickey import MickeyCluster, MickeyServer
from rocky.testing.stallone import write_stallone_metadata

_logger = logging.getLogger(__name__)

# The scenario is hard-coded to use only one machine.
def scenario_blast(num_messages: int, message_size: int, ms: MickeyServer) -> List[int]:
    send_times = []
    recv_times = []
    s = ms.sender(ms)
    r = ms.receiver(ms)
    build_msg: Callable[[int], bytes] = (
        lambda i: str(i).encode("ascii") + b"x" * message_size
    )

    def background() -> None:
        for i in range(num_messages):
            msg = r.recv()
            assert msg == build_msg(i)
            recv_times.append(perf_counter_ns())
            if i % 100 == 0:
                _logger.debug("Recv'd message %d", i)

    thr = Thread(target=background, daemon=True)
    thr.start()
    for i in range(num_messages):
        send_times.append(perf_counter_ns())
        s.send(build_msg(i))
    thr.join()
    assert len(send_times) == len(recv_times)
    return [r - s for r, s in zip(recv_times, send_times)]


@click.command()
@click.option(
    "--message-size",
    type=int,
    default=10_000,
    help="The size of message to send, in bytes",
    show_default=True,
)
@click.option(
    "--message-count",
    type=int,
    default=1_000,
    help="The number of messages to send",
    show_default=True,
)
@click.option(
    "--curl-delay",
    type=float,
    default=0.25,
    help="The number of seconds to sleep in between curls",
    show_default=True,
)
@click.option(
    "--static-file-size",
    type=int,
    default=1024 * 1024,
    help="The size (in bytes) of the file for curl to download on each invocation",
    show_default=True,
)
@click.option(
    "-o",
    "--out",
    default=str(rocky.ROOT / "target/mickey-bench-report.html"),
    show_default=True,
    help="The path to write the mickey benchmark report to",
)
@click.option(
    "--just-generate-report",
    help="(Mostly for debugging this script) Use the existing run in /tmp/rocky to generate the benchmark report.",
    default=False,
    is_flag=True,
)
@click.option(
    "--tmp-dir",
    help="What temporary directory should be used? (It will be deleted!)",
    default="/tmp/rocky",
    show_default=True,
)
def mickey(
    message_size: int,
    message_count: int,
    curl_delay: float,
    static_file_size: int,
    out: str,
    just_generate_report: bool,
    tmp_dir: str,
) -> None:
    """
    Run a Mickey benchmark.

    A mickey server will be set up, and asked to send messages to itself (using
    "unidirectional" Curl + Nginx as the transport).

    An output report will be written, in HTML.
    """
    TMP = Path(tmp_dir)
    if not just_generate_report:
        shutil.rmtree(TMP, ignore_errors=True)
        TMP.mkdir()
    BUILD_MODE = BuildMode.RELEASE
    # We'll build/download everything _now_, before we start any servers, to avoid timeouts.
    server_injection = cdylib_target("balboa-injection-nginx").build(BUILD_MODE)
    client_injection = cdylib_target("balboa-injection-firefox").build(BUILD_MODE)
    with local_machine() as m:
        # Set up the package sets we need.
        for ps in NginxServer.PKG_SETS:
            m.run(ps, ["true"])
    STATIC_ROOT = TMP
    STATIC_FILE_NAME = "the-static-file.bin"
    (STATIC_ROOT / STATIC_FILE_NAME).write_bytes(b"@" * static_file_size)
    CURL_STDOUT_PATH = TMP / "curl.stdout"

    def spawn_client(m: Machine, env: EnvBuilder, nginx: NginxServer) -> None:
        m.popen(
            pkgset("apps/curl"),
            [
                "bash",
                "-c",
                textwrap.dedent(
                    f"""
                    while true; do
                        echo -n "CURL DOWNLOADED: "
                        LD_PRELOAD={shlex.quote(str(client_injection.path))} DYLD_INSERT_LIBRARIES={shlex.quote(str(client_injection.path))} curl --verbose {shlex.quote(nginx.base_url + '/' + STATIC_FILE_NAME)} | wc -c
                        sleep {shlex.quote(str(curl_delay))}
                    done
                    """.strip()
                ),
            ],
            env=env.add_custom("STATIC_FILE_DIRECTORY", str(STATIC_ROOT))
            .add_custom("UPLOAD_FILE_DIRECTORY", str(STATIC_ROOT))
            .add_non_existent_sslkeylogfile()
            .build(),
            stdout=CURL_STDOUT_PATH,
            stderr=logfiles_path(m) / "curl.stderr",
        )

    stallone_metadata_path = TMP / "stallone-metadata.yml"
    if not just_generate_report:
        (TMP / "config-params.json").write_text(
            json.dumps(
                {
                    f.name: f.read_text()
                    for f in (rocky.ROOT / "mickey").glob("**/config-params/*.txt")
                }
            )
        )
        try:
            with MickeyCluster(
                base_path=TMP,
                build_mode=BUILD_MODE,
                count=1,
                spawn_server=lambda m, env: NginxServer(
                    m,
                    env.add_injection(server_injection),
                    static_root=STATIC_ROOT,
                    upload_root=STATIC_ROOT,
                ),
                spawn_client=spawn_client,
            ) as cluster:
                start = perf_counter_ns()
                latencies = scenario_blast(message_count, message_size, cluster[0])
                duration = perf_counter_ns() - start
                (TMP / "latencies.json").write_text(json.dumps(latencies))
                (TMP / "duration.txt").write_text(str(duration))
        finally:
            write_stallone_metadata(stallone_metadata_path)
    latencies = json.loads((TMP / "latencies.json").read_text())
    duration = int((TMP / "duration.txt").read_text())
    # STALLONE_TOOLS doesn't need to be built in release mode
    STALLONE_TOOLS = executable_target("stallone-tools").build(BUILD_MODE)
    with local_machine() as m:
        _logger.debug("Starting to parse stallone logs")
        stdout = m.popen(
            pkgset("empty"),
            [
                STALLONE_TOOLS.path,
                "decompress-logs",
                "--output-format",
                "json",
                TMP / "m1/logs/stallone_stlne/raw.bin",
                stallone_metadata_path,
            ],
            stdout=PIPE,
        ).stdout
        assert stdout is not None
        mickey_outgoing_rewrite_nanoseconds: List[int] = []
        mickey_incoming_rewrite_nanoseconds: List[int] = []
        mickey_outgoing_queue_update_nanoseconds: List[int] = []
        mickey_incoming_queue_update_nanoseconds: List[int] = []
        mickey_outgoing_thread_iteration_nanoseconds: List[int] = []
        mickey_incoming_thread_iteration_nanoseconds: List[int] = []
        how_many_times_did_we_recv_each_chunk_frame: DefaultDict[
            int, int
        ] = defaultdict(lambda: 0)
        how_many_times_did_we_discard_each_chunk_frame: DefaultDict[
            int, int
        ] = defaultdict(lambda: 0)
        discard_reasons: DefaultDict[str, int] = defaultdict(lambda: 0)
        amount_of_padding_bytes = 0
        num_acks_written = 0
        num_chunks_written = 0
        for line in stdout:
            # avoid json parsing if it's not for any of the events we care about.
            if not any(
                x in line
                for x in [
                    # Outgoing messages
                    b"Writing ACK",
                    b"Writing CHUNK",
                    b"Unable to dequeue chunk",
                    b"Mickey compress_context rewrite time",
                    # Incoming messages
                    b"Mickey decompress_context rewrite time",
                    b"Saw ack",
                    b"Saw chunk frame",
                    b"DISCARDING",
                    b"SUCCESSFULLY stored chunk",
                    b"Writing padding",
                    b"Outgoing queue update duration",
                    b"Incoming queue update duration",
                    b"Outgoing queue changed. Updating IPC queue.",
                    b"Incoming window changed. Updating IPC incoming window.",
                ]
            ):
                continue
            blob = json.loads(line)
            msg = blob["LogRecord"]["payload"]["metadata"]["message"]
            values = blob["LogRecord"]["payload"]["values"]
            UPDATE_DURATIONS = {
                "Outgoing queue update duration": mickey_outgoing_thread_iteration_nanoseconds,
                "Incoming queue update duration": mickey_incoming_thread_iteration_nanoseconds,
                "Mickey compress_context rewrite time": mickey_outgoing_rewrite_nanoseconds,
                "Mickey decompress_context rewrite time": mickey_incoming_rewrite_nanoseconds,
                "Incoming window changed. Updating IPC incoming window.": mickey_incoming_queue_update_nanoseconds,
                "Outgoing queue changed. Updating IPC queue.": mickey_outgoing_queue_update_nanoseconds,
            }
            if msg in UPDATE_DURATIONS:
                d = values["duration"]
                UPDATE_DURATIONS[msg].append(d["seconds"] * 10**9 + d["subsec_nanos"])
            elif msg == "Writing padding":
                amount_of_padding_bytes += values["nbytes"]
            elif msg == "Saw chunk frame":
                how_many_times_did_we_recv_each_chunk_frame[values["seqnum"][0]] += 1
                # There are some chunks we might not have discarded at all!
                how_many_times_did_we_discard_each_chunk_frame[values["seqnum"][0]] += 0
            elif "discard" in msg.lower():
                how_many_times_did_we_discard_each_chunk_frame[values["seqnum"][0]] += 1
                if msg == "DISCARDING CHUNK: failed to get incoming chunk":
                    msg += " ("
                    msg += list(values["e"].keys())[0]
                    msg += ")"
                elif msg == "DISCARDING Chunk state not EmptyIncoming (or reservable)":
                    msg += f" (state={values['initial']['state']}; reserved={values['initial']['reserved']})"
                discard_reasons[msg] += 1
            elif msg == "Writing ACK":
                num_acks_written += 1
            elif msg == "Writing CHUNK":
                num_chunks_written += 1
    max_chunk_seqnum = max(how_many_times_did_we_recv_each_chunk_frame.keys())
    curl_downloaded_bytes = 0
    number_of_curls = 0
    with CURL_STDOUT_PATH.open("rb") as f:
        for line in f:
            line = line.strip()
            if b"CURL DOWNLOADED:" not in line:
                continue
            number_of_curls += 1
            curl_downloaded_bytes += int(line.split()[-1])
    import jinja2

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(Path(__file__).parent)), autoescape=True
    )
    env.filters["mean"] = mean
    env.filters["median"] = median
    env.filters["stdev"] = stdev

    def cdfPlot(values: List[Union[int, float]]) -> str:
        id = str(uuid4())
        values = list(values)
        values.sort()
        x = [values[0]]
        y = [1]
        for value in values[1:]:
            if x[-1] != value:
                x.append(value)
                y.append(y[-1])
            y[-1] += 1
        data = [
            {
                "x": x,
                "y": [count / len(values) for count in y],
                "type": "scatter",
            }
        ]
        layout = {
            "title": "Empirical CDF",
            "xaxis": {
                "title": "X",
            },
            "yaxis": {
                "title": "Fraction of data, <= X",
            },
        }
        return f"""<div id="{id}" class="cdf"></div><script>Plotly.newPlot('{id}', {json.dumps(data)}, {json.dumps(layout)});</script>"""

    env.filters["cdfPlot"] = cdfPlot
    Path(out).write_text(
        env.get_template("mickey-bench-report.html").render(
            message_count=message_count,
            message_size=message_size,
            curl_delay=curl_delay,
            static_file_size=static_file_size,
            curl_downloaded_bytes=curl_downloaded_bytes,
            latencies=latencies,
            duration_ns=duration,
            mickey_outgoing_rewrite_nanoseconds=mickey_outgoing_rewrite_nanoseconds,
            mickey_incoming_rewrite_nanoseconds=mickey_incoming_rewrite_nanoseconds,
            how_many_times_did_we_recv_each_chunk_frame=list(
                how_many_times_did_we_recv_each_chunk_frame.values()
            ),
            max_chunk_seqnum=max_chunk_seqnum,
            how_many_times_did_we_discard_each_chunk_frame=list(
                how_many_times_did_we_discard_each_chunk_frame.values()
            ),
            discard_reasons=discard_reasons,
            fraction_of_chunks_received_exactly_once=sum(
                1
                for x in how_many_times_did_we_recv_each_chunk_frame.values()
                if x == 1
            )
            / len(how_many_times_did_we_recv_each_chunk_frame),
            number_of_curls=number_of_curls,
            amount_of_padding_bytes=amount_of_padding_bytes,
            num_chunks_written=num_chunks_written,
            num_acks_written=num_acks_written,
            config_params=json.loads((TMP / "config-params.json").read_text()),
            mickey_outgoing_thread_iteration_nanoseconds=mickey_outgoing_thread_iteration_nanoseconds,
            mickey_incoming_thread_iteration_nanoseconds=mickey_incoming_thread_iteration_nanoseconds,
            mickey_incoming_queue_update_nanoseconds=mickey_incoming_queue_update_nanoseconds,
            mickey_outgoing_queue_update_nanoseconds=mickey_outgoing_queue_update_nanoseconds,
        )
    )
    click.echo(
        click.style("Benchmark report was written to: ", bold=True, fg="blue")
        + click.style(out, underline=True)
    )
