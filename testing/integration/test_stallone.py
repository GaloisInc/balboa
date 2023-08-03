import json
import platform
from typing import cast

import networkx as nx  # type: ignore

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, executable_target
from rocky.testing.stallone import StalloneMaster

# TODO: test event dropping, ordering, context, process and thread start/end events.


def test_stallone_signal_safety() -> None:
    # We want to look specifically at debug mode.
    cg = executable_target("stallone-test-log").llvm_call_graph(BuildMode.DEBUG)

    def lookup_function(the_name: str) -> str:
        matches = [
            name
            for name in cg
            if name.startswith(the_name + "::") and "{{closure}}" not in name
        ]
        assert len(matches) == 1, repr(matches)
        return cast(str, matches[0])

    # Panicking isn't signal-safe. But if we're panicking, then we're gonna crash anyway.
    for f in [lookup_function("core::panicking::panic")] + [
        f for f in cg if f.startswith("std::panicking::begin_panic")
    ]:
        cg.remove_node(f)

    # This removes a dynamic dispatch edge. We know that this dynamic dispatch dispatches to a
    # signal-safe function, since we wrote the function that it dispatches to.
    stallone_emergency_log = lookup_function(
        "stallone_common::emergency_log::stallone_emergency_log"
    )
    for dst in list(cg[stallone_emergency_log]):
        if dst.startswith("core::fmt::Write::write_fmt"):
            cg.remove_edge(stallone_emergency_log, dst)

    try:
        # Allow the SYS_memfd_create syscall.
        cg.remove_edge(lookup_function("scm_rights::make_tempfile_fd"), "syscall")
    except nx.NetworkXError:
        # If the edge doesn't exist, that's okay.
        pass

    # cg, but transposed
    cgt = cg.reverse(copy=False)

    # This is a subset of signal-safe functions that we care about.
    # See https://man7.org/linux/man-pages/man7/signal-safety.7.html and
    # see https://www.gnu.org/software/libc/manual/
    SIGNAL_SAFE_FUNCTIONS = {
        "__errno_location",  # errno on Linux
        "__error",  # errno on macos
        "abort",
        "bcmp",
        "clock_gettime",
        "close",
        "close$NOCANCEL",
        "fcntl",
        "fstat64",
        "ftruncate",
        "getpid",
        "link",
        "lseek",
        "lseek64",
        "memchr",
        "memcmp",
        "mkstemp",
        "mmap",
        "munmap",
        "open",
        "open64",
        "poll",
        "pthread_getspecific",
        "pthread_setspecific",  # This is safe so long as the pthread_key_t is under 32.
        "read",
        "readlink",
        "rename",
        "sendmsg",
        "socketpair",
        "stallone_thread_local_access",  # see stallone/log/src/thread_local.c
        "strlen",
        "unlink",
        "write",
        # We _explicitly_ don't include syscall(). While syscall() itself _IS_ signal-safe,
        # parking_lot, for example, uses syscall() to invoke SYS_futex, which is probably not
        # signal-safe.
    }
    UNSAFE_FUNCTIONS = (set(cgt["UNDEFINED"]) | {"EXTERNAL"}) - SIGNAL_SAFE_FUNCTIONS

    TEST_SIGNAL_SAFETY_OF_FUNCTIONS = [
        lookup_function("stallone_test_log::log_simple_test_string"),
        lookup_function("stallone::global_state::fork_child_handler"),
        lookup_function("stallone_common::emergency_log::stallone_emergency_log"),
        # We dynamically dispatch to these functions from a signal-handler, so they should be
        # signal-safe, too.
        lookup_function(
            "<stallone_common::emergency_log::MiniFile as core::fmt::Write>::write_str"
        ),
        lookup_function(
            "<stallone_common::emergency_log::ArrayVecWriter<_> as core::fmt::Write>::write_str"
        ),
    ]
    failed = False
    for start in TEST_SIGNAL_SAFETY_OF_FUNCTIONS:
        printed_hdr = False
        for f in UNSAFE_FUNCTIONS:
            try:
                p = nx.shortest_path(cg, start, f)
                if not printed_hdr:
                    printed_hdr = True
                    print(start)
                print(f"    {f}: {p}")
                failed = True
            except nx.NetworkXNoPath:
                pass
    assert not failed


def test_stallone_forking(machine: Machine, build_mode: BuildMode) -> None:
    "Test that stallone deals with forking properly."
    stallone_tools = executable_target("stallone-tools").build(build_mode)
    stallone_test_fork = executable_target("stallone-test-fork").build(build_mode)
    stallone = StalloneMaster(
        machine,
        "stallone",
        add_to_default_env=False,
        check_returncode=True,
    )
    stdout = (
        machine.run(
            pkgset("empty"),
            [str(stallone_test_fork.path)],
            env={"STALLONE_MASTER": str(stallone.master_path), "RUST_BACKTRACE": "1"},
            stdout=PIPE,
        )
        .stdout.decode("ascii")
        .strip()
    )
    assert stdout.startswith("BASH PID ")
    bash_pid = int(stdout.replace("BASH PID ", ""))
    stallone.close()
    events = list(
        map(
            json.loads,
            machine.run(
                pkgset("empty"),
                [
                    str(stallone_tools.path),
                    "decompress-logs",
                    "-o",
                    "-",
                    "--output-format",
                    "json",
                    str(stallone.binary_log_out_path),
                    str(stallone_test_fork.path),
                ],
                stdout=PIPE,
            )
            .stdout.strip()
            .split(b"\n"),
        )
    )
    del events[0]  # Remove the info about the stallone master
    started_process_events = iter(
        [evt["StartedProcess"] for evt in events if "StartedProcess" in evt]
    )
    pid1_start = next(started_process_events)
    pid1_spid = pid1_start["pid"]
    pid1_pid = pid1_start["process_info"]["os_pid"]
    assert pid1_start["process_info"]["parent_pid"] is None
    # For checking that log events are correct, we first check to make sure that we have log events
    # with the proper content, and then we check the important parts of the ordering.
    log_records = dict()
    for evt in events:
        if "LogRecord" not in evt:
            continue
        msg = evt["LogRecord"]["payload"]["metadata"]["message"]
        assert msg not in log_records
        log_records[msg] = evt["LogRecord"]
    evt = log_records["Non-follow-fork parent"]
    assert evt["payload"]["values"]["pid"] == pid1_pid
    assert evt["pid"] == pid1_spid
    evt = log_records["Spawn follow-forks subprocess"]
    assert evt["pid"] == pid1_spid
    pid2_start = next(started_process_events)
    pid2_spid = pid2_start["pid"]
    pid2_pid = pid2_start["process_info"]["os_pid"]
    assert pid2_start["process_info"]["parent_pid"] is None
    bash_start = next(started_process_events)
    bash_spid = bash_start["pid"]
    assert bash_start["process_info"]["os_pid"] == bash_pid
    assert bash_start["process_info"]["parent_pid"] == pid2_spid
    for evt in (
        log_records["After spawning"],
        log_records["After wait"],
        log_records["Here I am in the parent"],
        log_records["Post fork parent"],
    ):
        assert evt["pid"] == pid2_spid
        assert evt["payload"]["values"]["pid"] == pid2_pid
    pid3_start = next(started_process_events)
    pid3_spid = pid3_start["pid"]
    pid3_pid = pid3_start["process_info"]["os_pid"]
    assert pid3_start["process_info"]["parent_pid"] == pid2_spid
    assert log_records["Post fork parent"]["payload"]["values"]["child_pid"] == pid3_pid
    for evt in (log_records["Post fork child 1"], log_records["Post fork child 2"]):
        assert evt["pid"] == pid3_spid
        assert evt["payload"]["values"]["pid"] == pid3_pid
    pid4_start = next(started_process_events)
    pid4_spid = pid4_start["pid"]
    pid4_pid = pid4_start["process_info"]["os_pid"]
    assert pid4_start["process_info"]["parent_pid"] == pid3_spid
    assert log_records["Post fork, subchild"]["payload"]["values"]["pid"] == pid4_pid
    assert log_records["Post fork, subchild"]["pid"] == pid4_spid
    assert (
        log_records["Post fork child 2"]["payload"]["values"]["child_pid"] == pid4_pid
    )
    build_ids = {
        bytes(evt["StartedProcess"]["process_info"]["build_id"])
        for evt in events
        if "StartedProcess" in evt
    }
    assert len(build_ids) == 1
    assert log_records["After wait"]["epoch_ms"] > next(
        evt["EndedProcess"]["timestamp"]["epoch_ms"]
        for evt in events
        if "EndedProcess" in evt and evt["EndedProcess"]["pid"] == bash_spid
    )


def test_stallone_emergency_log(machine: Machine, build_mode: BuildMode) -> None:
    "Test that stallone emergency logs get consumed."
    stallone_tools = executable_target("stallone-tools").build(build_mode)
    stallone_test_emergency_log = executable_target(
        "stallone-test-emergency-log"
    ).build(build_mode)
    stallone_test_log = executable_target("stallone-test-log").build(build_mode)
    stallone = StalloneMaster(
        machine,
        "stallone",
        add_to_default_env=False,
        check_returncode=True,
    )
    machine.run(
        pkgset("empty"),
        [str(stallone_test_emergency_log.path)],
        env={"STALLONE_MASTER": str(stallone.master_path)},
    )
    stallone.close()
    events = list(
        map(
            json.loads,
            machine.run(
                pkgset("empty"),
                [
                    str(stallone_tools.path),
                    "decompress-logs",
                    "-o",
                    "-",
                    "--output-format",
                    "json",
                    str(stallone.binary_log_out_path),
                    str(stallone_test_log.path),
                ],
                stdout=PIPE,
            )
            .stdout.strip()
            .split(b"\n"),
        )
    )
    del events[0]  # Remove the master's metadata
    for evt in events:
        if "EmergencyLog" in evt:
            assert "PID:" in evt["EmergencyLog"]["body"]
            assert evt["EmergencyLog"]["body"].endswith(
                "context\nAt "
                "stallone/log/examples/stallone-test-emergency-log.rs:7:64, "
                "my context: errno -1"
            )
            break
    else:
        assert False, "emergency log not found"


def test_stallone_test_log(machine: Machine, build_mode: BuildMode) -> None:
    "Test that some simple log events get properly logged."
    stallone_tools = executable_target("stallone-tools").build(build_mode)
    stallone_test_log = executable_target("stallone-test-log").build(build_mode)
    stallone = StalloneMaster(machine, "stallone", add_to_default_env=False)
    use_valgrind = platform.system() != "Darwin"
    machine.run(
        pkgset("valgrind" if use_valgrind else "empty"),
        (["valgrind"] if use_valgrind else []) + [str(stallone_test_log.path)],
        env={"STALLONE_MASTER": str(stallone.master_path)},
    )
    stallone.close()
    events = list(
        map(
            json.loads,
            machine.run(
                pkgset("empty"),
                [
                    str(stallone_tools.path),
                    "decompress-logs",
                    "-o",
                    "-",
                    "--output-format",
                    "json",
                    str(stallone.binary_log_out_path),
                    str(stallone_test_log.path),
                ],
                stdout=PIPE,
            )
            .stdout.strip()
            .split(b"\n"),
        )
    )
    actual_payloads = [
        evt["LogRecord"]["payload"] for evt in events if "LogRecord" in evt
    ]
    expected_payloads = json.loads(
        (
            rocky.ROOT / "testing/integration/test_stallone/test_stallone_test_log.json"
        ).read_bytes()
    )
    assert len(actual_payloads) == len(expected_payloads)
    for actual, expected in zip(actual_payloads, expected_payloads):
        try:
            for which in (actual, expected):
                # The "current_time" changes between runs, so we zero it out.
                dse = which["values"]["current_time"]["duration_since_epoch"]
                assert isinstance(dse["seconds"], int)
                assert isinstance(dse["subsec_nanos"], int)
                dse["seconds"] = 0
                dse["subsec_nanos"] = 0
        except KeyError:
            pass
        for which in (actual, expected):
            # A HashSet can be serialized in any order (since the hash is re-seeded on each run).
            # We avoid checking order for the hash set.
            if (
                which["metadata"]["message"] == "Collections"
                and which["metadata"]["file"]
                == "stallone/log/examples/stallone-test-log.rs"
            ):
                which["values"]["names"] = set(which["values"]["names"])
        assert actual == expected
