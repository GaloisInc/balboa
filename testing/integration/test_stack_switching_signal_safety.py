import json
import platform
from typing import cast

import networkx as nx  # type: ignore
import pytest

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, executable_target


@pytest.mark.skip(reason="This test fails due to issue #120")
def test_stack_switching_signal_safety() -> None:
    # We want to look specifically at debug mode.
    cg = executable_target("stacking_switching_signal_safety_test").llvm_call_graph(
        BuildMode.DEBUG
    )

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
    # cg, but transposed
    cgt = cg.reverse(copy=False)

    # This is a subset of signal-safe functions that we care about.
    # See https://man7.org/linux/man-pages/man7/signal-safety.7.html and
    # see https://www.gnu.org/software/libc/manual/
    SIGNAL_SAFE_FUNCTIONS = {
        "__errno_location",  # errno on Linux
        "__error",  # errno on macos
        "rust_psm_stack_direction",
        "rust_psm_on_stack",
        "munmap",
        "mprotect",
        "mmap",
    }
    UNSAFE_FUNCTIONS = (set(cgt["UNDEFINED"]) | {"EXTERNAL"}) - SIGNAL_SAFE_FUNCTIONS

    start = lookup_function("stacking_switching_signal_safety_test::do_the_test")
    failed = False
    for f in UNSAFE_FUNCTIONS:
        try:
            p = nx.shortest_path(cg, start, f)
            print(f"    {f}: {p}")
            failed = True
        except nx.NetworkXNoPath:
            pass
    assert not failed
