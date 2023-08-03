import os
import shutil
import sys
import tarfile
from pathlib import Path
from typing import List, Optional

import click

import rocky
from rocky.testing.stallone import write_stallone_metadata


@click.command()
@click.option(
    "--pdb",
    help="[pytest] Enter the Python DeBugger (PDB) on test failure.",
    default=False,
    is_flag=True,
)
@click.option(
    "--full-trace",
    help="[pytest] don't cut any tracebacks",
    default=False,
    is_flag=True,
)
@click.option(
    "--exit-first",
    help="[pytest] exit after the first test failure",
    default=False,
    is_flag=True,
)
@click.option(
    "--collect-only",
    help="[pytest] don't actually run the tests. Just list the tests that would've been run",
    default=False,
    is_flag=True,
)
@click.option(
    "--build-mode",
    default="debug",
    type=click.Choice(["debug", "release", "both"], case_sensitive=False),
    help="What build modes should the tests be run against",
)
@click.option(
    "--no-nightly-tests",
    default=False,
    is_flag=True,
    help="Do not run the tests marked 'nightlyonly'",
)
@click.option(
    "--junit-xml",
    help="[pytest] Emit information about the test run in JUnit XML format at the given path.",
)
@click.option(
    "--compress-logs-to",
    help="If provided, compress logs from the test run to the given .tar.xz path. "
    "The path must not already exist",
)
@click.option(
    "-v", "--verbose", count=True, help="[pytest] Tell pytest to be extra verbose"
)
@click.argument(
    "which_tests",
    nargs=-1,
    required=False,
)
def test(
    pdb: bool,
    full_trace: bool,
    exit_first: bool,
    collect_only: bool,
    build_mode: str,
    no_nightly_tests: bool,
    junit_xml: Optional[str],
    compress_logs_to: Optional[str],
    verbose: int,
    which_tests: List[str],
) -> None:
    """
    Run the Python tests.

    WHICH_TESTS, if present should contain the names of tests (or files to run),
    using the pytest CLI syntax.

    If a test fails, logs for the test will be written to `/tmp/rocky`.
    """
    # Because we will be specifying UNIX socket paths in this directory, it's
    # important that TMP has a short path.
    TMP = Path("/tmp/rocky")
    # TODO: should we remove this before every test run?
    shutil.rmtree(TMP, ignore_errors=True)
    os.chdir(str(rocky.ROOT))
    args = [
        f"--basetemp={TMP}",
        "--import-mode=importlib",
        "-rap",
        "--strict-markers",
        "--log-cli-level=debug",
        "-s",  # TODO: keep this?
    ]
    if junit_xml is not None:
        args.append(f"--junitxml={junit_xml}")
    if verbose > 0:
        arg = "-"
        for _ in range(verbose):
            arg += "v"
        args.append(arg)
    marker_expr: List[str] = []
    if no_nightly_tests:
        marker_expr.append("not nightlyonly")
    if build_mode == "both":
        pass  # add no extra marker exprs
    elif build_mode == "debug":
        marker_expr.append("not releasebuild")
    elif build_mode == "release":
        marker_expr.append("not debugbuild")
    else:
        assert False, f"unexpected build mode: {repr(build_mode)}"
    if len(marker_expr) > 0:
        args.append("-m")
        args.append(" and ".join(f"({body})" for body in marker_expr))
    if collect_only:
        args.append("--collect-only")
    if exit_first:
        args.append("--exitfirst")
    if pdb:
        args.append("--pdb")
    if full_trace:
        args.append("--full-trace")
    if len(which_tests) > 0:
        args += which_tests
    else:
        args.append("./testing/integration")
    import pytest

    rc = pytest.main(args)
    write_stallone_metadata(TMP / "stallone-metadata.yml")
    if compress_logs_to is not None:
        with tarfile.open(str(compress_logs_to), "x:xz") as tar:
            _IGNORE_SUFFIXES = [
                "covert-data.bin",
                "ssl-roots.crt",
                ".ogg",
                "-covert-data",
            ]
            tar.add(
                str(TMP),
                arcname="logs",
                filter=lambda info: None
                if any(info.name.endswith(suffix) for suffix in _IGNORE_SUFFIXES)
                else info,
            )
    sys.exit(rc)


TEST_COMMANDS = [test]
