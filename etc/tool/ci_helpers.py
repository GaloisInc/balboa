import click

import rocky
from rocky.etc.machine.local import local_machine
from rocky.etc.rust import BuildMode, ci_helper_compile_rust, ci_helper_test_rust
from rocky.etc.tool.utils import find_files

# These commands are mostly stop-gaps for now. They're used in CI.


@click.group()
def ci_helpers() -> None:
    "Commands that are useful for the CI to run."


@ci_helpers.command()
@click.option("--release/--debug", help="Compile the rust code in release mode")
def compile_rust(release: bool) -> None:
    "Compile all targets in the codebase."
    ci_helper_compile_rust(BuildMode.RELEASE if release else BuildMode.DEBUG)


@ci_helpers.command()
def test_rust() -> None:
    "Run the rust tests"
    ci_helper_test_rust()


CI_HELPER_COMMANDS = [ci_helpers]
