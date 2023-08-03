from typing import Sequence, Union

import click

from rocky.etc.tool.ci_helpers import CI_HELPER_COMMANDS
from rocky.etc.tool.doc import DOC_COMMANDS
from rocky.etc.tool.format import FORMAT_COMMANDS
from rocky.etc.tool.mypy import MYPY_COMMANDS
from rocky.etc.tool.test import TEST_COMMANDS
from rocky.testing.benchmark import BENCH_CMDS
from rocky.testing.detectability import DETECTABILITY_COMMANDS


@click.group()
@click.pass_context
def main(ctx: click.Context) -> None:
    """
    This is the main utility for the rocky codebase.

    Feel free to use `cargo` directly, instead of this tool, for rust compilation
    and tests.

    Setting the environment variable `ROCKY_IS_IN_CI=1` will enable the use of
    sccache for rust compilation. It will disable cargo incremental compilation.
    """
    if ctx.invoked_subcommand != "test":
        # We use pytest's logging inside the test command.
        import coloredlogs  # type: ignore

        coloredlogs.install(level="DEBUG")


# Mypy can't infer this type, I think because of variance issues surrounding lists. That's why we
# manually type this as a Sequence.
_CMDS_LIST: Sequence[Sequence[Union[click.Command, click.Group]]] = [
    DOC_COMMANDS,
    FORMAT_COMMANDS,
    MYPY_COMMANDS,
    TEST_COMMANDS,
    CI_HELPER_COMMANDS,
    DETECTABILITY_COMMANDS,
    BENCH_CMDS,
]
for cmds in _CMDS_LIST:
    for cmd in cmds:
        main.add_command(cmd)


@main.command()
def repl() -> None:
    """
    Open a REPL in the Python environment of the testing framework.

    This makes it easy to use the python implementations to manually spawn servers and clients using
    the APIs used in tests.
    """
    import logging

    import IPython  # type: ignore

    # Silence annoying debug messages.
    logging.getLogger("parso").setLevel(logging.ERROR)
    IPython.start_ipython(argv=[])
