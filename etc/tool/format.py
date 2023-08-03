import sys
from pathlib import Path
from typing import List, Sequence, Union

import click

import rocky
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset
from rocky.etc.tool.utils import find_files


@click.command(short_help="reformat the codebase")
@click.option(
    "--check",
    help="Abort if the codebase isn't properly formatted. Do not change any files.",
    default=False,
    is_flag=True,
)
def format(check: bool) -> None:
    """
    Reformat the *.rs, *.py, and *.nix files in the codebase to give them a
    consistent style.
    """
    with local_machine() as formatters:
        all_success = True

        def doit(*args: Sequence[Union[Path, str]]) -> None:
            nonlocal formatters
            nonlocal all_success
            final_args: List[Union[Path, str]] = []
            for x in args:
                final_args += x
            if (
                formatters.run(
                    pkgset("formatters"), final_args, check=False, cwd=rocky.ROOT
                ).returncode
                != 0
            ):
                all_success = False

        click.secho("Formatting Nix:", underline=True, bold=True)
        doit(
            ["nixpkgs-fmt"],
            (["--check"] if check else []),
            find_files(
                [rocky.ROOT / "etc/nix"],
                ext=".nix",
                exclude={
                    rocky.ROOT / "etc/nix/rust-overlay.nix",
                    rocky.ROOT / "etc/nix/sources.nix",
                },
            ),
        )
        click.secho("Formatting Python:", underline=True, bold=True)
        python_files = find_files(
            [
                rocky.ROOT / "rocky",
                rocky.ROOT / "testing",
                rocky.ROOT / "etc",
            ],
            ext=".py",
        )
        doit(
            ["isort", "--atomic", "--profile", "black", "--project", "rocky"],
            ["-c"] if check else [],
            python_files,
        )
        doit(
            ["black", "-t", "py38"],
            ["--check"] if check else [],
            python_files,
        )
        click.secho("Formatting Rust:", underline=True, bold=True)
        doit(["cargo", "fmt"] + (["--", "--check"] if check else []))
        if not all_success:
            click.secho("Some formatters failed!", fg="red")
            click.echo(
                "You should be able to correct these issues by running `./rocky format`"
            )
            sys.exit(1)


FORMAT_COMMANDS = [format]
