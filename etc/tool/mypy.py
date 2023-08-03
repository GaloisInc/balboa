import sys

import click

import rocky
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset


@click.command(short_help="Typecheck the python codebase")
def mypy() -> None:
    with local_machine() as machine:
        # To make sure that the root module gets named "rocky", we make a directory named rocky, and then symlink in all the files that we need.
        base = machine.tmp_dir / "rocky"
        base.symlink_to(rocky.ROOT)
        if (
            machine.run(
                pkgset("mypy"),
                [
                    "mypy",
                    "--strict",
                    "--allow-redefinition",
                    "--show-error-context",
                    "--sqlite-cache",
                    "--cache-dir",
                    rocky.ROOT / ".mypy_cache",
                    "--exclude",
                    r"/(target|third_party)",
                    "./rocky",
                ],
                cwd=machine.tmp_dir,
                check=False,
            ).returncode
            != 0
        ):
            sys.exit(1)


MYPY_COMMANDS = [mypy]
