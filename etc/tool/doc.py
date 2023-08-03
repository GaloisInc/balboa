import click

import rocky
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset


@click.command(short_help="Generate python documentation")
def pdoc() -> None:
    """
    Generate python documentation to `target/pdoc`
    """
    with local_machine() as machine:
        (machine.tmp_dir / "rocky").symlink_to(rocky.ROOT)
        dst = rocky.ROOT / "target/pdoc"
        dst.mkdir(exist_ok=True, parents=True)
        machine.run(
            pkgset("pdoc"),
            [
                "pdoc",
                "-o",
                dst,
                "--no-browser",
                "./rocky",
            ],
            cwd=machine.tmp_dir,
        )
    click.secho(
        "Python documentation was written to 'target/pdoc'", bold=True, fg="green"
    )


DOC_COMMANDS = [pdoc]
