import click

from rocky.testing.benchmark.mickey import mickey


@click.group()
def bench() -> None:
    "Rocky benchmarking"


bench.add_command(mickey)

BENCH_CMDS = [bench]
