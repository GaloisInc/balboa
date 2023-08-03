import json
import statistics
from pathlib import Path
from typing import cast

import click

import rocky
from rocky.etc.machine import PIPE
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset
from rocky.testing.detectability.scenarios import SCENARIOS


@click.group()
def detectability() -> None:
    """
    Measure how detectable Balboa is by observing packets.

    Balboa ought to be (modulo bugs and implementation errors) undetectable to an adversary on the
    wire, except for timing effects. The goal of the "detectability" subcommand is to:

    1. Collect packet captures from different "scenarios" with the `collect-pcaps` command, and then

    2. Analyze them with the `run-classifier` command to see if one specific classification
    algorithm can distinguish between the two packet captures.
    """


@detectability.group()
def collect_pcaps() -> None:
    "Run various scenarios to collect packet captures."


for scenario in SCENARIOS:
    collect_pcaps.add_command(scenario)


@detectability.command()
@click.argument("pcaps", required=True)
def run_classifier(pcaps: str) -> None:
    """
    Run a classifier to try to distinguish variants in the captured packets.

    Run tcptrace to compute aggregate statistics of the provided packet. Then run a random forest
    classifier with `RepeatedStratifiedKFold(n_splits=5, n_repeats=50)` to attempt to distinguish
    the variants in the captured packets.
    """
    # The classifier's dependencies are rather large (almost 1GB). As a result, we break them off
    # into a separate pkgset, so their dependencies will only be downloaded if they're needed.
    with local_machine() as machine:
        d = json.loads(
            machine.run(
                pkgset("classifier"),
                [
                    "python3",
                    rocky.ROOT / "testing/detectability/run-classifier.py",
                    Path(pcaps).resolve(),
                ],
                stdout=PIPE,
            ).stdout
        )
    for name, key in [
        ("Accuracy", "test_accuracy"),
        ("Precision", "test_precision"),
        ("Recall", "test_recall"),
    ]:
        lst = d[key]
        click.echo(
            click.style(f"{name}: ", bold=True, underline=True)
            + "%.02f ± %.02f"
            % (float(statistics.mean(lst)), float(statistics.stdev(lst)))
        )
    click.secho("Important Features:", bold=True, underline=True)
    for i, (key, value) in enumerate(
        sorted(
            d["feature_importances"][0].items(), key=lambda item: cast(float, -item[1])
        )
    ):
        # This epsilon was chosen since any values which are under this epsilon will display as 0.00
        if abs(value) <= 0.001:
            continue
        click.echo("%02d. (%.02f) %s" % (i, value, key))


DETECTABILITY_COMMANDS = [detectability]
