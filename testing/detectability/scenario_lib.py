import enum
import json
import logging
import random
import re
import shutil
import time
from collections import defaultdict
from datetime import timedelta
from functools import wraps
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, DefaultDict, Dict, List, Optional, Sequence, Type

import click

import rocky
from rocky.etc.machine.docker import DockerCluster, DockerImage
from rocky.etc.machine.docker.netem import NetEmNormalDelay, NetEmSettings
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps.icecast import IcecastServer
from rocky.testing.apps.media_players import MediaPlayer, Mplayer, Mpv, Vlc
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.certs import der_pubkey_file
from rocky.testing.env import EnvBuilder
from rocky.testing.stallone import StalloneMaster

_logger = logging.getLogger(__name__)

_DURATION_UNITS = {"s": 1, "ns": 10**-9, "us": 10**-6, "ms": 10**-3}
_FLOATING_POINT_WITH_UNIT_REGEX = (
    r"(([0-9]+(.[0-9]+)?)[\s]*(" + "|".join(_DURATION_UNITS.keys()) + "))"
)
_NORMAL_DELAY_REGEX = re.compile(
    "^"
    + _FLOATING_POINT_WITH_UNIT_REGEX
    + r"[\s]*\+\-[\s]*"
    + _FLOATING_POINT_WITH_UNIT_REGEX
    + "$"
)


def scenario(variants: List[str]) -> Callable[[Callable[..., Any]], click.Command]:
    if len(variants) < 2:
        raise ValueError("There need to be at least two variants.")

    def outer(f: Callable[..., Any]) -> click.Command:
        @click.command()
        @click.option(
            "--num-trials",
            "-n",
            help="How many trials of balboa enabled vs disabled should be run.",
            type=int,
            show_default=True,
            default=130,
        )
        @click.option(
            "-j",
            "--parallelism",
            default=1,
            show_default=True,
            type=int,
            help="The number of trials to run in parallel.",
        )
        @click.option(
            "-o",
            "--out-dir",
            required=True,
            type=click.Path(file_okay=False),
            help="The directory which packet captures should be written to. (Each variant will be a subdirectory.)",
        )
        @click.option(
            "--overwrite",
            is_flag=True,
            help="If specified, overwrite the provided output directory.",
        )
        @click.option(
            "--normal-delay",
            help=(
                "If specified, add an artifical network delay (to every container), "
                "which is normally distributed.\nThis should be formatted as, for example, "
                "`10us +- 0us`."
            ),
        )
        @click.option(
            "--save-logs",
            is_flag=True,
            help="If specified, do not delete the logs upon completion of the run.",
        )
        @wraps(f)
        def inner(
            num_trials: int,
            parallelism: int,
            out_dir: str,
            overwrite: bool,
            normal_delay: Optional[str],
            save_logs: bool,
            **kwargs: Any,
        ) -> None:
            out_path = Path(out_dir)
            if out_path.exists():
                if overwrite:
                    shutil.rmtree(out_path)
                else:
                    raise click.BadOptionUsage(
                        option_name="--out-dir",
                        message=f"Output path {out_dir} already exists. Use --overwrite to overwrite it.",
                    )
            out_path.mkdir()
            (out_path / "scenario.json").write_text(
                json.dumps(
                    dict(
                        scenario=f.__name__,
                        num_trials=num_trials,
                        parallelism=parallelism,
                        normal_delay=normal_delay,
                    )
                    | kwargs
                )
            )
            for variant in variants:
                (out_path / variant).mkdir()
            lock = Lock()
            tcp_dump_counts: DefaultDict[str, int] = defaultdict(lambda: 1)
            experiments = []
            exiting = False
            clusters: Dict[str, DockerCluster] = dict()
            for variant in variants:
                for _ in range(num_trials):
                    experiments.append(variant)
            random.shuffle(experiments)
            num_experiments = len(experiments)
            netem = NetEmSettings.no_effect()
            if normal_delay is not None:
                match = _NORMAL_DELAY_REGEX.match(normal_delay)
                if match is None:
                    raise click.BadOptionUsage(
                        option_name="--normal-delay",
                        message="Invalid delay. Did not match format.",
                    )
                groups = match.groups()
                netem.delay = NetEmNormalDelay(
                    mean=timedelta(
                        seconds=float(groups[1]) * _DURATION_UNITS[groups[3]]
                    ),
                    standard_deviation=timedelta(
                        seconds=float(groups[5]) * _DURATION_UNITS[groups[7]]
                    ),
                )

            def run_experiment(variant: str, tcpdump: bool) -> None:
                id = -1
                with lock:
                    if tcpdump:
                        id = tcp_dump_counts[variant]
                        tcp_dump_counts[variant] += 1
                        tmp_path = out_path / f"WIP{variant}.{id}.pcap"
                NUM_TRIALS = 3
                for trial_num in range(NUM_TRIALS):
                    try:
                        cluster = DockerCluster(netem=netem, save_logs=save_logs)
                        try:
                            with lock:
                                if exiting:
                                    return
                                clusters[cluster.name] = cluster
                            if tcpdump:
                                tmp_path.unlink(missing_ok=True)
                                cluster.tcpdump(tmp_path)
                            f(variant=variant, cluster=cluster, **kwargs)
                        finally:
                            cluster.close()
                            with lock:
                                if cluster.name in clusters:
                                    del clusters[cluster.name]
                        if tcpdump:
                            tmp_path.rename(out_path / variant / ("%06d.pcap" % id))
                        return
                    except Exception as e:
                        if trial_num == NUM_TRIALS - 1:
                            raise
                        else:
                            _logger.warning(
                                "Experiment %s %d failed at attempt #%d. Retrying.",
                                variant,
                                id,
                                trial_num + 1,
                                exc_info=True,
                            )
                            time.sleep(random.randint(1, 5))

            # Rather than trying to anticipate all the docker images and targets that we'll need for
            # each variant, we'll just run each variant once to warm things up, which should compile
            # everything. Then we'll start running everything for real. This isn't the "right"
            # solution, but the right solution probably involves using Bazel, so this is right
            # enough :)
            for variant in variants:
                _logger.info("Warming-up variant %s", variant)
                run_experiment(variant, tcpdump=False)
            try:
                with click.progressbar(length=num_experiments) as bar:

                    def background_thread() -> None:
                        while not exiting:
                            with lock:
                                if len(experiments) == 0:
                                    return
                                variant = experiments.pop()
                            # Stagger start times.
                            if parallelism > 1:
                                time.sleep(random.randint(0, 4))
                            run_experiment(variant, tcpdump=True)
                            with lock:
                                bar.update(num_experiments - len(experiments))

                    threads = [
                        Thread(target=background_thread) for _ in range(parallelism)
                    ]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join()
            finally:
                with lock:
                    exiting = True
                    cluster_values = list(clusters.values())
                for cluster in cluster_values:
                    cluster.close()

        return inner

    return outer
