import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from typing import List, Optional


class NetEmDelay(ABC):
    @abstractmethod
    def netem_arguments(self) -> List[str]:
        ...


class _NetEmNoDelay(NetEmDelay):
    def netem_arguments(self) -> List[str]:
        return []


NET_EM_NO_DELAY = _NetEmNoDelay()


@dataclass(frozen=True)
class NetEmNormalDelay(NetEmDelay):
    """
    The way that [`tc netem`](https://man7.org/linux/man-pages/man8/tc-netem.8.html) allows for the
    use of different distributions, there are several pre-generated tables, such as
    [this one for the standard normal distribution][1]. This table gets loaded
    into the kernel. Once inside the kernel, [`latency` is passed as `mu` and `jitter` is passed as
    `sigma` to the `tabledist()` function](https://elixir.bootlin.com/linux/v5.12.5/source/net/sched/sch_netem.c#L536).
    Inside [`tabledist()`](https://elixir.bootlin.com/linux/v5.12.5/source/net/sched/sch_netem.c#L335),
    a random value is (in a biased manner) used to pick a random entry from the table.

    `mu` and `sigma` are then used to, deterministically, manipulate the standard normal
    distribution by scaling and translating it by `mu` and `sigma`.

    [1]: https://github.com/shemminger/iproute2/blob/9f366536edb5158343152604e82b968be46dbf26/netem/normal.c
    """

    mean: timedelta
    standard_deviation: timedelta

    def netem_arguments(self) -> List[str]:
        if (
            self.standard_deviation.total_seconds() == 0
            or self.mean.total_seconds() == 0
        ):
            raise ValueError("Netem won't accept a mean or standard deviation of zero.")
        return [
            "delay",
            f"{self.mean.total_seconds() * 1_000_000}us",
            f"{self.standard_deviation.total_seconds() * 1_000_000}us",
            "distribution",
            "normal",
        ]


@dataclass
class NetEmSettings:
    "NetworkEMulation settings to simulate a real-world network."

    delay: NetEmDelay

    @classmethod
    def no_effect(cls) -> "NetEmSettings":
        return NetEmSettings(delay=NET_EM_NO_DELAY)

    def netem_command(self) -> List[str]:
        # eth0 is the name of the network interface inside a docker container.
        out = ["tc", "qdisc", "replace", "dev", "eth0", "root", "netem"]
        out += self.delay.netem_arguments()
        return out
