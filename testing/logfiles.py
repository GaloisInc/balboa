from pathlib import Path

from rocky.etc.machine import Machine


def logfiles_path(machine: Machine) -> Path:
    "Return a path suitable for storing logs."
    path = machine.tmp_dir / "logs"
    path.mkdir(exist_ok=True)
    return path
