from pathlib import Path
from typing import List, Set

import rocky


def find_files(roots: List[Path], ext: str, exclude: Set[Path] = set()) -> List[Path]:
    """
    Recursively search the roots for files with extension `ext` (`ext` should include a leading `.`)
    Of all the paths that don't match `exclude`, emit the paths that match, made relative to
    `rocky.ROOT`.
    """
    out: Set[Path] = set()

    def visit(x: Path) -> None:
        nonlocal out
        if x.is_file():
            out.add(x)
        elif x.is_dir():
            for y in x.iterdir():
                if y.is_dir():
                    visit(y)
                elif y.is_file() and y.suffix == ext:
                    visit(y)
                # We ignore symlinks

    for x in roots:
        visit(x)
    return [x.relative_to(rocky.ROOT) for x in out - set(exclude)]
