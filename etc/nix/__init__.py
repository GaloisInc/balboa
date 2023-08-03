import base64
import json
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Dict

import rocky


def to_nix_literal(x: object) -> str:
    "Serialize an object as a nix expression."
    if isinstance(x, str) or isinstance(x, int) or isinstance(x, bool):
        return json.dumps(x)
    elif isinstance(x, list) or isinstance(x, set) or isinstance(x, frozenset):
        return "[" + " ".join(f"({to_nix_literal(y)})" for y in x) + "]"
    elif isinstance(x, dict):
        out = "{"
        for k, v in x.items():
            assert isinstance(x, str)
            out += f"{k} = "
            out += to_nix_literal(v)
            out += ";"
        out += "}"
        return out
    else:
        raise Exception(f"IDK how to convert {repr(x)} to a nix literal")


_PKG_SET_INSTANTIATED_HASH_LOCK = Lock()
_PKG_SET_INSTANTIATED_HASH_CACHE: Dict[str, str] = dict()


@dataclass(frozen=True)
class PkgSet:
    """
    This corresponds to a nix file in `pkgsets`. To construct a pkgset, please use the pkgset
    function.
    """

    path: Path
    args: Dict[str, object]

    @property
    def cache_key(self) -> str:
        "Return a hashable key which contains the contents of this pkgset."
        return json.dumps([str(self.path), self.args], sort_keys=True)

    @property
    def instantiated_hash(self) -> str:
        """
        Return a url-safe base64-encoded string representing a hash of the contents of this package
        set.
        """
        ck = self.cache_key
        with _PKG_SET_INSTANTIATED_HASH_LOCK:
            if ck not in _PKG_SET_INSTANTIATED_HASH_CACHE:
                args = ["nix-instantiate", "--no-gc-warning"]
                for k, v in self.args.items():
                    args.append("--arg")
                    args.append(k)
                    args.append(to_nix_literal(v))
                args.append(str(self.path))
                drv_path = (
                    subprocess.run(args, check=True, stdout=subprocess.PIPE)
                    .stdout.decode("ascii")
                    .strip()
                )
                _PKG_SET_INSTANTIATED_HASH_CACHE[ck] = (
                    base64.urlsafe_b64encode(
                        sha256(
                            drv_path.encode("ascii")
                            + b"\n"
                            + Path(drv_path).read_bytes()
                        ).digest()
                    )
                    .decode("ascii")
                    .replace("=", "")  # strip off the padding
                )
            return _PKG_SET_INSTANTIATED_HASH_CACHE[ck]


def pkgset(name: str, args: Dict[str, object] = dict()) -> PkgSet:
    """
    Construct a package set with the given arguments.
    # Example
    ```python
    pkgset("apps/my-example", dict(my_arg=12))
    ```
    """
    path = rocky.ROOT / "etc/nix/pkgsets" / f"{name}.nix"
    if not path.is_file():
        raise Exception(
            f"Package set {repr(name)} corresponds to {path} which isn't a nix file"
        )
    return PkgSet(path=path, args=dict(args))
