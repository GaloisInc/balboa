import string
import tarfile
from dataclasses import dataclass
from fcntl import LOCK_EX, LOCK_NB, flock
from hashlib import sha256
from pathlib import Path
from shutil import rmtree

import rocky
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset


@dataclass(frozen=True)
class TestingAsset:
    name: str
    url: str
    sha256: str

    def __post_init__(self) -> None:
        assert len(self.sha256) == 64
        assert all(ch in string.digits + "abcdef" for ch in self.sha256)

    def __call__(self) -> Path:
        if rocky.IS_IN_CI:
            assets_dir = Path("/var/lib/rocky-sccache/testing-assets/")
        else:
            assets_dir = rocky.ROOT / "testing/assets/"
        assets_dir /= self.name
        assets_dir.mkdir(exist_ok=True, parents=True)
        tar_file = assets_dir / f"{self.name}-{self.sha256}.tar.gz.tmp"
        out = assets_dir / self.sha256
        lock_file = out.with_suffix(".lock")
        while True:
            with lock_file.open("w+") as lock_file_fd:
                try:
                    flock(lock_file_fd, LOCK_EX | LOCK_NB)
                except OSError:
                    print(f"Waiting to lock {lock_file}")
                    flock(lock_file_fd, LOCK_EX)
                if out.exists():
                    return out
                try:
                    with local_machine() as m:
                        m.run(pkgset("download"), ["curl", self.url], stdout=tar_file)
                    acu = sha256()
                    with tar_file.open("rb") as f:
                        while True:
                            chunk = f.read(8192)
                            if len(chunk) == 0:
                                break
                            acu.update(chunk)
                    hash = acu.hexdigest()
                    if hash != self.sha256:
                        raise Exception(
                            f"{self.name} hash mismatch. Got {hash}. Expected {self.sha256}"
                        )
                    tmp_dst = assets_dir / f"{self.name}-{self.sha256}.tmp"
                    rmtree(tmp_dst, ignore_errors=True)
                    tmp_dst.mkdir()
                    try:
                        with tarfile.open(tar_file, "r:gz") as tar:
                            tar.extractall(path=tmp_dst)
                        entries = list(tmp_dst.iterdir())
                        if len(entries) != 1:
                            raise Exception(
                                f"Tarfile doesn't contain exactly one entry {repr(entries)}"
                            )
                        entries[0].rename(out)
                        return out
                    finally:
                        rmtree(tmp_dst)
                finally:
                    tar_file.unlink()


BIG_BUCK_BUNNY_DASH = TestingAsset(
    name="big-buck-bunny",
    url="https://owncloud.galois.com/index.php/s/uztcketHZsQK5oB/download",
    sha256="a34fe3233c47dee5e884fc6c2fd2b64683542c4615f6e8a3829254255894072c",
)
