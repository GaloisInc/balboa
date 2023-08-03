import os
from pathlib import Path

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.machine.local import local_machine
from rocky.etc.nix import pkgset


def _make(target: str) -> Path:
    local_path = rocky.ROOT / "testing/certs" / target
    with local_machine() as machine:
        wd = rocky.ROOT / "testing/certs"
        machine.run(
            pkgset("certgen"),
            ["make", target],
            cwd=wd,
            stdout=PIPE,
            stderr=PIPE,
        )
    return local_path


def key_file(host: str) -> Path:
    "Generate a private key for the given `host`"
    return _make(f"{host}.key")


def der_pubkey_file(host: str) -> Path:
    "Generate the public key (in DER form) for the given `host`"
    return _make(f"{host}.der")


def crt_file(host: str) -> Path:
    "Generate a signed certificate for the given `host`"
    return _make(f"{host}.crt")


def key_crt_combined_pem_file(host: str) -> Path:
    "Generate a file containing both the private key and the signed cert for the given `host`"
    return _make(f"{host}.pem")


def root_ca_cert() -> Path:
    return _make("rootCA.crt")


def ssl_cert_file(machine: Machine) -> Path:
    "Generate a root certificate file containing the system root CAs and the rocky test root CA."
    out = machine.tmp_dir / "ssl-roots.crt"
    if not out.exists():
        out.parent.mkdir(exist_ok=True)
        assert "SSL_CERT_FILE" in os.environ
        initial = Path(os.environ["SSL_CERT_FILE"]).read_text()
        root_ca = root_ca_cert().read_text().strip()
        out.write_text(f"{initial}Rocky Testing Root CA\n{root_ca}\n\n")
    return out
