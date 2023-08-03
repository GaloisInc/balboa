from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Protocol

import pytest

import rocky
from rocky.etc.machine import PIPE, Machine
from rocky.etc.nix import pkgset
from rocky.etc.rust import BuildMode, cdylib_target
from rocky.testing.apps.web import Browser, NginxServer, run_browser_scenario
from rocky.testing.assets import BIG_BUCK_BUNNY_DASH
from rocky.testing.balboa_master import BalboaMasters
from rocky.testing.capabilities import generate_capability
from rocky.testing.certs import der_pubkey_file
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.env import EnvBuilder
from rocky.testing.integration.parameterize_utils import parameterize_test
from rocky.testing.logfiles import logfiles_path
from rocky.testing.stallone import StalloneMaster

NginxTestFactory = Callable[["NginxConfig"], NginxServer]
DEFAULT_CIPHER_SUITE = CipherSuite.Aes128GCM


@dataclass(frozen=True)
class NginxConfig:
    static_root: Path
    balboa_masters: Optional[BalboaMasters]
    should_inject: bool
    upload_file_root: Optional[Path] = None
    cipher_suite: CipherSuite = DEFAULT_CIPHER_SUITE
    tls_session_resumption: bool = False
    enable_plik: bool = False


@pytest.fixture(scope="function")
def nginx_test_factory(
    machine: Machine,
    build_mode: BuildMode,
    stallone_master: StalloneMaster,
) -> Callable[[NginxConfig], NginxServer]:
    def out(config: NginxConfig) -> NginxServer:
        if config.should_inject:
            assert config.balboa_masters is not None
        env = EnvBuilder(machine)
        if config.balboa_masters:
            env.add_balboa_master(config.balboa_masters.server)
        if config.should_inject:
            env.add_injection(cdylib_target("balboa-injection-nginx").build(build_mode))
        if config.upload_file_root is None:
            upload_file_root = machine.tmp_dir / "empty-upload-file-root"
            upload_file_root.mkdir(exist_ok=True)
        else:
            upload_file_root = config.upload_file_root
        return NginxServer(
            machine,
            env=env,
            static_root=config.static_root,
            upload_root=upload_file_root,
            tls_session_resumption=config.tls_session_resumption,
            cipher_suite=config.cipher_suite,
            enable_plik=config.enable_plik,
        )

    return out


@pytest.fixture(scope="function")
def standard_static_root(machine: Machine) -> Path:
    out = machine.tmp_dir / "standard-static-root"
    out.mkdir()
    (out / "test.txt").write_bytes(b"abcd" * (1024 * 1024))
    return out


def curl_env(
    machine: Machine,
    build_mode: BuildMode,
    balboa_masters: BalboaMasters,
    static_root: Path,
    upload_root: Optional[Path] = None,
) -> EnvBuilder:
    if upload_root is None:
        upload_file_root = machine.tmp_dir / "empty-upload-file-root"
        upload_file_root.mkdir(exist_ok=True)
    else:
        upload_file_root = upload_root
    return (
        EnvBuilder(machine)
        .add_injection(cdylib_target("balboa-injection-firefox").build(build_mode))
        .add_non_existent_sslkeylogfile()
        .add_balboa_master(balboa_masters.client)
        .add_custom("STATIC_FILE_DIRECTORY", str(static_root))
        .add_custom("UPLOAD_FILE_DIRECTORY", str(upload_file_root))
    )


class WebCppSetup(Protocol):
    def __call__(
        self,
        custom_env: Dict[str, str],
        assert_min_transmitted_data: int = 128,
        tls_session_resumption: bool = False,
        enable_plik: bool = False,
        upload_file_root: Optional[Path] = None,
    ) -> BalboaMasters:
        ...


@pytest.fixture(scope="function")
def web_cpp_setup(
    machine: Machine,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
    standard_static_root: Path,
) -> WebCppSetup:
    def out(
        custom_env: Dict[str, str],
        assert_min_transmitted_data: int = 128,
        tls_session_resumption: bool = False,
        enable_plik: bool = False,
        upload_file_root: Optional[Path] = None,
    ) -> BalboaMasters:
        balboa_masters = BalboaMasters(
            machine,
            machine,
        )
        balboa_masters.client.generate_capability_for(
            21, balboa_masters.server, spoil_pubkey=False
        )

        nginx = nginx_test_factory(
            NginxConfig(
                cipher_suite=DEFAULT_CIPHER_SUITE,
                should_inject=True,
                balboa_masters=balboa_masters,
                static_root=standard_static_root,
                tls_session_resumption=tls_session_resumption,
                enable_plik=enable_plik,
                upload_file_root=upload_file_root,
            )
        )
        machine.run(
            pkgset("testing/test_web"),
            ["test_web"],
            env=curl_env(
                machine,
                build_mode,
                balboa_masters,
                standard_static_root,
                upload_root=upload_file_root,
            )
            .add_custom("BASE_URL", nginx.base_url)
            .build()
            | custom_env,
            stdout=logfiles_path(machine) / "test_web.cpp.stdout",
            stderr=logfiles_path(machine) / "test_web.cpp.stderr",
        )
        return balboa_masters

    return out


# TODO: test balboa-disabled nginx


# TODO: try uploading multiple files while re-using a connection.


@pytest.fixture(
    scope="function",
    params=list(Browser),
)
def browser(request: Any) -> Iterator[Browser]:
    yield request.param


@pytest.mark.xfail(reason="FIXME. Issue #125")
def test_browser_badssl(browser: Browser, machine: Machine) -> None:
    "Make sure that the browser is checking certificates."
    run_browser_scenario(
        machine,
        EnvBuilder(machine),
        browser,
        "badssl",
    )


# TODO: Parameterize this test:
# - rocky_on_server: pass `should_inject=True/False` to NginxConfig
# - rocky_on_client: call `add_injection` (or not) to `run_browser_scenario
def test_browser_dash(
    browser: Browser,
    machine: Machine,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
) -> None:
    balboa_masters = BalboaMasters(machine, machine)

    dash_assets = BIG_BUCK_BUNNY_DASH()
    www = machine.tmp_dir / "www"
    www.mkdir()
    (www / "bbb").symlink_to(dash_assets)
    (www / "index.html").write_text(
        (rocky.ROOT / "testing/assets/dash.html")
        .read_text()
        .replace("INSERT_MPD_URL_HERE", "bbb/big_buck_bunny.mpd")
    )

    balboa_masters.client.generate_capability_for(
        21, balboa_masters.server, spoil_pubkey=False
    )

    nginx = nginx_test_factory(
        NginxConfig(
            should_inject=True,
            balboa_masters=balboa_masters,
            static_root=www,
        )
    )
    run_browser_scenario(
        machine,
        EnvBuilder(machine)
        .add_injection(cdylib_target("balboa-injection-firefox").build(build_mode))
        .add_balboa_master(balboa_masters.client)
        .add_custom("STATIC_FILE_DIRECTORY", str(www))
        .add_custom("UPLOAD_FILE_DIRECTORY", str(www)),
        browser,
        "play-dash",
        dict(url=f"{nginx.base_url}/index.html", sleep=20),
    )
    small_byte_count, large_byte_count = sorted(
        [balboa_masters.client_received_bytes, balboa_masters.server_received_bytes]
    )
    assert small_byte_count >= 16
    assert large_byte_count >= 1024 * 1024 * 2


def test_browser_plain_text(
    browser: Browser,
    machine: Machine,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
    standard_static_root: Path,
) -> None:
    balboa_masters = BalboaMasters(
        machine,
        machine,
    )
    balboa_masters.client.generate_capability_for(
        21, balboa_masters.server, spoil_pubkey=False
    )

    nginx = nginx_test_factory(
        NginxConfig(
            should_inject=True,
            balboa_masters=balboa_masters,
            static_root=standard_static_root,
        )
    )
    upload_file_root = machine.tmp_dir / "upload-file-root-ff"
    upload_file_root.mkdir()
    run_browser_scenario(
        machine,
        EnvBuilder(machine)
        .add_injection(cdylib_target("balboa-injection-firefox").build(build_mode))
        .add_balboa_master(balboa_masters.client)
        .add_custom("STATIC_FILE_DIRECTORY", str(standard_static_root))
        .add_custom("UPLOAD_FILE_DIRECTORY", str(upload_file_root)),
        browser,
        "plaintext-load",
        dict(url=f"{nginx.base_url}/test.txt"),
    )


def test_browser_plik_just_upload(
    browser: Browser,
    machine: Machine,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
    standard_static_root: Path,
) -> None:
    balboa_masters = BalboaMasters(
        machine,
        machine,
    )
    balboa_masters.client.generate_capability_for(
        21, balboa_masters.server, spoil_pubkey=False
    )

    upload_dir = machine.tmp_dir / "upload-dir"
    upload_dir.mkdir()
    file_to_upload = upload_dir / "file-to-upload"
    file_to_upload.write_text("I am a file that is FUN to upload!!!\n" * 10_000)
    nginx = nginx_test_factory(
        NginxConfig(
            should_inject=True,
            balboa_masters=balboa_masters,
            static_root=standard_static_root,
            upload_file_root=upload_dir,
            enable_plik=True,
        )
    )
    run_browser_scenario(
        machine,
        EnvBuilder(machine)
        .add_injection(cdylib_target("balboa-injection-firefox").build(build_mode))
        .add_balboa_master(balboa_masters.client)
        .add_custom("STATIC_FILE_DIRECTORY", str(standard_static_root))
        .add_custom("UPLOAD_FILE_DIRECTORY", str(upload_dir)),
        browser,
        "plik-just-upload",
        dict(url=f"{nginx.base_url}/plik/", file_to_upload=str(file_to_upload)),
        headless=True,
    )
    # Firefox sends the POST body in a second TLS record.
    # Data is also sent via HTTP headers, so we use a big file (which will send much more info than
    # the headers), so we can make sure the headers are working.
    assert balboa_masters.server_received_bytes >= file_to_upload.stat().st_size


def test_plik_just_upload(
    machine: Machine,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
    standard_static_root: Path,
) -> None:
    balboa_masters = BalboaMasters(
        machine,
        machine,
    )
    balboa_masters.client.generate_capability_for(
        21, balboa_masters.server, spoil_pubkey=False
    )

    upload_dir = machine.tmp_dir / "upload-dir"
    upload_dir.mkdir()
    file_to_upload = upload_dir / "file-to-upload"
    file_to_upload.write_text("I am a file that is FUN to upload!!!")
    nginx = nginx_test_factory(
        NginxConfig(
            should_inject=True,
            balboa_masters=balboa_masters,
            static_root=standard_static_root,
            upload_file_root=upload_dir,
            enable_plik=True,
        )
    )
    machine.run(
        pkgset("apps/curl"),
        [
            "curl",
            "--verbose",
            "--fail",
            "--form",
            f"file=@{file_to_upload}",
        ]
        + [f"{nginx.base_url}/plik/"],
        env=curl_env(
            machine,
            build_mode,
            balboa_masters,
            standard_static_root,
            upload_root=upload_dir,
        ).build(),
        stdout=PIPE,
        stderr=logfiles_path(machine) / "curl.client.stderr",
    )
    # Curl sends the POST body in a second TLS record.
    assert balboa_masters.server_received_bytes == file_to_upload.stat().st_size


def test_simple_nginx_curl(
    machine: Machine,
    cipher_suite: CipherSuite,
    build_mode: BuildMode,
    nginx_test_factory: NginxTestFactory,
    standard_static_root: Path,
) -> None:
    balboa_masters = BalboaMasters(
        machine,
        machine,
    )

    balboa_masters.client.generate_capability_for(
        21, balboa_masters.server, spoil_pubkey=False
    )

    nginx = nginx_test_factory(
        NginxConfig(
            cipher_suite=cipher_suite,
            should_inject=True,
            balboa_masters=balboa_masters,
            static_root=standard_static_root,
        )
    )
    out = machine.run(
        pkgset("apps/curl"),
        [
            "curl",
            "--verbose",
            "--fail",
        ]
        + [f"{nginx.base_url}/test.txt"],
        env=curl_env(machine, build_mode, balboa_masters, standard_static_root).build(),
        stdout=PIPE,
        stderr=logfiles_path(machine) / "curl.client.stderr",
    )
    assert out.stdout == (standard_static_root / "test.txt").read_bytes()


def test_simple_cpp(web_cpp_setup: WebCppSetup, standard_static_root: Path) -> None:
    web_cpp_setup(
        {"WHICH_TEST": "simple"},
        assert_min_transmitted_data=len(
            (standard_static_root / "test.txt").read_bytes()
        ),
    )


@pytest.mark.xfail(reason="We don't yet support TLS session resumption. See issue #93")
def test_tls_session_resumption(web_cpp_setup: WebCppSetup) -> None:
    web_cpp_setup(
        {"WHICH_TEST": "tls_session_resumption"},
        tls_session_resumption=True,
    )


def test_connection_reuse(
    web_cpp_setup: WebCppSetup, standard_static_root: Path
) -> None:
    web_cpp_setup(
        {"WHICH_TEST": "connection_reuse"},
        assert_min_transmitted_data=len(
            (standard_static_root / "test.txt").read_bytes() * 2
        ),
    )


@pytest.mark.xfail(reason="Issues #126,129")
def test_connection_reuse_upload(machine: Machine, web_cpp_setup: WebCppSetup) -> None:
    upload_dir = machine.tmp_dir / "upload-dir"
    upload_dir.mkdir()
    files = [f"This is my file to upload #{i}" for i in range(2)]
    for i, content in enumerate(files):
        (upload_dir / f"file-{i}").write_text(content)
    web_cpp_setup(
        {"WHICH_TEST": "connection_reuse_plik"},
        enable_plik=True,
        upload_file_root=upload_dir,
        assert_min_transmitted_data=sum(len(x) for x in files),
    )
