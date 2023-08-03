import enum
import json
from ipaddress import IPv4Address
from pathlib import Path
from string import Template
from typing import Any, Dict, Optional, Sequence
from uuid import uuid4

import rocky
from rocky.etc.machine import Machine
from rocky.etc.nix import PkgSet, pkgset
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.certs import crt_file, key_file, root_ca_cert
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path

# TODO: extend to other http servers and web browsers

_HTTPS_PORT = 9443
_PLIK_PORT = 8564


def _nginx_config(
    nginx_base_conf: Path,
    tmp_dir: Path,
    hostname: str,
    pem_path: Path,
    key_path: Path,
    bind: IPv4Address,
    cipher_suite: Optional[CipherSuite],
    access_log: Path,
    static_root: Path,
    tls_session_resumption: bool,
) -> str:
    # We don't use f-strings since nginx uses braces in its config language.
    # Nginx also uses dollar signs in its config language, so we use @ instead.
    class MyTemplate(Template):
        delimiter = "@"

    return MyTemplate(
        """
# We (rocky people) want several workers to help detect if there's race conditions in Balboa.
worker_processes  4;
daemon off;

error_log  stderr;
error_log  stderr  notice;
error_log  stderr  info;

pid /dev/null;


events {
    worker_connections  1024;
}


http {
    include       @mime_types;
    default_type  application/octet-stream;

    access_log @access_log;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    # HTTPS server
    #
    server {
        listen       @bind:@https_port ssl;
        server_name  @hostname;

        client_body_temp_path @tmp_dir/client_body;
        fastcgi_temp_path     @tmp_dir/fastcgi_temp;
        proxy_temp_path       @tmp_dir/proxy_temp;
        scgi_temp_path        @tmp_dir/scgi_temp;
        uwsgi_temp_path       @tmp_dir/uwsgi_temp;

        ssl_certificate      @pem_path;
        ssl_certificate_key  @key_path;

        @session_resumption

        ssl_ciphers  @cipher_suite;
        ssl_prefer_server_ciphers  on;
        ssl_protocols       TLSv1.2;

        location / {
            root @static_root;
            autoindex on;

            add_header 'Timing-Allow-Origin' '*';
            add_header 'Access-Control-Max-Age' '86400';
            add_header 'Access-Control-Allow-Credentials' 'true';
            add_header 'Access-Control-Expose-Headers' 'Server,range,Date,hdntl,hdnts,Akamai-Mon-Iucid-Ing,Akamai-Mon-Iucid-Del,Akamai-Request-BC,Content-Length,Content-Range,Geo-Info,Quic-Version';
            add_header 'Access-Control-Allow-Headers' 'origin,range,hdntl,hdnts,accept-encoding,referer,CMCD-Request,CMCD-Object,CMCD-Status,CMCD-Session';
            add_header 'Access-Control-Allow-Methods' 'GET,POST,OPTIONS';
            add_header 'Access-Control-Allow-Origin' '*';
        }
        location /plik {
            proxy_pass http://@bind:@plik_port;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_buffer_size 1M;
            proxy_buffers 8 1M;
            client_body_buffer_size 1M;
            proxy_set_header Host $host;
        }
        # These paths are used for specific testing purposes.
        location /nginx-is-up {
            return 200 "Yes, indeed!";
        }
        location /nginx-connection-close {
            keepalive_timeout 0;
            return 200 "This connection is closed!";
        }
    }

}
    """.strip(),
    ).substitute(
        mime_types=nginx_base_conf / "mime.types",
        pem_path=pem_path,
        key_path=key_path,
        hostname=hostname,
        bind=bind,
        tmp_dir=tmp_dir,
        access_log=access_log,
        https_port=_HTTPS_PORT,
        cipher_suite=cipher_suite.openssl_cipher_string
        if cipher_suite is not None
        else "HIGH:!aNULL:!MD5",
        static_root=static_root,
        session_resumption="""
        # These are the defaults
        # TODO: ssl_session_cache might cause a problem for us...
        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;
        """
        if tls_session_resumption
        else "ssl_session_cache off;\nssl_session_tickets off;",
        plik_port=_PLIK_PORT,
    )


def _plik_config(bind: IPv4Address, plik_dir: Path) -> str:
    return f"""
    #####
##
#  Plik - Configuration File
#

Debug               = true         # Enable debug mode
DebugRequests       = true         # Log HTTP request and responses
ListenPort          = {_PLIK_PORT} # Port the HTTP server will listen on
ListenAddress       = "{bind}"     # Address the HTTP server will bind on
Path                = "/plik/"            # HTTP root path

MaxFileSize         = 10000000000   # 10GB
MaxFilePerUpload    = 1000

DefaultTTL          =  60
MaxTTL              =  3600 # -1 => No limit
OneShot             = true          # Allow users to make one shot uploads
Removable           = true          # allow users to make removable uploads
Stream              = true          # Enable stream mode
ProtectedByPassword = true          # Allow users to protect the download with a password

SslEnabled          = false         # Enable SSL

DataBackend = "file"
[DataBackendConfig]
    Directory = "{plik_dir/'files'}"
[MetadataBackendConfig]
    Driver = "sqlite3"
    ConnectionString = "{plik_dir/'plik.db'}"
    Debug = false # Log SQL requests
    """.strip()


class NginxServer:
    """
    An NGINX HTTP Server.

    The NGINX HTTP Server will serve static assets from the directory specified in the configuration

    The following additional routes are configured:
    * `/nginx-is-up`: which will return a simple 200 response
    * `/nginx-connection-close`: which will return a 200 response with `Connection: close` set.

    If the `enable_plik` option is `True`, then plik will be hosted at `/plik/`.

    This NGINX server _does not_ have compression enabled. It does support HTTP caching.
    """

    PKG_SETS: Sequence[PkgSet] = [
        pkgset("apps/nginx"),
        pkgset("apps/curl"),
    ]
    "The package sets which nginx uses."

    base_url: str
    "The base url of this server, without the trailing slash."

    def __init__(
        self,
        machine: Machine,
        env: EnvBuilder,
        static_root: Path,
        upload_root: Path,
        enable_plik: bool = False,
        cipher_suite: Optional[CipherSuite] = None,
        tls_session_resumption: bool = False,
    ) -> None:
        """
        Initialize the NGINX server, and wait for it to start.

        The `static_root` argument tells the NGINX server the path to the directory containing the
        static assets that it should serve.
        """
        assert static_root.is_dir()
        nginx_base_conf = (
            machine.which(pkgset("apps/nginx"), "nginx").parent.parent / "conf"
        )
        nginx_config_path = machine.tmp_dir / "nginx.conf"
        nginx_tmp = machine.tmp_dir / "nginx.tmp"
        nginx_tmp.mkdir()
        nginx_config_path.write_text(
            _nginx_config(
                nginx_base_conf=nginx_base_conf,
                hostname=machine.hostname,
                pem_path=crt_file(machine.hostname),
                key_path=key_file(machine.hostname),
                bind=machine.bind,
                tmp_dir=nginx_tmp,
                cipher_suite=cipher_suite,
                access_log=logfiles_path(machine) / "nginx.access.log",
                static_root=static_root,
                tls_session_resumption=tls_session_resumption,
            )
        )
        final_env = (
            {
                "STATIC_FILE_DIRECTORY": str(static_root),
                "UPLOAD_FILE_DIRECTORY": str(upload_root),
            }
            | env.build()
            | machine.default_env
        )
        self._proc = machine.popen(
            pkgset("apps/nginx"),
            [
                "nginx",
                "-c",
                str(nginx_config_path),
                "-e",
                "stderr",
                "-g",
                # Tell nginx to inherit the envronment variables that we set.
                " ".join(f"env {name};" for name in final_env.keys()),
            ],
            stderr=logfiles_path(machine) / "nginx.stderr",
            env=final_env,
        )
        self._closed = False
        machine.add_cleanup_handler(self.close)
        self.base_url = f"https://{machine.hostname}:{_HTTPS_PORT}"

        def assert_nginx_is_up() -> None:
            # This will raise an exception if curl fails.
            machine.run(
                pkgset("apps/curl"),
                [
                    "curl",
                    "--verbose",
                    "--fail",
                    f"{self.base_url}/nginx-is-up",
                ],
                capture_output=True,
                env=EnvBuilder(machine).build(),
            )

        busy_wait_assert(assert_nginx_is_up)
        if enable_plik:
            plik_dir = machine.tmp_dir / "plik"
            plik_dir.mkdir()
            plik_cfg = plik_dir / "plik.cfg"
            plik_cfg.write_text(_plik_config(bind=machine.bind, plik_dir=plik_dir))
            (plik_dir / "files").mkdir()
            machine.popen(
                pkgset("apps/plik"),
                ["plikd", f"--config={plik_cfg}"],
                cwd=plik_dir,
                stdout=logfiles_path(machine) / "plik.stdout",
                stderr=logfiles_path(machine) / "plik.stderr",
            )

            def assert_plik_is_up() -> None:
                machine.run(
                    pkgset("apps/curl"),
                    [
                        "curl",
                        "--verbose",
                        "--fail",
                        f"http://{machine.bind}:{_PLIK_PORT}/plik/version",
                    ],
                    capture_output=True,
                )

            busy_wait_assert(assert_plik_is_up)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._proc.close()


@enum.unique
class Browser(enum.Enum):
    FIREFOX = "firefox"


def run_browser_scenario(
    machine: Machine,
    env_builder: EnvBuilder,
    browser: Browser,
    scenario_name: str,
    scenario_args: Dict[str, Any] = dict(),
    headless: bool = True,
    verbose_logs: bool = True,
) -> None:
    env = env_builder.add_non_existent_sslkeylogfile().build()
    for k in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES"]:
        if k in env:
            env["ROCKY_FIREFOX_DYLIB"] = env[k]
            del env[k]
    for k in [
        "MOZ_SANDBOX_LOGGING",
        "MOZ_DISABLE_CONTENT_SANDBOX",
        "MOZ_DISABLE_GMP_SANDBOX",
        "MOZ_DISABLE_RDD_SANDBOX",
        "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX",
    ]:
        env[k] = "1"
    home = machine.tmp_dir / f"browser-home-{uuid4()}"
    home.mkdir()
    env["HOME"] = str(home)
    certs_dir = home / ".mozilla/certificates"
    certs_dir.mkdir(parents=True)
    (certs_dir / "rockyRootCa.PEM").write_bytes(root_ca_cert().read_bytes())
    machine.run(
        pkgset(f"apps/{browser.value}"),
        [
            "python3",
            rocky.ROOT / "testing/apps/web_selenium.py",
            json.dumps(
                {
                    "browser": browser.value,
                    "headless": headless,
                    "verbose_logs": verbose_logs,
                    "scenario": scenario_name,
                }
                | scenario_args
            ),
        ],
        env=env,
        stdout=logfiles_path(machine) / f"{browser.value}.stdout",
        stderr=logfiles_path(machine) / f"{browser.value}.stderr",
    )
