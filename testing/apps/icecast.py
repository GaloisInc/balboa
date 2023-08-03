import shlex
from ipaddress import IPv4Address
from pathlib import Path
from textwrap import dedent
from typing import BinaryIO, Optional, Union

from rocky.etc.machine import DEV_NULL, PIPE, Machine
from rocky.etc.nix import PkgSet, pkgset
from rocky.testing.busy_wait import busy_wait_assert
from rocky.testing.certs import key_crt_combined_pem_file
from rocky.testing.cipher_suite import CipherSuite
from rocky.testing.env import EnvBuilder
from rocky.testing.logfiles import logfiles_path

_HTTP_PORT = 8080
_HTTPS_PORT = 8443
_ADMIN_PASSWORD = "adminpassword"
_SOURCE_PASSWORD = "sourcepassword"
_RELAY_PASSWORD = "relaypassword"
_MUSIC_PATH = "vorbis.ogg"


def _ezstream_xml(hostname: str) -> str:
    return dedent(
        f"""
        <!--
           EXAMPLE: Ogg Vorbis stream from standard input WITHOUT reencoding

           This example streams an Ogg Vorbis stream from standard input (stdin.)
           Since ezstream will not be doing any reencoding, the resulting stream
           format (quality/bitrate, samplerate, channels) will be of the respective
           input stream.
         -->
        <ezstream>
            <url>http://{hostname}:{_HTTP_PORT}/{_MUSIC_PATH}</url>
            <sourcepassword>{_SOURCE_PASSWORD}</sourcepassword>
            <format>VORBIS</format>
            <filename>stdin</filename>
            <!--
              Important:
              For streaming from standard input, the default for continuous streaming
              is bad. Set <stream_once /> to 1 here to prevent ezstream from spinning
              endlessly when the input stream stops:
             -->
            <stream_once>1</stream_once>
            <!--
              The following settings are used to describe your stream to the server.
              It's up to you to make sure that the bitrate/quality/samplerate/channels
              information matches up with your input stream files.
             -->
            <svrinfoname>My Stream</svrinfoname>
            <svrinfourl>https://www.example.com</svrinfourl>
            <svrinfogenre>RockNRoll</svrinfogenre>
            <svrinfodescription>This is a stream description</svrinfodescription>
            <svrinfobitrate>96</svrinfobitrate>
            <svrinfoquality>2.0</svrinfoquality>
            <svrinfochannels>2</svrinfochannels>
            <svrinfosamplerate>44100</svrinfosamplerate>
            <!-- Disallow the server from advertising the stream on a public YP directory: -->
            <svrinfopublic>0</svrinfopublic>
        </ezstream>
    """
    )


def _icecast_xml(
    icecast_base_path: str,
    ssl_cert_path: Optional[Path],
    bind_addr: IPv4Address,
    hostname: str,
    cipher_suite: Optional[CipherSuite],
) -> str:
    return dedent(
        f"""
        <icecast>
            <!-- location and admin are two arbitrary strings that are e.g. visible
                 on the server info page of the icecast web interface
                 (server_version.xsl). -->
            <location>Earth</location>
            <admin>icemaster@localhost</admin>

            <!-- IMPORTANT!
                 Especially for inexperienced users:
                 Start out by ONLY changing all passwords and restarting Icecast.
                 For detailed setup instructions please refer to the documentation.
                 It's also available here: http://icecast.org/docs/
            -->

            <limits>
                <clients>100</clients>
                <sources>2</sources>
                <queue-size>524288</queue-size>
                <client-timeout>30</client-timeout>
                <header-timeout>15</header-timeout>
                <source-timeout>10</source-timeout>
                <!-- If enabled, this will provide a burst of data when a client
                     first connects, thereby significantly reducing the startup
                     time for listeners that do substantial buffering. However,
                     it also significantly increases latency between the source
                     client and listening client.  For low-latency setups, you
                     might want to disable this. -->
                <burst-on-connect>1</burst-on-connect>
                <!-- same as burst-on-connect, but this allows for being more
                     specific on how much to burst. Most people won't need to
                     change from the default 64k. Applies to all mountpoints  -->
                <burst-size>65535</burst-size>
            </limits>

            <authentication>
                <!-- Sources log in with username 'source' -->
                <source-password>{_SOURCE_PASSWORD}</source-password>
                <!-- Relays log in with username 'relay' -->
                <relay-password>{_RELAY_PASSWORD}</relay-password>

                <!-- Admin logs in with the username given below -->
                <admin-user>admin</admin-user>
                <admin-password>{_ADMIN_PASSWORD}</admin-password>
            </authentication>
            <hostname>{hostname}</hostname>
            <listen-socket>
                <port>{_HTTP_PORT}</port>
                <bind-address>{bind_addr}</bind-address>
            </listen-socket>
            <listen-socket>
                <port>{_HTTPS_PORT}</port>
                <ssl>{int(bool(ssl_cert_path))}</ssl>
                <bind-address>{bind_addr}</bind-address>
                <!-- Excitingly, this feature is undocumented. -->
                <listen-backlog>128</listen-backlog>
            </listen-socket>
            <http-headers>
                <header name="Access-Control-Allow-Origin" value="*" />
            </http-headers>
            <fileserve>1</fileserve>
            <paths>
                <!-- basedir is only used if chroot is enabled -->
                <basedir>{icecast_base_path}</basedir>
                <logdir>/tmp/icecast-logdir-should-be-unused</logdir>
                <webroot>{icecast_base_path}/web</webroot>
                <adminroot>{icecast_base_path}/admin</adminroot>
                <alias source="/" destination="/status.xsl"/>
                <!-- The certificate file needs to contain both public and private part.
                     Both should be PEM encoded. -->
                {"<ssl-certificate>%s</ssl-certificate>" % ssl_cert_path if ssl_cert_path else ''}
                {
                    "<ssl-allowed-ciphers>%s</ssl-allowed-ciphers>" % cipher_suite.openssl_cipher_string
                    if cipher_suite else ''
                }
            </paths>

            <logging>
                <!-- log to stderr/stdout -->
                <accesslog>-</accesslog>
                <errorlog>-</errorlog>
                <!-- <playlistlog>playlist.log</playlistlog> -->
                <loglevel>4</loglevel> <!-- 4 Debug, 3 Info, 2 Warn, 1 Error -->
                <logsize>10000</logsize> <!-- Max size of a logfile -->
            </logging>

            <security>
                <chroot>0</chroot>
            </security>
        </icecast>
    """
    )


_OPENSSL_CNF = """
openssl_conf = default_conf_section

[default_conf_section]
ssl_conf = ssl_section

[ssl_section]
system_default = system_default_section

[system_default_section]
MaxProtocol = TLSv1.2
"""


class IcecastServer:
    """An Icecast server which serves a given music file."""

    PKG_SET: PkgSet = pkgset("apps/icecast")

    song_path: Path
    music_url: str

    def __init__(
        self,
        machine: Machine,
        env: EnvBuilder,
        song_path: Path,
        loop_song: bool,
        cipher_suite: Optional[CipherSuite],
    ) -> None:
        """
        Spawn an Icecast server which will, if it hasn't been closed manually, close when the
        `machine` is closed. `env` will be used to set the environment variables for the icecast
        binary. If `cipher_suite` is specified, Icecast will force its use.

        This constructor will not return until Icecast has successfully started, and the song is
        being streamed.
        """
        openssl_cnf_path = machine.tmp_dir / "icecast.openssl.cnf"
        openssl_cnf_path.write_text(_OPENSSL_CNF)
        remote_song_path = machine.tmp_dir / "icecast-song.ogg"
        remote_song_path.symlink_to(song_path)
        icecast_base_path = str(
            machine.which(self.PKG_SET, "icecast").parent.parent / "share/icecast"
        )
        icecast_xml = machine.tmp_dir / "icecast.xml"
        icecast_xml.write_text(
            _icecast_xml(
                icecast_base_path=icecast_base_path,
                ssl_cert_path=key_crt_combined_pem_file(machine.hostname),
                bind_addr=machine.bind,
                hostname=machine.hostname,
                cipher_suite=cipher_suite,
            )
        )
        icecast_xml.chmod(0o644)
        self.stderr_log = logfiles_path(machine) / "icecast.stderr"
        icecast = machine.popen(
            self.PKG_SET,
            [
                "icecast",
                "-c",
                str(icecast_xml),
            ],
            stdin=DEV_NULL,
            stdout=logfiles_path(machine) / "icecast.stdout",
            stderr=self.stderr_log,
            env=env.build()
            | {
                "OGG_FILE": str(remote_song_path),
                "OPENSSL_CONF": str(openssl_cnf_path),
            },
        )

        def assert_icecast_is_up() -> None:
            # This will raise an exception if curl fails.
            machine.run(
                pkgset("apps/icecast"),
                [
                    "curl",
                    "--verbose",
                    "--head",
                    "--fail",
                    # We just want to get the headers of the HTTP response, which is what --head
                    # does. However, that changes the HTTP method to HEAD, to tell the server not
                    # to send the body of the response. However, Icecast doesn't support HEAD!
                    # To get around this, we force the GET HTTP method. Curl will simply stop
                    # reading after it has seen the http headers.
                    "-X",
                    "GET",
                    f"http://{machine.hostname}:{_HTTP_PORT}/",
                ],
                capture_output=True,
            )

        busy_wait_assert(assert_icecast_is_up)
        ezstream_cfg = machine.tmp_dir / "ezstream.xml"
        ezstream_cfg.write_text(_ezstream_xml(machine.hostname))
        ezstream_cfg.chmod(0o644)
        ezstream_stdin: Union[BinaryIO, Path] = song_path
        if loop_song:
            stdout = machine.popen(
                pkgset("empty"),
                [
                    "bash",
                    "-c",
                    f"while true; do cat {shlex.quote(str(remote_song_path))}; done",
                ],
                stderr=DEV_NULL,
                stdout=PIPE,
                stdin=DEV_NULL,
            ).stdout
            assert stdout is not None
            ezstream_stdin = stdout
        ezstream = machine.popen(
            pkgset("apps/icecast"),
            [
                "ezstream",
                "-c",
                ezstream_cfg,
            ],
            stdin=ezstream_stdin,
            stdout=logfiles_path(machine) / "ezstream.stdout",
            stderr=logfiles_path(machine) / "ezstream.stderr",
        )
        self.song_path = song_path
        self.music_url = f"https://{machine.hostname}:{_HTTPS_PORT}/{_MUSIC_PATH}"
        self._machine = machine
        busy_wait_assert(self._assert_ezstream_is_up)
        self._procs = [ezstream, icecast]

    def _assert_ezstream_is_up(self) -> None:
        # This will raise an exception if curl fails.
        self._machine.run(
            pkgset("apps/icecast"),
            [
                "curl",
                "--verbose",
                "--fail",
                "--head",
                "-X",
                "GET",
                self.music_url,
            ],
            env=EnvBuilder(self._machine).build(),
            capture_output=True,
        )

    def close(self) -> None:
        """Manually close the icecast server."""
        for x in self._procs:
            x.close()
