{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    (stdenv.mkDerivation rec {
      name = "tcptrace";
      version = "6.6.7";
      buildInputs = [ libpcap ];
      patchPhase = ''
        sed -i 's/= pcap_offline_read/= pcap_dispatch/' tcpdump.c
      '';
      preBuild = ''
        sed -i -E 's/^PCAP_.+//g' Makefile
        #sed -i 's/DEFINES += -DGROK_TCPDUMP//' Makefile
        makeFlagsArray+=(LDFLAGS="-lpcap")
      '';
      src = fetchurl {
        url = https://distfiles.macports.org/tcptrace/tcptrace-6.6.7.tar.gz;
        sha256 = "1g8hd6sqwf1f41am5m30kyy0i4wmdzy9ssj7g64s0g4ka500lf33";
      };
      installPhase = ''
        mkdir -p "$prefix/bin"
        install -m 755 tcptrace "$prefix/bin/tcptrace"
      '';
    })
    (rockyPython.withPackages (py: with py; [
      scikitlearn
      numpy
      pandas
    ]))
    # One of the python libraries shells out to pgrep
    procps
  ];
}
