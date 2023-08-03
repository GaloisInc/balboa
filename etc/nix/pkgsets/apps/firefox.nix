{ pkgs ? (import ../../pkgs.nix { }) }:
with pkgs;
let
  rockyFirefox =
    if stdenv.isDarwin then
      let firefoxApp = stdenv.mkDerivation {
        name = "firefox";
        version = "91";
        src = fetchurl {
          name = "Firefox.dmg";
          url = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/91.0/mac/en-US/Firefox%2091.0.dmg";
          sha256 = "1yx647d1aibw3ydjpl8ysgz2smim48x6bykq2lq3y2rjj3s46v6j";
        };
        phases = [ "unpackPhase" "installPhase" ];
        nativeBuildInputs = [ undmg ];
        sourceRoot = ".";
        installPhase = ''
          mkdir -p $out/share
          cp -r Firefox.app $out/share/Firefox.app
        '';
      }; in
      writeShellScriptBin "firefox" ''
        exec ${firefoxApp}/share/Firefox.app/Contents/MacOS/firefox "$@"
      ''
    else firefox;
in
mkShell {
  buildInputs = [
    (writeShellScriptBin "rockyFirefoxDylibInjection" ''
      export LD_PRELOAD="" # blow away selenium's dylib injection
      if ! [[ -z "$ROCKY_FIREFOX_DYLIB" ]]; then
        export DYLD_INSERT_LIBRARIES="$ROCKY_FIREFOX_DYLIB"
        export LD_PRELOAD="$ROCKY_FIREFOX_DYLIB"
      fi
      export MOZ_LOG=all:5
      source ${rockyFirefox}/bin/firefox
    '')
    (rockyPython.withPackages (py: [ py.selenium ]))
    geckodriver
    nssTools
  ];
  inputsFrom = [ (import ../cacert.nix { inherit pkgs; }) ];
}
