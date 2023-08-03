{ pkgs ? (import ../../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    (stdenv.mkDerivation {
      name = "balboa-web-test";
      buildInputs = [ curl fmt ];
      nativeBuildInputs = [ pkg-config ];
      src = ../../../../testing/integration/test_web.cpp;
      unpackPhase = "true";
      buildPhase = ''
        $CXX -o test_web -g $(pkg-config --libs --cflags libcurl fmt) --std=c++17 $CFLAGS $LDFLAGS $src
      '';
      installPhase = ''
        mkdir -p $out/bin
        cp test_web $out/bin/test_web
      '';
      dontStrip = true;
    })
  ];
  inputsFrom = [ (import ../cacert.nix { inherit pkgs; }) ];
}
