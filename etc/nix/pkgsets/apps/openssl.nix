{ pkgs ? (import ../../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    openssl
    netcat-gnu
  ];
}
