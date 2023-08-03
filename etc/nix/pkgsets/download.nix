{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    curl
  ];
  inputsFrom = [ (import ./cacert.nix { }) ];
}
