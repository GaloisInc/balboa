{ pkgs ? (import ../../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    # Installs both `ffmpeg` and `ffplay`
    ffmpeg-full
  ];
}
