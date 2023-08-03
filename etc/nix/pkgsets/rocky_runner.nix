{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  shellHook = ''
    export NIX_BUILD_SHELL="bash"
    if [[ `uname` == "Darwin" ]]; then
      # Do this until https://github.com/NixOS/nix/pull/4038 gets released on a stable build.
      export NIX_IGNORE_SYMLINK_STORE=1
    fi
  '';
  buildInputs = [
    nixStable
    (rockyPython.withPackages (py: import ../python_pkgs.nix { pkgs = pkgs; py = py; }))
  ];
  inputsFrom = [ (import ./cacert.nix { }) ];
}
