{ pkgs ? import ./pkgs.nix { } }:
with pkgs;
mkShell {
  inputsFrom = [
    (import ./pkgsets/rust.nix { pkgs = pkgs; useMinimalProfile = false; })
    (import ./pkgsets/rocky_runner.nix { pkgs = pkgs; })
  ];
}
