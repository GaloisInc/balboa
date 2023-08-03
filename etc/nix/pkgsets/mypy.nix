{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    (rockyPython.withPackages (py:
      [ py.mypy ] ++ (import ../python_pkgs.nix { pkgs = pkgs; py = py; })
    ))
  ];
}
