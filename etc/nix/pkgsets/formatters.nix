{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    nixpkgs-fmt
    (rockyPython.withPackages (py: [
      # We use a custom derivation for black so that it doesn't depend on uvloop, which requires
      # pyopenssl, which doesn't run on systems with W^X protection.
      (py.buildPythonPackage rec {
        pname = "black";
        version = "22.3.0";
        src = py.fetchPypi {
          inherit pname version;
          hash = "sha256-NQILiIbAIs7ZKCtRtah1ttGrDDh7MaBluE23wzCFynk=";
        };
        nativeBuildInputs = [ py.setuptools-scm ];
        doCheck = false;
        propagatedBuildInputs = [
          py.aiohttp
          py.aiohttp-cors
          py.click
          py.colorama
          py.mypy-extensions
          py.pathspec
          py.platformdirs
          py.tomli
        ];
      })

      py.isort
    ]))
  ];
  inputsFrom = [ (import ./cacert.nix { }) (import ./rust.nix { addRustFmt = true; }) ];
}
