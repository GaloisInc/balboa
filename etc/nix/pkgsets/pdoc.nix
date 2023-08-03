{ pkgs ? (import ../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    (rockyPython.withPackages (py:
      let
        pdoc = py.buildPythonPackage rec {
          # We use pdoc instead of pdoc3 (a fork of pdoc), since pdoc3 is AGPL, and other reasons:
          # https://web.archive.org/web/20201111220605/https://github.com/pdoc3/pdoc/issues/64
          pname = "pdoc";
          version = "12.1.0";

          src = fetchFromGitHub {
            owner = "mitmproxy";
            repo = "pdoc";
            rev = "v12.1.0";
            sha256 = "sha256-H8DQhZiZBkvIHROmFeiSY+8q7WP0tzoQ1ZdW5+NH9xE=";
          };

          doCheck = false;
          propagatedBuildInputs = [ py.jinja2 py.pygments py.markupsafe ];
        };
      in
      [ pdoc ] ++ (import ../python_pkgs.nix {
        inherit pkgs py;
      })))
  ];
  inputsFrom = [ (import ./cacert.nix { }) ];
}
