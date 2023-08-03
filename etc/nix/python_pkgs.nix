{ py, pkgs }: with py;
[
  click
  colorama
  coloredlogs
  pytest
  ipython
  networkx
  jinja2
  (py.buildPythonPackage rec {
    pname = "pytest-reraise";
    version = "1.0.3";

    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-86EwiKoi5UncQ/+Fhkp2Me0lJiRaNPJ4938H98u2IsY=";
    };

    doCheck = false;
    propagatedBuildInputs = [ ];
  })

  (py.buildPythonPackage rec {
    pname = "rust-demangler";
    version = "1.0";
    src = pkgs.fetchurl {
      url = "mirror://pypi/r/rust-demangler/rust_demangler-1.0.tar.gz";
      sha256 = "03xxr074izicpncwa5s2m1jsqi5ymzczfdy1rqa2scliwqr81s53";
    };

    doCheck = false;
    propagatedBuildInputs = [ ];
  })
]
