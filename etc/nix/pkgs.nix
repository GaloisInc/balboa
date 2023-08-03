{ sources ? import ./sources.nix, system ? builtins.currentSystem }:
let
  srcs = _: _: { inherit sources; };
  vlc = self: super: {
    vlc =
      if super.stdenv.isDarwin then
        super.stdenv.mkDerivation
          {
            pname = "vlc-mac";
            version = "3.0.10";
            src = sources.vlc-mac;
            # We want to disable set-source-date-epoch-to-latest.sh
            unpackPhase = "tar -xf $src";
            buildPhase = ":";
            installPhase = ''
              mkdir -p $out/share/
              cp -r VLC.app $out/share/VLC.app
              mkdir -p $out/bin
              cat > $out/bin/vlc << EOF
              #!${super.runtimeShell}
              exec $out/share/VLC.app/Contents/MacOS/VLC "\$@"
              EOF
              chmod +x $out/bin/vlc
            '';
            fixupPhase = ":";
          }
      else
        super.vlc;
  };
  # Here's where we pick our version of python.
  rockyPython = self: super: {
    rockyPython = super.python310;
  };
  overlays = [ (import sources.rust-overlay) srcs vlc rockyPython ];
  config = { allowUnfree = true; };
in
import sources.nixpkgs { inherit config overlays system; }
