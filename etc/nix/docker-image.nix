{ pkgs ? import ./pkgs.nix { }, pkgsets, rocky_uid, name }:
let
  combinedPkgsets = pkgs.mkShell { inputsFrom = pkgsets; };
  # This function is from
  # https://github.com/NixOS/nixpkgs/blob/fc63be7ac8c33e4ef0e45b868e89a9181a1525e5/pkgs/build-support/docker/examples.nix
  nonRootShadowSetup = { user, uid, gid ? uid }: with pkgs; [
    (
      writeTextDir "etc/shadow" ''
        root:!x:::::::
        ${user}:!:::::::
      ''
    )
    (
      writeTextDir "etc/passwd" ''
        root:x:0:0::/root:${runtimeShell}
        ${user}:x:${toString uid}:${toString gid}::/home/${user}:
      ''
    )
    (
      writeTextDir "etc/group" ''
        root:x:0:
        ${user}:x:${toString gid}:
      ''
    )
    (
      writeTextDir "etc/gshadow" ''
        root:x::
        ${user}:x::
      ''
    )
    (
      writeTextDir "home/${user}/.create-homedir" ""
    )
  ];
  image = pkgs.dockerTools.streamLayeredImage {
    name = name;
    contents = combinedPkgsets.buildInputs ++ pkgs.stdenv.initialPath ++ [
      (pkgs.writeShellScriptBin "rocky-docker-server" ''
        ${combinedPkgsets.shellHook}
        export USER=rocky
        exec dumb-init ${pkgs.rockyPython.interpreter} -u ${../machine/docker/server.py} "$@"
      '')
      pkgs.iana-etc
      pkgs.dumb-init
      pkgs.iproute
      # We don't actually use gcc in most of our docker images, and not including it saves quite
      # a bit of space. Technically, this makes "DockerMachine" diverge from "LocalMachine", since
      # mkShell includes GCC.
      #pkgs.stdenv.cc
    ] ++ (nonRootShadowSetup { uid = rocky_uid; user = "rocky"; });
    config = {
      Cmd = [ "dumb-init" "sleep" "inf" ];
    };
    maxLayers = 2; # This seems to speed things up.
  };
in
pkgs.writeText "image-info"
  ''
    ${image.imageName}:${image.imageTag}
    ${image}
  ''
