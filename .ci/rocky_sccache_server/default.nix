{ pkgs ? (import ../../etc/nix/pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    sccache
    (buildGoModule {
      pname = "rocky_scache_server";
      version = "0.0.1";
      src = ./.;
      vendorSha256 = "sha256-paCJiOD5J5I3N2TLdXlYR/WD69UyGaYALWIdsIxQkCs";
    })
  ];
}
