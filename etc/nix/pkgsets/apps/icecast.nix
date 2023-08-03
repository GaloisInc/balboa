{ pkgs ? (import ../../pkgs.nix { }) }:
with pkgs;
mkShell {
  buildInputs = [
    (enableDebugging (icecast.overrideAttrs (old: {
      patches = [
        # This patches icecast to avoid a segfault.
        # Icecast's stats subsystem, as part of its initialization, needs to set some counters to 0.
        # Previously, this was done in a background thread which could initialize the counters.
        # However, it's possible for code to attempt to increment the counters before they were
        # initialized. This patch initializes the counters as part of the initialization of the
        # stats subsystem, so this race condition can't occur.
        ./icecast.diff
      ];
    })))
    ezstream
    curl.bin
  ];
}
