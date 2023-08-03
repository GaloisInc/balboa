To setup a CI runner, follow the standard instructions for setting up a gitlab CI runner, and then:

NOTE: this is not a secure/locked-down setup. Do not allow untrusted users to submit CI jobs to this system.

1. Install Nix (WITH THE NIX DAEMON) (Pass the --daemon option to the nix install script). If you're running ZFS, then /nix should be its own ZFS dataset
2. Create the /var/lib/rocky-sccache directory, and give it 0777 permissions
3. Register the runner, make sure to give it the `docker-nix` tag, with the `docker` executor
4. Modify the `/etc/gitlab-runner/config.toml` file for the runner you just added. The `runners.docker.volumes` key should contain:
    ```
    [
        "/nix/store:/nix/store:ro",
        "/nix/var/nix/db:/nix/var/nix/db:ro",
        "/nix/var/nix/daemon-socket:/nix/var/nix/daemon-socket:ro",
        "/var/lib/rocky-sccache:/var/lib/rocky-sccache"
    ]
    ```.
5. Restart the gitlab-runner service

# If things break...
## How to purge the caches
1. Pause the CI runner in the gitlab CI settings interface for the repo
2. SSH to the CI runner (and use htop to make sure that all CI jobs have finished)
3. Run `nix-collect-garbage` and `rm -rf /var/lib/rocky-sccache/*`
4. Un-pause the CI runner

The docker image produced by the Dockerfile in this directory lives in Galois' artifactory instance.
The gitlab repo configuration contains a setting for the `DOCKER_AUTH_CONFIG` environment variable
containing credentials to access the Docker image. These credentials will be used by the gitlab
runner to download the image.

