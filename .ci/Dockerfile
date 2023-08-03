# If you change this Dockerfile, you should push it to artifactory.galois.com, and update the image in the .gitlab-ci.yml file

# We expect the following volumes to be mounted:
# "/nix/store:/nix/store:ro"
# "/nix/var/nix/db:/nix/var/nix/db:ro"
# "/nix/var/nix/daemon-socket:/nix/var/nix/daemon-socket:ro"

# This was inspired by https://nixos.wiki/wiki/Gitlab_runner

FROM debian/snapshot:stable-20211011

# --no-install-recommends is important to prevent nix-setup-systemd from being installed
RUN apt-get update -y && apt-get install --no-install-recommends -y ca-certificates netbase sudo git nix-bin && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home rocky && usermod -aG sudo rocky && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN mkdir -p -m 0755 /nix/var/log/nix/drvs && \
    mkdir -p -m 0755 /nix/var/nix/gcroots && \
    mkdir -p -m 0755 /nix/var/nix/profiles && \
    mkdir -p -m 0755 /nix/var/nix/temproots && \
    mkdir -p -m 0755 /nix/var/nix/userpool && \
    mkdir -p -m 1777 /nix/var/nix/gcroots/per-user && \
    mkdir -p -m 1777 /nix/var/nix/profiles/per-user && \
    mkdir -p -m 0755 /nix/var/nix/profiles/per-user/root

USER rocky
ENV USER=rocky
ENV NIX_REMOTE=daemon
ENV NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /home/rocky
