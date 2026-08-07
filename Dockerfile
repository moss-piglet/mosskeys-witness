# syntax=docker/dockerfile:1

# mosskeys-witness container image.
#
# FROM scratch — the image contains exactly one file: the static musl
# mosskeys-witness binary. Deliberate decisions, matching the posture in
# docs/threat-model.md:
#
#   - No CA bundle. The serving path only ever listens (inbound POST
#     /add-checkpoint + the monitoring GET prefix), and the `sync`
#     subcommand's outbound feed fetch verifies TLS against webpki roots
#     embedded in the binary — so there is no root store to ship or maintain.
#     TLS termination for the serving path, where wanted, belongs in front
#     (reverse proxy / ingress).
#   - No shell, no package manager, no libc beyond the static binary. There
#     is nothing to exec and nothing to update in place — rebuild+redeploy.
#   - Non-root. Numeric uid/gid because scratch has no /etc/passwd.
#
# The binary is NOT built in this Dockerfile: the release workflow builds the
# x86_64/aarch64 unknown-linux-musl targets in its matrix (the same signed
# artifacts attached to the GitHub Release) and stages them at
# dist/linux-{amd64,arm64}/mosskeys-witness before invoking buildx.
FROM scratch

ARG TARGETARCH
COPY dist/linux-${TARGETARCH}/mosskeys-witness /usr/local/bin/mosskeys-witness

# Links the GHCR package back to this repository automatically on first push.
LABEL org.opencontainers.image.source="https://github.com/moss-piglet/mosskeys-witness" \
      org.opencontainers.image.description="Post-quantum-native C2SP tlog-witness (Ed25519 0x04 + ML-DSA-44 0x06 cosignatures)" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

USER 65532:65532

# Documentary only — the actual socket comes from `listen` in the mounted
# witness.toml (config.example.toml uses 0.0.0.0:8080).
EXPOSE 8080

# Subcommands are appended: `docker run ... mosskeys-witness run --config /witness.toml`
ENTRYPOINT ["/usr/local/bin/mosskeys-witness"]
