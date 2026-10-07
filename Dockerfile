# syntax=docker/dockerfile:1
#
# kachat-domains: the .kachat registry's contracts, deployed manifests and the
# `kachat-names` CLI in one image. Kaspa Quick Start builds it from this repo and
# runs it as one-shot commands (docs/KQS.md):
#
#   docker run --rm -v <dir>:/names kachat-domains publish   # verify, then hand the manifest over
#   docker run --rm kachat-domains verify                    # check the manifest against the sources
#   docker run --rm kachat-domains prices                    # any other `kachat-names` command
#
# Nothing is compiled at run time from outside the image: the contracts are
# recompiled in-process by `verify` (the pinned silverscript library is linked
# into the CLI), so the published manifest is checked against contracts/ and
# params/ every time.

ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-bookworm AS build
# rocksdb (bindgen -> libclang, cmake), gRPC (tonic/prost -> protoc)
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev cmake protobuf-compiler pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY harness/Cargo.toml harness/Cargo.lock harness/
COPY harness/src harness/src
COPY tools/kachat-names-cli/Cargo.toml tools/kachat-names-cli/Cargo.lock tools/kachat-names-cli/
COPY tools/kachat-names-cli/src tools/kachat-names-cli/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/tools/kachat-names-cli/target \
    cd tools/kachat-names-cli \
    && cargo build --release --locked --bin kachat-names \
    && install -D target/release/kachat-names /out/kachat-names

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/kachat-names /usr/local/bin/kachat-names
# The repository data the CLI reads (its root is found from KACHAT_DOMAINS_ROOT).
# .gitignore is there because `keygen` refuses to write a key into a tree that
# doesn't ignore .secrets/.
WORKDIR /opt/kachat-domains
COPY .gitignore README.md ./
COPY contracts contracts
COPY params params
COPY artifacts artifacts
COPY manifests manifests
COPY docker/entrypoint.sh /usr/local/bin/kachat-domains
ARG KACHAT_DOMAINS_COMMIT=unknown
ENV KACHAT_DOMAINS_ROOT=/opt/kachat-domains \
    KACHAT_DOMAINS_COMMIT=${KACHAT_DOMAINS_COMMIT}
LABEL org.opencontainers.image.source="https://github.com/KaspaSilver/kachat-domains" \
      org.opencontainers.image.revision="${KACHAT_DOMAINS_COMMIT}" \
      org.opencontainers.image.title="kachat-domains"
ENTRYPOINT ["/usr/local/bin/kachat-domains"]
CMD ["verify"]
