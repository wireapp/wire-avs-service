FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
       ca-certificates \
       curl \
       pkg-config \
       make \
       gcc \
       git \
       clang \
       clang-tools \
       libtool \
       autoconf \
       automake \
       protobuf-c-compiler \
       zlib1g-dev \
       libc++-dev \
       libc++abi-dev \
       libssl-dev \
       libreadline-dev \
       libx11-dev \
       libxcomposite-dev \
       libxdamage-dev \
       libxrender-dev \
       libprotobuf-c-dev \
       rsync \
       gettext-base \
    && rm -rf /var/lib/apt/lists/*

ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
ARG RUST_VERSION=1.71.1
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH
RUN curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
       -o /tmp/rustup-init \
       "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum --check --strict \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rm /tmp/rustup-init

WORKDIR /src
COPY . .

ARG SFT_VERSION=0.0.0-local
RUN make SFT_VERSION="${SFT_VERSION}" \
    && test "$(make --no-print-directory SFT_VERSION="${SFT_VERSION}" version)" = "${SFT_VERSION}"

FROM scratch AS binary
COPY --from=build /src/sftd /sftd

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq dumb-init \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build --chmod=555 /src/sftd /usr/local/bin/sftd

ENTRYPOINT ["/usr/bin/dumb-init", "--", "sftd"]
