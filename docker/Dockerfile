FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build

# LLVM 19 from apt.llvm.org, as wire-avs uses for WebRTC 20260605.102. The
# signing key is checked by fingerprint; the 19.x packages are not pinned.
ARG LLVM_KEY_FINGERPRINT=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y ca-certificates curl gnupg \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
       -o /tmp/llvm.asc https://apt.llvm.org/llvm-snapshot.gpg.key \
    && test "$(gpg --show-keys --with-colons /tmp/llvm.asc | grep -c '^pub:')" = 1 \
    && test "$(gpg --show-keys --with-colons /tmp/llvm.asc | awk -F: '$1 == "fpr" { print $10; exit }')" = "${LLVM_KEY_FINGERPRINT}" \
    && gpg --dearmor -o /usr/share/keyrings/llvm.gpg /tmp/llvm.asc \
    && rm /tmp/llvm.asc \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main" \
       > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y \
       pkg-config \
       make \
       gcc \
       git \
       clang-19 \
       clang-tools-19 \
       lld-19 \
       libtool \
       autoconf \
       automake \
       protobuf-c-compiler \
       zlib1g-dev \
       libreadline-dev \
       libglib2.0-dev \
       libx11-dev \
       libxcomposite-dev \
       libxdamage-dev \
       libxext-dev \
       libxfixes-dev \
       libxrender-dev \
       libprotobuf-c-dev \
       python3 \
       rsync \
       gettext-base \
       unzip \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100 \
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
RUN docker/get-webrtc.sh \
    && make SFT_VERSION="${SFT_VERSION}" \
    && make SFT_VERSION="${SFT_VERSION}" test \
    && test "$(make --no-print-directory SFT_VERSION="${SFT_VERSION}" version)" = "${SFT_VERSION}"

FROM scratch AS binary
COPY --from=build /src/sftd /sftd

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq dumb-init \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 31337 sftd \
    && useradd --system --uid 31337 --gid sftd --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sftd

COPY --from=build --chmod=555 /src/sftd /usr/local/bin/sftd

USER 31337:31337

ENTRYPOINT ["/usr/bin/dumb-init", "--", "sftd"]
