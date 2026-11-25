# Build environment of the Jenkins pipeline (Jenkinsfile). The image is built
# with docker/Dockerfile; keep the toolchain of both in step.
FROM ubuntu:22.04
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
       gdb \
       git \
       clang-19 \
       clang-tools-19 \
       lld-19 \
       dumb-init \
       rsync \
       gettext-base \
       libtool \
       autoconf \
       automake \
       cargo \
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
       unzip \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100 \
    && apt-get clean


WORKDIR /build/sftd
ENV HOME=/build/sftd

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN /build/sftd/.cargo/bin/rustup install 1.71.1
RUN /build/sftd/.cargo/bin/rustup default 1.71.1-x86_64-unknown-linux-gnu

# Needed to workaround JENKINS-38438
RUN chown -R 1015:1015 /build/sftd/.cargo

ENV PATH="/build/sftd/.cargo/bin:${PATH}"

#RUN make -C /build/sftd RELEASE=1 EXTRA_CFLAGS="" 

