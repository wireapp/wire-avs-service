FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y \
       curl \
       pkg-config \
       make \
       gcc \
       gdb \
       git \       
       clang \
       clang-tools \
       rsync \
       gettext-base \
       libtool \
       cargo \
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
       libprotobuf-c-dev

WORKDIR /build/sftd
ENV HOME /build/sftd

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Needed to workaround JENKINS-38438
RUN chown -R 1001:1001 /build/sftd/.cargo

ENV PATH="/build/sftd/.cargo/bin:${PATH}"

#RUN make -C /build/sftd RELEASE=1 EXTRA_CFLAGS="" 

