FROM ubuntu:24.04

ARG IKOS_VERSION=v3.5

ENV DEBIAN_FRONTEND=noninteractive
ENV IKOS_INSTALL_PREFIX=/opt/ikos
ENV PATH=/usr/lib/llvm-14/bin:/opt/ikos/bin:${PATH}

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      clang-14 \
      cmake \
      curl \
      gcc \
      g++ \
      git \
      libboost-all-dev \
      libgmp-dev \
      libmpfr-dev \
      libppl-dev \
      libsqlite3-dev \
      libtbb-dev \
      llvm-14 \
      llvm-14-dev \
      python3 \
      python3-venv \
      sqlite3 && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${IKOS_VERSION}" --depth 1 https://github.com/NASA-SW-VnV/ikos.git /tmp/ikos-src

RUN mkdir -p /tmp/ikos-src/build && \
    cd /tmp/ikos-src/build && \
    cmake \
      -DCMAKE_INSTALL_PREFIX="${IKOS_INSTALL_PREFIX}" \
      -DLLVM_CONFIG_EXECUTABLE=/usr/lib/llvm-14/bin/llvm-config \
      .. && \
    make -j"$(nproc)" && \
    make install

WORKDIR /

CMD ["ikos", "--version"]
