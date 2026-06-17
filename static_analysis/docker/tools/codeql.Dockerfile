# The CodeQL Linux bundle is published as linux64 (amd64), so the image must
# use an amd64 base even when built on Apple Silicon or other arm64 hosts.
ARG CODEQL_PLATFORM=linux/amd64
FROM --platform=${CODEQL_PLATFORM} debian:bookworm-slim

ARG CODEQL_VERSION=2.23.5
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      cmake \
      curl \
      gcc \
      g++ \
      git \
      make \
      maven \
      openjdk-17-jdk-headless \
      python3 \
      tar && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" -o /tmp/codeql-bundle.tar.gz && \
    tar -xzf /tmp/codeql-bundle.tar.gz -C /opt && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql && \
    rm -f /tmp/codeql-bundle.tar.gz

RUN codeql resolve queries \
      codeql/cpp-queries:Security/CWE \
      codeql/cpp-queries:experimental/Security/CWE \
      codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
      >/dev/null

CMD ["codeql", "version"]
