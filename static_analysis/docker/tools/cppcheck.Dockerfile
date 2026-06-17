FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends cppcheck ca-certificates && \
    rm -rf /var/lib/apt/lists/*

CMD ["cppcheck", "--version"]
