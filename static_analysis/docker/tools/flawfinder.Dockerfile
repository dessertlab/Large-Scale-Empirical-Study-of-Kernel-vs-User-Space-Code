FROM python:3.13-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN apt-get update && \
    apt-get install -y --no-install-recommends locales && \
    rm -rf /var/lib/apt/lists/* && \
    localedef -i en_US -f ISO-8859-1 en_US.ISO-8859-1 && \
    python -m pip install --upgrade pip && \
    python -m pip install flawfinder

# Some C/C++ sources (e.g. parts of the FreeBSD kernel) contain non-UTF-8 bytes.
# flawfinder reads files with the locale's encoding and, on a UTF-8 decode error,
# prints a warning to stdout (corrupting the SARIF) and exits non-zero. A Latin-1
# locale maps every byte, so flawfinder can read any input without encoding
# errors, exit 0, and emit a clean SARIF.
ENV PYTHONUTF8=0 \
    LANG=en_US.ISO-8859-1 \
    LC_ALL=en_US.ISO-8859-1

CMD ["flawfinder", "--version"]
