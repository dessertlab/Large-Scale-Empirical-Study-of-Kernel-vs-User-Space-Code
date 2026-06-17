#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: bash init_sats.sh [--no-cache]

Build the five analyzer container images used by this project.
EOF
}

NO_CACHE=0
while (($#)); do
  case "$1" in
    --no-cache)
      NO_CACHE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for tool in cppcheck semgrep codeql flawfinder ikos; do
  dockerfile="${ROOT_DIR}/static_analysis/docker/tools/${tool}.Dockerfile"
  image="static-analysis-${tool}:latest"
  platform_arg=""
  if [ "${tool}" = "codeql" ]; then
    platform_arg="--platform=linux/amd64"
  fi
  echo "Building ${image}"
  if ((NO_CACHE)); then
    docker build ${platform_arg:+"${platform_arg}"} --no-cache -f "${dockerfile}" -t "${image}" "${ROOT_DIR}"
  else
    docker build ${platform_arg:+"${platform_arg}"} -f "${dockerfile}" -t "${image}" "${ROOT_DIR}"
  fi
done

echo "Analyzer images are ready."
