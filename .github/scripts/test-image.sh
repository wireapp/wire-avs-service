#!/usr/bin/env bash
# Checks a locally built sftd image (IMAGE): every library of sftd resolves,
# the tools the chart calls are present, sftd runs as the non-root user
# 31337 of the chart, and sftd -v prints VERSION.
set -euo pipefail

: "${IMAGE:?IMAGE is required}"
: "${VERSION:?VERSION is required}"

docker run --rm --entrypoint /bin/sh "$IMAGE" -c '! ldd /usr/local/bin/sftd | grep "not found"'
docker run --rm --entrypoint /bin/sh "$IMAGE" -c 'for tool in curl jq dumb-init; do command -v "$tool" || exit 1; done'
[[ $(docker run --rm --entrypoint id "$IMAGE" -u) == 31337 ]] || { echo "error: the image does not run as uid 31337" >&2; exit 1; }
out=$(docker run --rm "$IMAGE" -v 2>&1 || true)
[[ $out == *"version: ${VERSION}"* ]] || { echo "error: sftd -v printed '$out', expected version ${VERSION}" >&2; exit 1; }
