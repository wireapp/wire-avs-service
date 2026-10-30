#!/usr/bin/env bash
# Packages charts/sftd at VERSION (chart version == appVersion == image tag)
# into OUT_DIR, with the sftd image of the helm.sh/images annotation (HIP-15)
# set to quay.io/wire/sftd:VERSION. Prints file=<path of the .tgz>, and
# appends it to $GITHUB_OUTPUT when set. The working tree is not modified.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${OUT_DIR:?OUT_DIR is required}"

placeholder='quay.io/wire/sftd:do-not-use'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp -R charts/sftd "$work/sftd"
grep -qF "$placeholder" "$work/sftd/Chart.yaml" \
  || { echo "error: $placeholder not found in charts/sftd/Chart.yaml" >&2; exit 1; }
sed -i "s|${placeholder}|quay.io/wire/sftd:${VERSION}|" "$work/sftd/Chart.yaml"

mkdir -p "$OUT_DIR"
helm package "$work/sftd" --version "$VERSION" --app-version "$VERSION" --destination "$OUT_DIR" >/dev/null
file="$OUT_DIR/sftd-${VERSION}.tgz"
[[ -f $file ]] || { echo "error: $file was not written" >&2; exit 1; }

echo "file=$file"
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  echo "file=$file" >> "$GITHUB_OUTPUT"
fi
