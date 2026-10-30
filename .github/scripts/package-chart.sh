#!/usr/bin/env bash
# Packages charts/sftd at VERSION (chart version == appVersion == image tag)
# into OUT_DIR, with the sftd image of the helm.sh/images annotation (HIP-15)
# set to quay.io/wire/sftd:VERSION. Keeps that prepared chart directory in
# OUT_DIR/src for publish-chart's chart-path, the only mode that lets a dev
# chart expire. Prints file=<path of the .tgz> and dir=<prepared directory>,
# and appends them to $GITHUB_OUTPUT when set. The working tree is not
# modified.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${OUT_DIR:?OUT_DIR is required}"

placeholder='quay.io/wire/sftd:do-not-use'
dir="$OUT_DIR/src/sftd"

rm -rf "$dir"
mkdir -p "$OUT_DIR/src"
cp -R charts/sftd "$dir"
grep -qF "$placeholder" "$dir/Chart.yaml" \
  || { echo "error: $placeholder not found in charts/sftd/Chart.yaml" >&2; exit 1; }
sed -i "s|${placeholder}|quay.io/wire/sftd:${VERSION}|" "$dir/Chart.yaml"

helm package "$dir" --version "$VERSION" --app-version "$VERSION" --destination "$OUT_DIR" >/dev/null
file="$OUT_DIR/sftd-${VERSION}.tgz"
[[ -f $file ]] || { echo "error: $file was not written" >&2; exit 1; }

printf 'file=%s\ndir=%s\n' "$file" "$dir"
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  printf 'file=%s\ndir=%s\n' "$file" "$dir" >> "$GITHUB_OUTPUT"
fi
