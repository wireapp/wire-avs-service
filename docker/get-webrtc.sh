#!/usr/bin/env bash
# Downloads the prebuilt WebRTC that sftd links through wire-avs: the headers
# and the linux-x86_64 library, checked against pinned SHA-256 sums. With
# these in place the wire-avs build does not run scripts/get_webrtc.py, which
# downloads the zips of every platform without checking them.
#
# Run from the top of the repository. Update the version and the sums when
# contrib/avs moves to another WebRTC release; the digests are listed by
# https://api.github.com/repos/wireapp/prebuilt-webrtc-binaries/releases
set -euo pipefail

WEBRTC_VER=20260605.102
HEADERS_SHA256=af3707b55b2ed69f06d2714bd245e6badfed7edc584902837e15afc3540f7d0f
LINUX_SHA256=4479ceaf833c46dc64f392788e54045ed4da390a1be77e9b0df3193db5c02b09

BASE_URL="https://github.com/wireapp/prebuilt-webrtc-binaries/releases/download/${WEBRTC_VER}"
DEST=contrib/avs/contrib/webrtc

avs_ver=$(sed -n 's/^WEBRTC_VER := //p' contrib/avs/mk/target.mk)
if [[ $avs_ver != "$WEBRTC_VER" ]]; then
	echo "error: contrib/avs uses WebRTC ${avs_ver}, $0 pins ${WEBRTC_VER}" >&2
	exit 1
fi

fetch() {
	local name=$1 sha256=$2

	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
		-o "${DEST}/${name}.part" "${BASE_URL}/${name}"
	echo "${sha256}  ${DEST}/${name}.part" | sha256sum --check --strict
	mv "${DEST}/${name}.part" "${DEST}/${name}"
}

mkdir -p "$DEST"
fetch "webrtc_${WEBRTC_VER}_headers.zip" "$HEADERS_SHA256"
fetch "webrtc_${WEBRTC_VER}_linux.zip" "$LINUX_SHA256"
