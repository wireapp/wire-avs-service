#!/bin/bash
#
# Build ./sftd-asan: sftd's own sources (src/, modules/sft, modules/reflow)
# compiled with AddressSanitizer + UndefinedBehaviorSanitizer and linked
# against the normal contrib libraries (libre, libavscore, usrsctp, ...).
#
# The contrib libraries are not instrumented, but ASan replaces malloc and
# free for the whole process, so any use-after-free / overflow touched by
# sftd code (sft.c, worker.c, ...) is still caught, with the allocation and
# free stacks, even when the memory came from libre's mem_alloc.
#
# Uses the normal build's flags (from the Makefile) and does not touch the
# normal build: objects go to build-arm64-asan/ (or $ASAN_BUILD).
#
# Usage: test/stress/make-asan.sh [-j N]
set -euo pipefail

cd "$(dirname "$0")/../.."
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
if [ "${1:-}" = "-j" ]; then JOBS=$2; fi

PRINT_MK=$(mktemp)
trap 'rm -f "$PRINT_MK"' EXIT
# $(info) prints the value verbatim (the shell would eat the quotes in
# e.g. -DSFT_VERSION='"5.0.local"'); the commands below eval it.
printf 'print-%%:\n\t$(info $($*))@:\n' > "$PRINT_MK"
var() { make -s -f Makefile -f "$PRINT_MK" "print-$1"; }

BUILD=$(var BUILD)
OUT=${ASAN_BUILD:-$BUILD-asan}
CC=$(var CC)
CPPFLAGS=$(var CPPFLAGS)
CFLAGS=$(var CFLAGS)
LFLAGS=$(var LFLAGS)
LIBS=$(var LIBS)
OBJS=$(var OBJS)
USRSCTP=$(var CONTRIB_USRSCTP_TARGET)
AVS=$(var CONTRIB_AVS_TARGET)

# -Os from re.mk would make reports harder to read; -O1 is ASan's usual.
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer \
-fno-optimize-sibling-calls -fno-sanitize-recover=undefined"
CFLAGS="$(echo "$CFLAGS" | sed -E 's/(^| )-O[0-3sz]( |$)/ /g') -O1 $SAN"

[ -f src/static.c ] || { echo "src/static.c missing: run make once" >&2; exit 2; }

echo "building $(echo $OBJS | wc -w | tr -d ' ') objects into $OUT"
pids=()
for o in $OBJS; do
	rel=${o#$BUILD/}
	src=${rel%.o}.c
	dst=$OUT/$rel
	mkdir -p "$(dirname "$dst")"
	# shellcheck disable=SC2086
	eval "$CC $CPPFLAGS $CFLAGS -c $src -o $dst" &
	pids+=($!)
	if [ ${#pids[@]} -ge "$JOBS" ]; then
		wait "${pids[0]}"; pids=("${pids[@]:1}")
	fi
done
for p in "${pids[@]}"; do wait "$p"; done
# (a failed compile also fails the wait above: set -e)

AOBJS=$(for o in $OBJS; do printf "%s " "$OUT/${o#$BUILD/}"; done)
# shellcheck disable=SC2086
eval "$CC $USRSCTP $AVS $AOBJS $LFLAGS -L$BUILD/lib $LIBS $SAN -o sftd-asan"
echo "built ./sftd-asan"
