#!/usr/bin/env bash
# Starts sftd with the DTLS options: -D reaches the reflow module, and an
# invalid -g stops sftd with EINVAL.
# Usage: test/startup.sh <path to sftd>
set -uo pipefail

SFTD=${1:?usage: $0 <sftd>}
LOG=$(mktemp)
LOG_DIR=$(mktemp -d)
trap 'rm -f "$LOG"; rm -rf "$LOG_DIR"' EXIT
failed=0

EINVAL=22
ENOENT=2

# Seconds that sftd may take to start (a loaded CI runner can be slow)
START_TIMEOUT=${START_TIMEOUT:-30}

# expect <name> <ok|exit status> <check> [sftd options]
#   ok: sftd starts and <check> succeeds, with $port set
#   <exit status>: sftd exits with this status
expect() {
	local name=$1 result=$2 check=$3 status=running i
	shift 3
	port=$((40000 + RANDOM % 9000))

	"$SFTD" -I 127.0.0.1 -p "$port" -A 127.0.0.1 -M 127.0.0.1 \
		-r $((port + 1)) -w 1 "$@" > "$LOG" 2>&1 &
	local pid=$!

	for i in $(seq $((START_TIMEOUT * 10))); do
		if ! kill -0 "$pid" 2> /dev/null; then
			wait "$pid"
			status=$?
			break
		fi
		grep -q "welcome to AVS-service" "$LOG" && break
		sleep 0.1
	done

	local ok=false
	if [[ $status == running ]]; then
		[[ $result == ok ]] && eval "$check" && ok=true
		# SIGINT would not do: background jobs ignore it
		kill -TERM "$pid"
		wait "$pid"
	else
		[[ $status == "$result" ]] && ok=true
	fi

	if $ok; then
		echo "[  OK  ] $name"
	else
		echo "[ FAIL ] $name (exit status: $status)"
		sed 's/^/    /' "$LOG"
		failed=$((failed + 1))
	fi
}

expect "-D: DTLS 1.3 only" ok \
	'grep -q "reflow: DTLS versions 1.3$" "$LOG"' -D
expect "-G: GCM SRTP only" ok \
	'grep -q "reflow: SRTP profiles GCM only$" "$LOG"' -G
expect "/metrics has the rejection counters" ok \
	'curl -s --max-time 5 "http://127.0.0.1:$((port + 1))/metrics" |
	 grep -q "sft_dtls_rejected_total{reason=\"version\"} 0"'
expect "-g X25519,bogus: exit status $EINVAL" $EINVAL true -g X25519,bogus
expect "-l: file stays open through shutdown" ok true -l "$LOG_DIR/sftd"
if grep -q "avsd quit -- cleaning up" "$LOG_DIR"/sftd_*.log 2>/dev/null; then
	echo "[  OK  ] -l: final shutdown message reaches the log"
else
	echo "[ FAIL ] -l: final shutdown message is missing"
	failed=$((failed + 1))
fi
expect "-l: nonexistent parent exits with $ENOENT" $ENOENT true \
	-l "$LOG_DIR/missing/sftd"

echo "$failed sftd startup tests failed"
[[ $failed == 0 ]]
