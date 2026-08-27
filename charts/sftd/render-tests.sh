#!/usr/bin/env bash
#
# Render assertions for the sftd chart.
#
# kubeconform checks that the rendered manifests match the Kubernetes schemas,
# but the sftd command line lives inside a container `command:` string, so
# nothing validates it. These cases render the chart with specific values and
# assert on the resulting argv.
#
# Usage: charts/sftd/render-tests.sh [chart-dir]

set -euo pipefail

CHART="${1:-charts/sftd}"
VALUES="${CHART}/values.test.yaml"

failures=0

# render <helm --set args...> -> rendered statefulset command block on stdout
TEMPLATE="templates/statefulset.yaml"

render() {
	helm template sftd "${CHART}" \
		--values "${VALUES}" \
		--show-only "${TEMPLATE}" \
		"$@"
}

# expect <description> <present|absent> <pattern> <helm --set args...>
expect() {
	local desc="$1" mode="$2" pattern="$3"
	shift 3

	local out found
	if ! out="$(render "$@" 2>&1)"; then
		printf 'FAIL %s\n     render failed:\n%s\n' "${desc}" "${out}"
		failures=$((failures + 1))
		return
	fi

	if grep -qF -- "${pattern}" <<<"${out}"; then
		found=present
	else
		found=absent
	fi

	if [ "${found}" = "${mode}" ]; then
		printf 'ok   %s\n' "${desc}"
	else
		printf 'FAIL %s\n     expected %s: %s\n' "${desc}" "${mode}" "${pattern}"
		failures=$((failures + 1))
	fi
}

# expect_error <description> <message substring> <helm --set args...>
expect_error() {
	local desc="$1" pattern="$2"
	shift 2

	local out
	if out="$(render "$@" 2>&1)"; then
		printf 'FAIL %s\n     expected the render to fail, but it succeeded\n' "${desc}"
		failures=$((failures + 1))
		return
	fi

	if grep -qF -- "${pattern}" <<<"${out}"; then
		printf 'ok   %s\n' "${desc}"
	else
		printf 'FAIL %s\n     expected error matching: %s\n     got:\n%s\n' \
			"${desc}" "${pattern}" "${out}"
		failures=$((failures + 1))
	fi
}

# -T is gated on turnDiscoveryEnabled
expect 'turnDiscoveryEnabled=false omits -T' absent '  -T \' \
	--set turnDiscoveryEnabled=false
expect 'turnDiscoveryEnabled=true passes -T' present '  -T \' \
	--set turnDiscoveryEnabled=true

# multiSFT selects a TURN URI by pod ordinal when given a list
expect 'multiSFT.turnServerURIs uses ordinal selection' present 'URI_INDEX=$((ORDINAL % URI_COUNT))' \
	--set multiSFT.enabled=true
expect 'multiSFT.turnServerURI uses the single URI directly' present '-t turn.wire.example' \
	--set multiSFT.enabled=true \
	--set multiSFT.turnServerURIs=null \
	--set multiSFT.turnServerURI=turn.wire.example

# auth args are mutually exclusive with multiSFT
expect 'sftTokenSecret without multiSFT enables auth' present 'AUTH_SFT_ARGS="-s /secrets/sftTokenSecret.txt -a"' \
	--set multiSFT.enabled=false \
	--set sftTokenSecret=some-secret
expect_error 'sftTokenSecret with multiSFT is rejected' 'please set the secret at multiSFT.secret' \
	--set multiSFT.enabled=true \
	--set sftTokenSecret=some-secret

# additionalCmdArgs is passed through verbatim
expect 'additionalCmdArgs is passed through' present '-x 42' \
	--set additionalCmdArgs='-x 42'

# advertiseInternalIp adds -B, but only in the branch that also sets -A, since
# sftd only advertises the alt candidate when the primary media address is set
expect 'advertiseInternalIp=false omits -B' absent '-B ${POD_IP}' \
	--set advertiseInternalIp=false
expect 'advertiseInternalIp=true adds -B alongside -A' present 'ACCESS_ARGS="${ACCESS_ARGS} -B ${POD_IP}"' \
	--set advertiseInternalIp=true
expect 'advertiseInternalIp=true warns when no media address is available' present 'no media address is available' \
	--set advertiseInternalIp=true
expect 'advertiseInternalIp=false does not warn' absent 'no media address is available' \
	--set advertiseInternalIp=false

# mediaIP selects the advertised media address and decides whether the
# get-external-ip helper runs at all
expect 'mediaIP unset keeps the external-ip helper' present '- name: get-external-ip'
expect 'mediaIP unset reads the helper output' present 'EXTERNAL_IP=$(cat /external-ip/ip)'
expect 'mediaIP=__SFT_HOST_IP__ drops the helper' absent '- name: get-external-ip' \
	--set mediaIP=__SFT_HOST_IP__
expect 'mediaIP=__SFT_HOST_IP__ does not read the helper output' absent 'cat /external-ip/ip' \
	--set mediaIP=__SFT_HOST_IP__
expect 'mediaIP=__SFT_HOST_IP__ empties EXTERNAL_IP at render time' present 'EXTERNAL_IP=""' \
	--set mediaIP=__SFT_HOST_IP__
expect 'mediaIP=__SFT_HOST_IP__ drops the initContainers key' absent 'initContainers:' \
	--set mediaIP=__SFT_HOST_IP__
expect 'mediaIP=__SFT_HOST_IP__ keeps initContainers for multiSFT discovery' present 'initContainers:' \
	--set mediaIP=__SFT_HOST_IP__ \
	--set multiSFT.discoveryRequired=true \
	--set multiSFT.turnDiscoveryURL=https://turn.wire.example/discovery
expect 'mediaIP literal is substituted verbatim' present 'MEDIA_IP="203.0.113.7"' \
	--set mediaIP=203.0.113.7
expect 'mediaIP unset resolves to the helper variable' present 'MEDIA_IP="${EXTERNAL_IP}"'
expect 'mediaIP=__SFT_HOST_IP__ resolves to HOST_IP' present 'MEDIA_IP="${HOST_IP}"' \
	--set mediaIP=__SFT_HOST_IP__
expect 'no sed runs on the discovered address' absent 's;__SFT_EXT_IP__;'

# advertiseInternalIp would duplicate the -A candidate when mediaIP is the pod address
expect_error 'advertiseInternalIp with mediaIP=__SFT_HOST_IP__ is rejected' 'advertiseInternalIp is redundant' \
	--set mediaIP=__SFT_HOST_IP__ --set advertiseInternalIp=true
expect_error 'advertiseInternalIp with mediaIP=__SFT_POD_IP__ is rejected' 'advertiseInternalIp is redundant' \
	--set mediaIP=__SFT_POD_IP__ --set advertiseInternalIp=true

# the node-read RBAC exists only for the helper, so it follows the same gate
TEMPLATE="templates/service-account.yaml"
expect 'mediaIP unset grants node-read RBAC' present 'kind: ClusterRoleBinding'
expect 'mediaIP=__SFT_HOST_IP__ drops node-read RBAC' absent 'kind: ClusterRoleBinding' \
	--set mediaIP=__SFT_HOST_IP__
expect 'mediaIP=__SFT_HOST_IP__ keeps the ServiceAccount' present 'kind: ServiceAccount' \
	--set mediaIP=__SFT_HOST_IP__
TEMPLATE="templates/statefulset.yaml"

# coredumps raise the core limit before exec
expect 'coredumps.enabled raises the core limit' present 'ulimit -c unlimited' \
	--set coredumps.enabled=true \
	--set coredumps.storageClassName=standard
expect_error 'coredumps.enabled without a storage class is rejected' 'coredumps.storageClassName is required' \
	--set coredumps.enabled=true
expect 'coredumps disabled does not raise the core limit' absent 'ulimit -c unlimited' \
	--set coredumps.enabled=false

if [ "${failures}" -ne 0 ]; then
	printf '\n%d assertion(s) failed\n' "${failures}"
	exit 1
fi

printf '\nall assertions passed\n'
