# sftd 5.1.0

The first sftd release built and published by this repository's own pipeline, with SemVer versions. It gathers everything since 5.0.60: fixes for federated calls, a reworked Helm chart with Gateway API support, and no more Bitnami images. The chart now comes from `oci://quay.io/wire/charts/stable/sftd` only. Check the list below if you override images or Helm values, or if you run the chart with `gateway.enabled`.

## Before upgrading

- Install the chart from `oci://quay.io/wire/charts/stable/sftd`, version `5.1.0`. The `charts-avs` Helm repository keeps the `0.x` versions and does not get 5.1.0.
- If you mirror or override images: `initImage` is gone, set `externalIpHelper.image` instead. The join-call proxy now runs `docker.io/nginxinc/nginx-unprivileged` as UID 101, so an override that still points to the Bitnami nginx image breaks it. Mirror `quay.io/wire/sftd_disco:1.1.1`, `docker.io/alpine/kubectl:1.35.1` and `docker.io/nginxinc/nginx-unprivileged:1.29.5-alpine3.23-perl`; the chart lists every image it uses in its `helm.sh/images` annotation.
- If your values set `multiSFT.discoveryRequired` or `multiSFT.turnDiscoveryURL`, remove them and configure `multiSFT.turnServerURI` or `multiSFT.turnServerURIs`. With `discoveryRequired: true` left in, the StatefulSet references a volume that no longer exists and is rejected.
- If you run with `gateway.enabled` (available since 5.0.80): HTTPS now attaches through a `ListenerSet`. Install Gateway API CRDs and a controller that support v1 `ListenerSet` (tested with Envoy Gateway 1.9.2). With an existing Gateway (`gateway.create: false`), its `allowedListeners` must admit the release namespace. With a `mergeGateways` GatewayClass, set `gateway.envoyProxy.create: false`.

## What's new

- **Versions and packaging**: the image `quay.io/wire/sftd` and the Helm chart now share one SemVer version, so the chart goes from its `0.x` versions to `5.1.0`. It is published to `oci://quay.io/wire/charts/stable/sftd`, no longer to `charts-avs`. The binary tarball stays attached to the GitHub release.
- **Federated calls**: an SFT that joins a federated group call already in progress now receives the video streams of the other SFTs. Federation also works with several TURN servers: `multiSFT.turnServerURIs` spreads the replicas over them.
- **Gateway API**: the chart can run behind Envoy Gateway instead of the nginx Ingress, with TLS 1.3 by default, an optional FIPS 202205 TLS profile, and the option to share the wire-ingress Gateway.
- **Media address**: `mediaIP` sets the address sftd advertises to clients. When it is a host or literal address, the external IP lookup, its node-read RBAC and its startup delay of up to 5 minutes all go away. When no external IP is found, the pod now starts and advertises its host addresses, with a warning, instead of crash-looping.
- **Images**: the external IP helper uses `alpine/kubectl` and the join-call proxy uses `nginx-unprivileged`, both maintained and running as non-root; `sftd_disco` is built in this repository.
- **Rollouts**: `terminationGracePeriodSeconds` now defaults to `0`, so a rollout no longer waits 10 seconds per pod; set it back to `10` to keep the old pause.
- Pods restart when their secrets change, and sftd logs less when a video SSRC is unknown.

---

## Details

### Breaking

- The chart is published to `oci://quay.io/wire/charts/stable/sftd` only, `charts-avs` stays on the `0.x` versions: [#68](https://github.com/wireapp/wire-avs-service/pull/68), [#75](https://github.com/wireapp/wire-avs-service/pull/75), WPB-29713
- `initImage` replaced by `externalIpHelper.image`, join-call image moved to `nginxinc/nginx-unprivileged`, new `sftd_disco` image: [#41](https://github.com/wireapp/wire-avs-service/pull/41), [#46](https://github.com/wireapp/wire-avs-service/pull/46), WPB-23247, WPB-23564
- TURN discovery removed from the chart (`multiSFT.turnDiscoveryURL`, `multiSFT.discoveryRequired`): [#35](https://github.com/wireapp/wire-avs-service/pull/35), WPB-21462
- Gateway mode attaches HTTPS through a `ListenerSet`, GatewayClass defaults to `envoy`: [#59](https://github.com/wireapp/wire-avs-service/pull/59), [#60](https://github.com/wireapp/wire-avs-service/pull/60), WPB-29098, WPB-26933

### Features

- Gateway API support with Envoy Gateway, `ingress.enabled` toggle: [#48](https://github.com/wireapp/wire-avs-service/pull/48), WPB-24491
- TLS 1.3, FIPS 202205 TLS profile, ListenerSet, sharing the wire-ingress Gateway: [#59](https://github.com/wireapp/wire-avs-service/pull/59), [#60](https://github.com/wireapp/wire-avs-service/pull/60), WPB-29098, WPB-26933
- Per-replica TURN servers for federation (`multiSFT.turnServerURIs`): [#35](https://github.com/wireapp/wire-avs-service/pull/35), WPB-21462
- `mediaIP`, external IP helper only when needed: [#56](https://github.com/wireapp/wire-avs-service/pull/56)
- `advertiseInternalIp`: [#34](https://github.com/wireapp/wire-avs-service/pull/34)
- `clusterDomain`: [#57](https://github.com/wireapp/wire-avs-service/pull/57), WPB-28402
- Chart images declared in the `helm.sh/images` annotation (HIP-15): [#50](https://github.com/wireapp/wire-avs-service/pull/50), WPB-27901
- Checksum annotations restart the pods when their secrets change: [`c8976e8`](https://github.com/wireapp/wire-avs-service/commit/c8976e8)

### Fixes

- Video streams sent to every SFT that joins a federated group call: [`534e539`](https://github.com/wireapp/wire-avs-service/commit/534e539), [`6ab125a`](https://github.com/wireapp/wire-avs-service/commit/6ab125a), [`439e229`](https://github.com/wireapp/wire-avs-service/commit/439e229)
- No crash loop when no external IP is found: [#54](https://github.com/wireapp/wire-avs-service/pull/54)
- `sftd_disco` and join-call security contexts: [#44](https://github.com/wireapp/wire-avs-service/pull/44), [#46](https://github.com/wireapp/wire-avs-service/pull/46), [#47](https://github.com/wireapp/wire-avs-service/pull/47)
- Less logging when a video SSRC is not found: [`5752897`](https://github.com/wireapp/wire-avs-service/commit/5752897), [`b8a5546`](https://github.com/wireapp/wire-avs-service/commit/b8a5546)

### Changes

- `terminationGracePeriodSeconds` default from `10` to `0`, for faster rollouts: [#49](https://github.com/wireapp/wire-avs-service/pull/49), WPB-27835
- usrsctp updated: [`74944c9`](https://github.com/wireapp/wire-avs-service/commit/74944c9)
- Release pipeline in GitHub Actions instead of Jenkins: SemVer versions, the image built from `docker/Dockerfile` on a pinned Ubuntu 22.04 base and declaring the non-root user 31337 that the chart already uses, release files in `publication/`: [#68](https://github.com/wireapp/wire-avs-service/pull/68), WPB-29713

### Configuration

| Key | Change | Required | Default |
|---|---|---|---|
| `initImage` | removed, use `externalIpHelper.image` | | |
| `externalIpHelper.image` | added | no | `docker.io/alpine/kubectl:1.35.1` |
| `joinCall.image` | changed | no | `docker.io/nginxinc/nginx-unprivileged:1.29.5-alpine3.23-perl` |
| `joinCall.securityContext.runAsUser` | added | no | `101` |
| `sftdDisco.image` | added | no | `quay.io/wire/sftd_disco:1.1.1` |
| `multiSFT.turnDiscoveryURL` | removed | | |
| `multiSFT.discoveryRequired` | removed | | |
| `multiSFT.turnServerURIs` | added | no | `[]` |
| `mediaIP` | added | no | unset (`__SFT_EXT_IP__`) |
| `advertiseInternalIp` | added | no | `false` |
| `clusterDomain` | added | no | `cluster.local` |
| `terminationGracePeriodSeconds` | changed | no | `0` (was `10`) |
| `ingress.enabled` | added | no | `true` |
| `gateway.*` | added | no | `gateway.enabled: false` |
| `FIPS_202205_tls_profile` | added | no | `false` |
