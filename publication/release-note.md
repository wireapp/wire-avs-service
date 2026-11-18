# sftd 5.2.0

The first sftd GA built by this repository's pipeline, from `dev`. It brings all the work that has been done since 5.0.80: the reworked Helm chart, the audio and video fixes for for the lip sync issue. The chart is still published to the legacy `charts-avs` Helm repository, as well as to `oci://quay.io/wire/charts/stable/sftd`.

## Before upgrading

- Coming from a `5.0.x` build (5.0.80 or later, the oldest build that upgrades directly): work through the "Before upgrading" section of the [5.1.0 release note](https://github.com/wireapp/wire-avs-service/blob/release/5.1/publication/release-note.md). Every chart change it lists is in 5.2.0.
- Coming from a 5.1.0 or 5.2.0 pre-release: nothing to change. The chart and its values are the same.
- Install the chart, version `5.2.0`, from `charts-avs` or from `oci://quay.io/wire/charts/stable/sftd`. Pre-releases are in `oci://quay.io/wire/charts/dev/sftd` and in `charts-avs`.

## What's new

- **Audio in group calls**: a new speaker now takes a free stream before taking over an active one, and only takes over a speaker who is clearly quieter. Two speakers of similar level no longer alternate on the same stream, which garbled the audio. Streams whose sender has gone quiet for more than a second are freed, and new participants start at silence instead of looking like the loudest speaker.
- **Audio delay**: audio no longer becomes very delayed after a stream has been unused for a while. When a new source takes over a stream, its timestamps follow the time that has actually passed, so the receiver's jitter buffer does not grow.
- **Federated calls**: each remote participant is compared with their own audio level instead of a level shared by the whole remote SFT, and video forwarding no longer uses uninitialised SSRCs when the sending participant is not found.
- **Chart repositories**: releases prepared from `dev` publish the chart to `charts-avs` and to the OCI repository, and pin it in `wire-builds`. The 5.1.0 pre-releases went to the OCI repository only.

---

## Details

### Breaking, coming from 5.0.x (the 5.1.0 chart)

- Images: `initImage` becomes `externalIpHelper.image`, the join-call proxy runs `nginx-unprivileged` as UID 101, `sftd_disco` has its own image: [#41](https://github.com/wireapp/wire-avs-service/pull/41), [#46](https://github.com/wireapp/wire-avs-service/pull/46)
- TURN discovery removed: drop `multiSFT.discoveryRequired` and `multiSFT.turnDiscoveryURL`, set `multiSFT.turnServerURI` or `multiSFT.turnServerURIs`: [#35](https://github.com/wireapp/wire-avs-service/pull/35)
- With `gateway.enabled`, HTTPS attaches through a v1 `ListenerSet`: [#59](https://github.com/wireapp/wire-avs-service/pull/59), [#60](https://github.com/wireapp/wire-avs-service/pull/60)
- SemVer versions shared by the image and the chart, which goes from `0.x` to `5.2.0`, in `charts-avs` and `oci://quay.io/wire/charts/stable/sftd`: [#68](https://github.com/wireapp/wire-avs-service/pull/68), [#75](https://github.com/wireapp/wire-avs-service/pull/75), WPB-29713

### Fixes

- Free audio streams preferred, a margin before taking over a speaker, streams reset on the right call when a participant leaves: [`0c03d6a`](https://github.com/wireapp/wire-avs-service/commit/0c03d6a), [`692fb2d`](https://github.com/wireapp/wire-avs-service/commit/692fb2d)
- Audio level starts at silence: [`7095c4f`](https://github.com/wireapp/wire-avs-service/commit/7095c4f)
- Idle selective streams freed after one second: [`a035e42`](https://github.com/wireapp/wire-avs-service/commit/a035e42)
- Audio level smoothed per federated participant: [`50d46bf`](https://github.com/wireapp/wire-avs-service/commit/50d46bf)
- Video SSRCs initialised in selective forwarding: [`a2e7b85`](https://github.com/wireapp/wire-avs-service/commit/a2e7b85)
- Selective stream timestamps kept in sync with the wall clock: [`633af34`](https://github.com/wireapp/wire-avs-service/commit/633af34)

### Changes

- The chart of releases prepared from `dev` still goes to `charts-avs` and `wire-builds` but releases of `release/X.Y` lines go to the OCI repository only: [#75](https://github.com/wireapp/wire-avs-service/pull/75), WPB-29713
- `sftd -h` lists the `-B` option: [`92a611c`](https://github.com/wireapp/wire-avs-service/commit/92a611c)

### Maintenance

- Dependabot keeps the GitHub Actions and the base image of `docker/Dockerfile` up to date

### Configuration

No change since the 5.1.0 chart. Coming from 5.0.x, the values added, removed and changed are in the [5.1.0 release note](https://github.com/wireapp/wire-avs-service/blob/release/5.1/publication/release-note.md).
