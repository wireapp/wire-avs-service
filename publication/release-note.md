## Overview

Version 5.1.0 is the first release of sftd built and published by this repository's own pipeline instead of Jenkins. The structured release declaration of this version is [`declaration.json`](declaration.json).

### Highlights

**SemVer versions**: releases are no longer `5.0.<build number>`. The image `quay.io/wire/sftd` and the Helm chart now carry the same version, so the chart jumps from `0.152.0` to `5.1.0`. It is still published to the `charts-avs` Helm repository, and also to `oci://quay.io/wire/charts/stable/sftd`.

**Release pipeline**: pre-releases and releases are prepared and published by the workflows of this repository, with the shared `wire-rm-actions`, and declared to the release manager. The binary tarball stays attached to the GitHub release.

## Maintenance

- Release files in `publication/`: compatibility, release note and release declaration
- PR checks for the release files, and a workflows lint (actionlint, zizmor)
- `CODEOWNERS`: the release managers review `.github/` and `publication/`

## Configuration

No configuration change.
