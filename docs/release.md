# Release procedure

This document describes the procedure for releasing a new version of the
`trendvidia/sops` fork. It is intended for maintainers of the project.

## Overview

The release is performed by:

1. Updating `CHANGELOG.md` and `version/version.go` via a pull request into
   `trendvidia` (the fork's default branch).
2. Tagging the merge commit as `vX.Y.Z` (signed) and pushing the tag.
3. The tag push triggers
   [`release.yml`](../.github/workflows/release.yml), which creates a
   **draft** GitHub release pointed at the tagged commit, with notes
   auto-generated from PR titles since the previous tag.
4. The maintainer opens the draft, polishes the prose to match the
   `CHANGELOG.md` style, and publishes from the GitHub UI.

The fork ships as a Go module — `go get github.com/trendvidia/sops@vX.Y.Z`
resolves as soon as the tag is on the remote, independently of whether
the GitHub release has been published. Publishing the release is for
human-facing notes; it is not on the consumer's code-distribution path.

This fork intentionally dropped the upstream GoReleaser pipeline
(cross-platform binaries, ghcr.io + Quay.io containers, SBOMs, SLSA
provenance, Cosign signing) because none of those serve a
Go-module-only consumer surface.

## Preparation

- [ ] Ensure that all changes intended for the release are merged into
  the `trendvidia` branch and that CI is green on `trendvidia`.
- [ ] Open a pull request that:
  - Adds a new top-level `## X.Y.Z` section to
    [`CHANGELOG.md`](../CHANGELOG.md) summarising changes since the
    last release, with PR references. Follow the existing fork style
    (narrative summary up top, bulleted detail underneath).
  - Bumps the `Version` constant in
    [`version/version.go`](../version/version.go) to the new version
    number.
- [ ] Get approval, merge.

## Release

- [ ] Make sure your local `trendvidia` matches origin:

  ```sh
  git checkout trendvidia
  git pull
  ```

- [ ] Create a **signed tag** on the merge commit:

  ```sh
  git tag -s -m vX.Y.Z vX.Y.Z
  ```

  Where `X`, `Y`, `Z` are integers per
  [semantic versioning](https://semver.org/).

- [ ] Push the tag:

  ```sh
  git push origin vX.Y.Z
  ```

- [ ] Wait for the
  [release workflow](../.github/workflows/release.yml) to run
  (~10 seconds). It creates a draft release at
  <https://github.com/trendvidia/sops/releases>.
- [ ] Open the draft. Replace the auto-generated PR-title list with
  the prose section you wrote in `CHANGELOG.md` for this version.
  Click **Publish**.

## If the draft doesn't appear

Check <https://github.com/trendvidia/sops/actions> for a failed
`Release` run. The workflow is single-step and only needs the
auto-provided `GITHUB_TOKEN`, so failures are almost always one of:

- The tag wasn't actually pushed (verify with
  `git ls-remote --tags origin`).
- The release already exists for this tag (delete it from the GitHub
  UI and re-push the tag to retrigger).
- A draft from a previous attempt is hiding — drafts only show in the
  releases UI when filtered to include drafts.
