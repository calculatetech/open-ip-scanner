# Release-candidate checklist

This checklist prepares and verifies a release candidate. The owner authorized
version `1.0.0` and an automated GitHub release on 2026-07-15. Publication still
requires the exact tagged commit to pass every remaining automated provenance
and verification item below.

## Source and scope

- [x] Every required pre-1.0 roadmap item is complete or has an explicit
  release-candidate deferral accepted by the owner.
- [x] `docs/`, README, Help, About, AppStream, package text, and changelog agree
  on behavior, support boundaries, privacy, and known limitations.
- [x] The version agrees in CMake-generated application, package, manual page,
  AppStream, changelog, and About output. The owner approved the final 1.0
  candidate before the version changed to `1.0.0`.
- [x] The candidate commit is on a reviewed branch, the worktree is clean, and
  main has only the intended reviewed commits.
- [x] Default-branch protection and required checks are configured at the
  release-candidate stage and verified against the documented workflow names.

## Automated validation

- [x] `./scripts/quality-gate.sh release` passes from the exact clean candidate
  commit.
- [x] Main CI passes the Ubuntu 24.04 compatibility-floor gate, Debian 13 newer
  gate, isolated mDNS responder, and downstream tested-package job.
- [x] Strict project warnings, metadata lint, ASan/UBSan, ThreadSanitizer's
  supported scenarios, package lifecycle, and Lintian all pass with documented
  exclusions only.
- [x] The release package is built on Ubuntu 24.04 and is the exact package that
  passed the downstream lifecycle and policy audit.
- [x] Hardening inspection confirms stack protection, fortification where
  supported, PIE, full RELRO, and immediate binding against the agreed baseline.
- [x] Two isolated builds have identical normalized artifacts or every remaining
  nondeterministic input has a reviewed disposition.

## Manual desktop qualification

On Kubuntu 26.04, use only an authorized local `/32` target and record concise,
non-identifying conclusions:

- [x] Start from the tested package on a clean user account with no stale app
  settings; confirm warning-free launch and accurate About information.
- [x] Check light, dark, high-contrast, 100%, and 200% scaling without clipped,
  moving, or oversized Settings controls.
- [x] Navigate every primary and Settings action by keyboard and inspect
  accessible names/roles with the available assistive-technology tool.
- [x] Confirm first-scan authorization, CIDR/range preference, adapter choice,
  progressive stable results, details, filtering, and scroll preservation.
- [x] Confirm Fast and Maximum descriptions/traffic, mDNS provenance when
  available, responsive Stop, close during scan, CSV export, printing, and
  diagnostics redaction.
- [x] Install and remove the package, then exercise local install/uninstall;
  confirm the other prefix and unrelated files remain untouched.

Completion evidence: on 2026-07-15 the repository owner reported that the
complete Kubuntu 26.04 checklist passed without exception.

## Artifacts and provenance

- [x] Produce one Debian package, source archive, SHA-256 checksum file, and
  SPDX JSON SBOM from the clean candidate commit.
- [x] Generate keyless GitHub build-provenance and SBOM attestations with the
  least required OIDC permissions and the immutable candidate commit identity.
- [x] Verify checksums and run `gh attestation verify` for the package and SPDX
  file against `calculatetech/open-ip-scanner` from a separate clean
  environment. Confirm that the package also has the SPDX document as its SBOM
  attestation predicate.
- [ ] Create the GitHub Release only after the exact `v1.0.0` tag workflow
  passes, and attach only the files downloaded from that successful run.
- [x] Confirm artifact names, versions, architecture, license/notices, manual
  page, support documents, dependencies, and retention policy.

Pre-1.0 candidate evidence: the release gate passed normal and strict 39/39,
ASan/UBSan 38/38, ThreadSanitizer 37/37, zero-warning Lintian, package
install/remove, hardening, two byte-identical package builds, source/checksum/
SPDX validation, and external checksum verification. The installable candidate
was `release/open-ip-scanner_0.7.9_amd64.deb`. Exact-commit 1.0 evidence belongs
in the pull request, release record, and ignored test-result record so recording
it cannot change the packaged candidate after validation.

## Human release decision

- [x] Review remaining known limitations and post-1.0 roadmap items.
- [x] Review security contact readiness and the private-reporting path.
- [x] Obtain final human product/accessibility approval.
- [x] Only then authorize `1.0.0`, tag creation, release notes, GitHub release,
  and package publication as separate actions.

## Exact-tag publication procedure

Create and push `v1.0.0` at the already merged, clean candidate commit; do not
allow a release command to create or move the tag implicitly. Wait for that
tag's `Release artifacts` run to pass. In a new empty verification directory,
download `open-ip-scanner-1.0.0` and
`open-ip-scanner-1.0.0-verification` from that run into that same directory so
the complete `SHA256SUMS` can verify the separately uploaded package together
with the source archive and SPDX document. Verify the package and SPDX
attestations, and the package's SPDX predicate, against
`calculatetech/open-ip-scanner`.

Only after those checks pass, create the GitHub Release with
`gh release create v1.0.0 --verify-tag` and attach the downloaded Debian
package, source archive, checksum file, and SPDX JSON file. This makes the
published tag, attestations, and downloadable files refer to one immutable
commit and prevents `gh release create` from silently creating an unvalidated
tag. Record the workflow URL and verification result in the release notes or
other external release record, not in a new tracked evidence commit.
