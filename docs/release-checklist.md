# Release-candidate checklist

This checklist prepares and verifies a release candidate. It does not authorize
a tag, GitHub release, package publication, branch-protection change, or version
`1.0.0`. Those are explicit human decisions after all required roadmap items
and final smoke evidence are complete.

## Source and scope

- [ ] Every required pre-1.0 roadmap item is complete or has an explicit
  release-candidate deferral accepted by the owner.
- [x] `docs/`, README, Help, About, AppStream, package text, and changelog agree
  on behavior, support boundaries, privacy, and known limitations.
- [x] The version agrees in CMake-generated application, package, manual page,
  AppStream, changelog, and About output. Keep the major version at `0` until
  the owner approves the final 1.0 candidate.
- [ ] The candidate commit is on a reviewed branch, the worktree is clean, and
  main has only the intended fast-forwarded commits.
- [x] Default-branch protection and required checks are configured at the
  release-candidate stage and verified against the documented workflow names.

## Automated validation

- [x] `./scripts/quality-gate.sh release` passes from a clean checkout.
- [ ] Main CI passes the Ubuntu 24.04 compatibility-floor gate, Debian 13 newer
  gate, isolated mDNS responder, and downstream tested-package job.
- [x] Strict project warnings, metadata lint, ASan/UBSan, ThreadSanitizer's
  supported scenarios, package lifecycle, and Lintian all pass with documented
  exclusions only.
- [ ] The release package is built on Ubuntu 24.04 and is the exact package that
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
- [ ] Generate keyless GitHub build-provenance and SBOM attestations with the
  least required OIDC permissions and the immutable candidate commit identity.
- [ ] Verify checksums and run `gh attestation verify` for the package and SPDX
  file against `calculatetech/open-ip-scanner` from a separate clean
  environment. Confirm that the package also has the SPDX document as its SBOM
  attestation predicate.
- [x] Confirm artifact names, versions, architecture, license/notices, manual
  page, support documents, dependencies, and retention policy.

Local 0.7.9 evidence from clean candidate commit `e4a53cd`: the release gate
passed normal and strict 39/39,
ASan/UBSan 38/38, ThreadSanitizer 37/37, zero-warning Lintian, package
install/remove, hardening, two byte-identical package builds, source/checksum/
SPDX validation, and external checksum verification. The installable candidate
is `release/open-ip-scanner_0.7.9_amd64.deb`.

## Human release decision

- [ ] Review remaining known limitations and post-1.0 roadmap items.
- [ ] Review security contact readiness and the private-reporting path.
- [ ] Obtain final human product/accessibility approval.
- [ ] Only then authorize `1.0.0`, tag creation, release notes, GitHub release,
  and package publication as separate actions.
