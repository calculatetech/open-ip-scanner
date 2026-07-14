# Changelog

All notable changes to this project are documented in this file.

## [0.4.3] - 2026-07-13

### Changed
- Distinguish open-port evidence from protocol-verified service identity and remove separate automatic device-detail traffic.
- Verify HTTP status lines, SSH banners, FTP/SMTP greetings, STARTTLS capability, and TLS-plus-application evidence on the original probe connection; label unsupported or mismatched protocols as probable services on open ports.
- Removed heuristic operating-system claims and separate automatic banner/detail requests; the details pane now renders only evidence already collected by enabled probes.

### Added
- Added deterministic response-classification coverage plus production plain-loopback coverage for verified, mismatched, fragmented, retried, and unconventional-port probes.

## [0.4.2] - 2026-07-13

### Changed
- Replaced unvalidated `/proc/net/arp` discovery with interface-scoped `ip -j neigh` parsing and kernel NUD freshness rules.
- Allow only `REACHABLE` entries with valid unicast MAC addresses to establish liveness; treat `STALE`, `DELAY`, `PROBE`, and `PERMANENT` as supplementary metadata and reject non-evidentiary states.

### Added
- Added deterministic coverage for every supported Linux NUD state, invalid MAC forms, malformed JSON, interface filtering, and overlapping addresses on different links.

## [0.4.1] - 2026-07-13

### Changed
- Automatically bound `/1` through `/19` adapter defaults to the local `/24` while preserving full usable `/20` through `/30`, both `/31` endpoints, and `/32` hosts.
- Keep Auto Select targets on the preferred adapter so every generated probe uses one valid source and route; selecting another adapter regenerates its defaults.
- Deduplicate overlapping defaults, enforce both the 4,096-host and 2,048-character input limits, and report addresses or adapters that were omitted.

### Added
- Added deterministic default-planning coverage for `/8`, `/16`, `/19`, `/20`, `/24`, `/30`, `/31`, `/32`, overlapping networks, cumulative limits, fragmented hosts, and production-parser acceptance.

## [0.4.0] - 2026-07-13

### Changed
- Standardized Settings dialog geometry at 600 by 440 logical pixels with consistent margins, section spacing, and internally scrolling pages.
- Aligned both Performance sliders to the same fixed length and reserved stable value and accuracy-description regions so changing a slider cannot move or resize nearby controls.

### Added
- Added the canonical UI layout specification and an automated Settings geometry contract.

## [0.3.4] - 2026-07-13

### Changed
- Made the accuracy slider explicitly scale ping and port-probe attempts from one short Fast pass through four longer Maximum passes.
- Added concrete timeout/attempt feedback beside the slider and guidance for quick discovery versus thorough investigation.
- Derived the internal safety ceiling from the selected profile and enabled-port count so every port retains the advertised attempts, including when all optional probes are enabled.

## [0.3.3] - 2026-07-13

### Fixed
- Prioritized enabled-port probing before optional MAC, hostname, and detail enrichment can exhaust a target's scan deadline.
- Added a durable scan-stage ordering check so optional enrichment cannot silently move ahead of service evidence again.

### Changed
- Removed the worst-case duration estimate from the normal scan status and explained it in plain language only when a large scan requires confirmation.
- Raised accuracy-profile safety ceilings and service timeouts so slower LAN switches, cameras, and embedded devices are not routinely clipped by the Balanced profile.

## [0.3.2] - 2026-07-13

### Changed
- Replaced open-ended accuracy retries with fixed one-, two-, four-, and eight-second per-target budgets.
- Removed the serial high-accuracy reconciliation pass so all targets use the configured worker pool once.
- Reused TCP discovery results during enrichment instead of probing the same enabled ports twice.
- Added a visible scan upper-bound estimate and confirmation before estimates longer than ten minutes.

### Added
- Added deterministic tests for accuracy profiles, target deadline expiry, worker-wave estimates, and edge inputs.

## [0.3.1] - 2026-07-13

### Changed
- Made ping, neighbor command, Avahi, system hostname, TCP connect, and banner waits observe scan cancellation in short bounded intervals.
- Changed window close during a scan to request cancellation and finish asynchronously instead of blocking the GUI thread.
- Suppressed queued progress and result publication after cancellation.

### Added
- Added deterministic cancellation deadline tests for active child processes, TCP reads, TCP connects, and hostname lookup entry.

## [0.3.0] - 2026-07-13

### Changed
- Replaced numeric roadmap identifiers with descriptive milestone names.
- Began SCAN-CONFIGURATION by capturing worker policy, adapter identity, timeouts, enabled probes, and vendor data in a value-owned `ScanOptions` snapshot before launch.
- Ensured active scan workers no longer read UI-owned mutable scan preferences or the window-owned cancellation pointer.

### Added
- Added concurrent snapshot-isolation coverage for every captured scan option, including a ThreadSanitizer validation path.
- Added repository rules for milestone versioning, branch isolation, human verification before merge, and automatic commit/push after successful review.

## [0.2.0] - 2026-02-27

### Added
- Adapter `Auto Select` mode that chooses the best adapter for entered targets.
- Usage Guide dialog under `Help`.
- Target history autocomplete improvements and optional remember-last-target toggle in `Settings`.
- Service probes for `SMTP` (25), `SMTPS` (465), and `SMTP-STARTTLS` (587), disabled by default.
- Command preflight checks for non-web service/program launches with clearer error feedback.
- Numeric sorting keys for IP and MAC columns to ensure correct sort ordering.
- Per-adapter binding checks with explicit status warnings when binding fails.

### Changed
- Default adapter preference now prioritizes internet-routable physical adapters.
- `Auto` target fill now uses selected adapter ranges; `Auto Select` can fill all detected ranges.
- Default accuracy changed to `Balanced`.
- About dialog now shows application version.
- RDP default launcher restored to `xdg-open rdp://{host}:3389`.

### Fixed
- Target limit validation now marks input red and clears warning state when back in range.
- Large out-of-range CIDR/range edits no longer freeze the UI.
- Adapter changes no longer reset custom target input.
- Restoring remembered target on launch no longer gets overwritten during startup signal flow.
