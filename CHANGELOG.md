# Changelog

All notable changes to this project are documented in this file.

## [0.5.6] - 2026-07-14

### Added

- Added a versioned first-scan authorization acknowledgement with the active
  ICMP, TCP, application, neighbor-cache, name-resolution, and retention
  behavior shown before any network probe starts.
- Added a persistent status-bar probe summary and detailed tooltip.
- Added separate Save Target History, Remember Last Target On Launch, and Clear
  Target History controls.

### Changed

- Target history is disabled on clean installs; disabling or clearing retention
  removes saved history and the saved last target immediately.

## [0.5.5] - 2026-07-14

### Changed

- Export CSV now explicitly offers filtered or all rows, preserves current row
  and visible-column order, and defaults to the filtered result set.
- CSV values use explicit UTF-8, quote embedded data, and neutralize leading
  spreadsheet formula sigils.
- Exports atomically replace the destination only after stream, flush, and
  commit checks succeed; concrete failures are shown without damaging an
  existing file.

## [0.5.4] - 2026-07-14

### Changed

- Replaced destructive settings-schema clearing with an explicit schema-2
  migration that preserves unrelated preferences and retains legacy target
  data only when retention was explicitly enabled.
- Persist intentionally empty service selections and the toolbar `Default`
  inheritance sentinel exactly across restarts and resets.
- Debounce remembered-target writes and report invalid custom OUI lines with a
  line-specific error instead of silently dropping them.

## [0.5.3] - 2026-07-14

### Added

- Added a persisted CIDR or begin/end preference for automatically generated
  Auto Select and adapter-specific targets, with CIDR as the default.
- Added exact CIDR serialization that preserves the parser's usable-host
  semantics, adapter routing, host counts, deduplication, and input limits.

## [0.5.2] - 2026-07-14

### Added

- Added a deterministic mDNS compatibility matrix covering positive and negative
  observations, cache expiry, malformed and mismatched replies, overlapping
  addresses, concurrent duplicate requests, cancellation, timeout, daemon
  recovery, missing backends, and hostname precedence and fallback.
- Added an isolated Avahi/D-Bus controlled responder that validates the real
  production backend, interface scoping, and active cancellation under CTest
  without depending on devices on the consumer LAN.

### Fixed

- Report an unavailable injected mDNS backend as `BackendUnavailable` instead
  of classifying it as a malformed response.

## [0.5.1] - 2026-07-14

- Capture the selected adapter's assigned DNS search suffixes, prefer the explicit PTR record matching that scope, qualify a short PTR when necessary, retain `.local` mDNS evidence separately, and place source labels directly after each hostname in Details.
- Keep DNS suffixes in Details but omit them from non-mDNS table hostnames, and elide long table text at the cell's character boundary without word wrapping.

### Changed

- Prefer the local OS hostname, explicit DNS PTR, and system-resolver evidence over mDNS while retaining every distinct detected name.
- Keep result rows value-only and show aligned, compact hostname and service evidence in the selected device's Details pane.

### Added

- Added Accuracy-scaled, cancellable IPv4 PTR lookup and explicit Local, PTR, System, and mDNS source tracking.
- Added hostname diagnostics with Avahi health/failure counts and a redacted JSON support bundle.

## [0.5.0] - 2026-07-14

### Added
- Added one asynchronous, interface-scoped Avahi D-Bus reverse resolver per scan with near-simultaneous positive and negative request coalescing.
- Added strict interface, IPv4 protocol, address, and hostname validation plus target-budgeted backend timeouts, prompt cancellation, and conservative 250 ms observation revalidation.
- Added hostname quality precedence so mDNS `.local` evidence replaces preliminary or system-resolver names while equal-quality values remain stable.
- Added deterministic resolver coverage and a live local Avahi backend check; Debian packages now recommend `avahi-daemon` instead of the unused command-line utilities.

## [0.4.5] - 2026-07-14

### Added
- Added an exact hidden `test` target that publishes 768 deterministic benchmark-network devices without network traffic or an adapter.
- Covered every configured service with confirmed and unknown-port evidence, known and unknown MAC vendors and hostnames, and varied service counts.
- Paced progressive fixture results from Fast through Maximum Accuracy while preserving normal table ordering, viewport behavior, and prompt Stop handling.

## [0.4.4] - 2026-07-13

### Changed
- Replaced per-cell result widgets with an interface-and-IP keyed table model and painted service tags.
- Publish results continuously in bounded UI batches while preserving deterministic insertion order, selection, and the anchored viewport.
- Reconcile authoritative completion results through the same bounded path without clearing, rebuilding, or unexpectedly sorting the table.
- Let Balanced through Maximum accuracy wait a bounded interval for valid cached neighbor evidence to become actively confirmed, improving detection of slow or sleeping devices without treating stale cache entries as definitive.

### Added
- Added a 4,096-row GUI responsiveness benchmark covering scrambled arrivals, explicit sorting, filtering, completion reconciliation, and scroll-anchor stability.

## [0.4.3] - 2026-07-13

### Changed
- Distinguish open-port evidence from protocol-verified service identity and remove separate automatic device-detail traffic.
- Verify HTTP status lines, SSH banners, FTP/SMTP greetings, STARTTLS capability, and TLS-plus-application evidence on the original probe connection; label unsupported or mismatched protocols as concise `Unknown:<port>` tags.
- Use enabled service probes to discover ping-silent hosts at every accuracy level, without probing the same service twice, and size each target deadline for the complete protocol-specific wait sequence.
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
