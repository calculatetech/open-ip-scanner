# Changelog

All notable changes to this project are documented in this file.

## [0.7.5] - 2026-07-15

### Fixed

- Install the CA certificate bundle with Git before Debian 13 checkout so the
  quality job can authenticate GitHub over HTTPS.

## [0.7.4] - 2026-07-15

### Fixed

- Install Git in the Debian 13 quality container so deterministic source-bundle
  contracts can inspect the checked-out source set.

## [0.7.3] - 2026-07-15

### Added

- Add an audited Release hardening baseline, reproducible two-build package
  comparison, deterministic source archive, SPDX JSON SBOM, and checksums.
- Add a dormant 1.0-only workflow for keyless GitHub build-provenance and SBOM
  attestations; creating or running a release remains a separate action.

## [0.7.2] - 2026-07-15

### Added

- Add and package canonical user, support, security, provenance, limitations,
  and release-candidate documentation.

## [0.7.1] - 2026-07-15

### Changed

- Make manifest and explicit-prefix uninstall operations isolated and safely
  repeatable, including staged installs and paths containing spaces.
- Add symmetric non-root desktop-cache refresh to dedicated local install and
  uninstall targets while leaving package and generic installs trigger-free.

## [0.7.0] - 2026-07-15

### Added

- Install a Debian-format copyright file, vendor-data source notice,
  deterministic compressed changelog, and manual page.
- Validate package metadata, dependencies, directory permissions, stripped
  binaries, documentation, Lintian results, and disposable installation and
  removal as part of the Release artifact build.

### Changed

- Use a complete Debian maintainer identity and extended description, retain
  `avahi-daemon` as an optional recommendation, and keep `avahi-utils`
  test-only.

## [0.6.9] - 2026-07-15

### Changed

- Use the supported pre-application high-DPI policy and add stable accessible
  names, descriptions, focus buddies, and keyboard shortcuts to primary and
  settings controls.

## [0.6.8] - 2026-07-15

### Changed

- Restore distinct palette-aware colors for verified service tags while keeping
  unknown open ports neutral and tag geometry stable.

## [0.6.7] - 2026-07-14

### Changed

- Search complete normalized device evidence, including alternate full
  hostnames and service ports, while preserving live result presentation.

## [0.6.6] - 2026-07-14

### Added

- Added stable reverse-DNS desktop and AppStream identity, complete release
  metadata, and a representative screenshot generated from the hidden test
  fixture.
- Added installed-tree contracts that keep the desktop entry, icons, Wayland
  identity, X11 window class, AppStream release, and package version coherent.

### Changed

- Migrated Linux desktop integration files to
  `io.github.calculatetech.OpenIpScanner` while retaining the
  `open-ip-scanner` executable and existing application settings identity.

## [0.6.5] - 2026-07-14

### Added

- Added deterministic desktop/XML/manifest metadata linting to every quality
  gate and direct contracts for the hosted workflow policy.
- Added a Release package job that runs only after both supported CI
  environments pass and tests the exact build before uploading it.

### Changed

- Limited branch push workflows to `main` while retaining pull-request checks,
  avoiding duplicate CI runs for the same commit after a fast-forward merge.

## [0.6.4] - 2026-07-14

### Added

- Added a reproducible, checksummed vendor database derived from the IEEE
  Registration Authority MA-L, MA-M, and MA-S public listings.
- Added longest-prefix vendor lookup across 24-, 28-, and 36-bit assignments,
  with private/randomized MAC detection and deterministic update checks.

### Changed

- About now cites the IEEE public-listing source and database version without
  including platform support-matrix or "tested on" text.

## [0.6.3] - 2026-07-14

### Added

- Added privacy-preserving local diagnostics with actionable capability and
  failure summaries, an opt-in rotating log, and redacted support export.
- Added scan completion counts by discovery method and failure category.

## [0.6.2] - 2026-07-14

### Changed

- Declared the supported 1.0 platform as Linux x86-64, IPv4, and Qt 6.4 or
  newer, with Ubuntu 24.04 as the compatibility floor and Debian 13 as the
  newer continuously tested environment.
- Updated About to report the actual Qt runtime and the supported platform
  scope, and made unsupported OS/architecture configurations fail clearly.

## [0.6.1] - 2026-07-14

### Added

- Added a newer Debian 13 quality-gate job alongside the Ubuntu 24.04
  compatibility-floor check.
- Added deterministic production regressions for consecutive window option
  snapshots and a virtual-clock 4,096-target scan budget.

## [0.6.0] - 2026-07-14

### Added

- Added one local quality-gate command with fast, full, and release modes for
  clean builds, CTest, strict warnings, supported sanitizers, optional
  Clang-Tidy, and Debian package creation.
- Added a stable full `quality` GitHub Actions check for pushes and pull
  requests on the Ubuntu 24.04 compatibility floor.

### Changed

- Enabled an opt-in strict compiler profile that promotes project conversion,
  sign-conversion, shadowing, format, and standard warnings to errors.
- Corrected the existing integer boundaries exposed by the strict profile.

## [0.5.18] - 2026-07-14

### Changed

- Moved production probe wiring and Linux default-gateway lookup into a
  window-free `ois_runtime` composition layer, while platform-neutral debug
  fixture execution now belongs to `ois_scan`.
- Scan-session work now captures only immutable options, hosts, and pure
  vendor/details callbacks; worker threads no longer invoke a UI object.

### Added

- Added direct contracts for valid lowest-metric route-table gateway selection,
  production composition/callback wiring, Linux gateway hex decoding, and
  debug-runner publication, progress, and cancellation.

## [0.5.17] - 2026-07-14

### Changed

- Moved MAC normalization/formatting and device-details HTML generation out of
  `ScannerWindow` into window-free UI-layer presentation functions.
- Wired production OUI lookup and details generation directly from immutable
  scan options, removing window captures from per-host enrichment callbacks.

### Added

- Added a pure device-presentation contract covering every MAC format, invalid
  input, HTML escaping, hostname provenance, and concise service evidence.

## [0.5.16] - 2026-07-14

### Changed

- Moved explicit PTR, system-hostname, and mDNS resolution coordination out of
  `ScannerWindow` into a shared, window-free `HostnameResolver`.
- Preserved adapter-suffix-aware PTR selection, independent `.local` mDNS
  evidence, resolver diagnostics, accuracy timeouts, cancellation, and the
  per-target budget across the new boundary.

### Added

- Added deterministic resolver contracts for evidence merging, every resolver
  outcome, timeout selection, cancellation boundaries, and budget expiry.

## [0.5.15] - 2026-07-14

### Changed

- Moved the service catalog, TCP/TLS connection attempts, interface-address
  binding, bounded response reads, and protocol verification out of
  `ScannerWindow` into `ServiceProbe`.
- Kept configured service order, accuracy-derived retries/timeouts, and concise
  `ServiceHit` evidence unchanged through the production backend boundary.

### Added

- Added a window-free service-probe contract for catalog order, verified versus
  open-port evidence, invalid binding, cancellation, and budget expiry.

## [0.5.14] - 2026-07-14

### Changed

- Moved Linux ping command selection, interface scoping, attempts, process
  deadlines, and cancellation out of `ScannerWindow` into `LinuxPingProbe`.
- Wired the production host backend to one shared stateless ping probe without
  changing accuracy-derived attempt or timeout policy.

### Added

- Added a production-path ping contract for exact arguments, retry success,
  attempt exhaustion, deadline expiry, cancellation, and immediate cutoffs.

## [0.5.13] - 2026-07-14

### Changed

- Moved interface-scoped Linux `ip -j neigh` execution, identity selection,
  budget handling, cancellation, and accuracy-dependent active confirmation
  from `ScannerWindow` into `LinuxNeighborProbe`.
- Wired the production host backend to one shared stateless neighbor probe while
  retaining the existing conservative NUD-state policy.

### Added

- Added a window-free injected neighbor-probe contract for delayed confirmation,
  immediate cutoffs, cancellation, budget expiry, and non-evidentiary input.

## [0.5.12] - 2026-07-14

### Fixed

- Replaced cross-thread Qt delivery calls in `ScanSession` with a standard
  synchronized record queue drained by an owner-thread timer, removing a
  sanitizer-visible race while retaining prompt owner-thread signals.
- Backed idle polling off to 25 ms and capped delivery at 128 records per GUI
  turn so long scans avoid busy polling and large result bursts yield between
  batches.
- Bound every queued delivery to its originating cancellation token so stale
  events cannot affect a later session after an explicit wait and restart.

## [0.5.11] - 2026-07-14

### Changed

- Moved per-host discovery, service-first liveness, neighbor confirmation,
  enrichment ordering, normalization, and cancellation boundaries from
  `ScannerWindow` into an injectable `ProductionHostScanBackend`.
- Reduced the window's production scan role to wiring existing concrete probe
  helpers into the scan-layer backend and starting `ScanEngine`.

### Added

- Added direct window-free production-backend contracts for service-first
  discovery, cached service reuse, neighbor confirmation, dead hosts, local
  identity, hostname evidence, and cancellation between stages.

## [0.5.10] - 2026-07-14

### Changed

- Moved bounded host scheduling, parallel dispatch, cancellation, progress,
  identity merging, progressive publication, and deterministic final ordering
  from `ScannerWindow` into a window-free `ScanEngine`.
- Routed the production per-host probe path through an explicit injectable
  `IHostScanBackend` boundary without changing discovery or enrichment order.
- Removed the final Qt Concurrent dependency; scan session and engine workers
  now have explicit join-based shutdown and synchronization.
- Contained backend and publication-callback failures as cancellation, suppressed
  post-cancel publication, and made same-address ordering deterministic by
  interface without merging distinct interface identities.

### Added

- Added deterministic engine coverage for concurrency bounds, exact host
  dispatch, result ordering, duplicate identity enrichment, publication, and
  cancellation.

## [0.5.9] - 2026-07-14

### Changed

- Replaced the window-owned top-level scan future and callback marshaling with
  a reusable `ScanSession` lifecycle in the scan layer.
- Routed production and hidden-fixture scans through the same session-owned
  cancellation, progress, incremental-result, and completion boundary.

### Added

- Added a deterministic injected-work lifecycle contract covering overlap
  rejection, GUI-thread callback delivery, one completion, cancellation, and
  suppression of late results.

## [0.5.8] - 2026-07-14

### Changed

- Extracted target parsing, OUI normalization and override precedence, settings
  migration, and target-history persistence from `ScannerWindow` into the core
  library.
- Added window-free contracts for supported target syntax, cumulative host
  limits, privacy-preserving settings migration, persistence failures, and OUI
  policy.

## [0.5.7] - 2026-07-14

### Changed

- Split the build into reusable `ois_core`, `ois_scan`, `ois_linux`, and
  `ois_ui` targets; the executable now owns only startup and resources.
- Tests link the narrowest production layer instead of recompiling production
  implementations into each test executable.
- Raised the build floor to CMake 3.28 and Qt 6.4, removing the untested Qt 5
  fallback.

### Added

- Added developer, release, ASan/UBSan, TSan, and Clang-Tidy CMake presets.

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
