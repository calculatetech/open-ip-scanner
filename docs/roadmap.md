# Open IP Scanner roadmap

This file is the single source of truth for unfinished product, engineering, documentation, and release work. Detailed evidence for why each 1.0 item exists is in [the production-readiness audit](production-readiness-audit.md). New ideas belong here rather than in a second backlog.

The audited baseline is `0.2.0` at commit `91e0a7a`; `0.4.4` is the latest human-verified version on `main`, and `0.4.5` is the active implementation branch. Version 1.0 is not ready. Every unchecked item under “Required for 1.0” is a release gate; the post-1.0 section is explicitly outside the first production release.

## Delivered implementation increments

The unchecked milestone boxes below mean their complete acceptance criteria are still open; they do not mean no work has landed. The cumulative implementation through `0.4.4` is human-verified.

- `0.3.0` — **SCAN-CONFIGURATION:** active scans receive an immutable `ScanOptions` snapshot, with concurrent value-isolation and ThreadSanitizer coverage.
- `0.3.1` — **SCAN-CANCELLATION:** Stop and close use bounded cancellation-aware process, socket, and hostname waits, with asynchronous window shutdown.
- `0.3.2` through `0.3.4` — **SCAN-BUDGETS:** removed the duplicate serial pass, added per-target safety ceilings, prioritized service evidence, restored active-port reporting, clarified large-scan estimates, and made Accuracy scale retry depth and timeouts.
- `0.4.0` — **ACCESSIBILITY:** added the canonical UI layout specification and a stable, internally scrolling 600-by-440 Settings dialog with aligned Performance controls.
- `0.4.1` — **TARGET-DEFAULTS:** generated bounded, parser-valid targets for large and point-to-point networks while keeping Auto Select probes on one valid adapter and route.
- `0.4.2` — **NEIGHBOR-VALIDATION:** validated interface-scoped Linux neighbor evidence, applied conservative kernel-state freshness rules, and preserved interface-plus-IP result identity.
- `0.4.3` — **SERVICE-EVIDENCE:** separated open ports from confirmed protocols, removed hidden detail traffic and OS guesses, restored all-accuracy TCP discovery, and corrected protocol-aware target budgeting.
- `0.4.4` — **RESULT-SCALING:** replaced per-cell widgets with a keyed live result model, preserved deterministic ordering and viewport stability, and added accuracy-scaled active confirmation for slow cached neighbors.

**RESULT-SCALING** is human-verified on version `0.4.4`. DUPLICATE-IP-CONFLICTS remains Post-1.0.

Version `0.4.4` also repaired a field-discovered neighbor timing gap: a ping-silent device could remain in Linux `DELAY` long enough for the scanner's single neighbor lookup to miss its later `REACHABLE` confirmation. Fast retains an immediate cutoff; Balanced, High, and Maximum allow progressively longer bounded confirmation windows, remain cancellation-aware, and still reject a cached MAC that never becomes actively confirmed.

## Priority definitions

- **Blocker:** The current behavior has a confirmed undefined-behavior path, cannot be regression-gated at all, or produces a policy/license-invalid primary artifact. Do this first.
- **High:** A core scanning, enrichment, data-integrity, or operational behavior is materially wrong. It remains required before 1.0.
- **Medium:** Production hardening, supportability, accessibility, or release quality that must be closed after the core blockers.

Priority matches the most severe audit finding an item closes. All items in the 1.0 section remain mandatory even when their priority is High or Medium.

## Required for 1.0

### Correctness and worker lifecycle

#### SCAN-CONFIGURATION

- [x] **Freeze scan configuration and ownership before starting workers.** `Blocker`
  - Introduce an immutable scan-options value containing accuracy, worker count, enabled probes, adapter identity, timeouts, and the vendor data needed by a scan. Pass it into the worker instead of reading mutable `ScannerWindow` members.
  - Current progress: `ScanOptions` captures those values and the production scan path no longer reads mutable window policy. CTest covers concurrent value-snapshot isolation for every captured field, including a ThreadSanitizer run.
  - Completion evidence: the human-verified production scan uses one captured immutable value, concurrent snapshot-isolation coverage exercises every field, and the same test passes under ThreadSanitizer.

#### SCAN-CANCELLATION

- [x] **Make Stop and window close bounded and cancellation-aware.** `High`
  - Replace uninterruptible helper calls with cancellable operations. Track and terminate child processes, abort sockets and asynchronous name lookups, and stop scheduling reconciliation work after cancellation.
  - Do not block the GUI thread in `closeEvent()` while waiting for network deadlines. Show a short shutdown state and complete cleanup asynchronously or enforce a documented hard deadline.
  - Current progress: shared bounded waits now cancel child processes, TCP connect/read/write operations, and asynchronous system lookups; queued publications are discarded after cancellation; window close waits asynchronously. Deterministic process and socket deadline tests complete in under 500 ms.
  - Completion evidence: cancellation-aware helper tests cover active processes, connects, reads, and hostname lookup; queued publication is suppressed; asynchronous close is implemented; and human validation confirmed Stop latency improved materially.

#### SCAN-BUDGETS

- [x] **Replace the duplicate accuracy pass with a budgeted scan engine.** `High`
  - Remove the serial retry of every missed host. Represent discovery methods as bounded attempts in one scheduler, avoid probing the same port twice, and cap total work per target and per scan mode.
  - Surface an estimated upper bound before starting a large scan and make the worker count meaningful across all discovery stages.
  - Current progress: every target runs once in the configured worker pool with a safety ceiling derived from the accuracy profile and every bounded wait required by enabled protocols; the serial reconciliation pass is removed; TCP discovery evidence is reused; enabled-port evidence is collected before optional enrichment at every accuracy level; and the accuracy slider scales ping and port attempts from one short pass through four longer passes. Only scans whose worst-case estimate exceeds ten minutes require confirmation. Unit tests cover profiles, protocol wait units, derived ceilings, stage priority, deadline expiry, and worker-wave estimates.
  - Completion evidence: the duplicate serial pass is removed, all targets use the worker pool once, accuracy profiles and derived ceilings have deterministic unit coverage, Stop remains cancellation-aware, and human validation confirmed SSH service evidence and expected scan behavior.

#### TARGET-DEFAULTS

- [x] **Make target and adapter defaults valid by construction.** `High`
  - Never place a subnet in the target field that the parser will immediately reject. For networks larger than the 4,096-host limit, offer a bounded local slice or require an explicit range choice.
  - Cover multiple adapters, cumulative limits, `/31` links, virtual adapters, overlapping private ranges, and route selection. Keep every probe tied to the selected interface/source address.
  - Current progress on `0.4.1`: `/1` through `/19` defaults become the adapter-local `/24`; `/20` through `/32` preserve their usable host semantics; overlapping addresses deduplicate; defaults stop at 4,096 unique hosts and at the target field's 2,048-character limit, reporting partial omissions. Auto Select uses only the preferred adapter so its probes retain one valid source and route, while selecting another adapter rebuilds the defaults for that adapter. Deterministic tests cover `/8`, `/16`, `/19`, `/20`, `/24`, `/30`, `/31`, `/32`, overlaps, cumulative limits, fragmented `/32` inputs, and production-parser acceptance.
  - Completion evidence: automated cases for `/8`, `/16`, `/19`, `/20`, `/24`, `/30`, `/31`, `/32`, overlapping and fragmented inputs, cumulative limits, and production-parser acceptance pass; human validation confirmed the generated targets scan as expected.

#### NEIGHBOR-VALIDATION

- [x] **Validate neighbor entries before calling a host alive.** `High`
  - Reject incomplete, failed, zero, broadcast, multicast, and malformed neighbor entries. Replace the state-blind `/proc/net/arp` shortcut with validated `ip neigh` data and treat stale-but-valid entries according to a documented freshness policy.
  - Preserve the interface in the identity key so duplicate addresses on different links do not collapse into one device.
  - Freshness policy: use the Linux kernel's Neighbor Unreachability Detection state instead of inventing an unavailable wall-clock age. Only a valid unicast-MAC entry in `REACHABLE` may establish liveness. `STALE`, `DELAY`, `PROBE`, and `PERMANENT` supply supplementary MAC metadata only after ping or a service probe establishes liveness. `INCOMPLETE`, `FAILED`, `NONE`, and `NOARP`, as well as entries with missing, zero, broadcast, multicast, or malformed MAC addresses, establish nothing.
  - Current progress on `0.4.2`: production discovery uses interface-scoped `ip -j neigh` JSON instead of `/proc/net/arp`, applies the freshness policy before consuming evidence, and keys neighbor observations and scan-result merging by interface plus IPv4 address. Deterministic tests cover every listed NUD state, invalid MAC forms, malformed JSON, interface filtering, and overlapping addresses on separate links.
  - Completion evidence: deterministic fixtures cover every listed Linux neighbor state, invalid MAC forms, interface filtering, and overlapping links; production UI coverage preserves interface-plus-IP identity; normal, lint, and ThreadSanitizer suites pass; and human validation confirmed expected scan behavior.
  - `0.4.4` validation repair: deterministic coverage confirms a supplementary `DELAY` observation is accepted only after a later `REACHABLE` observation, the wait is accuracy-scaled and cancellation-aware, and a guarded production-path check recovered the reported slow device from a stale starting state. Normal and strict suites pass 8/8, the relevant ThreadSanitizer set passes 4/4, a fresh adversarial review found no remaining issue, and renewed human validation passed before merge.

#### SERVICE-EVIDENCE

- [x] **Separate open-port evidence from verified service identity.** `High`
  - Display an open TCP port as an open port or “probable service” until a protocol-specific handshake confirms it. Do not claim HTTPS, SSH, RDP, SMTP, or an operating system merely from a conventional port number or an ambiguous banner.
  - Make banner and device-detail collection explicit, bounded, and lazy so a hidden details pane does not generate extra traffic for service-positive devices. Rebuild details when better host data arrives.
  - Current progress on `0.4.3`: every successful TCP connection is shown as `Unknown:<port>` unless the same connection yields protocol-specific evidence. HTTP requires a status line; HTTPS requires both TLS and an HTTP status line; SMTPS requires TLS and an SMTP greeting; SSH requires an `SSH-` banner; FTP and SMTP require matching greetings; and SMTP-STARTTLS additionally requires advertised STARTTLS capability. RDP, SMB, Telnet, and mismatches remain concise unknown-service tags. Enabled services participate in discovery at every accuracy level, higher accuracy can retry verification while retaining open-port evidence, the target ceiling accounts for each protocol's complete wait sequence, fragmented responses are bounded and accumulated, and the automatic detail stage sends no separate requests or OS inference. Pure fixtures cover every classifier and conventional/unconventional display, production option capture, and conventional/unconventional rendering, while production loopback coverage exercises plain verified, mismatched, fragmented, and retried probes on ephemeral ports.
  - Completion evidence: normal, strict-warning, and ThreadSanitizer suites pass; fresh adversarial review found no remaining issue; and human validation confirmed the concise service labels and active-port behavior.
  - Done when mock-port fixtures produce truthful labels independent of conventional port numbers, OS text is removed, enabled protocol-verification traffic is documented, and the details pane sends no hidden request.

#### RESULT-SCALING

- [x] **Replace per-row table rebuilding with a scalable result model.** `High`
  - Use a model keyed by interface and IP and coalesce only the UI notifications needed to keep the event loop responsive. Publish completed results continuously; do not hold them until scan completion. Insert each new row at its deterministic position under the active ordering so existing rows do not undergo repeated global re-sorts. Service sorting must use actual service data rather than empty table cells.
  - Preserve selection and the perceived scroll position—the top visible row identity and its exact pixel offset—during background updates and scan completion. The scrollbar's numeric value may change when rows are inserted above the viewport, but the content under the user's eyes must not move. Do not reconstruct, clear, or reorder the table at completion. A user-requested header sort may intentionally reorder rows and move the viewport; background updates must not cause an abrupt or delayed surprise sort or scroll jump.
  - Current progress on `0.4.4`: `ResultTableModel` owns interface-and-IP keyed records and deterministic active ordering; a delegate paints service tags without persistent cell widgets; arrivals and authoritative completion reconciliation use bounded 64-row UI batches; and every background batch anchors selection plus the top visible identity and pixel offset. Existing rows do not move when later evidence upgrades their fields; only an explicit header sort globally reorders the table. A scrambled-arrival 4,096-row benchmark covers real-time publication, deterministic IP and service ordering, filtering, an unseen completion-only row, no model reset, no persistent widgets, selection stability, exact viewport anchoring, a 10 ms heartbeat below the 250 ms ceiling, and the five-second runner budget.
  - Completion evidence: normal and strict-warning builds pass all 8 tests; the scrambled 4,096-row GUI contract remains below the five-second and 250 ms heartbeat ceilings. ThreadSanitizer passes the seven non-rendering tests but Qt 6's uninstrumented font-rendering pool reports QtCore/QtGui races when the offscreen benchmark paints; no report contains a project-owned result-model or batching frame. Fresh adversarial reviews found no remaining issue after active-filter, completion-action, and slow-neighbor repairs. Human validation confirmed all expected devices, stable live ordering, and viewport behavior.
  - Done when a GUI benchmark inserts, updates, explicitly sorts, and filters 4,096 synthetic results while the event loop remains responsive; progressive rows remain deterministically ordered and visible in real time; selection and the anchored viewport do not move during background publication or completion; completion causes no reset or reorder; service sorting is deterministic; and the final model equals the worker result set.

### mDNS reverse-hostname enrichment

#### MDNS-RESOLVER

- [ ] **Implement one asynchronous, interface-scoped Avahi reverse resolver per scan.** `High`
  - Replace one `avahi-resolve-address` child process per live host with an injectable asynchronous IPv4 reverse resolver. On Linux, use Avahi’s client API or an equivalently cancellable backend that binds every result to the selected interface.
  - Cache observations by interface plus IPv4 address, honor record lifetime, and never accept an answer from an ambiguous link. Keep DNS-SD browsing and IPv6 out of the 1.0 contract.
  - Define hostname quality/precedence so a later `.local` result can replace a preliminary local-host or gateway name when appropriate instead of being discarded merely because the first value was non-`Unknown`.
  - Done when controlled positive and negative reverse records enrich the correct rows within a documented deadline, duplicate preliminary results converge on the selected best hostname, and stopping the scan cancels resolution immediately.

#### ENRICHMENT-PROVENANCE

- [ ] **Expose enrichment provenance and Avahi health.** `High`
  - Store the source of each hostname and service: local host, direct Avahi reverse lookup, system resolver, neighbor cache, port inference, or verified handshake.
  - Add a diagnostic surface that distinguishes missing client library/tool, inactive daemon, multicast unavailable, no record, malformed response, timeout, and cancellation. Do not silently turn every failure into `Unknown`.
  - Make merge precedence explicit so the local machine’s known positive Avahi result is not queried and then discarded behind an earlier lower-quality name.
  - Done when the UI can identify which fields came from Avahi, a support bundle records capability and failure state without sensitive payloads, and scanning the local audit fixture shows its `.local` name as mDNS-derived.

#### MDNS-TESTS

- [ ] **Add a deterministic mDNS reverse-resolution compatibility suite.** `High`
  - Test success, no reverse record, delayed response, malformed data, preliminary-name merge precedence, expiry, missing daemon, missing backend, wrong interface, overlapping addresses, cancellation, and system-resolver fallback.
  - Include an end-to-end fixture with a controlled responder; do not rely on whatever consumer devices happen to be present on a developer LAN.
  - Done when these tests run under CTest in CI and prove both the parser/backend contract and visible row provenance.

### Settings, persisted data, and export

#### TARGET-FORMAT-PREFERENCE

- [ ] **Let users choose CIDR or begin/end notation for generated targets.** `Medium`
  - Add a persisted setting that formats automatically generated targets as compact CIDR notation or explicit begin/end ranges without changing which addresses will be scanned.
  - Keep CIDR and range choices semantically equivalent, preserve the existing 4,096-host and input-length protections, and use the same preference for Auto Select and adapter-specific defaults.
  - Done when both formats round-trip through the production parser to identical address sets, the preference survives restart, and changing it never changes adapter routing or target count.

#### SETTINGS-MIGRATIONS

- [ ] **Fix settings round trips and migrations.** `High`
  - Persist an intentionally empty enabled-service set instead of restoring defaults. Make toolbar “Default” inherit the global style and preserve that sentinel across restarts.
  - Replace schema-wide `clear()` with explicit migrations, validate custom OUI input with user-visible errors, and debounce settings writes instead of writing on every target keystroke.
  - Done when round-trip tests cover empty collections, every toolbar mode, old schemas, invalid OUI entries, and reset behavior without deleting unrelated valid preferences.

#### CSV-EXPORT

- [ ] **Make CSV export safe and failure-aware.** `High`
  - Define whether export includes all, visible, or filtered rows and label that choice in the dialog. Preserve display order intentionally.
  - Prevent spreadsheet-formula execution for fields beginning with formula sigils, write through an atomic save, choose UTF-8 explicitly for every supported Qt version, and check stream, flush, close, and disk-full errors before reporting success.
  - Done when tests cover commas, quotes, line breaks, Unicode, formula payloads, filtered rows, hidden columns, canceled saves, and injected write failures.

#### SCAN-PRIVACY

- [ ] **Define target-history privacy and safe-scan behavior.** `Medium`
  - Explain that target history is persisted even when “Remember Last Target On Launch” is off, or change the behavior so the control governs retention. Provide clear-history and disable-history controls.
  - Document exactly which ICMP, TCP, HTTP, and name-resolution traffic each mode sends. Put the authorization warning where a first-time user sees it before scanning, not only in Help and README.
  - Done when retention controls have tests, disabling retention removes saved target data, and the in-app scan summary describes the active probe set before launch.

### Testability, platform contract, and diagnostics

#### DEBUG-SCAN-FIXTURE

- [ ] **Provide a hidden, deterministic high-volume scan fixture.** `Medium`
  - Treat the exact target token `test` as an internal fixture trigger. It must bypass adapter, bind, parser, and network-probe paths and must not be advertised as an ordinary target format.
  - Publish hundreds of unique benchmark-network devices through the production result queue. Cover every configured service type with both confirmed and `Unknown:<port>` evidence, known-vendor and unknown MAC addresses, known and unknown hostnames, varied service counts, and stable details.
  - Pace fixture publication by Accuracy: Fast is quickest, followed by Balanced, High, and Maximum. Stop and close must cancel promptly, while the normal result ordering, filtering, selection, and viewport invariants remain in force.
  - Current progress on `0.4.5`: the exact case-sensitive `test` token is accepted by the target control and enables scanning even without an adapter. It bypasses parsing and network setup, then publishes 768 deterministic `198.18.0.0/15` benchmark devices through the ordinary asynchronous result queue. The data covers every configured service ID with both confirmed and `Unknown:<port>` evidence, known and unknown vendors and hostnames, varied service counts, and stable details. Accuracy selects strictly increasing per-result delays, and the ordinary Stop path interrupts those delays.
  - Validation evidence: normal and strict-warning builds pass all 9 tests. The generator contract proves uniqueness, deterministic data, exact-trigger isolation, benchmark-only addressing, every service/evidence combination, mixed vendor/hostname knowledge, and pacing order. The production GUI contract proves adapter-free launch, incremental publication, all 768 final rows, and sub-second cancellation at Maximum. The eight non-rendering tests pass under ThreadSanitizer; the previously documented Qt offscreen-rendering limitation remains unchanged. A fresh adversarial review found no actionable issue; human validation remains before completion.
  - Done when deterministic tests prove data coverage, uniqueness, pacing order, no real-network dependency, cancellation, exact-trigger isolation, and stable progressive GUI presentation; human validation confirms the fixture is useful for table stability and performance checks.

#### APPLICATION-LAYERS

- [ ] **Split the 3,534-line window into testable layers.** `Medium`
  - Extract target parsing, scan scheduling, process execution, name resolution, neighbor parsing, service verification, OUI lookup, settings serialization, and export from `ScannerWindow` behind small interfaces.
  - Keep UI objects on the GUI thread and pass plain immutable values across worker boundaries.
  - Done when core behavior can run without constructing a window, test doubles can inject time/process/network outcomes, and `ScannerWindow` contains presentation and coordination rather than the scan implementation.

#### QUALITY-GATE

- [ ] **Establish the automated 1.0 quality gate.** `Blocker`
  - Aggregate the feature-owned CTest suites specified by items such as MDNS-TESTS, SETTINGS-MIGRATIONS, and CSV-EXPORT, then add the remaining integration, GUI, cancellation, stress, and package coverage. Add CI for the oldest and newest supported compiler/Qt combinations.
  - Preserve deeper regression coverage from completed correctness work: inject every `ScannerWindow` setting across consecutive scans, distinguish production ping/Avahi/system-resolver cancellation, count attempts in a virtual-clock 4,096-target scan, and prove cancellation interrupts its active budget without real network timing.
  - Enable project warning flags and warnings-as-errors for project sources. Run Clang-Tidy or an agreed equivalent, CMake/metadata lint, AddressSanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer scenarios where supported.
  - Done when a clean checkout has one documented command that builds and runs all required checks, CI protects the default branch, the strict build has zero project warnings, and the release job refuses an untested artifact.

#### PLATFORM-SUPPORT

- [ ] **Declare and enforce a truthful 1.0 platform matrix.** `High`
  - Scope 1.0 to Linux, IPv4, and a documented Qt 6 range unless another backend is implemented and tested before the release. Remove the current Windows and Qt 5 claims/fallback if they are not part of that tested matrix.
  - Build packages on the oldest supported distribution so generated Qt symbol dependencies do not accidentally narrow compatibility. Make About report the actual Qt runtime and supported platform.
  - Done when README, CMake, About, CI, package dependencies, and release notes agree, and each listed environment passes the full quality gate.

#### DIAGNOSTICS

- [ ] **Add actionable diagnostics without collecting user data.** `High`
  - Record structured local events for missing or failed `ping`, `ip`, resolver, socket-bind, DNS, Avahi, export, and launcher operations. Include command exit status and bounded error text, but redact target history and service payloads from default support output.
  - Give the UI a scan summary with counts by discovery method and failure category instead of collapsing all problems into “no responding hosts.”
  - Done when every external dependency failure has a visible remediation, logs can be enabled/exported locally, and tests assert both useful content and redaction.

#### VENDOR-DATABASE

- [ ] **Curate, license, and update the vendor database reproducibly.** `High`
  - Record the exact IEEE source, retrieval date, license/redistribution terms, and checksum. Generate the embedded database with a reviewed script and cover MA-L, MA-M, and MA-S assignments as allowed by the source terms.
  - Detect locally administered or randomized MAC addresses before assigning a vendor, validate every prefix as hexadecimal, and expose the database version.
  - Done when legal review approves redistribution, regeneration is deterministic, parser fixtures cover all assignment widths and private addresses, and stale data can be updated without hand-editing a 6.3 MB file.

### Packaging and release operations

#### DEBIAN-PACKAGING

- [ ] **Make the Debian package policy-clean and license-complete.** `Blocker`
  - Install the MIT license/copyright file, compressed changelog, and a real extended description. Use `Name <email>` maintainer syntax, normalize directory modes to `0755`, strip the runtime binary or provide split debug symbols, and add a manual page or an intentional Lintian override with rationale.
  - Include all notices required for the OUI dataset and any new Avahi dependency. Decide whether mDNS is a required feature (`Depends`) or an optional capability with explicit UI state.
  - Done when a Release package built in a clean container has zero Lintian errors, every remaining warning has a documented reviewed disposition, installation/removal succeeds, and the installed copyright files satisfy every bundled asset’s terms.

#### DESKTOP-METADATA

- [ ] **Bring AppStream and desktop metadata to release quality.** `High`
  - Adopt a stable reverse-DNS component ID with a migration plan, then add homepage, developer, content rating, releases, launchable data, and representative screenshots as required by the chosen distribution channels.
  - Keep desktop ID, icon, executable, Wayland identity, AppStream version, and package version in sync from one version source.
  - Done when `desktop-file-validate`, XML validation, and `appstreamcli validate --no-net` all exit zero without warnings on the installed tree.

#### ARTIFACT-PROVENANCE

- [ ] **Apply release hardening and artifact provenance.** `High`
  - Build with the supported distribution hardening flags, full RELRO/immediate binding where supported, stack protection, and fortification. Produce reproducible artifacts or document every remaining nondeterministic input.
  - Generate an SBOM, checksums, signatures, source archive, and build provenance from CI. Never publish a package produced from a dirty working tree.
  - Done when hardening inspection meets the documented baseline, two clean builds produce matching artifacts after normalization, and users can verify signed checksums and provenance.

#### PREFIX-SAFETY

- [ ] **Make install and uninstall prefix-safe.** `High`
  - Remove only files from the manifest or explicitly selected prefix. A system-prefix uninstall must never also delete a separate `~/.local` installation.
  - Do not run desktop-cache tools as root in a user session; use packaging triggers or clearly scoped post-install behavior. Refresh caches symmetrically after local uninstall.
  - Done when isolated tests cover system install, local install, staged package creation, both installs coexisting, missing manifests, repeated uninstall, and paths containing spaces without deleting the other prefix.

#### ACCESSIBILITY

- [ ] **Fix startup warnings, accessibility, and theme behavior.** `Medium`
  - Set the Qt high-DPI rounding policy through the supported pre-application API or remove the override; clean startup must not emit the current policy-order warning.
  - Give icon-only controls explicit accessible names and keyboard paths, avoid hard-coded selection/service colors that defeat system contrast, test screen-reader labels and high scaling, and add scrolling/responsive sizing to dense settings pages.
  - Current progress: the canonical [UI layout specification](ui-layout-spec.md) limits Settings to 600 by 440, standardizes spacing and aligned Performance controls, reserves stable geometry for dynamic descriptions, and requires internal page scrolling. An automated geometry contract protects the dimensions and row fit.
  - Done when offscreen and real-session startup are warning-free, automated accessibility inspection finds names/roles for interactive controls, and light, dark, high-contrast, 200% scale, and keyboard-only smoke tests pass.

#### RELEASE-DOCS

- [ ] **Complete the 1.0 release documentation and support contract.** `Medium`
  - Reconcile README, Help, About, changelog, package metadata, and actual behavior. Document mDNS troubleshooting, scan limitations, permissions, privacy, data provenance, support channels, security-reporting process, compatibility, upgrade/migration behavior, and known limitations.
  - Add a 1.0 release checklist that consumes the automated gates, updates every version source, creates signed artifacts, and records validation evidence.
  - Done when a clean-machine installation and operator runbook can be followed without repository knowledge, all claims have a passing test or explicit limitation, and the 1.0 changelog is complete.

## Post-1.0

These are intentionally not promises for the Linux/IPv4 1.0 scope. Promoting one into 1.0 requires moving it above and adding its test and packaging work to the release gate.

### DUPLICATE-IP-CONFLICTS

- [ ] **Flag repeated evidence that one address belongs to different devices.**
  - Persist bounded network context across scans, including the scanned address range, interface or network identity, and DNS suffix, so observations are compared only within the same logical subnet.
  - Treat flip-flopping neighbor MAC addresses as one signal rather than definitive proof. Combine repeated contradictions with other strong identity evidence, record when and where each observation occurred, and visibly flag a probable duplicate-IP conflict without silently merging the devices.
  - Define retention, privacy, expiry, subnet-change, and user-clear behavior before storing network history.
  - Done when deterministic multi-scan fixtures distinguish a real duplicate-IP conflict from adapter changes, DHCP reassignment, randomized MAC addresses, stale neighbor data, and unrelated overlapping private subnets.

### IPV6-SUPPORT

- [ ] **Add end-to-end IPv6 scanning and enrichment.**
  - Cover address parsing, CIDR/ranges, interface scope IDs, neighbor discovery, ICMPv6, TCP binding, link-local target identity, mDNS AAAA records, display/sort/export, and tests before advertising IPv6 support.

### CROSS-PLATFORM-BACKENDS

- [ ] **Add tested non-Linux discovery backends if cross-platform support is desired.**
  - Implement Windows and/or macOS host discovery, neighbor lookup, routing, mDNS, packaging, and CI as complete platform backends. A build that discovers only the local host or a few open ports is not cross-platform support.

### PACKAGE-FORMATS

- [ ] **Add additional distribution formats only after the Debian release is repeatable.**
  - Evaluate Flatpak, AppImage, RPM, and native distribution repositories with sandbox/network permissions, Avahi integration, signed updates, and the same metadata/test gates.

### LOCALIZATION

- [ ] **Add localization after strings and layouts are designed for translation.**
  - Move user-visible text into Qt translation catalogs, add locale-aware UI/layout tests, and translate the in-app safety and privacy guidance with the rest of the interface.

### DNS-SD-DISCOVERY

- [ ] **Add DNS-SD device and advertised-service discovery if product scope requires it.**
  - Browse PTR service types and resolve SRV, TXT, and IPv4 A data through an interface-scoped backend. Merge only addresses inside the requested target set, and allow an advertised in-scope address to create a row even when ICMP and fixed TCP probes are silent.
  - Add AAAA and link-local IPv6 records only together with IPV6-SUPPORT. Cover service-instance identity, record lifetime, duplicate advertisements, allowed TXT fields, cancellation, and controlled `_http._tcp`, `_ssh._tcp`, and `_ipp._tcp` fixtures before claiming DNS-SD enrichment.

## Completed

No production-readiness milestone was complete at the audited `0.2.0` baseline. Move a milestone here only with links to validating tests, release artifacts, or documentation evidence; do not delete its identifier.
