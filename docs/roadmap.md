# Open IP Scanner roadmap

This file is the single source of truth for unfinished product, engineering, documentation, and release work. Detailed evidence for why each 1.0 item exists is in [the production-readiness audit](production-readiness-audit.md). New ideas belong here rather than in a second backlog.

The audited baseline is `0.2.0` at commit `91e0a7a`; `0.5.2` is the latest manually tested version, versions from `0.5.3` onward are being adversarially reviewed and merged under the explicit waiver for remaining pre-1.0 work, and `0.6.0` is the active QUALITY-GATE foundation branch. Version 1.0 is not ready. Every unchecked item under “Required for 1.0” is a release gate; the post-1.0 section is explicitly outside the first production release.

## Delivered implementation increments

The unchecked milestone boxes below mean their complete acceptance criteria are still open; they do not mean no work has landed. The cumulative implementation through `0.5.0` is human-verified.

- `0.3.0` — **SCAN-CONFIGURATION:** active scans receive an immutable `ScanOptions` snapshot, with concurrent value-isolation and ThreadSanitizer coverage.
- `0.3.1` — **SCAN-CANCELLATION:** Stop and close use bounded cancellation-aware process, socket, and hostname waits, with asynchronous window shutdown.
- `0.3.2` through `0.3.4` — **SCAN-BUDGETS:** removed the duplicate serial pass, added per-target safety ceilings, prioritized service evidence, restored active-port reporting, clarified large-scan estimates, and made Accuracy scale retry depth and timeouts.
- `0.4.0` — **ACCESSIBILITY:** added the canonical UI layout specification and a stable, internally scrolling 600-by-440 Settings dialog with aligned Performance controls.
- `0.4.1` — **TARGET-DEFAULTS:** generated bounded, parser-valid targets for large and point-to-point networks while keeping Auto Select probes on one valid adapter and route.
- `0.4.2` — **NEIGHBOR-VALIDATION:** validated interface-scoped Linux neighbor evidence, applied conservative kernel-state freshness rules, and preserved interface-plus-IP result identity.
- `0.4.3` — **SERVICE-EVIDENCE:** separated open ports from confirmed protocols, removed hidden detail traffic and OS guesses, restored all-accuracy TCP discovery, and corrected protocol-aware target budgeting.
- `0.4.4` — **RESULT-SCALING:** replaced per-cell widgets with a keyed live result model, preserved deterministic ordering and viewport stability, and added accuracy-scaled active confirmation for slow cached neighbors.
- `0.4.5` — **DEBUG-SCAN-FIXTURE:** added the hidden adapter-free `test` target with 768 deterministic, Accuracy-paced devices for repeatable table stability and performance checks.
- `0.5.0` — **MDNS-RESOLVER:** replaced per-host helper processes with one cancellable, interface-scoped Avahi D-Bus reverse resolver per scan and added explicit hostname evidence quality.
- `0.5.1` — **ENRICHMENT-PROVENANCE:** retained source-aware Local, PTR, System, and mDNS names while keeping the result table concise and moving compact provenance into Details and diagnostics.
- `0.5.2` — **MDNS-TESTS:** added the deterministic compatibility matrix, isolated controlled Avahi responder, and bounded hosted CI for both mDNS tests.
- `0.5.3` — **TARGET-FORMAT-PREFERENCE:** added exact persisted CIDR/range generation while preserving target sets, adapter selection, and limits.
- `0.5.4` — **SETTINGS-MIGRATIONS:** made schema upgrades lossless, preserved empty service sets and toolbar inheritance, validated OUI input atomically, and debounced remembered-target writes.
- `0.5.5` — **CSV-EXPORT:** added explicit filtered/all scope, spreadsheet-safe UTF-8, immutable snapshots, and checked atomic replacement.
- `0.5.6` — **SCAN-PRIVACY:** added disabled-by-default checked retention, first-scan authorization, and an exact immutable active-probe summary.

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
  - Current progress on `0.4.4`: `ResultTableModel` owns interface-and-IP keyed records and deterministic active ordering; a delegate paints service tags without persistent cell widgets; arrivals and authoritative completion reconciliation use bounded 16-row UI batches; empty searches avoid redundant whole-table filter passes; and every background batch anchors selection plus the top visible identity and pixel offset. Existing rows do not move when later evidence upgrades their fields; only an explicit header sort globally reorders the table. A scrambled-arrival 4,096-row benchmark covers real-time publication, deterministic IP and service ordering, filtering, an unseen completion-only row, no model reset, no persistent widgets, selection stability, exact viewport anchoring, a 10 ms heartbeat below the 250 ms ceiling, and the five-second runner budget.
  - Completion evidence: normal and strict-warning builds pass all 8 tests; the scrambled 4,096-row GUI contract remains below the five-second and 250 ms heartbeat ceilings. ThreadSanitizer passes the seven non-rendering tests but Qt 6's uninstrumented font-rendering pool reports QtCore/QtGui races when the offscreen benchmark paints; no report contains a project-owned result-model or batching frame. Fresh adversarial reviews found no remaining issue after active-filter, completion-action, and slow-neighbor repairs. Human validation confirmed all expected devices, stable live ordering, and viewport behavior.
  - Done when a GUI benchmark inserts, updates, explicitly sorts, and filters 4,096 synthetic results while the event loop remains responsive; progressive rows remain deterministically ordered and visible in real time; selection and the anchored viewport do not move during background publication or completion; completion causes no reset or reorder; service sorting is deterministic; and the final model equals the worker result set.

### mDNS reverse-hostname enrichment

#### MDNS-RESOLVER

- [x] **Implement one asynchronous, interface-scoped Avahi reverse resolver per scan.** `High`
  - Replace one `avahi-resolve-address` child process per live host with an injectable asynchronous IPv4 reverse resolver. On Linux, use Avahi’s client API or an equivalently cancellable backend that binds every result to the selected interface.
  - Cache observations by interface plus IPv4 address, honor record lifetime, and never accept an answer from an ambiguous link. Keep DNS-SD browsing and IPv6 out of the 1.0 contract.
  - Define hostname quality/precedence so a later `.local` result can replace a preliminary local-host or gateway name when appropriate instead of being discarded merely because the first value was non-`Unknown`.
  - Current progress on `0.5.0`: one `ScanMdnsResolver` per production scan owns an asynchronous Avahi system-D-Bus backend and coalesces duplicate interface-plus-address requests. Calls force multicast-only IPv4 resolution on the selected interface, accept only an exact returned interface, lookup protocol, address protocol, and normalized address, and reject malformed hostnames. Avahi's one-shot D-Bus reply exposes no record TTL, so completed positive and negative observations are retained for at most 250 ms—long enough to share near-simultaneous consumers, then revalidated through Avahi rather than kept for a minutes-long scan. The smaller of the two-second resolver ceiling and the caller's remaining target budget is passed to the D-Bus operation itself; Stop wakes waiting workers within 25 milliseconds. Explicit hostname quality makes Avahi mDNS evidence outrank system-resolver and preliminary local names while equal-quality evidence remains stable. Qt DBus is a linked dependency, packages recommend `avahi-daemon`, and no production path invokes `avahi-resolve-address`.
  - Completion evidence: normal and strict-warning builds pass all 10 tests. Controlled fixtures cover positive and negative coalescing plus expiry/revalidation, caller-budget propagation, explicit Avahi no-answer versus D-Bus transport-timeout classification, concurrent duplicates, wrong-interface and wrong-protocol rejection, invalid input, timeout, sub-500 ms cancellation, and stable quality precedence; the production hostname path upgrades a preliminary name to `fixture.local`. All nine non-rendering tests pass under ThreadSanitizer, and the real local Avahi D-Bus backend resolves the loopback reverse record with multicast-only flags. The generated 0.5.0 Debian package depends on Qt DBus and recommends `avahi-daemon`. Fresh adversarial review found no actionable issue, and human validation confirmed that mDNS names populate correctly.
  - Done when controlled positive and negative reverse records enrich the correct rows within a documented deadline, duplicate preliminary results converge on the selected best hostname, and stopping the scan cancels resolution immediately.

#### ENRICHMENT-PROVENANCE

- [x] **Expose enrichment provenance and Avahi health.** `High`
  - Store every distinct hostname and its source: local host, explicit DNS PTR lookup, system resolver, direct Avahi reverse lookup, or preliminary evidence. Store service evidence as open port or verified handshake.
  - Select the table hostname using this precedence: local OS hostname, explicit PTR, system resolver, mDNS, then preliminary evidence. A generic system-resolver result must remain labeled `System`; only an explicit PTR response may be labeled `PTR`.
  - Keep the results table concise. Its Hostname cell contains only the first label of the preferred Local, PTR, System, or preliminary name; a preferred mDNS name retains its `.local` suffix so that protocol-specific identity remains useful. Full FQDNs remain in Details. Long cell text uses character-boundary right elision at the actual cell width and never wraps or truncates at an earlier word boundary. Service tags remain `Name:port` or `Unknown:port`; do not add provenance suffixes, confidence badges, backend states, documentary tooltips, or extra provenance columns.
  - Put successful per-device provenance in the details pane. Use one visually aligned `Hostname(s):` list, preferred name first, with short parenthesized labels such as `(Local)`, `(PTR)`, `(System)`, and `(mDNS)` immediately after each hostname rather than in a separate evidence column. List every distinct detected name; normalize case and a trailing root dot for deduplication. When explicit PTR returns aliases, prefer the value matching the scanning adapter's assigned DNS search suffix; qualify a short PTR with that suffix when it is the best scoped record. Retain `.local` for mDNS and for PTR only when it matches the adapter suffix or no better scoped PTR is known. Combine labels when multiple sources report the same resulting FQDN. Service details use equally concise labels such as `(Verified)` and `(Open)`.
  - Add a diagnostic surface that distinguishes missing client library/tool, inactive daemon, multicast unavailable, no record, malformed response, timeout, and cancellation. Do not silently turn every failure into `Unknown`.
  - Opening or selecting the details pane must not trigger network traffic. Backend availability and failures belong in diagnostics rather than per-row prose.
  - Current progress on `0.5.1`: scan results retain normalized Local, selected PTR, System, mDNS, and preliminary observations while deriving one value-only table hostname with the required precedence. Linux adapter discovery captures non-route-only search domains from `systemd-resolved`; explicit PTR selection prefers the record matching that adapter scope, otherwise qualifies a short record with its primary suffix, and keeps an unmatched `.local` only as mDNS evidence when a better PTR exists. Matching Local and System short names group under the selected FQDN without duplicate source attribution. An explicit cancellable IPv4 PTR lookup and the existing system and Avahi resolvers use Accuracy-scaled cutoffs inside the target budget. Details renders one compact `Hostname(s):` list with each combined source list immediately after its hostname and compact `(Verified)`/`(Open)` service evidence. Help exposes hostname diagnostics that distinguish Avahi daemon, multicast, backend, record, response, timeout, and cancellation outcomes; its JSON support bundle contains application/platform capability and aggregate counts but no addresses or hostnames. Opening Details performs no lookup.
  - Completion evidence: deterministic contracts cover precedence and preferred spelling, normalization, duplicate-source grouping, adapter search-domain parsing, exact/apex/nested PTR scope selection, short PTR qualification, no-suffix and `.local` independence, PTR query construction, Accuracy-scaled resolver timeouts and whole-sequence deadlines, cancellation, diagnostic health distinctions, concise source-aware table hostnames, non-wrapping right elision, merged-update details markup, and support-bundle redaction. Normal and strict-warning suites pass 11/11, all ten non-rendering tests pass under ThreadSanitizer, the live Avahi backend check passes, and the generated 0.5.1 package retains Qt Network/DBus dependencies plus the `avahi-daemon` recommendation. Review findings were repaired, the final fresh review found no actionable issue, and human validation confirmed adapter-scoped PTR selection, compact inline Details provenance, concise table hostnames, and cell-width elision before merge.
  - Done when the table remains value-only, selected-device details show compact hostname and service evidence lists without detached hostname labels or duplicate source attribution across short/FQDN aliases, a support bundle records capability and failure state without sensitive payloads, and deterministic conflicts select the required preferred name without discarding genuine alternate evidence.

#### MDNS-TESTS

- [x] **Add a deterministic mDNS reverse-resolution compatibility suite.** `High`
  - Test success, no reverse record, delayed response, malformed data, explicit PTR and system-resolver precedence, local-name precedence, alternate-name retention, expiry, missing daemon, missing backend, wrong interface, overlapping addresses, cancellation, and fallback behavior.
  - Include an end-to-end fixture with a controlled responder; do not rely on whatever consumer devices happen to be present on a developer LAN.
  - Current progress on `0.5.2`: deterministic contracts cover success, no record, delayed and coalesced replies, positive and negative cache expiry, malformed names and mismatched reply fields, missing daemon/backend distinctions, daemon recovery, wrong interfaces, overlapping addresses, cancellation, timeout, explicit PTR/System/Local/mDNS precedence, alternate retention, and fallback. An opt-in CTest runs the production Avahi D-Bus backend against a private D-Bus daemon and an interface-scoped Avahi responder on an isolated dummy network; it proves positive resolution, wrong-interface rejection, and prompt active cancellation without touching the consumer LAN. A bounded GitHub Actions job builds and runs that CTest fixture for relevant changes.
  - Completion evidence: normal and strict-warning suites pass 11/11, all ten non-rendering tests pass under ThreadSanitizer, both mDNS compatibility CTests pass in an isolated user/network namespace, and the live local Avahi backend check passes. The generated 0.5.2 package retains Qt D-Bus/Network dependencies and the `avahi-daemon` recommendation. Final fresh review found no code, CI, or fixture issue, and GitHub Actions run `29358490668` passed the containerized two-test compatibility suite. Human verification remains before merge.
  - Done when these tests run under CTest in CI, prove the parser/backend contract, show only the selected plain hostname in the table, and show every distinct source-labeled name in the aligned details list.

### Settings, persisted data, and export

#### TARGET-FORMAT-PREFERENCE

- [x] **Let users choose CIDR or begin/end notation for generated targets.** `Medium`
  - Add a persisted setting that formats automatically generated targets as compact CIDR notation or explicit begin/end ranges without changing which addresses will be scanned.
  - Keep CIDR and range choices semantically equivalent, preserve the existing 4,096-host and input-length protections, and use the same preference for Auto Select and adapter-specific defaults.
  - Current progress on `0.5.3`: Appearance settings offers persisted CIDR and begin/end choices, defaulting to CIDR. Auto Select and adapter-specific default planners share the preference. The formatter emits exact CIDR tokens using the production parser's `/1`–`/30` usable-host and `/31`–`/32` endpoint semantics; both renderings are constrained against the same accepted address prefix so format changes cannot alter target count, deduplication, route selection, or the 2,048-character limit.
  - Completion evidence: deterministic default-planner cases cover CIDR and range output for bounded large networks, `/20`, `/24`, `/31`, `/32`, partial multi-network plans, overlap, host caps, and text caps. Production-parser coverage proves both formats produce identical ordered host lists; Settings-flow coverage changes Auto Select from CIDR to range and an explicit second adapter from range to CIDR without changing selection or parsed hosts; settings round-trip coverage restores the range choice; and the formatter limit path completes in bounded time. Normal and strict suites pass 11/11, all ten non-rendering tests pass under ThreadSanitizer, the generated Debian package reports version 0.5.3, the initial review finding was repaired, and final fresh review found no actionable issue.
  - Done when both formats round-trip through the production parser to identical address sets, the preference survives restart, and changing it never changes adapter routing or target count.

#### SETTINGS-MIGRATIONS

- [x] **Fix settings round trips and migrations.** `High`
  - Persist an intentionally empty enabled-service set instead of restoring defaults. Make toolbar “Default” inherit the global style and preserve that sentinel across restarts.
  - Replace schema-wide `clear()` with explicit migrations, validate custom OUI input with user-visible errors, and debounce settings writes instead of writing on every target keystroke.
  - Current progress on `0.5.4`: schema 2 upgrades schema 0/1 in place without clearing unknown keys, removes legacy target history only when remember-last was not explicitly enabled, and preserves explicitly retained target data. Enabled-service persistence distinguishes an absent key from an intentionally empty list. Per-action toolbar mode `-1` remains an inheritance sentinel and resolves dynamically against every global mode; the toolbar Defaults action restores inheritance. Remembered-target edits use a restartable 350 ms save timer. Custom OUI parsing accepts comments and normalized 24-bit hexadecimal prefixes, rejects malformed lines atomically with a line-numbered warning, and validates vendor text before changing live settings.
  - Completion evidence: deterministic settings contracts cover schema 0 and 1 migration, unrelated-key retention, privacy migration branches, empty service save/load, every global and explicit toolbar mode, sentinel inheritance, known-key reset without unrelated deletion, valid and malformed OUI input, debounced rapid target edits, target-format persistence, and accepted Settings dialog behavior. Normal and strict-warning suites pass 11/11 after one loaded-run GUI benchmark retry; all ten non-rendering tests pass under ThreadSanitizer, and package metadata reports version 0.5.4. The initial atomic-acceptance review finding was repaired, focused normal and strict tests passed again, and final fresh adversarial review found no actionable issue.
  - Done when round-trip tests cover empty collections, every toolbar mode, old schemas, invalid OUI entries, and reset behavior without deleting unrelated valid preferences.

#### CSV-EXPORT

- [x] **Make CSV export safe and failure-aware.** `High`
  - Define whether export includes all, visible, or filtered rows and label that choice in the dialog. Preserve display order intentionally.
  - Prevent spreadsheet-formula execution for fields beginning with formula sigils, write through an atomic save, choose UTF-8 explicitly for every supported Qt version, and check stream, flush, close, and disk-full errors before reporting success.
  - Current progress on `0.5.5`: Export CSV first offers clearly counted Filtered rows or All rows, defaults to the filtered set, identifies that visible columns are exported, and preserves current row and visual column order. A core exporter quotes every cell, doubles quotes, retains commas/line breaks/Unicode, prefixes every required leading formula sigil, selects UTF-8 explicitly on Qt 5 and 6, and writes through `QSaveFile`. Success is reported only after stream, flush, and atomic commit checks; errors retain concrete sink detail.
  - Completion evidence: deterministic contracts cover filtered/all scope, hidden and visually reordered columns, row order, cancellation, commas, quotes, line breaks, Unicode, all formula sigils, open failure, disk-full/flush failure, commit failure, existing destination preservation, and successful atomic replacement. Normal and strict-warning suites pass 12/12, all eleven non-rendering tests pass under ThreadSanitizer, and package metadata reports version 0.5.5. The initial live-scan snapshot consistency finding was repaired, focused normal and strict tests passed again, and final fresh adversarial review found no actionable issue.
  - Done when tests cover commas, quotes, line breaks, Unicode, formula payloads, filtered rows, hidden columns, canceled saves, and injected write failures.

#### SCAN-PRIVACY

- [x] **Define target-history privacy and safe-scan behavior.** `Medium`
  - Explain that target history is persisted even when “Remember Last Target On Launch” is off, or change the behavior so the control governs retention. Provide clear-history and disable-history controls.
  - Document exactly which ICMP, TCP, HTTP, and name-resolution traffic each mode sends. Put the authorization warning where a first-time user sees it before scanning, not only in Help and README.
  - Current progress on `0.5.6`: schema 3 separates Save Target History from Remember Last Target On Launch, keeps retention disabled on clean installs, preserves an explicit schema-2 opt-in, and prevents the dependent restore choice unless retention is enabled. Disabling retention or choosing Clear removes both saved history and last-input keys immediately. A versioned first-real-scan authorization dialog appears after validation and local bind checks but before history recording or network traffic, states the authorization requirement, and lists exact active ICMP attempts, enabled TCP ports, application payload/banner behavior, neighbor-cache reads, reverse-name lookups, and retention state. The main status bar continuously shows a concise active summary with the exact detail in its tooltip; Help documents the same behavior.
  - Completion evidence: deterministic contracts cover schemas 0–2, clean-install non-retention, explicit retention and restore, immediate clear, disable-and-delete, dependent control state, mode/port/application/resolver summary content, active-scan policy and actual-retention pinning, acknowledged authorization without a modal prompt, and injected settings deletion/migration/history-write failures. Normal and strict-warning suites pass 12/12, all eleven non-rendering tests pass under ThreadSanitizer, and package metadata reports version 0.5.6. Adversarial review findings covering checked persistence, migration failure, and immutable active summaries were repaired; focused normal and strict builds/tests pass after the final repair.
  - Done when retention controls have tests, disabling retention removes saved target data, and the in-app scan summary describes the active probe set before launch.

### Testability, platform contract, and diagnostics

#### DEBUG-SCAN-FIXTURE

- [x] **Provide a hidden, deterministic high-volume scan fixture.** `Medium`
  - Treat the exact target token `test` as an internal fixture trigger. It must bypass adapter, bind, parser, and network-probe paths and must not be advertised as an ordinary target format.
  - Publish hundreds of unique benchmark-network devices through the production result queue. Cover every configured service type with both confirmed and `Unknown:<port>` evidence, known-vendor and unknown MAC addresses, known and unknown hostnames, varied service counts, and stable details.
  - Pace fixture publication by Accuracy: Fast is quickest, followed by Balanced, High, and Maximum. Stop and close must cancel promptly, while the normal result ordering, filtering, selection, and viewport invariants remain in force.
  - Current progress on `0.4.5`: the exact case-sensitive `test` token is accepted by the target control and enables scanning even without an adapter. It bypasses parsing and network setup, then publishes 768 deterministic `198.18.0.0/15` benchmark devices through the ordinary asynchronous result queue. The data covers every configured service ID with both confirmed and `Unknown:<port>` evidence, known and unknown vendors and hostnames, varied service counts, and stable details. Accuracy selects strictly increasing per-result delays, and the ordinary Stop path interrupts those delays.
  - Completion evidence: normal and strict-warning builds pass all 9 tests. The generator contract proves uniqueness, deterministic data, exact-trigger isolation, benchmark-only addressing, every service/evidence combination, mixed vendor/hostname knowledge, and pacing order. The production GUI contract proves adapter-free launch, incremental publication, all 768 final rows, and sub-second cancellation at Maximum. The eight non-rendering tests pass under ThreadSanitizer; the previously documented Qt offscreen-rendering limitation remains unchanged. A fresh adversarial review found no actionable issue, and human validation confirmed expected fixture behavior.
  - Done when deterministic tests prove data coverage, uniqueness, pacing order, no real-network dependency, cancellation, exact-trigger isolation, and stable progressive GUI presentation; human validation confirms the fixture is useful for table stability and performance checks.

#### APPLICATION-LAYERS

- [x] **Split the 3,534-line window into testable layers.** `Medium`
  - Extract target parsing, scan scheduling, process execution, name resolution, neighbor parsing, service verification, OUI lookup, settings serialization, and export from `ScannerWindow` behind small interfaces.
  - Keep UI objects on the GUI thread and pass plain immutable values across worker boundaries.
  - Completed in `0.5.18`: the build has explicit reusable `ois_core`, `ois_scan`, `ois_linux`, `ois_runtime`, and `ois_ui` targets with narrow public include paths and one-way link dependencies. Target parsing, settings/OUI policy, persistence, export, session delivery, scheduling, per-host discovery, concrete neighbor/ping/service/hostname probes, Linux gateway selection, production composition, and debug execution all run without constructing or dereferencing a window. Platform-neutral debug orchestration belongs to `ois_scan`; Linux probes belong to `ois_linux`; the composition root depends on both without reversing either layer. Pure UI-layer functions own MAC/details presentation. `ScannerWindow` captures immutable values and pure callbacks when starting `ScanSession`; UI objects remain on the owner thread.
  - Scan-runner evidence: direct contracts cover exact little-endian gateway decoding; interface, destination, mask, flags, nonzero gateway, and lowest-metric route selection; malformed/missing routes; injected production dependency creation, gateway identity, probe option propagation, vendor/details callbacks, publication, and progress; immediate fixture cancellation; ordered progressive publication; and cancellation after five results. Existing window-free backend/probe contracts retain injected network/process outcomes. Normal, warning-as-error, and release suites pass 24/24; all twenty-two sanitizer-compatible non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.18. Fresh adversarial route-policy, production-seam, and layer-ownership findings were repaired before the final gate rerun without recursive review.
  - Device-presentation evidence: a direct window-free UI-layer contract covers all seven MAC formats, malformed and unknown input, hostile values in every interpolated field, hostname provenance, verified and open-only service evidence, and genuinely empty details. Production vendor lookup and details formatting consume only immutable scan options. Normal, warning-as-error, and release suites pass 23/23; all twenty-one sanitizer-compatible non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.17.
  - Hostname-resolver evidence: a direct window-free contract preserves preliminary, suffix-selected PTR, qualified system, and independent `.local` mDNS evidence; maps every PTR, system, and mDNS outcome; proves all four Accuracy-derived timeout profiles; and stops later resolver stages at cancellation and budget boundaries. Normal, warning-as-error, and release suites pass 22/22; all twenty sanitizer-compatible non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.16. Fresh adversarial findings about missing-event masking and incomplete timeout/cutoff assertions were repaired before the final gate rerun without recursive review.
  - Service-probe evidence: direct window-free tests preserve catalog order/defaults; distinguish verified SSH, HTTPS, and SMTPS from open-only plain and failed-handshake services; interrupt a live TLS handshake; and enforce local binding, filtering, ordered `ServiceHit` propagation, between-service cancellation, and budget cutoffs. The existing deterministic protocol matrix calls `ServiceProbe` directly for HTTP, SSH, FTP, SMTP, STARTTLS, fragmentation, retries, and concise evidence. Normal, warning-as-error, and release suites pass 21/21; all nineteen sanitizer-compatible non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.15. The real TLS fixture passes every non-TSan suite and is excluded only from TSan because the system GLib/GIO backend reports internal races. Fresh adversarial TLS and scan-orchestration coverage findings were repaired before the final gate rerun without recursive review.
  - Linux-ping-probe evidence: a production-path fixture covers exact scoped arguments, retry success, attempt exhaustion, owned live-process deadline/cancellation, and immediate cancellation/budget cutoffs. Normal, warning-as-error, and release suites pass 19/19; all eighteen non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.14. A fresh adversarial orphaned-fixture-process finding was repaired before the final gate rerun without recursive review.
  - Production-backend evidence: direct window-free tests prove service probing precedes optional neighbor enrichment, discovery service evidence is reused, only confirmed neighbors establish liveness, dead hosts remain absent, local and gateway identity bypass discovery probes, unknown fields normalize consistently, every cancellation boundary suppresses later stages, and one backend supports four overlapping engine workers. Normal, warning-as-error, and release suites pass 17/17; the changed engine/backend tests pass 2/2 under ThreadSanitizer; and Debian package metadata reports version 0.5.11. The broad non-rendering sanitizer suite is 15/16 because its older `ScanSession` test reproducibly reports races in Qt queued-functor delivery; that session concern is the next APPLICATION-LAYERS correction rather than being silently attributed to this backend. Fresh adversarial concurrency, cancellation, and branch-coverage findings were repaired and every relevant gate rerun without recursive review.
  - Session-delivery correction evidence: progress, result, and completion records cross the worker boundary only under a standard mutex and are emitted by the owner-thread timer. Token identity rejects stale records after an explicit wait/restart, canceled records remain suppressed, and the worker is joined before completion. Idle polling backs off from 1 ms to 25 ms, while a maximum of 128 records per GUI turn prevents a 4,096-result burst from starving an independent zero-interval heartbeat. The session contract passes ten consecutive ThreadSanitizer repetitions and the complete sixteen-test non-rendering sanitizer suite. Normal, warning-as-error, and release suites pass 17/17, and Debian package metadata reports version 0.5.12. Fresh adversarial polling and burst-responsiveness findings were repaired before every gate was rerun without recursive review.
  - Linux-neighbor-probe evidence: injected tests cover a `DELAY` observation becoming `REACHABLE`, already-live and Fast cutoffs, canceled and expired lookup, and invalid evidence without constructing a window. A production-path fixture asserts exact scoped `ip` arguments, correct IP/interface selection amid decoys, malformed and nonzero output rejection, and bounded live-process deadline/cancellation. The neutral budget value now belongs to `ois_core`, preserving one-way platform and scan dependencies. Normal, warning-as-error, and release suites pass 18/18; all seventeen non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.13. Fresh adversarial dependency and production-path coverage findings were repaired before the final gate rerun without recursive review.
  - Core-extraction evidence: direct core tests cover single IP, CIDR `/30` through `/32`, short and full ranges, sorting/deduplication, cumulative host limits, privacy-preserving schema migration, retention writes and failures, and custom-over-built-in OUI precedence. Normal, strict-warning, and release suites pass 14/14; all thirteen non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.8. Fresh adversarial review findings were repaired by making override parsing atomic, rejecting whitespace-only targets, proving custom precedence on a collision, and directly testing history persist/clear failures. Clang-Tidy remains unavailable on the development host, so the strict warning-as-error build is the available lint gate for this increment.
  - Session-seam evidence: an injected deterministic worker proves overlap rejection, owner-thread signal delivery, progressive results and progress, one completion, prompt cooperative cancellation, and suppression of deliberately attempted late result signals. Normal, strict-warning, and release suites pass 15/15; all fourteen non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.9. ThreadSanitizer exposed Qt thread-pool teardown internals during development, so the final session owns a joinable standard worker thread and uses Qt only for queued owner-thread delivery. Fresh adversarial findings were repaired with an early window-destructor cancel/join boundary, checked worker launch and UI rollback, thread-construction exception handling, deterministic late-callback attempts, and accurate worker terminology.
  - Engine-extraction evidence: thread-safe fake backends prove exact dispatch, a four-worker ceiling with real overlap, sorted final output from reverse input, progressive publication, complete duplicate-identity enrichment, distinct same-address interface identities with deterministic tie-breaking, backend and callback exception containment, and barrier-controlled cancellation with no late publication. Normal, strict-warning, and release suites pass 16/16; all fifteen non-rendering tests pass under ThreadSanitizer; and Debian package metadata reports version 0.5.10. ThreadSanitizer exposed unsynchronized Qt future completion before final sorting, so the final engine uses joined standard workers and a standard mutex, removing the last Qt Concurrent dependency. Fresh adversarial findings were repaired by containing external callback exceptions, rechecking cancellation at each publication boundary, ordering equal addresses by interface, replacing timing-dependent cancellation coverage, and expanding identity/enrichment assertions.
  - Foundation evidence: normal and strict-warning layered suites pass 12/12, all eleven non-rendering layered tests pass under ThreadSanitizer, `BUILD_TESTING=OFF` configures and builds without Qt Test, preset discovery succeeds, and package metadata reports version 0.5.7. Adversarial review findings were repaired by moving the fixture above core into `ois_scan`, narrowing Linux exports, making Qt Test conditional, and reconciling README/toolchain/status language; full normal and strict suites plus the production-only build passed after those repairs.
  - Done when core behavior can run without constructing a window, test doubles can inject time/process/network outcomes, and `ScannerWindow` contains presentation and coordination rather than the scan implementation.

#### QUALITY-GATE

- [ ] **Establish the automated 1.0 quality gate.** `Blocker`
  - Aggregate the feature-owned CTest suites specified by items such as MDNS-TESTS, SETTINGS-MIGRATIONS, and CSV-EXPORT, then add the remaining integration, GUI, cancellation, stress, and package coverage. Add CI for the oldest and newest supported compiler/Qt combinations.
  - Preserve deeper regression coverage from completed correctness work: inject every `ScannerWindow` setting across consecutive scans, distinguish production ping/Avahi/system-resolver cancellation, count attempts in a virtual-clock 4,096-target scan, and prove cancellation interrupts its active budget without real network timing.
  - Enable project warning flags and warnings-as-errors for project sources. Run Clang-Tidy or an agreed equivalent, CMake/metadata lint, AddressSanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer scenarios where supported.
  - Done when a clean checkout has one documented command that builds and runs all required checks, CI protects the default branch, the strict build has zero project warnings, and the release job refuses an untested artifact.
  - Current progress on `0.6.0`: `scripts/quality-gate.sh` provides isolated `fast`, `full`, and `release` modes that work from a clean checkout and reuse their dedicated build trees on safe reruns. The full gate runs all 24 contracts normally and with strict conversion/sign/shadow/format warnings as errors, 23 non-recovering AddressSanitizer/UndefinedBehaviorSanitizer-compatible contracts, and 22 ThreadSanitizer-compatible contracts; the offscreen settings rendering/timing benchmark is excluded from sanitizers and the real TLS fixture is excluded only from ThreadSanitizer. Clang-Tidy runs when installed, with the strict compiler profile as the documented equivalent when unavailable. A stable Ubuntu 24.04 `quality` check now runs the full functional gate for every push and pull request while recording, but not enforcing, hardware-dependent UI wall-clock thresholds; its ASan run disables leak detection because Ubuntu's Qt system-proxy path retains `libproxy`/GLib allocations, while the local release gate enforces timing and LeakSanitizer. The newer-environment CI job, deeper production-window/budget regressions, metadata lint, and artifact dependency remain before this item can close.

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

#### SEARCH-ENRICHMENT

- [ ] **Include enrichment evidence in result searches.** `Medium`
  - Search the complete normalized result evidence rather than only the currently displayed cell text. Match IP address, MAC address, vendor, preferred and alternate hostnames including full DNS suffixes, service names, and service ports.
  - Update filtering as enrichment arrives without reordering results, resetting the model, changing selection, or disturbing the anchored viewport. Source labels and backend failure prose remain details/diagnostic presentation rather than searchable device identity.
  - Done when deterministic model tests find a row by every supported evidence field—including an alternate FQDN hidden from the table—remove and restore matches as evidence changes, and preserve active ordering, selection, and viewport behavior.

#### SERVICE-PILL-THEMING

- [ ] **Restore distinct, palette-aware service pill colors.** `Medium`
  - Give verified service families visually distinct pill colors while keeping `Unknown:<port>` neutral. Derive foreground, background, border, selection, and disabled colors from the active Qt palette so light, dark, and high-contrast themes remain legible.
  - Keep pill text, spacing, corner radius, and geometry stable across services, theme changes, selection, and live result updates. Do not reintroduce persistent cell widgets or encode verification solely through color.
  - Done when automated delegate tests prove stable geometry and sufficient text/background contrast in representative light, dark, high-contrast, selected, and disabled palettes, and the 768-device fixture retains responsive scrolling and correct concise labels.

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
