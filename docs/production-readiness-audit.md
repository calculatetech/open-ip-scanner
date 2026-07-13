# Open IP Scanner 1.0 production-readiness audit

- **Audit date:** 2026-07-13
- **Audited revision:** `91e0a7a` (`v0.2.0`, `main`)
- **Primary environment:** Debian 13.5, Linux 7.0.12, x86-64, GCC 14.2, CMake 3.31.6, Qt 6.8.2, Avahi 0.8
- **Disposition:** **No-go for 1.0**

## Executive verdict

The application is a credible prototype and its Qt 6 build succeeds, but it is not production-ready. The audit found three blockers, eighteen high-severity findings, and nine medium-severity findings. The blockers are an actual unsynchronized settings/worker data race, the complete absence of automated tests and a release quality gate, and a Debian package with policy and license-completeness errors.

The mDNS suspicion is substantially correct, with an important nuance: the Avahi command does run and return a hostname. An input/output trace of the local-only scan captured Avahi writing the audit host’s `.local` record, but result merging discarded that better name because an earlier non-`Unknown` local hostname had already won. Remote success remains unproven. The feature is also much narrower than device discovery: it runs one silent reverse-address lookup after a target is found by ping, the neighbor table, or fixed TCP ports. It does not browse DNS-SD advertisements or read SRV/TXT service metadata. That broader DNS-SD capability is not promised by the current README and is therefore documented as post-1.0 work, not misclassified as a current release blocker.

Do not tag 1.0 until every item in the [Required for 1.0](roadmap.md#required-for-10) roadmap section is complete. The roadmap, not this report, owns the remaining-work list and completion criteria.

## How to read the findings

- **Blocker:** A credible crash/undefined-behavior path, an invalid release artifact, or no way to prevent regressions.
- **High:** A core scan, enrichment, performance, integrity, or operational behavior is materially wrong.
- **Medium:** Production hardening, supportability, accessibility, privacy, or documentation is incomplete.
- **Confirmed:** Directly established by source or deterministic command output.
- **Observed:** Reproduced in the audit environment.
- **Source-supported risk:** The unsafe or pathological path is present, but this audit did not trigger it against other devices or destructive conditions.

This is a static and local-runtime audit, not a claim that every network, desktop, or distribution has been exercised. The limitations section states what could not be proven live.

## The mDNS/Avahi answer

### What the application actually does

The current flow is:

    User targets
        |
        v
    ping / existing neighbor entry / selected fixed TCP port
        |
        | only after the host is considered alive
        v
    avahi-resolve-address -4 <ip> (one process, 1.2 s application deadline)
        |
        | empty/error/timeout
        v
    synchronous system reverse resolver
        |
        v
    candidate Hostname string
        |
        v
    merge replaces only empty/Unknown hostname

    local IP and gateway are also published early with preliminary names
        |
        +----> any earlier non-Unknown name wins over the Avahi candidate

    DNS-SD service advertisements --------------------> no input path

`lookupMdnsHostname()` invokes only `avahi-resolve-address -4` (`src/scannerwindow.cpp:1436-1470`). The Services column is produced separately from a hard-coded TCP-port list (`src/scannerwindow.cpp:1506-1547`). There is no `avahi-browse`, Avahi client API, DNS-SD record model, or advertised service parser anywhere in the repository.

That distinction matters. Multicast DNS defines local name and reverse-address resolution; DNS-Based Service Discovery uses PTR records to enumerate instances, SRV records for host/port, and TXT records for instance metadata. These are separate operations in [RFC 6762](https://www.rfc-editor.org/info/rfc6762/) and [RFC 6763](https://www.rfc-editor.org/info/rfc6763/). Calling the current operation “mDNS probing” or “mDNS reverse lookup” is reasonable; calling it device discovery or service enrichment overstates it.

### What was proven locally

Avahi is installed, enabled, active, joined to IPv4 and IPv6 multicast groups on `enp2s0`, and listening on UDP 5353. The command syntax used by the application is valid:

    $ avahi-resolve-address --version
    avahi-resolve-address 0.8

    $ systemctl is-active avahi-daemon
    active

    $ avahi-resolve-address -4 10.10.30.34
    10.10.30.34    minidebian.local

An ignored, disposable Qt harness then set the real window’s target to only that local address and invoked the real scan slot:

    Scan complete. 1 host(s) detected.
    rows=1
    10.10.30.34
    minidebian
    58:47:CA:79:14:FB
    IEEE Registration Authority

The displayed name alone originally appeared to implicate the self-host shortcut at `src/scannerwindow.cpp:1131-1142`. A subsequent input/output `strace` proved that the normal worker executed Avahi for the same address and that Avahi wrote a successful answer:

    execve("/usr/bin/avahi-resolve-address",
           ["/usr/bin/avahi-resolve-address", "-4", "10.10.30.34"], ...) = 0
    write(1, "10.10.30.34\tminidebian.local\n", 29) = 29

The actual defect is merge precedence. The self row publishes `minidebian` first; the worker later obtains `minidebian.local`; `publishResult()` replaces a hostname only when the stored value equals `Unknown` (`src/scannerwindow.cpp:1109-1112`). The better Avahi result is discarded. Conversely, a gateway with no reverse mDNS record followed Avahi’s approximately five-second failure window:

    $ time avahi-resolve-address -4 10.10.30.1
    Failed to resolve address '10.10.30.1': Timeout reached
    real    0m5.007s

The application kills that operation after 1.2 seconds and records no reason. A resolved all-service browse returned no remote entries on this LAN, so there was no honest way to demonstrate a positive remote enrichment during the audit.

Source inspection shows that a successful remote name would be retained when no earlier non-`Unknown` hostname exists: `publishResult()` performs that conditional merge (`src/scannerwindow.cpp:1088-1128`), `finishScan()` rebuilds from final results (`src/scannerwindow.cpp:1894-1936`), and `addOrUpdateResultRow()` writes the name into the Hostname column (`src/scannerwindow.cpp:1968-2051`). Live remote success is still unproven.

### Why users see no Avahi enrichment

Several independent conditions produce the same visible `Unknown`:

1. The device is visible through DNS-SD but does not publish the reverse record queried by `avahi-resolve-address`.
2. The device was not first found by ping, a neighbor entry, or a selected fixed TCP port, so hostname lookup never runs.
3. The resolver executable is absent, its daemon is unavailable, multicast is blocked, the record is absent, the answer arrives after 1.2 seconds, or output is malformed. Every case is silently discarded.
4. A result arrives on another interface or an overlapping private link. The mDNS call is not scoped to the selected adapter.
5. The scanned device is the local machine or pre-published gateway. Avahi can run later, but its better result is discarded when the earlier hostname is already non-`Unknown`.
6. Avahi did succeed, but the table has no field provenance, so an Avahi hostname and a system-resolver hostname look identical.

The required correction is itemized in [ROADMAP-008](roadmap.md#roadmap-008), [ROADMAP-009](roadmap.md#roadmap-009), and [ROADMAP-010](roadmap.md#roadmap-010).

## Findings summary

| Area | Blocker | High | Medium | 1.0 assessment |
|---|---:|---:|---:|---|
| mDNS and DNS-SD | 0 | 4 | 1 | Promised reverse-hostname enrichment is unreliable and opaque; DNS-SD is post-1.0 |
| Core scan engine | 1 | 6 | 0 | Race, cancellation, timing, accuracy, and scaling failures |
| Settings, data, and export | 0 | 3 | 2 | Persistence, integrity, and vendor-data gaps |
| Platform contract | 0 | 1 | 1 | Current Windows/Qt 5 claim is unsupported; IPv6 is absent |
| Quality architecture | 1 | 0 | 1 | No tests/CI gate; monolith prevents practical isolation |
| Operations | 0 | 1 | 0 | External dependency failures are opaque |
| Packaging and release | 1 | 3 | 0 | Lintian/AppStream/hardening/uninstall failures |
| UX and accessibility | 0 | 0 | 2 | Startup warning and unverified accessibility/theme behavior |
| Privacy and scan disclosure | 0 | 0 | 1 | Persistent targets and hidden extra probes need controls |
| Documentation and support | 0 | 0 | 1 | Claims and release/support contract do not match the product |
| **Total** | **3** | **18** | **9** | **No-go** |

## Detailed findings

### mDNS and DNS-SD

- **MDNS-01 — Reverse lookup is not DNS-SD discovery or service enrichment.** `Medium · Confirmed scope gap`

  `lookupMdnsHostname()` can supply only one name for an address the scanner already knows. It cannot enumerate service instances, import advertised ports or TXT attributes, or add a DNS-SD-only device. The fixed TCP probe table is unrelated to Avahi. This explains why no advertised service data appears, but the current README promises only optional “mDNS hostname resolution,” so full DNS-SD browsing is clarified future scope rather than a 1.0 defect. See post-1.0 [ROADMAP-029](roadmap.md#roadmap-029).

- **MDNS-02 — A successful local Avahi name is discarded by merge precedence.** `High · Confirmed and observed`

  Hostname lookup occurs only after ping, neighbor lookup, or selected TCP probes mark a target alive (`src/scannerwindow.cpp:1191-1235`, `1275-1309`). The self row is also published early with `QHostInfo::localHostName()` (`1131-1142`), but the normal worker does not skip it: tracing captured `avahi-resolve-address -4 10.10.30.34`. The controlled scan still displayed `minidebian` instead of Avahi’s `minidebian.local` because `publishResult()` will not replace one non-`Unknown` hostname with a better one (`1109-1112`). See [ROADMAP-008](roadmap.md#roadmap-008) and [ROADMAP-009](roadmap.md#roadmap-009).

- **MDNS-03 — Every failure and every success source is opaque.** `High · Confirmed`

  Missing executable, start failure, daemon failure, timeout, nonzero exit, empty output, and malformed output all return an empty string without a log or status (`src/scannerwindow.cpp:1439-1462`). The synchronous system reverse resolver then runs and may also become `Unknown` (`1416-1433`); depending on host NSS configuration, that resolver may itself consult files, mDNS, or unicast DNS. `ScanResult` stores no source (`src/scannerwindow.h:47-57`), so even success cannot be identified as Avahi. See [ROADMAP-009](roadmap.md#roadmap-009) and [ROADMAP-017](roadmap.md#roadmap-017).

- **MDNS-04 — The resolver is per-host, hard-deadlined, unscoped, and not cancellable.** `High · Confirmed with observed timing`

  Each live remote host spawns a child process and waits up to 1,200 ms (`src/scannerwindow.cpp:1444-1448`). The selected interface is not passed into hostname lookup (`1223`, `1294`, `1436-1445`), and neither the Avahi nor `QHostInfo::fromName()` call receives the cancellation token. At four workers, 254 live devices without reverse records can consume about 76 seconds in application-side Avahi waits alone. Multi-homed and overlapping-address correctness is undefined. See [ROADMAP-002](roadmap.md#roadmap-002), [ROADMAP-008](roadmap.md#roadmap-008), and [ROADMAP-009](roadmap.md#roadmap-009).

- **MDNS-05 — There is no controlled compatibility test or adequate operational contract.** `High · Confirmed`

  CMake has no tests. The Debian package only recommends `avahi-utils` (`CMakeLists.txt:101-102`), and README calls it optional without explaining daemon state, multicast/firewall constraints, the reverse-record limitation, expected UI evidence, or troubleshooting (`README.md:32-39`). The audit LAN had no remote advertisement, demonstrating why opportunistic developer testing is insufficient. See [ROADMAP-010](roadmap.md#roadmap-010), [ROADMAP-019](roadmap.md#roadmap-019), and [ROADMAP-024](roadmap.md#roadmap-024).

### Core scan engine

- **CORE-01 — Preferences can race active workers and cause undefined behavior.** `Blocker · Confirmed`

  The Settings menu remains active during a scan. Accepting the dialog writes `maxParallelProbes_`, `accuracyLevel_`, `macDisplayFormat_`, `enabledServiceIds_`, and `customOuiVendors_` (`src/scannerwindow.cpp:2805-2855`) while scan code reads those same fields and containers (`1168`, `1177-1234`, `1404-1413`, `1522-1547`, `1598-1633`, `2936-2992`). There is no shared lock, atomic wrapper, immutable snapshot, or UI exclusion. Qt documents its ordinary implicitly shared value containers as reentrant, not safe for simultaneous access to the same instance; unsynchronized C++ scalar access is also a data race. A crash is not required for this to be a release blocker. See [ROADMAP-001](roadmap.md#roadmap-001).

- **CORE-02 — Stop and close are not bounded.** `High · Confirmed`

  Cancellation is checked only between blocking pings, process waits, socket waits, DNS lookups, detail probes, and hosts. `closeEvent()` then blocks the GUI thread in `scanWatcher_.waitForFinished()` (`src/scannerwindow.cpp:761-768`). At Maximum accuracy, one ping helper alone may wait four times for as much as 5.5 seconds before checking cancellation (`1327-1345`, `2962-2969`). The window can look hung during shutdown. See [ROADMAP-002](roadmap.md#roadmap-002).

- **CORE-03 — High and Maximum accuracy repeat missed hosts serially.** `High · Confirmed`

  After the parallel pass, accuracy levels 2 and 3 loop over every missed host on one thread and repeat ping, neighbor, and service probes (`src/scannerwindow.cpp:1255-1311`). This defeats the worker setting and duplicates traffic. From the code’s enforced process/socket deadlines, a fully unresponsive 4,096-target Maximum scan at the default four workers has a source-derived upper bound measured in tens of hours; any hosts eventually found can then add blocking system-resolver work. Exact live time depends on early OS errors, but the algorithmic failure is deterministic. See [ROADMAP-003](roadmap.md#roadmap-003).

- **CORE-04 — Auto can generate targets that Scan immediately rejects.** `High · Confirmed`

  Default-network detection accepts prefixes from `/1` through `/30` and emits the whole CIDR (`src/scannerwindow.cpp:514-575`, `643-650`). Parsing rejects any CIDR with more than 4,096 usable hosts (`926-940`). A common `/16` therefore produces a red, unusable default; multiple otherwise valid networks can also exceed the cumulative cap. Valid `/31` links are excluded from defaults. See [ROADMAP-004](roadmap.md#roadmap-004).

- **CORE-05 — Incomplete ARP entries can become false-positive devices.** `High · Confirmed`

  `/proc/net/arp` results are accepted by matching only IP and interface, without checking flags or rejecting the all-zero MAC (`src/scannerwindow.cpp:1363-1379`). Any nonempty string then makes a ping-failed target “alive” (`1197-1201`, `1277-1280`). Neighbor state, freshness, and link identity are not modeled. See [ROADMAP-005](roadmap.md#roadmap-005).

- **CORE-06 — An open port is presented as a verified service, and details overclaim evidence.** `High · Confirmed`

  A successful TCP connect to a conventional port creates labels such as HTTPS, SSH, RDP, or SMTP without a protocol handshake (`src/scannerwindow.cpp:1506-1569`). `collectDeviceDetails()` runs for every result, and for hosts already found to expose HTTP, SSH, FTP, or Telnet it performs extra HTTP/banner requests even when the pane is hidden (`1216-1235`, `1710-1760`). It also labels a weak string heuristic as “OS signature.” This can misinform users and generate under-disclosed traffic for service-positive hosts. See [ROADMAP-006](roadmap.md#roadmap-006).

- **CORE-07 — The result table has quadratic-style update work and broken service sorting.** `High · Source-supported risk`

  Every result linearly searches rows, may sort the whole table, filters every row, and resizes columns to contents (`src/scannerwindow.cpp:1968-2125`, `2300-2305`, `3374-3382`, `3419-3441`). `finishScan()` rebuilds every result through the same path (`1908-1914`). Service cells retain empty item text while buttons carry the visible data (`2052-2075`, `2089-2108`), so sorting the Services column compares empty cells. No 4,096-row stress test exists. See [ROADMAP-007](roadmap.md#roadmap-007).

### Settings, data, and export

- **DATA-01 — “Disable all service probes” does not survive restart.** `High · Confirmed`

  Saving an empty enabled-service set is valid, but loading clears defaults only if the stored list is nonempty (`src/scannerwindow.cpp:3087-3095`). After a user disables every probe, the next launch silently restores HTTP, HTTPS, SSH, and RDP defaults from `applyDefaultSettings()` (`2995-3011`). This is both a correctness and scan-intent violation. See [ROADMAP-011](roadmap.md#roadmap-011).

- **DATA-02 — Toolbar “Default” does not inherit the global style.** `Medium · Confirmed`

  The UI represents Default as `-1` (`src/scannerwindow.cpp:2601-2607`, `2754-2781`), but rendering clamps it to icon-only (`3344-3347`) and loading clamps persisted `-1` to `0` (`3064-3069`). Defaults also prepopulate every button with an explicit icon-only override (`3003-3008`), making the global display choice ineffective for those actions. See [ROADMAP-011](roadmap.md#roadmap-011).

- **DATA-03 — Merged rows can retain stale details.** `Medium · Confirmed`

  `publishResult()` upgrades MAC, vendor, hostname, and services independently, but replaces details only when the old details string is empty (`src/scannerwindow.cpp:1088-1123`). A gateway or duplicate result can therefore display improved columns while its details pane still says `Unknown` or lists an earlier service set. See [ROADMAP-006](roadmap.md#roadmap-006).

- **DATA-04 — CSV export lacks spreadsheet and write-failure defenses.** `High · Confirmed code path / source-supported exploit risk`

  `csvEscape()` only quotes and doubles quote characters (`src/scannerwindow.cpp:3481-3486`); spreadsheet formula sigils are preserved. Network-derived or custom vendor text can therefore become an active formula when opened in common spreadsheet software. Export also reports success without checking `QTextStream` status, flush/close errors, or disk-full behavior (`2380-2417`), and silently includes filtered-out rows while exporting only visible columns. See [ROADMAP-012](roadmap.md#roadmap-012).

- **DATA-05 — The OUI database has no auditable supply or correctness lifecycle.** `High · Confirmed`

  A 6.3 MB IEEE-style MA-L text dump was committed once with no source URL, retrieval date, checksum, update script, or redistribution notice. The parser supports only six-hex-digit prefixes (`src/scannerwindow.cpp:470-512`, `3488-3498`), accepts non-hex custom prefixes, and does not distinguish locally administered/randomized addresses before assigning a vendor. The generated Debian package also omits all copyright files. See [ROADMAP-018](roadmap.md#roadmap-018) and [ROADMAP-019](roadmap.md#roadmap-019).

### Platform contract

- **PLATFORM-01 — The advertised Windows and Qt 5 support is not implemented or tested.** `High · Confirmed`

  README advertises Linux and Windows builds and CMake falls back to any discoverable Qt 5 (`README.md:3`, `CMakeLists.txt:12-18`). On non-Linux, ping always returns false, MAC lookup and gateway lookup return empty, and Avahi returns empty (`src/scannerwindow.cpp:1321-1357`, `1360-1401`, `1436-1474`, `1477-1504`). At the default Balanced accuracy, remote devices are not rescued by TCP discovery. About also says “Qt6” even in a Qt 5 build (`2885-2894`). No Windows or Qt 5 CI exists. See [ROADMAP-016](roadmap.md#roadmap-016) and post-1.0 [ROADMAP-026](roadmap.md#roadmap-026).

- **PLATFORM-02 — The product is IPv4-only and does not state that contract clearly.** `Medium · Confirmed`

  Target validation, interface selection, masks, sorting, ping, neighbor lookup, binding, and Avahi explicitly reject or skip IPv6 (`src/scannerwindow.cpp:518-545`, `888-1008`, `1439-1446`). IPv6 multicast groups being available on the audit host cannot help. Scope 1.0 truthfully to IPv4 and defer complete IPv6 work rather than partially enabling a field. See [ROADMAP-016](roadmap.md#roadmap-016) and post-1.0 [ROADMAP-025](roadmap.md#roadmap-025).

### Quality architecture and operations

- **QUALITY-01 — There are zero automated tests, no lint target, and no CI.** `Blocker · Observed`

  CMake defines only the executable, install, package, and uninstall targets (`CMakeLists.txt:1-120`). `ctest --test-dir build-audit -N` reported `Total Tests: 0`; target help listed no lint target; the repository has no CI configuration. A manually enabled strict GCC build linked but emitted four project warnings. The current mDNS, parser, settings, cancellation, concurrency, UI, export, install, and package behavior can all regress without a gate. See [ROADMAP-010](roadmap.md#roadmap-010), [ROADMAP-014](roadmap.md#roadmap-014), and [ROADMAP-015](roadmap.md#roadmap-015).

- **QUALITY-02 — Almost the entire product is one window implementation.** `Medium · Confirmed`

  `src/scannerwindow.cpp` is 3,534 lines and owns UI, target parsing, routing, process execution, scan scheduling, concurrency, DNS, mDNS, ARP, ports, banners, OS inference, settings, vendor data, export, print, and launcher behavior. Private methods directly depend on UI-owned state, which is why deterministic tests and safe worker ownership are difficult. See [ROADMAP-014](roadmap.md#roadmap-014).

- **OPS-01 — External dependency and scan failures are operationally invisible.** `High · Confirmed`

  Failed or missing `ping`, `ip`, Avahi, DNS, and most socket probes collapse into false/empty values. Final status usually says only that no responding hosts were detected (`src/scannerwindow.cpp:1321-1474`, `1947-1957`). There is no log level, per-method count, capability check, diagnostic export, or distinction between “no host” and “scanner backend failed.” See [ROADMAP-017](roadmap.md#roadmap-017).

### Packaging and release

- **PACKAGE-01 — The generated Debian package fails basic policy and license checks.** `Blocker · Observed`

  CPack successfully generated `open-ip-scanner_0.2.0_amd64.deb`, but Lintian reported five errors, twelve warnings, and one informational hardening issue. Errors were empty extended description, missing changelog, missing copyright file, malformed maintainer phrase, and unstripped binary. Ten installed directories were mode `0775`; warnings also covered failed AppStream metadata and no manual page. Omitting the MIT notice from the binary package also defeats the repository license’s redistribution condition. See [ROADMAP-019](roadmap.md#roadmap-019).

- **PACKAGE-02 — AppStream metadata does not pass validation.** `High · Observed`

  `desktop-file-validate` and XML well-formedness passed, but `appstreamcli validate --no-net` exited 3. It reported a non-reverse-DNS component ID and missing homepage, plus informational omissions for content rating and developer information. The file also has no release history, screenshots, or version linkage (`resources/linux/open-ip-scanner.metainfo.xml:1-16`). See [ROADMAP-020](roadmap.md#roadmap-020).

- **PACKAGE-03 — Release hardening and provenance do not exist.** `High · Observed and confirmed`

  CMake defines no warning, hardening, reproducibility, or release-policy flags. `hardening-check` found no immediate binding, stack-protector symbol, or fortified functions in the Release binary; `readelf` confirmed no `BIND_NOW`. There is no release workflow, clean-tree guard, SBOM, checksum/signature generation, build provenance, or compatibility build matrix. The package built on Debian 13 requires its newer Qt symbol set, but no oldest-supported distribution is defined. See [ROADMAP-015](roadmap.md#roadmap-015) and [ROADMAP-021](roadmap.md#roadmap-021).

- **PACKAGE-04 — Uninstall can remove a separate local installation.** `High · Confirmed`

  The uninstall script always appends `~/.local` files when `$HOME` exists (`cmake_uninstall.cmake.in:27-41`), even when the install manifest refers to a system or different prefix. Running generic uninstall can therefore delete both the manifest installation and an unrelated local copy. Install-time cache refresh can also invoke desktop tools in the installing user/root context (`CMakeLists.txt:76-89`) rather than relying on package triggers. See [ROADMAP-022](roadmap.md#roadmap-022).

### UX, accessibility, privacy, and documentation

- **UX-01 — Clean Qt 6 startup emits a high-DPI policy-order warning.** `Medium · Observed`

  `main.cpp:11-14` writes `QT_SCALE_FACTOR_ROUNDING_POLICY` immediately before constructing `QApplication`, but Qt 6.8.2 emitted `setHighDpiScaleFactorRoundingPolicy must be called before creating the QGuiApplication instance` on every offscreen startup. A valid policy supplied externally produced the same application startup warning path. Use the supported pre-application API or remove the override. See [ROADMAP-023](roadmap.md#roadmap-023).

- **UX-02 — Accessibility and theme behavior have no acceptance evidence.** `Medium · Source-supported risk`

  Main actions default to icon-only text removal, with no explicit accessible names in source (`src/scannerwindow.cpp:3338-3371`). Selection and service colors are hard-coded (`113-146`, `275-293`) rather than derived entirely from palette roles, and dense settings pages have no scroll container. User-facing strings are hard-coded rather than translatable. No keyboard-only, screen-reader, contrast, or high-scale test exists. See [ROADMAP-023](roadmap.md#roadmap-023) and post-1.0 [ROADMAP-028](roadmap.md#roadmap-028).

- **PRIVACY-01 — Persistent target data and extra active probes are under-disclosed.** `Medium · Confirmed`

  Every scan saves target history, and `saveSettings()` writes the last target even when “Remember Last Target On Launch” is false (`src/scannerwindow.cpp:3229-3243`, `3177-3214`). There is no clear-history or disable-history control. For hosts with detected HTTP, SSH, FTP, or Telnet, details collection sends an HTTP HEAD or reads an application banner whether the pane is shown or not (`1710-1760`). The authorization warning exists only in README and Help (`README.md:120-122`, `src/scannerwindow.cpp:2922`). See [ROADMAP-006](roadmap.md#roadmap-006) and [ROADMAP-013](roadmap.md#roadmap-013).

- **DOCS-01 — Product claims and release/support documentation drift from behavior.** `Medium · Confirmed`

  Windows and Qt 5 claims conflict with Linux-only backends and a Qt6-only About message. CHANGELOG says the RDP launcher includes `:3389`, while the default command does not (`CHANGELOG.md:21`, `src/scannerwindow.cpp:3015-3017`). There is no support matrix, mDNS troubleshooting, privacy/traffic description, security-reporting policy, release checklist, known-limitations document, or complete changelog history. See [ROADMAP-016](roadmap.md#roadmap-016) and [ROADMAP-024](roadmap.md#roadmap-024).

## Validation results

| Check | Result | Evidence / interpretation |
|---|---|---|
| Debug configure and build | Pass | Qt 6.8.2 target linked successfully |
| Release build with manual strict warnings | Build pass, lint fail | Four warnings: three `qsizetype`→`int` conversions and one shadowing warning |
| CTest | Fail as a release gate | `No tests were found!!!` / `Total Tests: 0` |
| Project lint target | Missing | CMake target help lists none; Clang-Tidy, Cppcheck, Clazy, and Markdownlint are not configured or installed |
| ASan/UBSan offscreen startup | Limited pass | No sanitizer finding during three-second startup; this did not exercise an active scan and timeout termination bypassed a normal leak check |
| Offscreen application startup | Functional with warning | Window event loop stayed up; high-DPI policy-order warning emitted |
| Local-only real scan harness plus process trace | Merge defect reproduced | Avahi executed for the self IP, but the row retained the earlier `minidebian` instead of `minidebian.local` |
| Direct Avahi positive lookup | Pass | Local IPv4 resolved to `minidebian.local` |
| Direct Avahi negative lookup | Five-second timeout | Demonstrates why the app’s 1.2-second silent kill is observable only as missing data |
| Resolved DNS-SD browse | No remote fixture found | No entry was available to prove positive remote UI enrichment |
| Desktop entry validation | Pass | `desktop-file-validate` exited 0 |
| XML well-formedness | Pass | AppStream XML and SVG passed `xmllint --noout` |
| AppStream validation | Fail | Exit 3; two warnings, two informational omissions, one pedantic item |
| CPack Debian generation | Pass | Package generated with shlib dependencies plus `iputils-ping`, `iproute2`, and recommended `avahi-utils` |
| Lintian | Fail | 5 errors, 12 warnings, 1 info |
| Binary hardening inspection | Fail against a production baseline | PIE and RELRO present; immediate binding absent; no detected stack protector or fortification |

The build and audit commands, including the disposable self-scan harness, are preserved in `docs/execplans/1.0-production-readiness-audit.md` and should become automated targets through [ROADMAP-015](roadmap.md#roadmap-015).

## What is already sound

Several implementation choices should be retained while refactoring:

- The Qt 6 Debug and Release builds complete on the audit host.
- Target input is bounded to 4,096 unique IPv4 addresses before large host lists are materialized.
- Service sockets bind to the selected local IPv4, and ping/neighbor commands include the selected interface.
- External launch commands use `QProcess` argument splitting rather than a shell, and executable existence is checked.
- Avahi command syntax and successful-output parsing are valid for Avahi 0.8.
- Successful remote hostname data has a clear merge path into the final table.
- The desktop file is valid, the XML/SVG files are well-formed, and CPack computes shared-library dependencies.
- HTML print output escapes cell text, and CSV quoting correctly handles commas, quotes, and line breaks even though formula/write defenses remain missing.

These positives do not offset the release blockers, but they narrow the necessary redesign.

## Audit limitations

- The LAN exposed no remote DNS-SD service during the audit. The remote success path is supported by source review, not a live device result.
- No broad LAN scan was launched. The disposable harness targeted only the audit machine’s own IPv4 to avoid impacting other systems.
- No Windows, macOS, Qt 5, IPv6 target, multi-interface overlap, VPN, large subnet, printer, cast device, or sleeping mobile device was available for live validation.
- No destructive disk-full export, package install into the host root, or uninstall was performed. Those findings come from source, staged package contents, and validators.
- Sanitizers covered startup only. There is no injectable scan engine or test suite with which to exercise timeout and data-race paths safely; that absence is itself a blocker.
- Accessibility observations are source-supported risks, not the result of a complete assistive-technology study.

## 1.0 exit criteria

The release becomes a candidate—not automatically a final release—when all [Required for 1.0](roadmap.md#required-for-10) items are checked with linked evidence. At minimum, the candidate must have no shared-state race, bounded cancellation, reliable and observable interface-scoped mDNS reverse-hostname enrichment, deterministic tests, a responsive 4,096-row UI, truthful Linux/IPv4/Qt support claims, policy-clean packaging, passing AppStream metadata, documented data licensing, hardened signed artifacts, and a clean-machine operator runbook.

Until then, retain the `0.x` version line and describe the Avahi behavior only as experimental best-effort reverse hostname lookup.
