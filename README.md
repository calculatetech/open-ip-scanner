# Open IP Scanner

A Qt-based desktop IPv4 scanner for Linux x86-64 focused on practical network discovery: live hosts, hostnames, MAC/vendor lookup, service probing, filtering, and export.

Yes, this project is **100% vibe coded**.

## Features

- Auto-detect connected routable subnets
- Custom target input:
  - CIDR (`192.168.1.0/24`)
  - Explicit ranges (`10.0.0.10-10.0.0.50`)
  - Short ranges (`10.0.0.10-50`)
  - Comma-separated combinations
- Adapter-aware scanning and quick adapter refresh
- Parallel scanning with tunable performance and accuracy
- Progressive results table with:
  - IP, Hostname, MAC, Vendor, Services
  - Sorting, column reordering, column visibility controls
  - Alternate row highlighting
- Service probing (configurable ports/services)
- Clickable service actions (launch browser/SSH/etc. via configured programs)
- Device details pane with concise hostname and service evidence sources
- Redacted hostname diagnostics and support-bundle export
- OUI vendor lookup from embedded IEEE data + custom user overrides
- MAC display format options (colon/hyphen/cisco/plain, upper/lower)
- Search/filter bar with scope selection (all columns, vendor, services, OUI prefix, etc.)
- CSV export and print support
- Toolbar customization (Dolphin/Kate style: available/current actions, order, separators, style)
- Settings persistence with schema versioning
- Linux desktop integration assets (`.desktop`, icon, metainfo)

## Supported platform

The 1.0 support contract is Linux x86-64, IPv4, and Qt 6.4 or newer. Ubuntu
24.04 is the compatibility floor and Debian 13 is the newer continuously tested
environment. Kubuntu 26.04 passed the complete release-candidate desktop smoke
test. Windows, macOS, Qt 5, ARM, and IPv6 scanning are not supported for 1.0
because they do not have complete discovery backends and release qualification.

See [the canonical platform support contract](docs/platform-support.md) for the
tested matrix and qualification boundaries.

## Documentation

- [User guide](docs/user-guide.md): install, scan modes, results, troubleshooting,
  privacy, upgrade, and uninstall
- [Known limitations](docs/known-limitations.md): discovery and support boundaries
- [Support](docs/support.md): non-sensitive bug reports and support bundles
- [Security and privacy](docs/security.md): authorized use, local data, and
  private vulnerability reporting
- [Data provenance](docs/data-provenance.md): embedded IEEE assignment snapshot
- [Release-candidate checklist](docs/release-checklist.md): automated, manual,
  package, SBOM, attestation, and human approval gates

## Prerequisites

### Runtime (Linux)

- `iputils-ping`
- `iproute2`
- Optional for mDNS hostname resolution: `avahi-daemon`

### Build

- CMake >= 3.28
- C++17 compiler (GCC/Clang)
- Python 3 with PyYAML, `appstreamcli`, `desktop-file-validate`, and `xmllint`
  for the quality gate
- Qt 6.4 or newer development packages:
  - `Widgets`
  - `Network`
  - `PrintSupport`
  - `DBus`

Example (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y \
  appstream build-essential cmake desktop-file-utils libxml2-utils ninja-build \
  python3 python3-yaml \
  qt6-base-dev qt6-tools-dev \
  iputils-ping iproute2 avahi-daemon
```

## Build

```bash
cmake --preset dev
cmake --build --preset dev
```

Run the stable developer validation binary:

```bash
./build/dev/open-ip-scanner
```

All repository-local generated output lives beneath `build/`. Remove that one
directory at any time to return to a source-only working tree.

## Quality gates

Run the normal build, metadata lint, and all CTest contracts:

```bash
./scripts/quality-gate.sh fast
```

`full` adds warnings-as-errors, supported sanitizers, and Clang-Tidy when it is
available. `release` runs that complete gate, then builds and tests the exact
Debian package placed in `release/`. That directory contains only installable
packages; reproducibility and provenance intermediates are removed.

## Install (local)

```bash
cmake --preset release
cmake --build --preset release --target install-local
```

This target installs under `~/.local` and refreshes available desktop caches as
the current non-root user. Generic and packaged installs do not invoke user
session cache tools; distribution packages use their normal triggers.

## Uninstall (local)

```bash
cmake --build --preset release --target uninstall-local
```

Generic uninstall target (uses the last atomic uninstall-state manifest):

```bash
cmake --build --preset release --target uninstall
```

The local uninstall target refreshes the same available desktop caches after
removing only the known Open IP Scanner files beneath `~/.local`.

## Debian Packaging

Packaging metadata is included via CPack in `CMakeLists.txt`.

When ready to generate and fully validate a `.deb`:

```bash
./scripts/build-release-artifact.sh
```

The installable package is written to `release/`. Rebuilding the same version
atomically replaces only that version's package; other releases are retained
until a human removes them. Direct CPack output is scratch data and is not a
supported publication path.

## Notes

- Scanning accuracy depends on target behavior, enabled probes, neighbor
  visibility, firewalls, and power saving. Absence is not proof that an address
  is unused.
- Use this tool only on networks you own or are authorized to test. See the
  [user guide](docs/user-guide.md) before scanning a production network.

## License

See `LICENSE`.
