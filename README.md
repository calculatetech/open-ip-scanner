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
environment. Kubuntu 26.04 is scheduled for the release-candidate desktop smoke
test; it is not yet a completed support claim. Windows, macOS, Qt 5, ARM, and
IPv6 scanning are not supported for 1.0 because they do not have complete
discovery backends and release qualification.

See [the canonical platform support contract](docs/platform-support.md) for the
tested matrix and qualification boundaries.

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
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Run:

```bash
./build/open-ip-scanner
```

## Quality gates

Run the normal build, metadata lint, and all CTest contracts:

```bash
./scripts/quality-gate.sh fast
```

`full` adds warnings-as-errors, supported sanitizers, and Clang-Tidy when it is
available. `release` runs that complete gate, then builds and tests the exact
Debian package placed in `build/release-artifacts/`.

## Install (local)

```bash
cmake --build build --target install-local
```

This target installs under `~/.local` and refreshes available desktop caches as
the current non-root user. Generic and packaged installs do not invoke user
session cache tools; distribution packages use their normal triggers.

## Uninstall (local)

```bash
cmake --build build --target uninstall-local
```

Generic uninstall target (uses the last atomic uninstall-state manifest):

```bash
cmake --build build --target uninstall
```

The local uninstall target refreshes the same available desktop caches after
removing only the known Open IP Scanner files beneath `~/.local`.

## Debian Packaging

Packaging metadata is included via CPack in `CMakeLists.txt`.

When ready to generate a `.deb`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cpack --config build/CPackConfig.cmake -G DEB
```

## Notes

- Scanning accuracy depends on target behavior (ICMP, ARP visibility, firewall rules, sleeping devices).
- Android/iOS devices may be intermittent due to power saving and private MAC behavior.
- Use this tool only on networks you own or are authorized to test.

## License

See `LICENSE`.
