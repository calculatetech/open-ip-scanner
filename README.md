# Open IP Scanner

A Qt-based desktop IP scanner for Linux (and Windows builds) focused on practical network discovery: live hosts, hostnames, MAC/vendor lookup, service probing, filtering, and export.

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
- Device details pane with additional detected info
- OUI vendor lookup from embedded IEEE data + custom user overrides
- MAC display format options (colon/hyphen/cisco/plain, upper/lower)
- Search/filter bar with scope selection (all columns, vendor, services, OUI prefix, etc.)
- CSV export and print support
- Toolbar customization (Dolphin/Kate style: available/current actions, order, separators, style)
- Settings persistence with schema versioning
- Linux desktop integration assets (`.desktop`, icon, metainfo)

## Prerequisites

### Runtime (Linux)

- `iputils-ping`
- `iproute2`
- Optional for mDNS hostname resolution: `avahi-utils`

### Build

- CMake >= 3.16
- C++17 compiler (GCC/Clang)
- Qt 6 dev packages (or Qt 5 fallback is supported by CMake):
  - `Widgets`
  - `Network`
  - `Concurrent`
  - `PrintSupport`

Example (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build \
  qt6-base-dev qt6-tools-dev \
  iputils-ping iproute2 avahi-utils
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

## Install (local)

```bash
cmake --install build --prefix ~/.local
```

If icon/menu updates lag on KDE:

```bash
gtk-update-icon-cache ~/.local/share/icons/hicolor
update-desktop-database ~/.local/share/applications
kbuildsycoca6
```

## Uninstall (local)

```bash
cmake --build build --target uninstall-local
```

Generic uninstall target (uses install manifest):

```bash
cmake --build build --target uninstall
```

If desktop/icon cache entries linger:

```bash
update-desktop-database ~/.local/share/applications
kbuildsycoca6 --noincremental
```

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
