# Platform support

Open IP Scanner 1.0 supports Linux on x86-64 processors, IPv4 scanning, and Qt
6.4 or newer. The application intentionally rejects unsupported operating
systems and processor architectures at CMake configure time because its ping,
neighbor, route, and mDNS discovery implementations are Linux-specific.

## Tested matrix

| Environment | Role | Qualification |
| --- | --- | --- |
| Ubuntu 24.04, Qt 6.4, GCC 13 | Compatibility floor and package builder | Full automated quality gate on every main push and pull request; downstream tested package is built here after both environments pass |
| Debian 13, Qt 6.8, GCC 14 | Newer toolchain | Full automated quality gate on every main push and pull request |
| Kubuntu 26.04 | Release-candidate desktop | Manual light/dark, scaling, keyboard, installation, scan, and uninstall smoke test remains required before 1.0 |

The Qt contract is a minimum of 6.4 rather than an unbounded promise about
future major versions. Every environment advertised as tested must run the
repository quality gate. Release packages must be built on the Ubuntu 24.04 floor
so their generated shared-library dependencies do not accidentally require the
newer Debian 13 Qt ABI.

## Explicit exclusions

Windows, macOS, ARM, Qt 5, and IPv6 scanning are outside the 1.0 support
contract. Portable core algorithms may compile elsewhere, but that is not a
supported application build without complete discovery backends and the same
release qualification. These exclusions avoid presenting partial discovery as
a working network scanner.
