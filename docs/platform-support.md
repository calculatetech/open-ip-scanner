# Platform support

Open IP Scanner 1.0 supports Linux on x86-64 processors, IPv4 scanning, and Qt
6.4 or newer. The application intentionally rejects unsupported operating
systems and processor architectures at CMake configure time because its ping,
neighbor, route, and mDNS discovery implementations are Linux-specific.

## Tested matrix

| Environment | Role | Qualification |
| --- | --- | --- |
| Ubuntu 24.04, Qt 6.4, GCC 13 | Compatibility floor and package builder | Full automated quality gate on every main push and pull request; downstream tested package is built here after both environments pass and is installed in a clean Ubuntu container |
| Debian 13, Qt 6.8, GCC 14 | Newer toolchain and package consumer | Full automated quality gate on every main push and pull request; the exact Ubuntu-floor package is installed, launched offscreen, and removed in a clean Debian 13 container |
| Kubuntu 26.04 | Release-candidate desktop | Complete manual light/dark, high-contrast, 100%/200% scaling, keyboard/accessibility, installation, scan/stop, export, and uninstall smoke passed on 2026-07-15 |

The Qt contract is a minimum of 6.4 rather than an unbounded promise about
future major versions. Every environment advertised as tested must run the
repository quality gate. Release packages are built on the Ubuntu 24.04 floor
so generated symbol requirements do not accidentally require the newer Debian
13 Qt ABI. Packaging retains those generated version requirements while using
Debian alternative relations for the Qt binary-package names that differ
between Ubuntu 24.04 and Debian 13.

## Explicit exclusions

Windows, macOS, ARM, Qt 5, and IPv6 scanning are outside the 1.0 support
contract. Portable core algorithms may compile elsewhere, but that is not a
supported application build without complete discovery backends and the same
release qualification. These exclusions avoid presenting partial discovery as
a working network scanner.
