# Desktop metadata and identity

Open IP Scanner uses `io.github.calculatetech.OpenIpScanner` as its stable
Linux desktop and AppStream identity. The installed desktop entry, AppStream
component, hicolor icon, pixmap icon, and KDE Wayland desktop identity all
derive from that value in `CMakeLists.txt`.

The executable remains `open-ip-scanner`. The application also retains its
existing `OpenIPScanner` organization and application settings keys, so this
desktop integration migration does not move or discard user settings.
`StartupWMClass` likewise remains `open-ip-scanner` because it must match the
runtime X11 window class rather than the Wayland desktop-file identity.

An install into a selected prefix removes the legacy
`open-ip-scanner.desktop`, `open_ip_scanner.desktop`, and matching legacy icon
and metainfo filenames only from that same prefix. It does not search for or
modify installations in other prefixes. Package installation therefore
replaces old launchers without changing the command users may already invoke.

`resources/linux/open-ip-scanner.desktop.in` and
`resources/linux/open-ip-scanner.metainfo.xml.in` are configured from the
single project version. `tests/metadatacontract_test.py` stages an installation
and validates the resulting files, identities, release version, icons, and
screenshot. The representative 1200 by 700 image at
`docs/images/main-window.png` is generated with the test-only
`metadata_screenshot_tool`; it displays all 768 completed deterministic
documentation-range devices and fake evidence rather than a real network. PNG
text metadata records the fixture, row count, and Fast accuracy profile so the
installed-tree contract can reject a same-size image from another source.
