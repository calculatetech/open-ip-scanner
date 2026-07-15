#!/usr/bin/env python3

"""Validate installed desktop integration metadata as one coherent contract."""

from __future__ import annotations

import argparse
import configparser
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, env=env)


def png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    require(data[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG")
    require(data[12:16] == b"IHDR", f"{path} has no PNG IHDR")
    return struct.unpack(">II", data[16:24])


def require_fixture_provenance(path: Path) -> None:
    data = path.read_bytes()
    for marker in (
        b"Open IP Scanner hidden test",
        b"FixtureRows",
        b"768",
        b"FixtureAccuracy",
        b"Fast",
    ):
        require(marker in data, f"tracked screenshot lacks fixture marker: {marker!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    build_dir = args.build_dir.resolve()
    install_state_files = (
        build_dir / "install_manifest.txt",
        build_dir / "ois_uninstall_state.txt",
    )
    original_install_state = {
        path: path.read_bytes() if path.exists() else None
        for path in install_state_files
    }
    source_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="ois-metadata-") as temporary:
        stage = Path(temporary)
        legacy_paths = (
            stage / "usr" / "share" / "applications" / "open-ip-scanner.desktop",
            stage / "usr" / "share" / "applications" / "open_ip_scanner.desktop",
            stage / "usr" / "share" / "metainfo" / "open-ip-scanner.metainfo.xml",
            stage / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps" / "open-ip-scanner.svg",
            stage / "usr" / "share" / "pixmaps" / "open-ip-scanner.svg",
        )
        for legacy in legacy_paths:
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("legacy fixture\n", encoding="utf-8")
        env = os.environ.copy()
        env["DESTDIR"] = str(stage)
        try:
            run(
                ["cmake", "--install", str(build_dir), "--prefix", "/usr"],
                env=env,
            )
        finally:
            for path, contents in original_install_state.items():
                if contents is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(contents)

        installed = stage / "usr"
        binary = installed / "bin" / "open-ip-scanner"
        desktop = installed / "share" / "applications" / f"{args.app_id}.desktop"
        metainfo = installed / "share" / "metainfo" / f"{args.app_id}.metainfo.xml"
        hicolor_icon = (
            installed
            / "share"
            / "icons"
            / "hicolor"
            / "scalable"
            / "apps"
            / f"{args.app_id}.svg"
        )
        pixmap_icon = installed / "share" / "pixmaps" / f"{args.app_id}.svg"
        user_guide = installed / "share" / "doc" / "open-ip-scanner" / "user-guide.md"

        for required in (binary, desktop, metainfo, hicolor_icon, pixmap_icon, user_guide):
            require(required.is_file(), f"installed metadata asset is missing: {required}")

        guide_text = user_guide.read_text(encoding="utf-8")
        require("./open-ip-scanner_*_amd64.deb" in guide_text,
                "user guide lacks a shell-safe version-neutral package command")
        require(not re.search(r"open-ip-scanner_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb",
                              guide_text),
                "user guide contains a stale-prone concrete package version")

        require(not any(path.exists() for path in legacy_paths),
                "a legacy desktop-integration filename remains installed")

        run(["desktop-file-validate", str(desktop)])
        run(["xmllint", "--noout", str(metainfo)])
        run(["appstreamcli", "validate", "--no-net", "--strict", str(metainfo)])

        desktop_config = configparser.ConfigParser(interpolation=None)
        desktop_config.optionxform = str
        desktop_config.read(desktop, encoding="utf-8")
        entry = desktop_config["Desktop Entry"]
        require(entry["Exec"] == "open-ip-scanner", "desktop Exec changed")
        require(entry["TryExec"] == "open-ip-scanner", "desktop TryExec changed")
        require(entry["Icon"] == args.app_id, "desktop icon does not use the app ID")
        require(entry["StartupWMClass"] == "open-ip-scanner",
                "desktop startup class no longer matches the runtime WM_CLASS")
        require(entry["X-KDE-Wayland-Desktop-File"] == f"{args.app_id}.desktop",
                "Wayland desktop identity does not use the app ID")

        tree = ET.parse(metainfo)
        root = tree.getroot()
        require(root.findtext("id") == args.app_id, "AppStream component ID differs")
        require(root.findtext("launchable") == f"{args.app_id}.desktop",
                "AppStream launchable differs")
        require(root.findtext("developer/name") == "Calculate Tech",
                "AppStream developer differs")
        homepage = root.find("url[@type='homepage']")
        require(homepage is not None and homepage.text ==
                "https://github.com/calculatetech/open-ip-scanner",
                "AppStream homepage differs")
        require(root.find("content_rating[@type='oars-1.1']") is not None,
                "AppStream OARS 1.1 content rating is missing")
        release = root.find("releases/release")
        require(release is not None and release.get("version") == args.version,
                "AppStream release does not match the package version")

        screenshot_url = (
            "https://raw.githubusercontent.com/calculatetech/open-ip-scanner/"
            "main/docs/images/main-window.png"
        )
        screenshot = root.find("screenshots/screenshot/image[@type='source']")
        require(screenshot is not None and screenshot.text == screenshot_url,
                "AppStream screenshot URL differs")
        require(screenshot.get("width") == "1200" and screenshot.get("height") == "700",
                "AppStream screenshot dimensions differ")
        screenshot_path = source_root / "docs" / "images" / "main-window.png"
        require(png_dimensions(screenshot_path) == (1200, 700),
                "tracked screenshot is not exactly 1200 by 700")
        require_fixture_provenance(screenshot_path)

        require("@OIS_" not in desktop.read_text(encoding="utf-8"),
                "desktop template placeholder was not configured")
        require("@PROJECT_VERSION@" not in metainfo.read_text(encoding="utf-8"),
                "AppStream version placeholder was not configured")

    print("installed metadata contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
