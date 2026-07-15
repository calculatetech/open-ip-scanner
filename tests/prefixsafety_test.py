#!/usr/bin/env python3

"""Exercise prefix-isolated install, uninstall, and cache refresh behavior."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, check=False, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def run_expect_failure(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, check=False, env=env, capture_output=True, text=True)
    if result.returncode == 0:
        raise RuntimeError(f"command unexpectedly succeeded: {' '.join(command)}")


def installed_files(prefix: Path, app_id: str) -> tuple[Path, ...]:
    return (
        prefix / "bin" / "open-ip-scanner",
        prefix / "share" / "applications" / f"{app_id}.desktop",
        prefix / "share" / "icons" / "hicolor" / "scalable" / "apps" / f"{app_id}.svg",
        prefix / "share" / "pixmaps" / f"{app_id}.svg",
        prefix / "share" / "metainfo" / f"{app_id}.metainfo.xml",
        prefix / "share" / "doc" / "open-ip-scanner" / "copyright",
        prefix / "share" / "doc" / "open-ip-scanner" / "changelog.gz",
        prefix / "share" / "doc" / "open-ip-scanner" / "vendor-data-sources.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "user-guide.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "support.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "data-provenance.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "security.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "known-limitations.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "release-checklist.md",
        prefix / "share" / "doc" / "open-ip-scanner" / "platform-support.md",
        prefix / "share" / "man" / "man1" / "open-ip-scanner.1.gz",
    )


def require_installed(prefix: Path, app_id: str) -> None:
    missing = [path for path in installed_files(prefix, app_id) if not path.is_file()]
    require(not missing, f"installation is incomplete under {prefix}: {missing}")


def require_removed(prefix: Path, app_id: str) -> None:
    remaining = [path for path in installed_files(prefix, app_id) if path.exists()]
    require(not remaining, f"uninstall left files under {prefix}: {remaining}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--app-id", required=True)
    args = parser.parse_args()

    build_dir = args.build_dir.resolve()
    uninstall_script = build_dir / "cmake_uninstall.cmake"
    source_root = Path(__file__).resolve().parents[1]
    refresh_script = source_root / "cmake" / "refresh_desktop_caches.cmake"
    manifest = build_dir / "install_manifest.txt"
    uninstall_state = build_dir / "ois_uninstall_state.txt"
    original_manifest = manifest.read_bytes() if manifest.exists() else None
    original_uninstall_state = (
        uninstall_state.read_bytes() if uninstall_state.exists() else None
    )

    with tempfile.TemporaryDirectory(prefix="ois-prefix-safety-") as temporary:
        root = Path(temporary)
        system_prefix = root / "system"
        local_prefix = root / "local"
        spaced_prefix = root / "prefix with spaces"

        try:
            run(["cmake", "--install", str(build_dir), "--prefix", str(system_prefix)])
            run(["cmake", "--install", str(build_dir), "--prefix", str(local_prefix)])
            require_installed(system_prefix, args.app_id)
            require_installed(local_prefix, args.app_id)

            run(["cmake", "-P", str(uninstall_script)])
            require_installed(system_prefix, args.app_id)
            require_removed(local_prefix, args.app_id)

            legacy = system_prefix / "share" / "applications" / "open_ip_scanner.desktop"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("legacy\n", encoding="utf-8")
            run([
                "cmake",
                f"-DUNINSTALL_PREFIX={system_prefix}",
                "-P",
                str(uninstall_script),
            ])
            require_removed(system_prefix, args.app_id)
            require(not legacy.exists(), "explicit uninstall retained a legacy file")
            run([
                "cmake",
                f"-DUNINSTALL_PREFIX={system_prefix}",
                "-P",
                str(uninstall_script),
            ])

            run(["cmake", "--install", str(build_dir), "--prefix", str(spaced_prefix)])
            require_installed(spaced_prefix, args.app_id)
            run([
                "cmake",
                f"-DUNINSTALL_PREFIX={spaced_prefix}",
                "-P",
                str(uninstall_script),
            ])
            require_removed(spaced_prefix, args.app_id)

            staged_root = root / "staged package"
            staged_env = os.environ.copy()
            staged_env["DESTDIR"] = str(staged_root)
            run(
                ["cmake", "--install", str(build_dir), "--prefix", "/usr"],
                env=staged_env,
            )
            staged_prefix = staged_root / "usr"
            require_installed(staged_prefix, args.app_id)
            run(["cmake", "-P", str(uninstall_script)])
            require_removed(staged_prefix, args.app_id)

            run(["cmake", "--install", str(build_dir), "--prefix", str(local_prefix)])
            require_installed(local_prefix, args.app_id)
            uninstall_state.unlink()
            run(["cmake", "-P", str(uninstall_script)])
            require_installed(local_prefix, args.app_id)
            run([
                "cmake",
                f"-DUNINSTALL_PREFIX={local_prefix}",
                "-P",
                str(uninstall_script),
            ])

            escaped_state_file = root / "state-escape-survivor"
            escaped_state_file.write_text("must survive\n", encoding="utf-8")
            uninstall_state.write_text(
                "OIS-UNINSTALL-STATE-1\n"
                f"root={local_prefix}\n"
                f"file={local_prefix}/../{escaped_state_file.name}\n",
                encoding="utf-8",
            )
            run_expect_failure(["cmake", "-P", str(uninstall_script)])
            require(escaped_state_file.is_file(),
                    "state manifest escaped its recorded root")

            unrelated_file = local_prefix / "unrelated-user-file"
            unrelated_file.parent.mkdir(parents=True, exist_ok=True)
            unrelated_file.write_text("must survive\n", encoding="utf-8")
            uninstall_state.write_text(
                "OIS-UNINSTALL-STATE-1\n"
                f"root={local_prefix}\n"
                f"file={unrelated_file}\n",
                encoding="utf-8",
            )
            run_expect_failure(["cmake", "-P", str(uninstall_script)])
            require(unrelated_file.is_file(),
                    "state manifest deleted a contained file outside the allowlist")

            prefix_injection_survivor = root / "prefix-injection-survivor"
            prefix_injection_survivor.write_text("must survive\n", encoding="utf-8")
            run_expect_failure([
                "cmake",
                f"-DUNINSTALL_PREFIX={local_prefix};{prefix_injection_survivor}",
                "-P",
                str(uninstall_script),
            ])
            require(prefix_injection_survivor.is_file(),
                    "explicit-prefix list injection deleted an unrelated file")

            unsafe_build = root / "unsafe-build"
            run([
                "cmake",
                "-S",
                str(source_root),
                "-B",
                str(unsafe_build),
                "-G",
                "Ninja",
                "-DBUILD_TESTING=OFF",
                "-DCMAKE_INSTALL_BINDIR=../shared/bin",
            ])
            unsafe_prefix = root / "unsafe-prefix"
            escaped_file = root / "shared" / "bin" / "open-ip-scanner"
            escaped_file.parent.mkdir(parents=True)
            escaped_file.write_text("must survive\n", encoding="utf-8")
            run_expect_failure([
                "cmake",
                f"-DUNINSTALL_PREFIX={unsafe_prefix}",
                "-P",
                str(unsafe_build / "cmake_uninstall.cmake"),
            ])
            require(escaped_file.is_file(), "explicit uninstall escaped its selected prefix")

            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            cache_log = root / "cache.log"
            for name in ("update-desktop-database", "gtk-update-icon-cache", "kbuildsycoca6"):
                program = fake_bin / name
                program.write_text(
                    "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$OIS_CACHE_LOG\"\n",
                    encoding="utf-8",
                )
                program.chmod(0o755)
            fake_id = fake_bin / "id"
            fake_id.write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
            fake_id.chmod(0o755)
            test_home = root / "home with spaces"
            cache_env = os.environ.copy()
            cache_env["PATH"] = f"{fake_bin}:{cache_env['PATH']}"
            cache_env["HOME"] = str(test_home)
            cache_env["OIS_CACHE_LOG"] = str(cache_log)
            injected_home_env = cache_env.copy()
            injected_home_env["HOME"] = f"{test_home};{prefix_injection_survivor}"
            run_expect_failure(
                ["cmake", "--build", str(build_dir), "--target", "uninstall-local"],
                env=injected_home_env,
            )
            require(prefix_injection_survivor.is_file(),
                    "local-target HOME injection deleted an unrelated file")
            run(
                ["cmake", "--build", str(build_dir), "--target", "install-local"],
                env=cache_env,
            )
            target_prefix = test_home / ".local"
            require_installed(target_prefix, args.app_id)
            run(
                ["cmake", "--build", str(build_dir), "--target", "uninstall-local"],
                env=cache_env,
            )
            require_removed(target_prefix, args.app_id)
            calls = cache_log.read_text(encoding="utf-8").splitlines()
            for name in ("update-desktop-database", "gtk-update-icon-cache", "kbuildsycoca6"):
                require(sum(line.startswith(f"{name} ") for line in calls) == 2,
                        f"local targets did not refresh caches symmetrically: {name}")

            cache_prefix = root / "root cache prefix"
            (cache_prefix / "share" / "applications").mkdir(parents=True)
            (cache_prefix / "share" / "icons" / "hicolor").mkdir(parents=True)
            run([
                "cmake",
                f"-DREFRESH_PREFIX={cache_prefix}",
                "-DOIS_TEST_EFFECTIVE_UID=0",
                "-P",
                str(refresh_script),
            ], env=cache_env)
            require(cache_log.read_text(encoding="utf-8").splitlines() == calls,
                    "root cache refresh invoked a user-session tool")
        finally:
            if original_manifest is None:
                manifest.unlink(missing_ok=True)
            else:
                manifest.write_bytes(original_manifest)
            if original_uninstall_state is None:
                uninstall_state.unlink(missing_ok=True)
            else:
                uninstall_state.write_bytes(original_uninstall_state)

    print("prefix safety contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
