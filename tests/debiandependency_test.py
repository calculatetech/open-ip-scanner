#!/usr/bin/env python3

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "portable-dpkg-shlibdeps.py"
SPEC = importlib.util.spec_from_file_location("portable_dpkg_shlibdeps", WRAPPER)
assert SPEC and SPEC.loader
DEPENDENCIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPENDENCIES)


UBUNTU_DEPENDS = (
    "libc6 (>= 2.34), libgcc-s1 (>= 3.0), libqt6core6t64 (>= 6.4.0), "
    "libqt6dbus6t64 (>= 6.4.0), libqt6gui6t64 (>= 6.1.2), "
    "libqt6network6t64 (>= 6.1.2), libqt6printsupport6t64 (>= 6.1.2), "
    "libqt6widgets6t64 (>= 6.3.0), libstdc++6 (>= 12)"
)
DEBIAN_DEPENDS = (
    "libc6 (>= 2.34), libgcc-s1 (>= 3.0), libqt6core6t64 (>= 6.8.2), "
    "libqt6dbus6 (>= 6.4.0), libqt6gui6 (>= 6.1.2), "
    "libqt6network6 (>= 6.1.2), libqt6printsupport6 (>= 6.1.2), "
    "libqt6widgets6 (>= 6.3.0), libstdc++6 (>= 12)"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(value: str, message: str) -> None:
    try:
        DEPENDENCIES.normalize_depends(value)
    except DEPENDENCIES.DependencyError:
        return
    raise AssertionError(message)


def test_supported_outputs() -> None:
    ubuntu = DEPENDENCIES.normalize_depends(UBUNTU_DEPENDS)
    debian = DEPENDENCIES.normalize_depends(DEBIAN_DEPENDS)
    for module in DEPENDENCIES.PORTABLE_QT_MODULES:
        t64_name, unsuffixed_name = DEPENDENCIES.portable_names(module)
        require(
            f"{t64_name} (" in ubuntu and f" | {unsuffixed_name} (" in ubuntu,
            f"Ubuntu output lacks portable {module} alternatives",
        )
        require(
            f"{t64_name} (" in debian and f" | {unsuffixed_name} (" in debian,
            f"Debian output lacks portable {module} alternatives",
        )
    require("libqt6core6t64 (>= 6.4.0)" in ubuntu,
            "Ubuntu Qt Core constraint changed")
    require("libqt6core6t64 (>= 6.8.2)" in debian,
            "Debian Qt Core constraint changed")
    require("libqt6gui6t64 (>= 6.1.2) | libqt6gui6 (>= 6.1.2)" in ubuntu,
            "module-specific version constraint was not preserved")

    for value in (ubuntu, debian):
        complete = "iputils-ping, iproute2, " + value
        DEPENDENCIES.validate_final_depends(complete)


def test_fail_closed_inputs() -> None:
    expect_error(
        UBUNTU_DEPENDS.replace(", libqt6widgets6t64 (>= 6.3.0)", ""),
        "missing Qt module was accepted",
    )
    expect_error(
        UBUNTU_DEPENDS + ", libqt6dbus6 (>= 6.4.0)",
        "duplicate Qt module was accepted",
    )
    expect_error(
        UBUNTU_DEPENDS.replace(
            "libqt6dbus6t64 (>= 6.4.0)",
            "libqt6dbus6t64 (>= 6.4.0) | libqt6dbus6 (>= 6.4.0)",
        ),
        "pre-normalized alternative was accepted",
    )
    expect_error(
        UBUNTU_DEPENDS.replace("libqt6gui6t64 (>= 6.1.2)", "libqt6gui6t64"),
        "unversioned Qt dependency was accepted",
    )
    for malformed in ("(nonsense)", "(=> 6.1.2)", "(>= not-a-version)"):
        expect_error(
            UBUNTU_DEPENDS.replace("(>= 6.1.2)", malformed),
            f"malformed Qt constraint was accepted: {malformed}",
        )
    for output in ("", "noise\n", "shlibs:Depends=x\nshlibs:Depends=y\n"):
        try:
            DEPENDENCIES.normalize_output(output)
        except DEPENDENCIES.DependencyError:
            continue
        raise AssertionError("malformed dpkg-shlibdeps output was accepted")

    portable = DEPENDENCIES.normalize_depends(UBUNTU_DEPENDS)
    invalid_final = "iputils-ping, iproute2, " + portable.replace(
        "libqt6dbus6t64 (>= 6.4.0) | libqt6dbus6 (>= 6.4.0)",
        "libqt6dbus6t64 (>= 6.4.0)",
    )
    try:
        DEPENDENCIES.validate_final_depends(invalid_final)
    except DEPENDENCIES.DependencyError:
        pass
    else:
        raise AssertionError("standalone final Qt dependency was accepted")

    malformed_final = "iputils-ping, iproute2, " + portable.replace(
        "(>= 6.4.0)", "(nonsense)"
    )
    try:
        DEPENDENCIES.validate_final_depends(malformed_final)
    except DEPENDENCIES.DependencyError:
        pass
    else:
        raise AssertionError("malformed final version constraints were accepted")


def test_backend_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-shlibdeps-test-") as temporary:
        backend = Path(temporary) / "dpkg-shlibdeps"
        backend.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if '--fail' in sys.argv:\n"
            "    print('fixture failure', file=sys.stderr)\n"
            "    raise SystemExit(23)\n"
            "if '--version' in sys.argv:\n"
            "    print('dpkg-shlibdeps version 1.22.0')\n"
            "elif '-O' in sys.argv:\n"
            f"    print({('shlibs:Depends=' + UBUNTU_DEPENDS)!r})\n"
            "else:\n"
            "    print('fixture passthrough')\n",
            encoding="utf-8",
        )
        backend.chmod(0o755)
        environment = os.environ.copy()
        environment["OIS_DPKG_SHLIBDEPS_EXECUTABLE"] = str(backend)

        version = subprocess.run(
            [sys.executable, str(WRAPPER), "--version"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(version.returncode == 0 and version.stdout ==
                "dpkg-shlibdeps version 1.22.0\n",
                "version passthrough changed backend output")

        generated = subprocess.run(
            [sys.executable, str(WRAPPER), "-O", "/fixture/binary"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(generated.returncode == 0,
                "valid backend dependency output failed")
        require("libqt6dbus6t64 (>= 6.4.0) | libqt6dbus6 (>= 6.4.0)" in
                generated.stdout, "backend output was not normalized")

        failed = subprocess.run(
            [sys.executable, str(WRAPPER), "--fail"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(failed.returncode == 23 and "fixture failure" in failed.stderr,
                "backend failure status or diagnostic was not preserved")


def main() -> int:
    test_supported_outputs()
    test_fail_closed_inputs()
    test_backend_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
