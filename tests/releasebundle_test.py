#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generate_release_bundle", ROOT / "tools/generate_release_bundle.py"
)
assert SPEC and SPEC.loader
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def make_package(root: Path, version: str) -> Path:
    package_root = root / "package-root"
    control = package_root / "DEBIAN"
    binary = package_root / "usr/bin/open-ip-scanner"
    control.mkdir(parents=True)
    binary.parent.mkdir(parents=True)
    (control / "control").write_text(
        "Package: open-ip-scanner\n"
        f"Version: {version}\n"
        "Architecture: amd64\n"
        "Maintainer: Fixture <fixture@example.invalid>\n"
        "Description: Release bundle fixture\n",
        encoding="utf-8",
    )
    binary.write_text("fixture\n", encoding="utf-8")
    binary.chmod(0o755)
    package = root / f"open-ip-scanner_{version}_amd64.deb"
    subprocess.run(
        ["dpkg-deb", "--build", "--root-owner-group", str(package_root), str(package)],
        check=True,
        capture_output=True,
        text=True,
    )
    return package


def main() -> int:
    version = "0.7.3"
    epoch = 1_700_000_000
    with tempfile.TemporaryDirectory(prefix="ois-release-bundle-") as temporary:
        root = Path(temporary)
        package = make_package(root, version)
        first = root / "first"
        second = root / "second"
        first.mkdir()
        second.mkdir()
        first_package = first / package.name
        second_package = second / package.name
        shutil.copy2(package, first_package)
        shutil.copy2(package, second_package)

        for output, candidate in ((first, first_package), (second, second_package)):
            source = output / f"open-ip-scanner-{version}.tar.gz"
            sbom = output / f"open-ip-scanner_{version}_amd64.spdx.json"
            BUNDLE.create_source_archive(ROOT, source, version, epoch)
            BUNDLE.generate_spdx(candidate, sbom, epoch)
            BUNDLE.write_checksums(
                [candidate, source, sbom], output / "SHA256SUMS"
            )

        for name in (
            f"open-ip-scanner-{version}.tar.gz",
            f"open-ip-scanner_{version}_amd64.spdx.json",
            "SHA256SUMS",
        ):
            require(
                (first / name).read_bytes() == (second / name).read_bytes(),
                f"release metadata is nondeterministic: {name}",
            )

        document = json.loads(
            (first / f"open-ip-scanner_{version}_amd64.spdx.json").read_text(
                encoding="utf-8"
            )
        )
        require(document["spdxVersion"] == "SPDX-2.3", "wrong SPDX version")
        require(document["packages"][0]["versionInfo"] == version,
                "wrong SBOM package version")
        package_sha = hashlib.sha256(first_package.read_bytes()).hexdigest()
        require(package_sha in (first / "SHA256SUMS").read_text(encoding="utf-8"),
                "package is absent from SHA256SUMS")
        require(document["files"], "SBOM contains no installed files")
        require(all(item["fileName"].startswith("./") for item in document["files"]),
                "SBOM file names are not relative to the package root")

        validator = ROOT / "scripts/validate-release-bundle.sh"
        optimized_environment = os.environ.copy()
        optimized_environment["PYTHONOPTIMIZE"] = "1"
        valid_result = subprocess.run(
            [str(validator), str(first), version],
            check=False,
            capture_output=True,
            text=True,
            env=optimized_environment,
        )
        require(valid_result.returncode == 0,
                "valid bundle failed with optimized Python")

        document["files"][0]["fileName"] = "/usr/bin/open-ip-scanner"
        sbom_path = first / f"open-ip-scanner_{version}_amd64.spdx.json"
        sbom_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        BUNDLE.write_checksums(
            [first_package, first / f"open-ip-scanner-{version}.tar.gz", sbom_path],
            first / "SHA256SUMS",
        )
        invalid_result = subprocess.run(
            [str(validator), str(first), version],
            check=False,
            capture_output=True,
            text=True,
            env=optimized_environment,
        )
        require(invalid_result.returncode != 0,
                "optimized Python disabled the package-relative SPDX check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
