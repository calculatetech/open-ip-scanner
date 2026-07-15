#!/usr/bin/env python3

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_source_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        candidate = root / relative
        if candidate.is_file() or candidate.is_symlink():
            paths.append(relative)
    return sorted(paths, key=lambda path: os.fsencode(path.as_posix()))


def create_source_archive(root: Path, output: Path, version: str, epoch: int) -> None:
    prefix = f"open-ip-scanner-{version}"
    with output.open("wb") as raw_stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_stream,
                           compresslevel=9, mtime=epoch) as gzip_stream:
            with tarfile.open(fileobj=gzip_stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative in tracked_source_paths(root):
                    source = root / relative
                    info = archive.gettarinfo(str(source), f"{prefix}/{relative.as_posix()}")
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = epoch
                    if info.isfile():
                        executable = bool(source.stat().st_mode & stat.S_IXUSR)
                        info.mode = 0o755 if executable else 0o644
                        with source.open("rb") as stream:
                            archive.addfile(info, stream)
                    else:
                        info.mode = 0o777
                        archive.addfile(info)


def package_field(package: Path, field: str) -> str:
    return subprocess.run(
        ["dpkg-deb", "-f", str(package), field],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def spdx_file_id(name: str) -> str:
    return "SPDXRef-File-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:24]


def generate_spdx(package: Path, output: Path, epoch: int) -> None:
    package_hash = sha256(package)
    version = package_field(package, "Version")
    architecture = package_field(package, "Architecture")
    files = []
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-open-ip-scanner",
    }]
    verification_hashes = []

    with tempfile.TemporaryDirectory(prefix="ois-spdx-") as temporary:
        stage = Path(temporary)
        subprocess.run(["dpkg-deb", "-x", str(package), str(stage)], check=True)
        for path in sorted((item for item in stage.rglob("*") if item.is_file()),
                           key=lambda item: item.relative_to(stage).as_posix()):
            name = "./" + path.relative_to(stage).as_posix()
            file_sha256 = sha256(path)
            file_sha1 = hashlib.sha1(path.read_bytes()).hexdigest()
            identifier = spdx_file_id(name)
            files.append({
                "SPDXID": identifier,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": file_sha1},
                    {"algorithm": "SHA256", "checksumValue": file_sha256},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": name,
                "licenseConcluded": "NOASSERTION",
            })
            verification_hashes.append(file_sha1)
            relationships.append({
                "spdxElementId": "SPDXRef-Package-open-ip-scanner",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": identifier,
            })

    verification_code = hashlib.sha1(
        "".join(sorted(verification_hashes)).encode("ascii")
    ).hexdigest()
    created = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: open-ip-scanner-generate-release-bundle"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://github.com/calculatetech/open-ip-scanner/"
            f"spdx/{version}/{package_hash}"
        ),
        "files": files,
        "name": f"open-ip-scanner-{version}-{architecture}",
        "packages": [{
            "SPDXID": "SPDXRef-Package-open-ip-scanner",
            "checksums": [{"algorithm": "SHA256", "checksumValue": package_hash}],
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": f"pkg:deb/open-ip-scanner@{version}?arch={architecture}",
                "referenceType": "purl",
            }],
            "filesAnalyzed": True,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": "open-ip-scanner",
            "packageFileName": package.name,
            "packageVerificationCode": {
                "packageVerificationCodeValue": verification_code
            },
            "versionInfo": version,
        }],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")


def write_checksums(paths: list[Path], output: Path) -> None:
    lines = [f"{sha256(path)}  {path.name}" for path in sorted(paths, key=lambda p: p.name)]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    package = args.package.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.epoch < 0:
        parser.error("--epoch must be non-negative")
    if package_field(package, "Version") != args.version:
        parser.error("package Version does not match --version")

    source = output_dir / f"open-ip-scanner-{args.version}.tar.gz"
    sbom = output_dir / f"open-ip-scanner_{args.version}_amd64.spdx.json"
    create_source_archive(root, source, args.version, args.epoch)
    generate_spdx(package, sbom, args.epoch)
    write_checksums([package, source, sbom], output_dir / "SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
