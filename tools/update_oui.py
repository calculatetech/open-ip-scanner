#!/usr/bin/env python3
"""Update or verify the embedded IEEE public-assignment snapshot."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
IEEE = DATA / "ieee"
MANIFEST = DATA / "oui-manifest.json"
TSV = DATA / "oui.tsv"
SOURCES = (
    ("ma-l", "MA-L", 24, "https://standards-oui.ieee.org/oui/oui.csv"),
    ("ma-m", "MA-M", 28, "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("ma-s", "MA-S", 36, "https://standards-oui.ieee.org/oui36/oui36.csv"),
)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def deterministic_gzip(payload: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as archive:
        archive.write(payload)
    return output.getvalue()


def download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Open-IP-Scanner-OUI-Updater/1.0"})
    with urlopen(request, timeout=60) as response:
        return response.read()


def parse_source(
    payload: bytes, registry: str, bits: int
) -> tuple[list[tuple[int, str, str]], int]:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError(f"{registry} is not valid UTF-8: {error}") from error
    reader = csv.DictReader(io.StringIO(text, newline=""))
    expected = ["Registry", "Assignment", "Organization Name", "Organization Address"]
    if reader.fieldnames != expected:
        raise ValueError(f"{registry} headers changed: {reader.fieldnames!r}")
    records: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    duplicates = 0
    expected_digits = bits // 4
    for line, row in enumerate(reader, start=2):
        if row["Registry"].strip() != registry:
            raise ValueError(f"{registry} row {line} has a different registry")
        prefix = row["Assignment"].strip().upper()
        if len(prefix) != expected_digits or any(ch not in "0123456789ABCDEF" for ch in prefix):
            raise ValueError(f"{registry} row {line} has invalid assignment {prefix!r}")
        organization = " ".join(row["Organization Name"].split())
        if not organization:
            raise ValueError(f"{registry} row {line} has no organization")
        if prefix in seen:
            duplicates += 1
            continue
        seen.add(prefix)
        records.append((bits, prefix, organization))
    if not records:
        raise ValueError(f"{registry} contains no assignments")
    return records, duplicates


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build(update: bool) -> tuple[dict[str, object], bytes, dict[Path, bytes]]:
    previous = json.loads(MANIFEST.read_text("utf-8")) if MANIFEST.exists() else {}
    retrieved = (datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                 if update else previous.get("retrieved_at_utc"))
    if not retrieved:
        raise ValueError("offline generation requires an existing retrieval timestamp")

    all_records: list[tuple[int, str, str]] = []
    source_entries: list[dict[str, object]] = []
    compressed_outputs: dict[Path, bytes] = {}
    for stem, registry, bits, url in SOURCES:
        path = IEEE / f"{stem}.csv.gz"
        raw = download(url) if update else gzip.decompress(path.read_bytes())
        records, duplicate_rows = parse_source(raw, registry, bits)
        compressed = deterministic_gzip(raw)
        compressed_outputs[path] = compressed
        all_records.extend(records)
        source_entries.append({
            "registry": registry,
            "prefix_bits": bits,
            "url": url,
            "rows": len(records),
            "duplicate_rows_ignored": duplicate_rows,
            "raw_sha256": sha256(raw),
            "compressed_sha256": sha256(compressed),
        })

    all_records.sort(key=lambda record: (record[0], record[1], record[2]))
    seen: set[tuple[int, str]] = set()
    lines = ["prefix_bits\tprefix\torganization\n"]
    for bits, prefix, organization in all_records:
        identity = (bits, prefix)
        if identity in seen:
            raise ValueError(f"duplicate {bits}-bit assignment {prefix}")
        seen.add(identity)
        lines.append(f"{bits}\t{prefix}\t{organization}\n")
    tsv = "".join(lines).encode("utf-8")
    manifest: dict[str, object] = {
        "schema": 1,
        "retrieved_at_utc": retrieved,
        "source": "IEEE Registration Authority public listings",
        "sources": source_entries,
        "generated": {
            "path": "data/oui.tsv",
            "records": len(all_records),
            "sha256": sha256(tsv),
        },
    }
    return manifest, tsv, compressed_outputs


def encoded_manifest(manifest: dict[str, object]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--update", action="store_true", help="download current public listings")
    mode.add_argument("--offline", action="store_true", help="use committed compressed inputs")
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()
    if args.update and args.check:
        parser.error("--check is supported only with --offline")

    manifest, tsv, compressed = build(args.update)
    outputs = {**compressed, TSV: tsv, MANIFEST: encoded_manifest(manifest)}
    if args.check:
        mismatches = [str(path.relative_to(ROOT)) for path, payload in outputs.items()
                      if not path.exists() or path.read_bytes() != payload]
        if mismatches:
            raise SystemExit("generated vendor data differs: " + ", ".join(mismatches))
        print(f"verified {manifest['generated']['records']} assignments")
        return 0
    for path, payload in outputs.items():
        atomic_write(path, payload)
    print(f"generated {manifest['generated']['records']} assignments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
