#!/usr/bin/env python3
"""Focused contracts for deterministic vendor-data generation."""

from __future__ import annotations

import gzip
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("update_oui", ROOT / "tools/update_oui.py")
assert SPEC is not None and SPEC.loader is not None
UPDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATE)


def main() -> int:
    source = (
        "Registry,Assignment,Organization Name,Organization Address\r\n"
        "MA-L,00163E,First organization,Address\r\n"
        "MA-L,00163E,Older duplicate,Address\r\n"
        "MA-L,DCADBE,Second organization,Address\r\n"
    ).encode()
    records, duplicates = UPDATE.parse_source(source, "MA-L", 24)
    assert records == [
        (24, "00163E", "First organization"),
        (24, "DCADBE", "Second organization"),
    ]
    assert duplicates == 1

    first = UPDATE.deterministic_gzip(source)
    second = UPDATE.deterministic_gzip(source)
    assert first == second
    assert gzip.decompress(first) == source

    bad_header = source.replace(b"Organization Name", b"Vendor")
    try:
        UPDATE.parse_source(bad_header, "MA-L", 24)
    except ValueError as error:
        assert "headers changed" in str(error)
    else:
        raise AssertionError("changed source headers were accepted")

    bad_prefix = source.replace(b"00163E", b"00163G", 1)
    try:
        UPDATE.parse_source(bad_prefix, "MA-L", 24)
    except ValueError as error:
        assert "invalid assignment" in str(error)
    else:
        raise AssertionError("non-hexadecimal assignment was accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
