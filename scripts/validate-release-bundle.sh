#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 || ! -d $1 || ! $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY VERSION" >&2
    exit 2
fi

artifact_dir=$1
version=$2
package="$artifact_dir/open-ip-scanner_${version}_amd64.deb"
source_archive="$artifact_dir/open-ip-scanner-${version}.tar.gz"
sbom="$artifact_dir/open-ip-scanner_${version}_amd64.spdx.json"
checksums="$artifact_dir/SHA256SUMS"

for required in "$package" "$source_archive" "$sbom" "$checksums"; do
    if [[ ! -s $required ]]; then
        echo "release bundle file is missing or empty: $required" >&2
        exit 1
    fi
done

(cd "$artifact_dir" && sha256sum --check --strict SHA256SUMS)
gzip -t "$source_archive"
archive_root=$(tar -tzf "$source_archive" | sed -n '1s,/.*,,'p)
if [[ $archive_root != "open-ip-scanner-${version}" ]]; then
    echo "source archive has unexpected root: $archive_root" >&2
    exit 1
fi

python3 - "$sbom" "$package" "$version" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

sbom_path = Path(sys.argv[1])
package = Path(sys.argv[2])
version = sys.argv[3]
document = json.loads(sbom_path.read_text(encoding="utf-8"))

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

require(document["spdxVersion"] == "SPDX-2.3", "wrong SPDX version")
require(document["dataLicense"] == "CC0-1.0", "wrong SPDX data license")
require(document["packages"][0]["name"] == "open-ip-scanner",
        "wrong SPDX package name")
require(document["packages"][0]["versionInfo"] == version,
        "wrong SPDX package version")
checksums = document["packages"][0]["checksums"]
expected = hashlib.sha256(package.read_bytes()).hexdigest()
require({item["algorithm"]: item["checksumValue"] for item in checksums}["SHA256"] == expected,
        "SPDX package checksum differs")
require(document["files"], "SBOM has no installed files")
for item in document["files"]:
    name = item["fileName"]
    require(name.startswith("./") and not name.startswith("./../") and "/../" not in name,
            f"SPDX fileName is not package-relative: {name}")
contained = {
    item["relatedSpdxElement"]
    for item in document["relationships"]
    if item["relationshipType"] == "CONTAINS"
}
require(contained == {item["SPDXID"] for item in document["files"]},
        "SPDX package/file relationships are incomplete")
PY

echo "release bundle metadata: PASS"
