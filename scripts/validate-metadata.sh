#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir="$root/build/metadata-lint"
cd "$root"

for command_name in appstreamcli cmake desktop-file-validate ninja xmllint python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "metadata lint requires $command_name" >&2
        exit 1
    fi
done

cmake -S . -B "$build_dir" -G Ninja -DBUILD_TESTING=OFF
desktop_file="$build_dir/generated-resources/io.github.calculatetech.OpenIpScanner.desktop"
metainfo_file="$build_dir/generated-resources/io.github.calculatetech.OpenIpScanner.metainfo.xml"
desktop-file-validate "$desktop_file"
xmllint --noout "$metainfo_file"
appstreamcli validate --no-net --strict "$metainfo_file"
python3 -m json.tool data/oui-manifest.json >/dev/null

echo "metadata lint: PASS"
