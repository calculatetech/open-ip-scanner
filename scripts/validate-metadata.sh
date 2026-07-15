#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

for command_name in appstreamcli desktop-file-validate xmllint python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "metadata lint requires $command_name" >&2
        exit 1
    fi
done

desktop-file-validate resources/linux/open-ip-scanner.desktop
xmllint --noout resources/linux/open-ip-scanner.metainfo.xml
appstreamcli validate --no-net \
    --override 'cid-desktopapp-is-not-rdns=pedantic,url-homepage-missing=pedantic,content-rating-missing=pedantic,developer-info-missing=pedantic' \
    resources/linux/open-ip-scanner.metainfo.xml
python3 -m json.tool data/oui-manifest.json >/dev/null

echo "metadata lint: PASS"
