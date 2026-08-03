#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || ! -f $1 || $1 != *.deb ]]; then
    echo "usage: $0 PACKAGE.deb" >&2
    exit 2
fi

container_engine=${OIS_CONTAINER_ENGINE:-docker}
if ! command -v "$container_engine" >/dev/null 2>&1; then
    echo "supported-package validation requires $container_engine" >&2
    exit 1
fi

package=$(realpath -e "$1")
images=(ubuntu:24.04 debian:13)
for image in "${images[@]}"; do
    echo "validating package installation on $image"
    "$container_engine" run --pull=always --rm \
        --mount "type=bind,source=$package,target=/tmp/open-ip-scanner.deb,readonly" \
        "$image" sh -euxc '
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y /tmp/open-ip-scanner.deb
            dpkg --status open-ip-scanner | grep -Fqx "Status: install ok installed"
            if ldd /usr/bin/open-ip-scanner | grep -F "not found"; then
                echo "installed executable has unresolved shared libraries" >&2
                exit 1
            fi
            QT_QPA_PLATFORM=offscreen timeout 15s \
                /usr/bin/open-ip-scanner --startup-smoke
            apt-get remove -y open-ip-scanner
            test ! -e /usr/bin/open-ip-scanner
        '
done

echo "supported package install/start/remove validation: PASS"
