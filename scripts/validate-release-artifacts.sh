#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || ! -d $1 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY" >&2
    exit 2
fi

artifact_dir=$1
mapfile -t packages < <(find "$artifact_dir" -maxdepth 1 -type f -name '*.deb' -print)
if [[ ${#packages[@]} -ne 1 ]]; then
    echo "release artifact build produced ${#packages[@]} Debian packages; expected 1" >&2
    exit 1
fi

dpkg-deb --info "${packages[0]}" >/dev/null
dpkg-deb --contents "${packages[0]}" >/dev/null
printf '%s\n' "${packages[0]}"
