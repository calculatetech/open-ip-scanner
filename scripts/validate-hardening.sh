#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 || ! -f $1 || ! -d $2 ]]; then
    echo "usage: $0 PACKAGE BUILD_DIRECTORY" >&2
    exit 2
fi

package=$1
build_dir=$2
for command in hardening-check readelf; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "hardening validation requires $command" >&2
        exit 1
    fi
done

temporary=$(mktemp -d -t ois-hardening-XXXXXX)
trap 'rm -rf "$temporary"' EXIT
dpkg-deb -x "$package" "$temporary"
binary="$temporary/usr/bin/open-ip-scanner"
# hardening-check returns nonzero when any architecture-specific category is
# absent. Its ARM Branch Protection category is not applicable to supported
# x86-64 builds, so validate the audited fields below instead of its aggregate
# status.
report=$(hardening-check "$binary" 2>&1 || true)
for expected in \
    'Position Independent Executable: yes' \
    'Stack protected: yes' \
    'Fortify Source functions: yes' \
    'Read-only relocations: yes' \
    'Immediate binding: yes' \
    'Control flow integrity: yes'; do
    if ! grep -Fq "$expected" <<<"$report"; then
        printf '%s\n' "$report" >&2
        echo "hardening baseline is missing: $expected" >&2
        exit 1
    fi
done

for flag in \
    -fstack-protector-strong \
    -fstack-clash-protection \
    -fcf-protection=full \
    -D_FORTIFY_SOURCE=3 \
    -Wl,-z,relro,-z,now; do
    if ! grep -Fq -- "$flag" "$build_dir/build.ninja"; then
        echo "Release build does not contain required flag: $flag" >&2
        exit 1
    fi
done

program_headers=$(readelf -lW "$binary")
dynamic_flags=$(readelf -dW "$binary")
grep -Fq GNU_RELRO <<<"$program_headers"
grep -Fq BIND_NOW <<<"$dynamic_flags"
grep -Eq 'FLAGS_1.*PIE' <<<"$dynamic_flags"

echo "hardening baseline: PASS"
