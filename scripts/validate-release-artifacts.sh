#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

basic=false
if [[ ${1:-} == --basic ]]; then
    basic=true
    shift
fi

if [[ $# -ne 1 || ! -d $1 ]]; then
    echo "usage: $0 [--basic] ARTIFACT_DIRECTORY" >&2
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

if $basic; then
    printf '%s\n' "${packages[0]}"
    exit 0
fi

package=${packages[0]}
for command in dpkg file gzip lintian od python3 readelf stat tar; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "release artifact validation requires $command" >&2
        exit 1
    fi
done

require_field() {
    local field=$1
    local expected=$2
    local actual
    actual=$(dpkg-deb -f "$package" "$field")
    if [[ $actual != "$expected" ]]; then
        echo "$field differs: expected '$expected', found '$actual'" >&2
        exit 1
    fi
}

require_field Maintainer "Michael Beutler <mikebeutler84@gmail.com>"
require_field Homepage "https://github.com/calculatetech/open-ip-scanner"
require_field Recommends "avahi-daemon"

description=$(dpkg-deb -f "$package" Description)
if [[ $description != *"Open IP Scanner discovers devices"* ||
      $description != *"privacy-preserving diagnostics"* ]]; then
    echo "Debian package lacks the required extended description" >&2
    exit 1
fi

depends=$(dpkg-deb -f "$package" Depends)
if ! python3 "$root/scripts/portable-dpkg-shlibdeps.py" \
    --ois-validate-depends "$depends"; then
    echo "Debian dependencies are not portable across supported systems" >&2
    exit 1
fi
control=$(dpkg-deb -f "$package")
if [[ $control == *avahi-utils* ]]; then
    echo "test-only avahi-utils leaked into runtime dependencies" >&2
    exit 1
fi

if ! payload_listing=$(dpkg-deb --fsys-tarfile "$package" 2>&1 | tar -tvf - 2>&1); then
    printf '%s\n' "$payload_listing" >&2
    echo "could not inspect package payload modes" >&2
    exit 1
fi
directory_count=0
while IFS= read -r entry; do
    permissions=${entry%% *}
    [[ $permissions == d* ]] || continue
    ((directory_count += 1))
    if [[ $permissions != drwxr-xr-x ]]; then
        echo "package directory has non-0755 mode: $permissions" >&2
        exit 1
    fi
done <<<"$payload_listing"
if ((directory_count == 0)); then
    echo "package payload contains no directories" >&2
    exit 1
fi

temporary=$(mktemp -d -t ois-package-validation-XXXXXX)
trap 'rm -rf "$temporary"' EXIT
stage="$temporary/stage"
dpkg-deb -x "$package" "$stage"

copyright="$stage/usr/share/doc/open-ip-scanner/copyright"
changelog="$stage/usr/share/doc/open-ip-scanner/changelog.gz"
data_notice="$stage/usr/share/doc/open-ip-scanner/vendor-data-sources.md"
manpage="$stage/usr/share/man/man1/open-ip-scanner.1.gz"
binary="$stage/usr/bin/open-ip-scanner"
for required in "$copyright" "$changelog" "$data_notice" "$manpage" "$binary"; do
    if [[ ! -f $required ]]; then
        echo "required package file is missing: ${required#"$stage"}" >&2
        exit 1
    fi
done

require_mode() {
    local path=$1
    local expected=$2
    local actual
    actual=$(stat -c '%a' "$path")
    if [[ $actual != "$expected" ]]; then
        echo "installed file has mode $actual, expected $expected: ${path#"$stage"}" >&2
        exit 1
    fi
}
require_mode "$binary" 755
for document in "$copyright" "$changelog" "$data_notice" "$manpage"; do
    require_mode "$document" 644
done

for compressed in "$changelog" "$manpage"; do
    gzip -t "$compressed"
    if [[ $(od -An -t u1 -j 4 -N 4 "$compressed" | tr -d ' ') != 0000 ]]; then
        echo "gzip timestamp is not deterministic: ${compressed#"$stage"}" >&2
        exit 1
    fi
done

version=$(dpkg-deb -f "$package" Version)
changelog_text=$(gzip -cd "$changelog")
changelog_first_line=${changelog_text%%$'\n'*}
if [[ $changelog_first_line != "open-ip-scanner ($version) unstable; urgency=medium" ]]; then
    echo "installed changelog does not begin with the package version" >&2
    exit 1
fi
manpage_text=$(gzip -cd "$manpage")
if [[ $manpage_text != *'.TH OPEN-IP-SCANNER 1'* ]]; then
    echo "installed manual page is malformed" >&2
    exit 1
fi
for notice in \
    'Permission is hereby granted, free of charge' \
    'https://standards-oui.ieee.org/oui/oui.csv' \
    'https://standards-oui.ieee.org/oui28/mam.csv' \
    'https://standards-oui.ieee.org/oui36/oui36.csv'; do
    if ! grep -Fq "$notice" "$copyright"; then
        echo "installed copyright lacks required notice: $notice" >&2
        exit 1
    fi
done

binary_description=$(file "$binary")
if [[ $binary_description != *', stripped'* ||
      $binary_description == *'not stripped'* ]]; then
    echo "Release package binary is not stripped" >&2
    exit 1
fi
section_table=$(readelf -S "$binary")
if grep -Eq '\.(debug_|symtab)' <<<"$section_table"; then
    echo "Release package binary retains debug or static symbol sections" >&2
    exit 1
fi

dpkg_root="$temporary/dpkg-root"
admindir="$dpkg_root/var/lib/dpkg"
mkdir -p "$admindir/updates" "$admindir/info" "$admindir/parts" "$admindir/triggers"
: >"$admindir/status"
: >"$admindir/available"
if ! dpkg --root="$dpkg_root" --admindir="$admindir" --force-not-root \
    --log="$temporary/dpkg.log" --force-depends --unpack "$package" \
    >/dev/null 2>"$temporary/dpkg-unpack.stderr"; then
    cat "$temporary/dpkg-unpack.stderr" >&2
    exit 1
fi
if ! dpkg --root="$dpkg_root" --admindir="$admindir" --force-not-root \
    --log="$temporary/dpkg.log" --force-depends --configure open-ip-scanner \
    >/dev/null 2>"$temporary/dpkg-configure.stderr"; then
    cat "$temporary/dpkg-configure.stderr" >&2
    exit 1
fi
if ! dpkg --root="$dpkg_root" --admindir="$admindir" --force-not-root \
    --log="$temporary/dpkg.log" --force-depends --remove open-ip-scanner \
    >/dev/null 2>"$temporary/dpkg-remove.stderr"; then
    cat "$temporary/dpkg-remove.stderr" >&2
    exit 1
fi
if [[ -e $dpkg_root/usr/bin/open-ip-scanner ]]; then
    echo "dpkg removal left the runtime binary installed" >&2
    exit 1
fi

lintian_output=$(lintian --fail-on error --display-level '>=warning' \
    --tag-display-limit 0 "$package" 2>&1) || {
    printf '%s\n' "$lintian_output" >&2
    exit 1
}
if grep -Eq '^[EW]:' <<<"$lintian_output"; then
    printf '%s\n' "$lintian_output" >&2
    echo "Lintian warnings require an explicit reviewed disposition" >&2
    exit 1
fi

echo "lintian errors: 0; warnings: 0" >&2
echo "package install/remove validation: PASS" >&2
printf '%s\n' "${packages[0]}"
