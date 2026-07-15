#!/usr/bin/env bash

set -euo pipefail

cleanup_transient_output() {
    local status=$?
    trap - EXIT
    for transient in "${package_root:-}" "${bundle_dir:-}"; do
        if [[ -n $transient ]] && ! cmake -E remove_directory "$transient"; then
            echo "failed to remove transient release output: $transient" >&2
        fi
    done
    if [[ ${publish_owned:-0} -eq 1 ]] && ! cmake -E rm -f "$publish_path"; then
        echo "failed to remove transient release package: $publish_path" >&2
    fi
    if [[ $status -ne 0 && ${provenance_owned:-0} -eq 1 ]] &&
       ! cmake -E remove_directory "$provenance_dir"; then
        echo "failed to remove incomplete provenance output: $provenance_dir" >&2
    fi
    exit "$status"
}

stage_release_package() {
    local package=$1
    local candidate_version
    local candidate_architecture
    local candidate_package
    local expected_name
    local package_name
    package_name=$(basename "$package")
    if [[ -L $release_dir || ( -e $release_dir && ! -d $release_dir ) ]]; then
        echo "release destination must be a real directory: $release_dir" >&2
        return 1
    fi
    cmake -E make_directory "$release_dir"
    candidate_package=$(dpkg-deb --field "$package" Package)
    candidate_version=$(dpkg-deb --field "$package" Version)
    candidate_architecture=$(dpkg-deb --field "$package" Architecture)
    expected_name="open-ip-scanner_${candidate_version}_${candidate_architecture}.deb"
    if [[ $candidate_package != open-ip-scanner || $package_name != "$expected_name" ]]; then
        echo "candidate package filename and metadata disagree: $package" >&2
        return 1
    fi
    publish_target="$release_dir/$package_name"
    publish_path=$(mktemp "$release_dir/.open-ip-scanner-package.XXXXXX.tmp")
    publish_owned=1
    cmake -E copy "$package" "$publish_path"
    cmp --silent "$package" "$publish_path"
}

publish_staged_release() {
    local status
    if mv -f -- "$publish_path" "$publish_target"; then
        trap - EXIT
        return 0
    else
        status=$?
        return "$status"
    fi
}

prepare_provenance_directory() {
    if [[ -z $provenance_dir ]]; then
        return
    fi
    if [[ $provenance_dir != /* ]]; then
        echo "OIS_PROVENANCE_DIR must be an absolute path" >&2
        return 1
    fi
    if [[ -e $provenance_dir || -L $provenance_dir ]]; then
        echo "OIS_PROVENANCE_DIR must not already exist: $provenance_dir" >&2
        return 1
    fi

    local parent
    local canonical_parent
    local lexical_parent
    parent=$(dirname "$provenance_dir")
    if [[ ! -d $parent ]]; then
        echo "OIS_PROVENANCE_DIR parent must already exist: $parent" >&2
        return 1
    fi
    canonical_parent=$(realpath -e "$parent")
    lexical_parent=$(realpath -s "$parent")
    if [[ $canonical_parent != "$lexical_parent" ]]; then
        echo "OIS_PROVENANCE_DIR parent must not traverse symlinks: $parent" >&2
        return 1
    fi
    provenance_dir="$canonical_parent/$(basename "$provenance_dir")"
    if [[ $provenance_dir == "$root" || $provenance_dir == "$root"/* ]]; then
        echo "OIS_PROVENANCE_DIR must be outside the repository" >&2
        return 1
    fi

    if ! mkdir -- "$provenance_dir"; then
        echo "OIS_PROVENANCE_DIR could not be created exclusively: $provenance_dir" >&2
        return 1
    fi
    provenance_owned=1
}

main() {
    local jobs=${OIS_BUILD_JOBS:-2}
    local root
    local first_build_dir
    local second_build_dir
    local first_package_dir
    local second_package_dir
    local release_dir
    local source_date_epoch
    local version
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    first_build_dir="$root/build/release-check/repro-a"
    second_build_dir="$root/build/release-check/repro-b"
    package_root="$root/build/release-check/package-scratch"
    first_package_dir="$package_root/a"
    second_package_dir="$package_root/b"
    bundle_dir="$root/build/release-check/bundle-scratch"
    release_dir="$root/release"
    provenance_dir=${OIS_PROVENANCE_DIR:-}
    cd "$root"

    trap cleanup_transient_output EXIT
    cmake -E remove_directory "$package_root"
    cmake -E remove_directory "$bundle_dir"
    cmake -E make_directory "$bundle_dir"
    prepare_provenance_directory

    ./scripts/validate-metadata.sh

    source_date_epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
    if [[ ! $source_date_epoch =~ ^[0-9]+$ ]]; then
        echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
        exit 1
    fi
    export SOURCE_DATE_EPOCH=$source_date_epoch
    version=$(sed -nE 's/^project\(OpenIpScanner VERSION ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' \
        CMakeLists.txt)
    if [[ -z $version ]]; then
        echo "could not read the project version" >&2
        exit 1
    fi

    build_candidate() {
        local build_dir=$1
        local package_dir=$2
        cmake -E remove_directory "$build_dir"
        cmake -E remove_directory "$package_dir"
        cmake -E make_directory "$package_dir"
        cmake -S . -B "$build_dir" -G Ninja -DBUILD_TESTING=ON \
            -DCMAKE_BUILD_TYPE=Release -DOIS_WARNINGS_AS_ERRORS=ON
        cmake --build "$build_dir" --parallel "$jobs"
        ctest --test-dir "$build_dir" --output-on-failure
        cpack --config "$build_dir/CPackConfig.cmake" -G DEB -B "$package_dir"
    }

    local first_package
    local second_package
    build_candidate "$first_build_dir" "$first_package_dir"
    first_package=$(./scripts/validate-release-artifacts.sh --basic "$first_package_dir")
    build_candidate "$second_build_dir" "$second_package_dir"
    second_package=$(./scripts/validate-release-artifacts.sh --basic "$second_package_dir")
    local first_sha
    local second_sha
    first_sha=$(sha256sum "$first_package" | cut -d' ' -f1)
    second_sha=$(sha256sum "$second_package" | cut -d' ' -f1)
    if [[ $first_sha != "$second_sha" ]]; then
        echo "isolated Release packages are not reproducible" >&2
        echo "first:  $first_sha" >&2
        echo "second: $second_sha" >&2
        if command -v diffoscope >/dev/null 2>&1; then
            diffoscope "$first_package" "$second_package" >&2 || true
        fi
        exit 1
    fi
    echo "release artifacts reproducible: PASS"

    cp "$first_package" "$bundle_dir/"

    local package
    package=$(./scripts/validate-release-artifacts.sh "$bundle_dir")
    ./scripts/validate-hardening.sh "$package" "$first_build_dir"
    python3 tools/generate_release_bundle.py \
        --root "$root" \
        --package "$package" \
        --output-dir "$bundle_dir" \
        --version "$version" \
        --epoch "$source_date_epoch"
    ./scripts/validate-release-bundle.sh "$bundle_dir" "$version"

    if [[ -n $provenance_dir ]]; then
        cmake -E copy \
            "$bundle_dir/open-ip-scanner-$version.tar.gz" \
            "$bundle_dir/open-ip-scanner_${version}_amd64.spdx.json" \
            "$bundle_dir/SHA256SUMS" \
            "$provenance_dir/"
    fi

    stage_release_package "$package"
    cmake -E remove_directory "$package_root"
    cmake -E remove_directory "$bundle_dir"
    echo "publishing installable package: $release_dir/$(basename "$package")"
    publish_staged_release
}

package_root=
bundle_dir=
publish_path=
publish_owned=0
publish_target=
provenance_dir=
provenance_owned=0
release_dir=
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
