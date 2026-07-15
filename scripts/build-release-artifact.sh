#!/usr/bin/env bash

set -euo pipefail

cleanup_failed_artifacts() {
    local status=$?
    trap - EXIT
    if [[ $status -ne 0 ]]; then
        if ! cmake -E remove_directory "$artifact_dir"; then
            echo "failed to remove incomplete release artifacts: $artifact_dir" >&2
        fi
    fi
    exit "$status"
}

main() {
    local jobs=${OIS_BUILD_JOBS:-2}
    local root
    local first_build_dir
    local second_build_dir
    local first_package_dir
    local second_package_dir
    local source_date_epoch
    local version
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    first_build_dir="$root/build/release-check/repro-a"
    second_build_dir="$root/build/release-check/repro-b"
    first_package_dir="$root/build/release-check/packages/a"
    second_package_dir="$root/build/release-check/packages/b"
    artifact_dir="$root/build/artifacts/release"
    cd "$root"

    trap cleanup_failed_artifacts EXIT
    cmake -E remove_directory "$artifact_dir"
    cmake -E make_directory "$artifact_dir"

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

    cp "$first_package" "$artifact_dir/"

    local package
    package=$(./scripts/validate-release-artifacts.sh "$artifact_dir")
    ./scripts/validate-hardening.sh "$package" "$first_build_dir"
    python3 tools/generate_release_bundle.py \
        --root "$root" \
        --package "$package" \
        --output-dir "$artifact_dir" \
        --version "$version" \
        --epoch "$source_date_epoch"
    ./scripts/validate-release-bundle.sh "$artifact_dir" "$version"
    trap - EXIT
    echo "tested release bundle: $artifact_dir"
}

artifact_dir=
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
