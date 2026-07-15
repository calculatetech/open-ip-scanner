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
    local build_dir
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    build_dir="$root/build/release-artifact"
    artifact_dir="$root/build/release-artifacts"
    cd "$root"

    trap cleanup_failed_artifacts EXIT
    cmake -E remove_directory "$artifact_dir"
    cmake -E make_directory "$artifact_dir"

    ./scripts/validate-metadata.sh

    cmake -S . -B "$build_dir" -G Ninja -DBUILD_TESTING=ON \
        -DCMAKE_BUILD_TYPE=Release -DOIS_WARNINGS_AS_ERRORS=ON
    cmake --build "$build_dir" --parallel "$jobs"
    ctest --test-dir "$build_dir" --output-on-failure

    cpack --config "$build_dir/CPackConfig.cmake" -G DEB -B "$artifact_dir"

    local package
    package=$(./scripts/validate-release-artifacts.sh "$artifact_dir")
    trap - EXIT
    echo "tested release artifact: $package"
}

artifact_dir=
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
