#!/usr/bin/env bash

set -euo pipefail

mode=${1:-fast}
jobs=${OIS_BUILD_JOBS:-2}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}
cd "$root"

case "$mode" in
    fast|full|release) ;;
    *)
        echo "usage: $0 {fast|full|release}" >&2
        exit 2
        ;;
esac

build_suite() {
    local build_dir=$1
    shift
    cmake -S . -B "$build_dir" -G Ninja -DBUILD_TESTING=ON "$@"
    cmake --build "$build_dir" --parallel "$jobs"
}

run_suite() {
    local build_dir=$1
    shift
    build_suite "$build_dir" "$@"
    ctest --test-dir "$build_dir" --output-on-failure
}

run_suite_except() {
    local build_dir=$1
    local exclusion=$2
    shift 2
    build_suite "$build_dir" "$@"
    ctest --test-dir "$build_dir" --output-on-failure -E "$exclusion"
}

run_suite build/quality-fast -DCMAKE_BUILD_TYPE=Debug

if [[ $mode == full || $mode == release ]]; then
    run_suite build/quality-strict \
        -DCMAKE_BUILD_TYPE=Debug -DOIS_WARNINGS_AS_ERRORS=ON

    run_suite_except build/quality-asan 'settings_dialog_stability' \
        -DCMAKE_BUILD_TYPE=Debug \
        '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer' \
        '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'

    cmake -S . -B build/quality-tsan -G Ninja -DBUILD_TESTING=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        '-DCMAKE_CXX_FLAGS=-fsanitize=thread -fno-omit-frame-pointer' \
        '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread'
    cmake --build build/quality-tsan --parallel "$jobs"
    tsan_exclusion='settings_dialog_stability|service_probe_tls_integration'
    if [[ -n ${OIS_TSAN_EXCLUDE:-} ]]; then
        tsan_exclusion+="|${OIS_TSAN_EXCLUDE}"
    fi
    ctest --test-dir build/quality-tsan --output-on-failure \
        -E "$tsan_exclusion"

    if command -v clang-tidy >/dev/null 2>&1; then
        cmake -S . -B build/quality-clang-tidy -G Ninja -DBUILD_TESTING=OFF \
            -DCMAKE_BUILD_TYPE=Debug \
            '-DCMAKE_CXX_CLANG_TIDY=clang-tidy;--warnings-as-errors=*'
        cmake --build build/quality-clang-tidy --parallel "$jobs"
    else
        echo "quality gate: clang-tidy unavailable; strict compiler warnings are the configured equivalent"
    fi
fi

if [[ $mode == release ]]; then
    run_suite build/quality-release -DCMAKE_BUILD_TYPE=Release \
        -DOIS_WARNINGS_AS_ERRORS=ON
    cpack --config build/quality-release/CPackConfig.cmake -G DEB
fi

echo "quality gate ($mode): PASS"
