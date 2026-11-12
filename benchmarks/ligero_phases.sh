#!/usr/bin/env bash
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
#
# Build the standalone Ligero phase benchmark in Release mode and run it.
# Override LIGERO_BUILD_DIR or LIGERO_CXX_FLAGS when needed; all other
# arguments are passed to ligero_phase_bench.

set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${LIGERO_BUILD_DIR:-$repo_dir/build-ligero-release}"
if [[ "$build_dir" != /* ]]; then
  build_dir="$repo_dir/$build_dir"
fi

if [[ ! -f "$build_dir/CMakeCache.txt" ]]; then
  cmake -S "$repo_dir/lib" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="${LIGERO_CXX_FLAGS:--march=native}" \
    -DPROOFS_DIAGNOSTICS=ON
fi
cmake --build "$build_dir" --target ligero_phase_bench --parallel
exec "$build_dir/bench/ligero_phase_bench" "$@"
