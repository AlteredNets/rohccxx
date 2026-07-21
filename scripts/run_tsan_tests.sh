#!/usr/bin/env bash
# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-build-tsan}"

cmake -B "${repo_root}/${build_dir}" -S "${repo_root}" \
  -DROHCCXX_BUILD_TESTS=ON \
  -DROHCCXX_THREAD_SANITIZER=ON
cmake --build "${repo_root}/${build_dir}"
ctest --test-dir "${repo_root}/${build_dir}" -L tsan --output-on-failure
