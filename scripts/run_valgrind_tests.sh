#!/usr/bin/env bash
# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-build-valgrind}"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind is required; install it with your platform package manager" >&2
  exit 1
fi

cmake -B "${repo_root}/${build_dir}" -S "${repo_root}" \
  -DROHCCXX_BUILD_TESTS=ON \
  -DROHCCXX_ENABLE_VALGRIND_TESTS=ON
cmake --build "${repo_root}/${build_dir}"
ctest --test-dir "${repo_root}/${build_dir}" -L valgrind --output-on-failure
