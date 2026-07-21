<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Contributing

Thank you for helping improve `rohccxx`.

## License Expectations

This repository is source-available under `LICENSE.md`. Personal and academic non-commercial use is free, while commercial use requires a paid license from AlteredNets Cyber Solutions, Inc.

By submitting a contribution, you represent that you have the right to submit it and that your contribution may be distributed under the repository license or a separate written agreement with AlteredNets Cyber Solutions, Inc.

## Development Setup

```bash
git submodule update --init --recursive
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Quality Gates

Run the normal CTest suite before submitting changes. For shared-state, packet-format, or buffer-management changes, also run the relevant heavier gate:

```bash
cmake -B build-asan -S . -DROHCCXX_BUILD_TESTS=ON -DROHCCXX_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

```bash
scripts/run_tsan_tests.sh
scripts/run_valgrind_tests.sh
```

## Standards Changes

Protocol changes should update the matching tests and documentation under `docs/`, especially `docs/rfc_traceability_matrix.md`, `docs/rfc_compliance.md`, and any generated corpus documentation affected by the change.
