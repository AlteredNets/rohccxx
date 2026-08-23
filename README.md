<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx

`rohccxx` is a source-available C++ ROHC/ROHCv2 implementation with a C API compatibility layer, deterministic interoperability corpora, RFC traceability documentation, thread-safety coverage, and sanitizer/Valgrind quality gates.

## License

Personal and academic non-commercial use is free under [`LICENSE.md`](LICENSE.md). Commercial use requires a paid license from AlteredNets Cyber Solutions, Inc.; contact [AlteredNets.com](https://AlteredNets.com) for commercial licensing.

This repository is source-available under those terms, not OSI open-source.

## Standards And Integration Docs

- Standards status and adapter boundaries are tracked in [`docs/rfc_compliance.md`](docs/rfc_compliance.md), [`docs/rfc_traceability_matrix.md`](docs/rfc_traceability_matrix.md), [`docs/rohc_standards_roadmap.md`](docs/rohc_standards_roadmap.md), [`docs/lower_layer_assisted_contract.md`](docs/lower_layer_assisted_contract.md), and [`docs/ppp_adapter_contract.md`](docs/ppp_adapter_contract.md).
- Third-party integration guidance is provided in [`howto.md`](howto.md), including public API entry points and protocol-specific transmit/receive flows.
- Mandatory bidirectional rohc-lib interoperability for the RFC 5225 RTP/UDP/IP,
  UDP/IP, ESP/IP, and IP-only profiles, plus the remaining optional oracle hooks,
  is documented in [`docs/external_oracle.md`](docs/external_oracle.md).

## Dependencies

Initialize test dependencies before configuring the build:

```bash
git submodule update --init --recursive
```

The ROHC interop tests use the `tests/third_party/rohc-lib` submodule. Third-party components remain under their own license terms.

## Development Build

```bash
mkdir build && cd build
cmake .. -DROHCCXX_BUILD_TESTS=OFF
cmake --build .
```

## Build And Install

```bash
cmake -B build -S . -DCMAKE_INSTALL_PREFIX=$HOME/rohccxx-test -DROHCCXX_BUILD_TESTS=OFF
cmake --build build
cmake --install build
```

## Versioning And Binary Packages

Release builds derive the project version from an exact git tag at `HEAD`. Tags may use either `vX.Y.Z` or `X.Y.Z`; the configured project version strips a leading `v`. Untagged builds use the version in the checked-in `VERSION` file, and local builds may override the version explicitly:

```bash
cmake -B build -S . -DROHCCXX_VERSION=1.0.0
```

The installed C API exposes the compiled release version:

```c
const char* version = rohccxx_version_string();
unsigned major = rohccxx_version_major();
unsigned minor = rohccxx_version_minor();
unsigned patch = rohccxx_version_patch();
```

The Debian package installs only the stable external integration headers: `rohccxx.h` and `rohccxx/version.h`. Internal C++ headers under the source-tree `include/rohccxx/` subdirectories are not part of the installed ABI contract.

The shared library uses the normal Linux ELF naming and symlink chain:

```text
librohccxx.so -> librohccxx.so.<major>
librohccxx.so.<major> -> librohccxx.so.<major>.<minor>.<patch>
librohccxx.so.<major>.<minor>.<patch>
```

The Debian package is named `librohccxx` and the generated package file is `librohccxx-X.Y.Z.deb`. Installing a newer package version upgrades the package-owned shared library files and updates the loader cache through `ldconfig`. Debian package builds require `dpkg-dev` so CPack can run `dpkg-shlibdeps` and derive shared-library dependencies automatically.

```bash
git tag v1.0.0
cmake -B build -S . -DROHCCXX_BUILD_TESTS=OFF
cmake --build build
cmake --build build --target package
sudo dpkg -i build/librohccxx-1.0.0.deb
```

## Execute Tests

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Debug ROHC Interop Tests

```bash
ROHCCXX_INTEROP_DEBUG=1 ROHCCXX_INTEROP_TRACE=1 ctest --test-dir build -R interop --output-on-failure
```

## Optional External Oracle Hooks

These hooks are optional corroboration points for users who have access to a separate ROHCv2 or RFC 4362 implementation. The generated in-repo corpora remain the normal test baseline.

```bash
ROHCCXX_EXTERNAL_ORACLE=/path/to/rohc-v2-oracle ctest --test-dir build -R external_rohcv2_oracle --output-on-failure
ROHCCXX_RFC5225_CO_ORACLE=/path/to/rfc5225-co-oracle ctest --test-dir build -R external_rfc5225_co_oracle --output-on-failure
ROHCCXX_RFC4362_ORACLE=/path/to/rfc4362-oracle ctest --test-dir build -R external_rfc4362_oracle --output-on-failure
```

## Legacy In-Tree Install Example

```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=$HOME/rohccxx-test -DROHCCXX_BUILD_TESTS=OFF ..
cmake --build .
cmake --install .
```

# RFC 4362 lower-layer-assisted ROHC

RFC 4362 support is exposed through explicit assisting-layer APIs rather than by sending no-header, context synchronization, or context check packets through ordinary `rohc_decompress4()` input. Enable the boundary only after the embedding lower layer satisfies the RFC 3243 zero-byte flow assumptions and the RFC 3409 context-packet protection assumptions:

```c
rohccxx_lla_contract_t contract = {0};
contract.identifies_packet_types = 1;
contract.preserves_order = 1;
contract.reports_loss = 1;
contract.reports_residual_errors = 1;
contract.delivers_feedback = 1;
contract.protects_context_packets = 1;
contract.supports_context_synchronization = 1;
contract.supports_context_check = 1;

rohccxx_lla_flow_t flow = {0};
flow.ipv4_udp_rtp = 1;
flow.udp_checksum_disabled = 1;
flow.rtp_sequence_increments_by_one = 1;
flow.compressor_observed_in_order = 1;
flow.synchronized_timing = 1;

rohc_comp_enable_rfc4362_lla(comp, &contract, &flow);
rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow);
```

Use `rohc_comp_rfc4362_emit_nhp()` / `rohc_decomp_rfc4362_receive_nhp()` for zero-byte no-header operation, `rohc_comp_rfc4362_emit_csp()` / `rohc_decomp_rfc4362_receive_csp()` for context synchronization, and `rohc_comp_rfc4362_emit_ccp()` / `rohc_decomp_rfc4362_receive_ccp()` for context checks. Large-CID assisted NHP/CCP dispatch uses `rohc_decomp_rfc4362_receive_nhp_for_cid()` and `rohc_decomp_rfc4362_receive_ccp_for_cid()` because the assisting layer supplies that CID out of band.

Source-tree native C++ users can use the matching `rohccxx::Compressor` and `rohccxx::Decompressor` RFC 4362 wrapper methods. These C++ helper headers are not installed by the Debian package. The optional `rfc4362_oracle_corpus` test executable emits a deterministic hex corpus for external RFC 4362-capable oracle adapters.

# RFC 5795 segmentation

Segmentation is opt-in and follows the negotiated MRRU value. Call `rohc_comp_set_mrru()` and `rohc_decomp_set_mrru()` with a non-zero value to enable segmentation and reassembly; pass `0` to disable it. When `rohc_compress4()` has to segment a compressed packet, it returns the first segment and exposes remaining segments through `rohc_comp_has_segment()` / `rohc_comp_get_segment()`.

`rohc_decompress4()` returns `1` after accepting a non-final segment, `0` once the final segment has been reassembled and decompressed into an IP packet, and `-1` for malformed, out-of-order, oversized, or unnegotiated segmented input.

# Thread safety

The installed public C API is thread-safe at the opaque-handle boundary, and the source-tree native C++ compressor/decompressor classes serialize their mutable context state:

- Separate `rohc_comp`, `rohc_decomp`, `rohccxx::Compressor`, and `rohccxx::Decompressor` instances may be used concurrently from different threads.
- Calls that share a single compressor or decompressor handle/object are serialized internally with standard C++ locking primitives.
- Pure ROHCoIPsec helper APIs operate only on caller-provided buffers and do not use shared global state.
- A handle or object must not be freed/destroyed while another thread is using it; callers own lifetime coordination.
- Caller-provided input/output buffers must not be concurrently modified by another thread for the duration of a call.

The unit suite includes concurrent C and C++ API coverage implemented with `std::thread`. Use the sanitizer build below when auditing future changes that touch shared state.

# To build tests with sanitizers
cmake -B build-asan -S . -DROHCCXX_BUILD_TESTS=ON -DROHCCXX_SANITIZERS=ON
cmake --build build-asan
cd build-asan
ctest --output-on-failure

# To audit shared-state changes with ThreadSanitizer
cmake -B build-tsan -S . -DROHCCXX_BUILD_TESTS=ON -DROHCCXX_THREAD_SANITIZER=ON
cmake --build build-tsan
ctest --test-dir build-tsan -L tsan --output-on-failure

# Convenience wrapper for the same TSAN quality gate
scripts/run_tsan_tests.sh

# To audit memory correctness with Valgrind Memcheck
cmake -B build-valgrind -S . -DROHCCXX_BUILD_TESTS=ON -DROHCCXX_ENABLE_VALGRIND_TESTS=ON
cmake --build build-valgrind
ctest --test-dir build-valgrind -L valgrind --output-on-failure

# Convenience wrapper for the same Valgrind quality gate
scripts/run_valgrind_tests.sh


# To test the install process locally
#    call these commands from the top level directory
cmake -B build -S . \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build build

DESTDIR=/tmp/rohccxx-stage cmake --install build


# To Build Debian Installation Package
cmake -B build -S . \
  -DROHCCXX_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build build
cmake --build build --target package

sudo dpkg -i build/librohccxx-*.deb

# To Build an RPM Installation package
cmake -B build -S . \
  -DROHCCXX_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build build
cpack --config build/CPackConfig.cmake -G RPM

sudo rpm -Uvh build/librohccxx-*.rpm
