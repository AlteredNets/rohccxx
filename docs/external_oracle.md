<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# External ROHCv2 Oracle Harness

`rohccxx` keeps deterministic in-repo parity fixtures and generated corpora for every supported RFC 5225 profile family. It also builds the pinned rohc-lib submodule and runs mandatory bidirectional, exact-reconstruction tests for the tested IPv4, small-CID-0, no-IP-options subset of RTP/UDP/IP, UDP/IP, ESP/IP, and IP-only. Each side compresses an equivalent deterministic three-packet flow and the other side independently decompresses it. This evidence does not extend to IPv6, nonzero or large CIDs, IP options, extension-header chains, or packet families absent from those flows.

The mandatory oracle tests use small CID 0 and the RFC 5225 profile identifiers. Corpus records are strictly ordered and carry an explicit profile, packet index, original length, compressed length, and hexadecimal packet bodies; invalid hexadecimal data, length disagreement, unsupported profiles, duplicate or out-of-order records, and incomplete flows are errors rather than skips.

rohc-lib does not expose the RFC 5225 UDP-Lite profiles used by this project, so RTP/UDP-Lite/IP and UDP-Lite/IP are explicitly outside this external-oracle claim. RFC 4362 remains covered only by the optional hook below. The 364-case formal CO corpus remains internal grammar/CRC evidence and is not described as end-to-end interoperability.

A second ROHCv2-capable implementation can optionally be added as corroborating evidence by consuming the generated corpus from `rohccxx_oracle_corpus` or `rfc5225_co_corpus`. This is useful for commercial acceptance testing or independent validation, but it is not required for the in-tree conformance suite to pass. See `docs/external_oracle_gap_register.md` for optional third-party corroboration targets.

## Corpus Format

The first line is a version header:

```text
rohccxx-oracle-corpus-v1 profiles=6 packets_per_profile=3 encoding=hex
```

Each following line contains one packet case:

```text
case profile=<name> step=<0..2> ip_len=<n> rohc_len=<n> ip=<hex> rohc=<hex>
```

The oracle should decode `rohc` and compare the produced IP packet to `ip`. If it can also encode, it may encode `ip` and compare either exact bytes or documented semantic equivalence, depending on its packet grammar choices.

## Running An External Oracle

Build with tests enabled, then set `ROHCCXX_EXTERNAL_ORACLE` to an optional executable that reads the corpus on standard input and exits non-zero on mismatch:

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
ROHCCXX_EXTERNAL_ORACLE=/path/to/oracle-checker ctest --test-dir build -R external_rohcv2_oracle --output-on-failure
```

If `ROHCCXX_EXTERNAL_ORACLE` is unset, the optional CTest case is skipped. The corpus self-test still runs and validates that the emitted ROHC packets round-trip through `rohccxx`.

## RFC 5225 Formal CO Corpus

`rfc5225_co_corpus` emits the byte-level current-FO plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` CID-boundary corpus for every active RFC 5225 compressed profile:

```text
rohccxx-rfc5225-co-corpus-v4 profiles=6 cid_cases=7 implemented_variants=52 cases=364 encoding=hex
```

Each formal `co_common` and `co_repair` line includes `crc_data`, `control_crc_data`, and `rohc` fields so an external checker can validate both the header CRC-7 and control CRC-3 inputs independently. Build with tests enabled, then set `ROHCCXX_RFC5225_CO_ORACLE` to a checker that reads this corpus on standard input:

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
ROHCCXX_RFC5225_CO_ORACLE=/path/to/rfc5225-co-oracle ctest --test-dir build -R external_rfc5225_co_oracle --output-on-failure
```

If `ROHCCXX_RFC5225_CO_ORACLE` is unset, the optional CTest case is skipped. The in-repo corpus self-test still runs and validates corpus generation and `rohccxx` round-trips.


## RFC 4362 Lower-Layer-Assisted Corpus

`rfc4362_oracle_corpus` emits a deterministic corpus for external implementations that understand the RFC 4362 assisting-layer boundary:

```text
rohccxx-rfc4362-oracle-corpus-v1 cases=5 encoding=hex
case kind=ir rohc=<hex> ip=<hex>
case kind=irdyn rohc=<hex> ip=<hex>
case kind=nhp payload=<hex> expected_ip=<hex>
case kind=csp csp=<hex> ip=<hex>
case kind=ccp ccp=<hex>
```

The oracle should treat NHP/CSP/CCP as explicit assisting-layer events, not as ordinary `rohc_decompress4()` byte streams. Build with tests enabled, then set `ROHCCXX_RFC4362_ORACLE` to a checker that reads this corpus on standard input:

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
ROHCCXX_RFC4362_ORACLE=/path/to/rfc4362-oracle ctest --test-dir build -R external_rfc4362_oracle --output-on-failure
```

If `ROHCCXX_RFC4362_ORACLE` is unset, the optional CTest case is skipped. The in-repo corpus self-test still runs and validates corpus generation.
