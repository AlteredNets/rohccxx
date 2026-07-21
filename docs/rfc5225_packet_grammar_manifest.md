<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# RFC 5225 Packet Grammar Manifest

This manifest is the first machine-readable checkpoint for the exhaustive RFC 5225 effort. The executable source of truth is `include/rohccxx/core/rfc5225_grammar.hpp`; this document explains the row model and how the generated corpus is consumed.

## Manifest Scope

The active RFC 5225 compressed profiles are:

| Profile name | Profile ID | RFC area | Current manifest state |
| --- | ---: | --- | --- |
| `rtp_udp_ip` | `0x0101` | RTP/UDP/IP | IR, IR-DYN, and current CO/FO row implemented. |
| `udp_ip` | `0x0102` | UDP/IP | IR, IR-DYN, and current CO/FO row implemented. |
| `esp_ip` | `0x0103` | ESP/IP | IR, IR-DYN, and current CO/FO row implemented. |
| `ip_only` | `0x0104` | IP-only | IR, IR-DYN, and current CO/FO row implemented. |
| `rtp_udplite_ip` | `0x0107` | RTP/UDP-Lite/IP | IR, IR-DYN, and current CO/FO row implemented. |
| `udplite_ip` | `0x0108` | UDP-Lite/IP | IR, IR-DYN, and current CO/FO row implemented. |

## Case Row Model

Each row has a stable `id` plus these dimensions:

| Dimension | Meaning |
| --- | --- |
| `profile` | RFC 5225 profile or `framework` when the row applies across profiles. |
| `family` | `ir`, `ir_dyn`, `co`, `feedback`, `cid`, `chain`, `encoding`, `negative`, `oracle`, or `traceability`. |
| `kind` | `positive`, `negative`, `requirement`, or `oracle`. |
| `status` | `implemented`, `planned`, or `optional_oracle`. |
| `cid_modes` | `small`, `add`, `large`, or `none`. |
| `chains` | Header/static/dynamic/list chain features touched by the row. |
| `encodings` | Encoding methods touched by the row. |
| `section` | RFC 5225 section hint used for traceability. |

## Generated Corpus

Build tests and run the corpus generator:

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=ON
cmake --build build
build/tests/interop/rfc5225_grammar_corpus
```

CTest also runs the manifest and IR/IR-DYN CID corpus as:

```bash
ctest --test-dir build -R "interop_rfc5225_(grammar|ir|co)_corpus" --output-on-failure
```

The first line is a version header:

```text
rohccxx-rfc5225-grammar-corpus-v2 profiles=6 cases=36 co_variants=52 encoding=text
```

Every following line is a stable case row. Future generated packet corpora should use these IDs as prefixes so a failing byte-level packet can be traced back to this grammar manifest.

## Current Completion

| Area | Manifest status |
| --- | --- |
| Active profiles | Complete: six active compressed RFC 5225 profiles are enumerated. |
| Current packet paths | Complete: IR, IR-DYN, current CO/FO, and formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` rows exist for every active compressed profile where the RFC defines them. Generated IR/IR-DYN, current-FO, and formal CO byte corpora now cover all active profiles across CID boundaries. |
| CID modes | Implemented for IR/IR-DYN and current-FO boundary coverage: CID 0, nonzero small-CID/Add-CID boundaries, large-CID 0/127/128/16383, small-CID overflow, large-CID overflow, truncated SDVL, invalid SDVL prefixes, and non-minimal two-octet encodings are tested. |
| Extension/list chains | Implemented for this grammar batch: IPv4 options, IPv6 extensions, RTP CSRC, RTP extension headers, and RTP padding rows have generated helper, malformed, boundary, CRC, and public C API preservation coverage. Generic list-compression property tests are covered by the encoding-method batch. |
| Encoding methods | Complete for the encoding-method batch: W-LSB `p` intervals, scaled/timer RTP timestamps, offset IP-ID, SDVL, and generic list helpers have boundary and malformed coverage in `tests/unit/test_encoding_methods.cpp`. CRC mutation coverage is closed for implemented generated packet families, including formal CO helpers. |
| Negative coverage | Complete for implemented packet set: malformed packet-start tests reject unknown/reserved/truncated/impossible starts, generated CRC mutations cover every implemented IR, IR-DYN, and current-FO CID case, and formal CO tests reject CRC/control/reserved-bit failures. |
| Feedback/state-machine coverage | Complete for the formal CO matrix: generated tests cover RFC 5795 feedback packet Code/Size framing, Add-CID feedback CIDs, ACK/NACK/STATIC-NACK, U/O/R mode requests, piggybacking, and context-state transitions across the full implemented CO set. |
| External oracle | Optional: the CO corpus and optional `ROHCCXX_RFC5225_CO_ORACLE` hook are available for users with a third-party implementation; no independent executable is bundled or required. |


## CO Variant Inventory

The executable manifest also tracks a profile-by-profile CO variant inventory. Each active profile now has its current-FO row plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` packet formats implemented where the profile defines them.

| Profile group | Implemented CO rows | Planned formal CO rows | Notes |
| --- | ---: | ---: | --- |
| RTP/UDP/IP | 12 | 0 | Current FO plus all RTP-family formal CO rows. |
| RTP/UDP-Lite/IP | 12 | 0 | Same RTP-family formal packet surface, with UDP-Lite coverage behavior. |
| UDP/IP | 7 | 0 | Current FO plus all non-RTP formal CO rows. |
| ESP/IP | 7 | 0 | Same non-RTP formal packet surface, with ESP/IP behavior. |
| IP-only | 7 | 0 | Same non-RTP formal packet surface, with IP-only behavior. |
| UDP-Lite/IP | 7 | 0 | Same non-RTP formal packet surface, with UDP-Lite coverage behavior. |

Totals: 52 CO inventory rows, 52 implemented rows, and 0 planned formal RFC 5225 CO rows.

`rfc5225_co_corpus` emits the byte-level current-FO and formal `co_common`/`co_repair`/`pt_0`/`pt_1`/`pt_2` CID boundary corpus for every active compressed profile. The first line is:

```text
rohccxx-rfc5225-co-corpus-v4 profiles=6 cid_cases=7 implemented_variants=52 cases=364 encoding=hex
```

## Acceptance Rules

1. New RFC 5225 packet-family work must add or update manifest rows before adding packet bytes.
2. New generated packet tests must use stable manifest case IDs.
3. A row can move from `planned` to `implemented` only with positive, negative, CRC, CID, and buffer-limit test evidence where applicable.
4. Negative and CRC rows are closed for implemented packet families; any future profile-specific packet variant must be wired into the generated negative/CRC harness before its row can move to `implemented`.
5. Optional oracle rows are corroboration hooks only; in-tree grammar rows require generated positive, negative, CRC, CID, and buffer-limit coverage.

## IR/IR-DYN CID Corpus

`rfc5225_ir_corpus` emits the byte-level IR and IR-DYN CID boundary corpus for every active compressed profile. The first line is:

```text
rohccxx-rfc5225-ir-corpus-v1 profiles=6 cid_cases=7 packets=2 cases=84 encoding=hex
```

Each case line includes the stable profile, packet family, CID value, CID mode, ROHC byte length, and hex-encoded ROHC packet.
