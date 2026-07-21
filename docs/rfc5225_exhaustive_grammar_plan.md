<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# RFC 5225 Exhaustive Grammar Plan

Decision: for `rohccxx`, "100 percent RFC 5225 compliance" means every possible packet grammar and encoding variant defined for the active ROHCv2 profiles, not just every currently supported profile path. The current implementation is strong for implemented IR, IR-DYN, FO, CID, feedback, segmentation, IPv6, and encoding-method paths; this plan defines the remaining formal exhaustive work.

## Exit Criteria

RFC 5225 exhaustive compliance is closed only when all of these are true:

1. Every RFC 5225 profile is represented in a machine-readable grammar manifest: RTP/UDP/IP, UDP/IP, ESP/IP, IP-only, RTP/UDP-Lite/IP, and UDP-Lite/IP.
2. Every IR, IR-DYN, CO, feedback, Add-CID, small-CID, and large-CID variant has positive decode, positive encode, negative parse, CRC mutation, and buffer-limit tests.
3. Every formal encoding method used by those packet families has boundary, randomized, and cross-profile tests.
4. Every static, dynamic, irregular, extension, option, and list chain has generated coverage for IPv4 and IPv6.
5. Generated corpora are available for optional third-party corroboration without making the in-tree compliance gate depend on a commercial oracle.
6. `docs/rfc_traceability_matrix.md` maps each RFC 5225 requirement row to test evidence.

## Progress

| Date | Steps | Status | Evidence |
| --- | --- | --- | --- |
| 2026-07-18 | 2-4 foundation | Complete | `include/rohccxx/core/rfc5225_grammar.hpp`, `docs/rfc5225_packet_grammar_manifest.md`, `tests/unit/test_rfc5225_grammar.cpp`, and `tests/interop/rfc5225_grammar_corpus.cpp` define and validate the manifest/corpus foundation. |
| 2026-07-18 | 5-8 IR/IR-DYN CID boundaries | Complete | `tests/unit/test_rfc5225_grammar.cpp` and `tests/interop/rfc5225_ir_corpus.cpp` cover small CID, Add-CID, large-CID SDVL, malformed CID forms, and generated IR/IR-DYN packets across all active profiles. |
| 2026-07-19 | 9-15 CO inventory and current-FO corpus | Complete for implemented FO subset; formal variants tracked separately | `include/rohccxx/core/rfc5225_grammar.hpp` inventories 52 CO variants across the active profiles. `tests/unit/test_rfc5225_grammar.cpp` and `tests/interop/rfc5225_co_corpus.cpp` cover the six implemented current-FO paths across CID boundaries, CRC mutation, buffer limits, and CID overflow rejection. |
| 2026-07-24 | 16-20 extension/list grammar | Complete | `include/rohccxx/core/rfc5225_chains.hpp` and `src/c_api/rohc_c_api.cpp` preserve IPv4 options, IPv6 extension lists, RTP CSRC lists, RTP extension headers, and RTP padding. `tests/unit/test_rfc5225_grammar.cpp` covers insert/remove/reorder/duplicate, boundary, malformed-length, and CRC mutation cases; `tests/unit/test_packet_parse.cpp` validates public C API RTP CSRC/extension/padding round-trips. |
| 2026-07-24 | 21-26 encoding methods | Complete | `include/rohccxx/core/encoding_methods.hpp` exposes W-LSB interpretation intervals with explicit `p`, residue-aware RTP timestamp scaling, offset IP-ID W-LSB decoding, strict SDVL, and strict generic-list helpers. `tests/unit/test_encoding_methods.cpp` covers p-values, wraparound, stride/residue/timer boundaries, sequential/swapped/random/zero IP-ID cases, SDVL boundaries, and malformed generic-list forms. |
| 2026-07-24 | 27-28 negative and CRC generated scaffolding | Complete for implemented packet set | `tests/unit/test_rfc5225_grammar.cpp` rejects unknown/reserved/truncated/impossible packet starts and mutates both CRC bytes and protected payload bytes for every implemented IR, IR-DYN, and current-FO generated CID case. Formal CO coverage now rejects header CRC, control CRC, buffer-limit, and `co_repair` reserved-bit failures. |
| 2026-07-24 | 9-15 formal CO pt-0 slice | Complete for formal `pt_0_crc3` and `pt_0_crc7` across all profiles | `include/rohccxx/core/formal_co.hpp` implements formal pt-0 Add-CID, large-CID, discriminator, MSN, CRC-3, and CRC-7 wire handling. `tests/unit/test_rfc5225_grammar.cpp` covers all active profiles and CID modes; `tests/interop/rfc5225_co_corpus.cpp` emits current-FO plus formal pt-0 cases. |
| 2026-07-24 | 9-15 formal CO pt-1/pt-2 slice | Complete for formal `pt_1`/`pt_2` packet formats across applicable profiles | `include/rohccxx/core/formal_co.hpp` now implements the RTP/RTP-UDP-Lite `pt_1_rnd`, `pt_1_seq_id`, `pt_1_seq_ts`, `pt_2_rnd`, `pt_2_seq_id`, `pt_2_seq_both`, and `pt_2_seq_ts` wire grammars plus non-RTP `pt_1_seq_id` and `pt_2_seq_id`. `tests/unit/test_rfc5225_grammar.cpp` covers discriminators, LSB field widths, CRC mutation, CID placement, and short buffers; `tests/interop/rfc5225_co_corpus.cpp` emits 280 cases for 40 implemented CO rows. |
| 2026-07-24 | 9-15 formal CO co_common/co_repair plus feedback/oracle hooks | Complete for in-tree compliance; external oracle attachment is optional | `include/rohccxx/core/formal_co.hpp` implements profile-directed formal `co_common` and `co_repair` wire grammars across all six active profiles. `tests/unit/test_rfc5225_grammar.cpp` covers CID placement, header CRC-7, control CRC-3, opaque irregular/dynamic chains, short buffers, reserved-bit rejection, U/O/R feedback piggyback cross-products, and compressor state transitions; `tests/interop/rfc5225_co_corpus.cpp` emits 364 cases for all 52 implemented CO rows; `tests/interop/CMakeLists.txt` adds the optional `ROHCCXX_RFC5225_CO_ORACLE` gate. |

## Step-by-step Work Plan

| Step | Work item | Deliverable | Gate |
| ---: | --- | --- | --- |
| 1 | Freeze the current green baseline. | Commit current sanitizer/test/doc state. | Normal, ASAN/UBSAN, TSAN, and Valgrind gates green. |
| 2 | Extract RFC 5225 formal notation into a manifest worklist. | `docs/rfc5225_packet_grammar_manifest.md` with profiles, packet families, fields, conditions, CRCs, and encodings. | Foundation complete; broaden the manifest as each formal packet family is implemented. |
| 3 | Define a C++ grammar table schema. | Internal structs/enums for profile, packet type, discriminator, CID mode, field list, and encoding method. | Foundation complete in `rfc5225_grammar.hpp`; unit tests validate profile, case, CID, chain, and encoding coverage. |
| 4 | Build a generated corpus harness. | Generator that emits positive and negative packet cases with stable case IDs. | Foundation complete via `interop_rfc5225_grammar_corpus`; future work expands rows into byte-level packet corpora. |
| 5 | Add small-CID and Add-CID exhaustiveness. | Generated cases for CID 0, max small CID, Add-CID prefixes, bad Add-CID, and out-of-range CID. | Complete for IR/IR-DYN corpus: CID 0, Add-CID 1/15, malformed Add-CID packet starts, and small-CID overflow rejection are covered. |
| 6 | Add large-CID SDVL exhaustiveness. | Generated cases for 1-octet, 2-octet, boundary, maximum negotiated, malformed, truncated, and out-of-range SDVL CIDs. | Complete for IR/IR-DYN corpus: one-octet, two-octet, boundary, maximum, truncated, invalid-prefix, overflow, and non-minimal SDVL cases are covered. |
| 7 | Expand IR grammar for every profile. | Generated IR cases covering static chains, dynamic chains, CRC-8, profile IDs, and CID modes. | Complete for current static/dynamic chain grammar across all active profiles and CID modes; extension/list expansion remains in steps 16-20. |
| 8 | Expand IR-DYN grammar for every profile. | Generated IR-DYN cases covering dynamic chain changes, CRC-7/CRC-8 as applicable, and CID modes. | Complete for current dynamic chain grammar across all active profiles and CID modes; extension/list expansion remains in steps 16-20. |
| 9 | Inventory every CO packet family and discriminator. | Checklist table that names each formal CO packet variant by profile. | Complete: `co_variant_manifest` inventories 52 rows and all 52 are implemented. |
| 10 | Implement/generated-test RTP CO families. | RTP packet variants beyond current FO path, including MSN/TS/marker/payload-type changes. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` variants are covered for RTP across CID boundaries, discriminator bits, CRC mutation, short buffers, and CID overflow. |
| 11 | Implement/generated-test UDP/IP CO families. | UDP-specific CO variants, inferred lengths, checksum behavior, and profile-state transitions. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0_crc3`, `pt_0_crc7`, `pt_1_seq_id`, and `pt_2_seq_id` are covered for UDP/IP across CID boundaries. |
| 12 | Implement/generated-test IP-only CO families. | IPv4, IPv6, AH, GRE, MINE, extension-header, and generic next-header variants. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0_crc3`, `pt_0_crc7`, `pt_1_seq_id`, and `pt_2_seq_id` are covered for IP-only across CID boundaries. |
| 13 | Implement/generated-test ESP/IP CO families. | ESP SPI/sequence behavior, IP chain changes, and ROHCoIPsec separation checks. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0_crc3`, `pt_0_crc7`, `pt_1_seq_id`, and `pt_2_seq_id` are covered for ESP/IP across CID boundaries. |
| 14 | Implement/generated-test RTP/UDP-Lite/IP CO families. | RTP plus UDP-Lite coverage behavior, checksum coverage changes, and packet variants. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` variants are covered for RTP/UDP-Lite/IP across CID boundaries. |
| 15 | Implement/generated-test UDP-Lite/IP CO families. | UDP-Lite-only coverage behavior and packet variants. | Complete: current FO plus formal `co_common`, `co_repair`, `pt_0_crc3`, `pt_0_crc7`, `pt_1_seq_id`, and `pt_2_seq_id` are covered for UDP-Lite/IP across CID boundaries. |
| 16 | Complete IPv4 option compression/list coverage. | Generated option-list insert, remove, reorder, duplicate, empty, and malformed cases. | Complete: IPv4 option-list helper tests cover empty, insert, duplicate, reorder, maximum local corpus, invalid markers, zero-length non-empty markers, and truncation. |
| 17 | Complete IPv6 extension-list compression coverage. | Destination Options, Hop-by-Hop, Routing, AH, GRE, MINE, nested/ordered chains, and malformed-length cases. | Complete: IPv6 extension-list tests cover ordered Hop-by-Hop/Destination/Routing chains terminating in AH, GRE, and MINE plus malformed and unencodable lengths. |
| 18 | Complete RTP CSRC list compression. | Insert, remove, reorder, duplicate, maximum CC, malformed CC, and CRC mutation cases. | Complete: RTP extras-list tests cover empty, duplicate/reordered CSRC bytes, maximum CC, malformed CC, and IR-DYN CRC mutation rejection. |
| 19 | Complete RTP extension-header coverage. | Extension length boundaries, payload preservation, and malformed lengths. | Complete: RTP extension-header tests cover 4-byte, 8-byte, and 256-byte extension boundaries plus public C API payload preservation. |
| 20 | Complete RTP padding semantics. | Padding present/absent, padding length boundaries, malformed padding, and payload preservation. | Complete: RTP padding tests cover absent, 1-byte, 255-byte, malformed final count, and public C API payload preservation. |
| 21 | Exhaust W-LSB behavior. | Per-field p-values, interpretation intervals, wraparound, reorder-depth, loss-depth, min-width, and failure cases. | Complete: W-LSB tests cover explicit `p` values, interval boundaries, wraparound, default field decoding, and malformed width/LSB/p values. |
| 22 | Exhaust scaled RTP timestamp behavior. | Stride discovery, stride changes, irregular timestamps, wraparound, marker interactions, and regular 160-clock traces. | Complete: scaled timestamp tests cover stride inference, sequence/timestamp wraparound, invalid stride changes, residue-aware scaling, and FO parity traces. |
| 23 | Exhaust timer-based timestamp behavior. | time_stride negotiation, arrival-time reconstruction, jitter windows, missing time reference, and fallback cases. | Complete: timer timestamp tests cover elapsed and zero-elapsed reconstruction, wraparound, missing time stride rejection, and packet-context FO decode. |
| 24 | Exhaust IP-ID behavior. | Sequential, sequential-swapped, random, zero, offset encoding, wraparound, IPv4-only applicability, and IPv6 non-applicability. | Complete: offset IP-ID tests cover sequential, swapped, random/full-width, zero, wraparound, and invalid offset-WLSB forms. |
| 25 | Exhaust SDVL field usage beyond CID. | Boundary values, non-minimal encodings, truncated encodings, and cross-field users. | Complete: SDVL tests cover 0, 1, 127, 128, mid-range, 16383, overflow, short buffers, truncation, invalid prefixes, and non-minimal encodings. |
| 26 | Exhaust generic list compression. | Empty list, static list, dynamic list, insertion, deletion, reordering, reference invalidation, and malformed item lengths. | Complete: generic-list tests cover empty, maximum static/dynamic lists, reordering, writer limits, invalid non-empty markers, zero-count markers, truncation, and capacity failures. |
| 27 | Generate malformed packet-start coverage. | Every reserved/unknown packet start, truncated packet family, impossible field combination, and forbidden profile state. | Complete for implemented packet set: parser tests reject unknown/reserved starts, Add-CID truncation, large-CID truncation/non-minimal/invalid prefixes, missing profile IDs, impossible large-CID RTP embedded-CID starts, and formal CO reserved/CRC failures. |
| 28 | Generate CRC mutation coverage. | For every positive generated case, mutate each CRC-protected region and verify rejection/feedback. | Complete for implemented packet set: IR, IR-DYN, current-FO, and formal CO generated cases cover CRC mutation across all active profiles and CID modes. |
| 29 | Generate state-machine coverage. | U-mode, O-mode, R-mode, ACK, NACK, STATIC-NACK, loss, reordering, context refresh, and profile transition cases across packet families. | Complete for formal CO families: U/O/R with ACK/NACK/STATIC-NACK piggybacked feedback is generated across all active profiles, CID modes, and formal CO variants, and the decoded feedback is applied to NoContext, StaticEstablished, DynamicEstablished, and second-NACK recovery states. |
| 30 | Add external oracle corpus v2. | Corpus includes case ID, profile, packet family, CID mode, input IP, ROHC bytes, expected output IP, and semantic-equivalence hints. | Complete for CO corpus plumbing: `rfc5225_co_corpus` v4 emits all implemented CO rows and `ROHCCXX_RFC5225_CO_ORACLE` can optionally consume it. |
| 31 | Attach optional independent oracle if available. | Configure `ROHCCXX_EXTERNAL_ORACLE`/`ROHCCXX_RFC5225_CO_ORACLE` in CI/local gates only when a compatible third-party implementation is available. | Optional: the CTest hooks are attached and skipped when unset; no independent executable is bundled or required. |
| 32 | Close traceability rows. | `docs/rfc_traceability_matrix.md` links each RFC 5225 row to generated tests and optional oracle evidence. | Exhaustive in-repo rows are closed; third-party oracle corroboration remains optional. |

## Recommended Implementation Batches

| Batch | Steps | Goal |
| --- | --- | --- |
| A | 1-4 | Turn the RFC grammar into a trackable manifest and generator skeleton. |
| B | 5-8 | Make CID, IR, and IR-DYN exhaustive before touching the larger CO space. |
| C | 9-15 | Inventory every profile-specific CO packet family and exhaustively test current-FO plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2`. |
| D | 16-20 | Finish extension, option, CSRC, RTP extension, and padding grammar. |
| E | 21-26 | Exhaust the encoding methods across boundary and randomized cases. |
| F | 27-29 | Add negative, CRC, and state-machine cross-product coverage. |
| G | 30-31 | Attach independent external oracle validation. |
| H | 32 | Close documentation and traceability. |

## Practical Notes

1. The manifest should be reviewed before implementation begins; it becomes the checklist that prevents silent omissions.
2. Generated tests should use stable case IDs so failures can be mapped directly back to RFC grammar rows.
3. Byte-identical encoding should be required when the grammar leaves no choice; semantic-equivalence checks are acceptable only when RFC 5225 permits more than one valid encoding.
4. The current deterministic corpus remains valuable, but it is not enough for the exhaustive definition because it covers supported paths rather than every formal packet/encoding variant.
5. External oracle integration should be added only when a compatible third-party implementation is available; otherwise the generated in-repo corpus remains the release baseline.
