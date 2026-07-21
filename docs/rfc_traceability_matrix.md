<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# RFC Requirement Traceability Matrix

This matrix is the active compliance worklist for the RFCs currently in scope for `rohccxx`. It paraphrases RFC requirements into implementable rows; the RFC Editor text remains the source of truth. RFC 3242 is intentionally inactive because RFC 4362 obsoletes it.

Boundaries:

- `Library`: behavior that `rohccxx` must implement, expose, reject, or test directly.
- `Adapter`: behavior owned by a PPP driver, lower layer, IKEv2 implementation, or IPsec stack. `rohccxx` should provide a safe API seam and validation gate, but should not become that driver or stack.

## Source Inventory

| RFC | Source | RFC2119 keyword hits | Active handling |
| --- | --- | ---: | --- |
| RFC 5225 | https://www.rfc-editor.org/rfc/rfc5225.txt | 69 | Active ROHCv2 profile grammar and encoding target. |
| RFC 3241 | https://www.rfc-editor.org/rfc/rfc3241.txt | 19 | Active PPP adapter API target. |
| RFC 3243 | https://www.rfc-editor.org/rfc/rfc3243.txt | 0 | Active zero-byte assumption target; no RFC2119 keyword inventory. |
| RFC 3408 | https://www.rfc-editor.org/rfc/rfc3408.txt | 18 | Active R-mode zero-byte lower-layer-assisted target. |
| RFC 3409 | https://www.rfc-editor.org/rfc/rfc3409.txt | 0 | Active lower-layer guideline target; no RFC2119 keyword inventory. |
| RFC 4362 | https://www.rfc-editor.org/rfc/rfc4362.txt | 56 | Active lower-layer-assisted profile API target. |
| RFC 5795 | https://www.rfc-editor.org/rfc/rfc5795.txt | 46 | Active ROHC framework, feedback, segmentation, and uncompressed profile target. |
| RFC 5856 | https://www.rfc-editor.org/rfc/rfc5856.txt | 39 | Active ROHCoIPsec architecture seam target. |
| RFC 5857 | https://www.rfc-editor.org/rfc/rfc5857.txt | 45 | Active IKEv2 ROHCoIPsec negotiation helper target. |
| RFC 5858 | https://www.rfc-editor.org/rfc/rfc5858.txt | 45 | Active IPsec ROHC packet processing helper target. |

## Status Legend

| Status | Meaning |
| --- | --- |
| Closed | Implemented and covered by tests or deterministic fixtures. |
| Boundary closed | `rohccxx` exposes the helper/gate and tests it; the real driver, link, IKEv2 exchange, or IPsec stack remains outside the library. |
| Open exhaustive | Current supported paths are covered, but every possible formal grammar or encoding variant is not yet implemented and generated. |
| Optional oracle | In-repo coverage exists, and optional third-party corroboration hooks are available when a compatible implementation is available. |
| Outside library | Documented as integration responsibility, not a `rohccxx` feature. |

## RFC 5225: ROHCv2 Profiles

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 5225-REQ-001 | MUST | Expose and preserve ROHCv2 profile identifiers for RTP/UDP/IP, UDP/IP, ESP/IP, IP-only, RTP/UDP-Lite/IP, and UDP-Lite/IP. | Library | `tests/compat/test_rtp_compat.cpp`, `include/rohccxx.h` | Closed | Keep IDs stable. |
| 5225-REQ-002 | MUST | Classify supported IPv4 and IPv6 protocol stacks into the correct ROHCv2 profile family. | Library | `tests/compat/test_rtp_compat.cpp` | Closed | Add generated classification cases for every future extension-chain variant. |
| 5225-REQ-003 | MUST | Maintain compressor/decompressor context state per CID and profile. | Library | `tests/unit/test_packet_parse.cpp`, `tests/unit/test_sprint5_basic.cpp`, `tests/unit/test_sprint6_roundtrip.cpp` | Closed | Extend generated tests to every packet family. |
| 5225-REQ-004 | MUST/MAY | Support small CID, Add-CID, and large-CID SDVL framing where negotiated. | Library | `tests/unit/test_packet_parse.cpp` | Closed for current packet families | Add exhaustive SDVL boundary corpus to grammar plan. |
| 5225-REQ-005 | MUST | Encode/decode IR and IR-DYN headers with profile, CRC, static chain, and dynamic chain semantics. | Library | `tests/unit/test_packet_parse.cpp`, `tests/interop/rohccxx_oracle_corpus.cpp` | Closed for current profile paths | Open exhaustive for all formal chain variants. |
| 5225-REQ-006 | MUST | Encode/decode CO packet formats for each supported profile. | Library | `tests/unit/test_packet_parse.cpp`, `tests/compat/test_rtp_compat.cpp`, `tests/unit/test_rfc5225_grammar.cpp`, `tests/interop/rfc5225_co_corpus.cpp` | Closed | Current FO plus formal `co_common`, `co_repair`, `pt_0`, `pt_1`, and `pt_2` paths are implemented for all applicable active profiles. |
| 5225-REQ-007 | MUST | Validate CRC behavior for IR, IR-DYN, CO, Add-CID, and malformed packet cases. | Library | `tests/unit/test_sprint7_crcs.cpp`, `tests/unit/test_packet_parse.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed for implemented generated packet set | Keep generated CRC mutations synchronized with any future packet-family additions. |
| 5225-REQ-008 | MUST | Reconstruct inferred IPv4, IPv6, UDP, UDP-Lite, RTP, ESP, AH, GRE, and MINE fields consistently with profile rules. | Library | `tests/compat/test_rtp_compat.cpp`, `tests/unit/test_encoding_methods.cpp` | Closed for implemented paths | Open exhaustive for every formal header-chain and extension-list variant. |
| 5225-REQ-009 | MUST/SHOULD | Implement W-LSB, offset IP-ID, scaled RTP timestamp, timer-based timestamp, SDVL, and list-compression methods where the formal grammar uses them. | Library | `tests/unit/test_encoding_methods.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed for encoding-method batch | Keep packet-family cross-products synchronized with future grammar additions. |
| 5225-REQ-010 | MAY/MUST | Support RTP CSRC lists, RTP extension headers, RTP padding, IPv4 options, and IPv6 extension headers according to the compressed-chain grammar. | Library | `tests/unit/test_rfc5225_grammar.cpp`, `tests/unit/test_packet_parse.cpp`, `tests/unit/test_encoding_methods.cpp` | Closed for extension/list grammar batch | Extend only if formal CO variants introduce additional list-bearing packet encodings. |
| 5225-REQ-011 | MUST | Handle profile feedback formats and options, including ACK/NACK/STATIC-NACK and mode requests. | Library | `tests/unit/test_sprint7_crcs.cpp`, `tests/unit/test_packet_parse.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed for implemented packet grammar | RFC 5795 feedback Code/Size framing and Add-CID feedback CIDs are covered; extend only if future packet families add profile-specific feedback options. |
| 5225-REQ-012 | MUST/SHOULD | Preserve U/O/R mode behavior, optimistic updates, ACK-gated R-mode progress, and recovery after feedback. | Library | `tests/unit/test_packet_parse.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed for implemented packet grammar | Formal CO cross-products now apply ACK/NACK/STATIC-NACK to NoContext, StaticEstablished, DynamicEstablished, and second-NACK recovery states; extend only when new packet families or deeper framework features add mode-state surface. |
| 5225-REQ-013 | MUST | Reject malformed, truncated, out-of-range, or CRC-invalid packets without corrupting context. | Library | `tests/unit/test_packet_parse.cpp`, `tests/unit/test_sprint7_crcs.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed for implemented generated packet set | Keep negative corpus synchronized with future packet-family additions. |
| 5225-REQ-014 | SHOULD/MAY | Provide robustness for loss and reordering using MSN/window behavior and timer/scaled timestamp support. | Library | `tests/unit/test_sprint8_*.cpp`, `tests/unit/test_encoding_methods.cpp` | Closed for current RTP/FO behavior | Add generated loss/reordering windows for every CO variant that carries MSN-derived fields. |
| 5225-REQ-015 | MUST | Keep deterministic encoder/decoder parity traces for profile behavior. | Library | `tests/interop/rohccxx_oracle_corpus.cpp`, `docs/external_oracle.md` | Closed for current supported paths | Attach independent external oracle for non-rohclib coverage. |
| 5225-REQ-016 | MUST | Treat RFC 5225 100 percent compliance as every possible packet grammar and encoding variant, not just supported profile paths. | Library | `docs/rfc5225_exhaustive_grammar_plan.md`, `docs/rfc5225_packet_grammar_manifest.md`, `include/rohccxx/core/rfc5225_grammar.hpp`, `tests/interop/rfc5225_grammar_corpus.cpp`, `tests/interop/rfc5225_co_corpus.cpp` | Closed | Exhaustive in-repo packet grammar rows are implemented and generated corpora are available for optional third-party corroboration. |
## RFC 3241: ROHC over PPP

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 3241-REQ-001 | MUST | Identify ROHC PPP protocol values, including small-CID and large-CID channel demux. | Library helper plus PPP adapter | `tests/unit/test_packet_parse.cpp`, `docs/ppp_adapter_contract.md` | Boundary closed | PPP driver owns actual framing. |
| 3241-REQ-002 | MUST | Validate ROHC option payload shape before accepting PPP channel settings. | Library helper | `tests/unit/test_packet_parse.cpp` | Boundary closed | Keep parser strict. |
| 3241-REQ-003 | MUST | Parse and write MAX_CID, MRRU, profile list, and CID mode option data. | Library helper | `tests/unit/test_packet_parse.cpp` | Boundary closed | PPP negotiation state machine remains adapter-owned. |
| 3241-REQ-004 | MUST NOT | Avoid enabling conflicting profile identifiers with the same low-order profile byte. | Library helper | `tests/unit/test_packet_parse.cpp` | Boundary closed | Mirror any new profile IDs in helper validation. |
| 3241-REQ-005 | SHOULD/MAY | Allow adapters to merge local and peer ROHC option settings safely. | Library helper | `tests/unit/test_packet_parse.cpp` | Boundary closed | No PPP driver in `rohccxx`. |

## RFC 3243: 0-byte IP/UDP/RTP Assumptions

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 3243-REQ-001 | Assumption | Confirm the lower layer identifies zero-byte/no-header packets separately from ordinary ROHC packets. | Adapter signal plus library gate | `tests/rfc3243/test_rfc3243_conformance.cpp`, `docs/lower_layer_assisted_contract.md` | Boundary closed | Real packet-type signal remains lower-layer-owned. |
| 3243-REQ-002 | Assumption | Confirm in-order delivery, loss indication, residual error indication, and feedback delivery before zero-byte use. | Adapter signal plus library gate | `tests/rfc3243/test_rfc3243_conformance.cpp` | Boundary closed | Real indications remain lower-layer-owned. |
| 3243-REQ-003 | Assumption | Restrict zero-byte behavior to eligible IPv4/UDP/RTP flows with stable flow assumptions. | Library gate | `tests/rfc3243/test_rfc3243_conformance.cpp` | Boundary closed | Keep masks synchronized with new flow validators. |
| 3243-REQ-004 | Assumption | Report each missing zero-byte prerequisite independently and in aggregate. | Library API | `tests/rfc3243/test_rfc3243_conformance.cpp` | Closed | None. |

## RFC 3408: R-mode Zero-byte Support

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 3408-REQ-001 | MUST | Gate R-mode no-header packet emission on reliable feedback support. | Library gate plus adapter signal | `tests/unit/test_packet_parse.cpp` | Boundary closed | Lower layer owns reliable delivery. |
| 3408-REQ-002 | MUST | Require ACK progression before emitting R-mode no-header packets. | Library | `tests/unit/test_packet_parse.cpp` | Closed | Extend generated mode tests with exhaustive grammar. |
| 3408-REQ-003 | MUST | Treat STATIC-NACK/NACK as context refresh triggers for R-mode zero-byte operation. | Library | `tests/unit/test_packet_parse.cpp` | Closed | None for current grammar. |
| 3408-REQ-004 | MAY | Allow zero-byte R-mode only when RFC 3243 assumptions are simultaneously satisfied. | Library gate plus adapter signal | `tests/unit/test_packet_parse.cpp`, `tests/rfc3243/test_rfc3243_conformance.cpp` | Boundary closed | None. |

## RFC 3409: Lower-layer Guidelines

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 3409-REQ-001 | Guideline | Require near-zero residual error probability or explicit error indication for invalid packets. | Adapter signal plus library gate | `tests/unit/test_packet_parse.cpp`, `docs/lower_layer_assisted_contract.md` | Boundary closed | Lower layer owns real error detection. |
| 3409-REQ-002 | Guideline | Provide packet length information needed to infer compressed IP/UDP lengths. | Adapter | `docs/lower_layer_assisted_contract.md` | Outside library | Adapter must supply packet length. |
| 3409-REQ-003 | Guideline | Negotiate profile, CID, MRRU, and channel parameters consistently. | Library helper plus adapter | `tests/unit/test_packet_parse.cpp`, `docs/ppp_adapter_contract.md` | Boundary closed | Real negotiation remains adapter-owned. |
| 3409-REQ-004 | Guideline | Provide packet type identification when ROHC packets share a lower-layer channel with other packet types. | Adapter signal plus library gate | `tests/unit/test_packet_parse.cpp` | Boundary closed | Lower layer owns demux. |
| 3409-REQ-005 | Guideline | Avoid duplication and reordering on the compressor-to-decompressor path unless explicitly modeled. | Adapter policy | `docs/lower_layer_assisted_contract.md` | Outside library | Adapter/channel policy. |
| 3409-REQ-006 | Guideline | Transport feedback packets quickly enough for O-mode/R-mode operation. | Adapter signal plus library feedback APIs | `tests/unit/test_packet_parse.cpp` | Boundary closed | Link scheduling remains adapter-owned. |

## RFC 4362: Link-layer-assisted Profile

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 4362-REQ-001 | MUST | Treat profile `0x0005` as the lower-layer-assisted RTP profile and require explicit assisting-layer opt-in. | Library | `tests/unit/test_packet_parse.cpp`, `docs/lower_layer_assisted_contract.md` | Closed | None. |
| 4362-REQ-002 | MUST | Emit and reconstruct NHP/no-header packets only when the lower-layer contract permits them. | Library gate plus adapter signal | `tests/unit/test_packet_parse.cpp`, `tests/interop/rfc4362_oracle_corpus.cpp` | Boundary closed | Attach independent external RFC 4362 oracle if available. |
| 4362-REQ-003 | MUST | Support CSP context synchronization and CCP context check packets. | Library API plus adapter scheduling | `tests/unit/test_packet_parse.cpp`, `tests/interop/rfc4362_oracle_corpus.cpp` | Boundary closed | Adapter chooses when to schedule context packets. |
| 4362-REQ-004 | MUST | Reject LLA packets through ordinary decompress paths unless RFC 4362 has been negotiated. | Library | `tests/unit/test_packet_parse.cpp` | Closed | None. |
| 4362-REQ-005 | MUST/SHOULD | Preserve large-CID assisted dispatch and lower-layer loss/residual-error feedback. | Library API plus adapter signal | `tests/unit/test_packet_parse.cpp` | Boundary closed | Lower layer owns real signal source. |
| 4362-REQ-006 | MAY | Provide external oracle corpus for NHP/CSP/CCP semantics. | Library test harness | `tests/interop/rfc4362_oracle_corpus.cpp`, `docs/external_oracle.md` | Optional oracle | Optional third-party RFC 4362 oracle can consume the generated corpus when available. |
## RFC 5795: ROHC Framework

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 5795-REQ-001 | MUST | Maintain channel parameters, profile registration, CID space, and context lifecycle. | Library | `tests/unit/test_packet_parse.cpp` | Closed | Keep aligned with new packet families. |
| 5795-REQ-002 | MUST | Provide uncompressed profile behavior with context isolation and malformed packet feedback. | Library | `tests/unit/test_packet_parse.cpp` | Closed | None for current boundary. |
| 5795-REQ-003 | MUST | Format, parse, and deliver feedback packets without corrupting compressed payload handling. | Library | `tests/unit/test_sprint7_crcs.cpp`, `tests/unit/test_packet_parse.cpp`, `tests/unit/test_rfc5225_grammar.cpp` | Closed | Feedback packet Code/Size framing, Add-CID CIDs 1-15, options, mode requests, interspersed/piggybacked feedback, and context-state application are covered for the implemented grammar. |
| 5795-REQ-004 | MUST/MAY | Support segmentation/reassembly only when MRRU is negotiated and reject malformed segment streams. | Library | `tests/unit/test_packet_parse.cpp` | Closed | Adapter-specific in-order policy remains outside library. |
| 5795-REQ-005 | MUST | Preserve CRC validation and decompressor feedback behavior on failures. | Library | `tests/unit/test_sprint7_crcs.cpp` | Closed | Add generated CRC cases for exhaustive RFC 5225 grammar. |
| 5795-REQ-006 | SHOULD/MAY | Allow bidirectional feedback, interspersed feedback, and piggybacked feedback where channel policy permits. | Library helper plus adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | Adapter owns channel scheduling. |

## RFC 5856: ROHC over IPsec Architecture

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 5856-REQ-001 | MUST | Bind ROHC channel parameters to an IPsec SA and preserve one-way channel semantics. | Library SA helper plus IPsec adapter | `tests/unit/test_packet_parse.cpp`, `docs/embedding_stack_integration.md` | Boundary closed | SPD/SAD ownership remains outside library. |
| 5856-REQ-002 | MUST | Apply ROHC before outbound IPsec protection and after inbound IPsec validation. | Library helper plus IPsec adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | Kernel/user-space packet ownership remains outside library. |
| 5856-REQ-003 | MUST/SHOULD | Support ROHC-specific integrity material and feedback-for-SA metadata. | Library helper | `tests/unit/test_packet_parse.cpp` | Boundary closed | Additional transforms can be added if negotiated. |
| 5856-REQ-004 | MAY | Allow deployments to disable ROHC when negotiation or integrity requirements cannot be satisfied. | Library helper plus IPsec adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | Adapter decides SA enablement. |

## RFC 5857: IKEv2 Extensions

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 5857-REQ-001 | MUST | Encode/decode ROHC_SUPPORTED notify data carrying ROHC channel attributes. | Library helper plus IKEv2 adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | Real IKEv2 payload exchange remains outside library. |
| 5857-REQ-002 | MUST | Require MAX_CID, at least one ROHC_PROFILE, and at least one ROHC_INTEG attribute. | Library helper | `tests/unit/test_packet_parse.cpp` | Closed | None. |
| 5857-REQ-003 | MUST | Reject duplicate, unsupported, or low-byte-conflicting profile attributes. | Library helper | `tests/unit/test_packet_parse.cpp` | Closed | Add new profile IDs to validation table as needed. |
| 5857-REQ-004 | MUST/MAY | Select exactly one negotiated integrity algorithm, with NONE allowed only with coherent ICV length semantics. | Library helper | `tests/unit/test_packet_parse.cpp` | Closed | Add transforms as deployment requires. |
| 5857-REQ-005 | MUST/MAY | Handle ROHC_ICV_LEN and MRRU as optional one-way channel parameters. | Library helper | `tests/unit/test_packet_parse.cpp` | Closed | None. |
| 5857-REQ-006 | MUST | Do not enable ROHC on a Child SA when the responder does not accept ROHC parameters. | IKEv2 adapter decision using library validation | `docs/embedding_stack_integration.md` | Boundary closed | Real IKEv2 state machine outside library. |

## RFC 5858: IPsec Extensions

| ID | Level | Requirement summary | Responsibility | Evidence | Status | Remaining action |
| --- | --- | --- | --- | --- | --- | --- |
| 5858-REQ-001 | MUST | Use ROHC protocol number 142 and correct AH/ESP Next Header decisions for compressed ROHC packets. | Library helper plus IPsec adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | AH/ESP framing remains outside library. |
| 5858-REQ-002 | MUST | Append and verify ROHC integrity check values according to negotiated algorithm and ICV length. | Library | `tests/unit/test_packet_parse.cpp` | Closed | Add transforms beyond NONE/HMAC-SHA-256 if required. |
| 5858-REQ-003 | MUST | Enforce outbound compress-then-protect and inbound validate-then-decompress order. | Library helper plus IPsec adapter | `tests/unit/test_packet_parse.cpp` | Boundary closed | Packet ownership remains outside library. |
| 5858-REQ-004 | MUST NOT | Reject packets whose ICV or Next Header state is incoherent with negotiated ROHCoIPsec state. | Library | `tests/unit/test_packet_parse.cpp` | Closed | None. |
| 5858-REQ-005 | SHOULD/MAY | Support both no-integrity and keyed-integrity deployments according to negotiated policy. | Library | `tests/unit/test_packet_parse.cpp` | Closed | Add deployment-specific transforms only by negotiation. |

## Closeout Rules

1. A row can move to `Closed` only with a named unit, compatibility, interoperability, or generated corpus test.
2. A row can move to `Boundary closed` only when the public API rejects unsafe missing prerequisites and the adapter responsibility is documented.
3. Optional third-party oracle rows are corroboration hooks, not mandatory release blockers, unless a customer or deployment contract explicitly requires them.
4. RFC 5225 can be called complete under the in-tree exhaustive definition when `docs/rfc5225_exhaustive_grammar_plan.md` is executed and every generated grammar row has positive, negative, CRC, CID, and buffer-limit coverage.
