<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Optional External Oracle Register

This register tracks behavior that can be corroborated by a third-party implementation if one is available. The bundled rohc-lib interoperability path and generated in-repo corpora remain the normal test baseline. This document complements `docs/external_oracle.md`, which documents the optional oracle executable contract.

## Current Oracle Coverage

| Oracle source | Coverage | Status |
| --- | --- | --- |
| Bundled rohc-lib submodule | Current RTP/UDP/IP interop path that rohc-lib can validate | Active in CTest. |
| `rohccxx_oracle_corpus` | Deterministic in-repo corpus for all currently supported RFC 5225 profile families | Active self-test; external checker optional. |
| `rfc5225_co_corpus` | Deterministic formal CO corpus for all RFC 5225 active profiles, CID modes, and implemented CO variants | Active self-test; external checker optional through `ROHCCXX_RFC5225_CO_ORACLE`. |
| `rfc4362_oracle_corpus` | Deterministic in-repo corpus for NHP, CSP, and CCP assisting-layer events | Active self-test; external checker optional. |
| `ROHCCXX_EXTERNAL_ORACLE` | User-provided ROHCv2 oracle executable for profile corpus validation | Optional CTest hook; currently skipped when unset. |
| `ROHCCXX_RFC5225_CO_ORACLE` | User-provided RFC 5225 formal CO oracle executable for generated CO corpus validation | Optional CTest hook; currently skipped when unset. |
| `ROHCCXX_RFC4362_ORACLE` | User-provided RFC 4362 oracle executable for LLA corpus validation | Optional CTest hook; currently skipped when unset. |

## Optional Corroboration Targets

| Target ID | Behavior suitable for third-party corroboration | rohc-lib limitation | Optional oracle | Current status | Acceptance gate |
| --- | --- | --- | --- | --- | --- |
| ORACLE-001 | RFC 5225 RTP/UDP/IP, UDP/IP, ESP/IP, and IP-only | Closed with mandatory bidirectional tests against the pinned rohc-lib: each implementation compresses three deterministic packets and the other reconstructs the exact IP packets. | Keep the pinned oracle and strict corpus adapter in the required CTest set. | Mandatory | `interop_rfc5225_rohccxx_to_rohclib` and `interop_rfc5225_rohclib_to_rohccxx` pass. |
| ORACLE-002 | RFC 5225 RTP/UDP-Lite/IP and UDP-Lite/IP | rohc-lib does not expose compatible ROHCv2 UDP-Lite profiles. | A maintained independent implementation with RFC 5225 UDP-Lite support. | Unsupported by current oracle; no silent skip or interoperability claim. | Add mandatory bidirectional exact-reconstruction tests if a compatible oracle becomes available. |
| ORACLE-003 | IPv6 base headers, IPv6 extension-header chains, AH/GRE/MINE preservation, and IPv4 options | rohc-lib parity is not attached for the full extension-chain surface | Oracle with formal-chain support or generated standards-vector checker | Optional | External oracle validates every generated extension-chain case. |
| ORACLE-004 | Every formal RFC 5225 CO packet family and discriminator variant | rohc-lib is not attached as an exhaustive formal CO oracle for all active profiles and packet variants | Oracle able to parse `rfc5225_co_corpus` v4, including `crc_data`, `control_crc_data`, and generated ROHC bytes | Optional; in-repo corpus is available through `ROHCCXX_RFC5225_CO_ORACLE` | External oracle validates generated positive and negative corpus. |
| ORACLE-005 | W-LSB, scaled RTP timestamp, timer-based timestamp, offset IP-ID, SDVL, and list-compression edge combinations across all packet families | rohc-lib is not attached as an exhaustive encoding-method oracle | Formal-vector checker or second implementation with traceable field reconstruction | Optional | External oracle validates boundary values and randomized generated cases. |
| ORACLE-006 | RFC 4362 NHP/CSP/CCP link-layer-assisted behavior | Ordinary rohc-lib decompression is not an assisting-layer oracle for RFC 4362 events | RFC 4362-aware lower-layer-assisted implementation or checker | Optional | `ROHCCXX_RFC4362_ORACLE` runs green on NHP, CSP, CCP, loss, and residual-error corpus. |
| ORACLE-007 | ROHCoIPsec IKEv2/IPsec end-to-end behavior | rohc-lib does not validate IKEv2 Notify payload exchange, AH/ESP packet ownership, or SPD/SAD integration | Embedding-stack integration test using a real or simulated IKEv2/IPsec adapter | Outside library; optional integration corroboration | Adapter test proves negotiation, KEYMAT, Next Header, ICV, and processing order around `rohccxx` APIs. |

## Oracle Attachment Contract

An external oracle should meet these rules before it is used as an optional release corroboration gate:

1. It must be version-pinned and repeatable in CI or documented as an optional local gate.
2. It must consume the generated corpus on stdin or through a stable file path without requiring manual packet editing.
3. For decode validation, it must reconstruct byte-identical IP packets from `rohccxx` ROHC packets.
4. For encode validation, it may require byte-identical ROHC output or a documented semantic-equivalence comparison when the RFC permits multiple valid encodings.
5. It must fail closed on malformed, truncated, unknown-profile, bad-CRC, bad-CID, and bad-ICV cases.
6. It must report the failing corpus case identifier so regressions are debuggable.

## Optional Oracle Work

1. Keep the in-repo deterministic corpus as the baseline for current supported paths.
2. Attach a third-party checker to `ROHCCXX_RFC5225_CO_ORACLE` for the formal CO corpus if one becomes available.
3. Attach a non-rohclib ROHCv2 oracle to `ROHCCXX_EXTERNAL_ORACLE` if one becomes available.
4. Attach an RFC 4362-aware checker to `ROHCCXX_RFC4362_ORACLE` if a lower-layer-assisted implementation becomes available.
5. Treat ROHCoIPsec end-to-end validation as embedding-stack integration, not as a replacement for the library unit tests.
