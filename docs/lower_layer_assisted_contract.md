<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Lower-Layer-Assisted ROHC Contract

This document defines the `rohccxx` library boundary for lower-layer-assisted ROHC work. The library can validate assumptions, expose packet grammar helpers, and reject unsafe use. The embedding link layer owns packet classification signals, ordering, retransmission/loss indication, and any radio or driver-specific behavior.

## Obsoleted RFC 3242 Note

RFC 3242 is not tracked as an active compliance target because it is obsoleted by RFC 4362. The shared profile identifier `0x0005` is exposed as `ROHCCXX_PROFILE_LLA_RTP` / `rohccxx::Profile::LLA_RTP` for RFC 4362 lower-layer-assisted RTP. The library still requires the RFC 3243 zero-byte flow assumptions before any no-header packet behavior may be enabled.

## RFC 3243 Zero-Byte Assumptions

RFC 3243-style zero-byte operation is only safe when the assisting lower layer provides all of these properties:

| Requirement | `rohccxx` contract field | Reason |
| --- | --- | --- |
| Packet type identification | `identifies_packet_types` | The receiver must distinguish zero-byte/no-header packets from ordinary lower-layer frames. |
| In-order delivery for the assisted flow | `preserves_order` | Zero-byte decompression depends on synchronized context progression. |
| Loss indication | `reports_loss` | The decompressor must know when context progression cannot be trusted. |
| Residual error indication | `reports_residual_errors` | Corrupted assisted packets must not silently update context. |
| Feedback delivery | `delivers_feedback` | The decompressor must be able to request repair or refresh. |

Use `rohccxx::lla::validate_rfc3243_zero_byte_assumptions()` before enabling no-header packet emission. `rohccxx::lla::can_emit_no_header_packet()` is the convenience gate used by tests. C adapters can call `rohc_lla_validate_rfc3243_zero_byte_assumptions()` and inspect the `ROHCCXX_LLA_MISSING_*` bitmask before enabling the same path.

## RFC 3408 R-Mode Zero-Byte Support

RFC 3408 extends zero-byte operation into reliable mode. `rohccxx` exposes this as a stronger validation gate layered on the RFC 3243 assumptions. In addition to packet-type identification, ordering, loss/error reporting, and feedback delivery, the assisting layer must advertise reliable-mode support plus ACK and STATIC-NACK delivery. Use `rohccxx::lla::validate_rfc3408_r_mode_zero_byte_support()` or `rohccxx::lla::can_emit_reliable_mode_no_header_packet()` before enabling reliable-mode no-header packet emission. C adapters can call `rohc_lla_validate_rfc3408_r_mode_zero_byte_support()` and `rohc_lla_can_emit_reliable_mode_no_header_packet()`.

## RFC 3409 Lower-Layer Guidelines

RFC 3409 adds lower-layer guidance for robust assisted RTP/UDP/IP compression. For `rohccxx`, the practical library boundary is stronger than the RFC 3243 zero-byte gate because context synchronization and context check packets must be protected as control information.

| Requirement | `rohccxx` contract field | Reason |
| --- | --- | --- |
| Context packet protection | `protects_context_packets` | CSP/CCP packets must not be delivered as untrusted ordinary data. |
| Context synchronization support | `supports_context_synchronization` | The assisting layer must explicitly allow CSP use. |
| Context check support | `supports_context_check` | The assisting layer must explicitly allow CCP use. |

Use `rohccxx::lla::validate_rfc3409_lower_layer_guidelines()` before enabling RFC 4362 CSP/CCP behavior. C adapters can call `rohc_lla_validate_rfc3409_lower_layer_guidelines()`, `rohc_lla_can_emit_context_synchronization_packet()`, and `rohc_lla_can_emit_context_check_packet()`. Ordinary decompressor input still rejects these packets unless an embedding adapter performs the explicit assisting-layer negotiation and dispatch.

## RFC 4362 Runtime API Boundary

The public C API exposes an explicit assisting-layer path for live RFC 4362 behavior:

| API area | Purpose |
| --- | --- |
| `rohc_lla_validate_rfc3243_zero_byte_assumptions()` / `rohc_lla_validate_rfc3243_zero_byte_flow()` | Return missing-assumption bitmasks before zero-byte operation is enabled. |
| `rohc_lla_validate_rfc3408_r_mode_zero_byte_support()` / `rohc_lla_validate_rfc3409_lower_layer_guidelines()` | Validate reliable-mode and robust lower-layer assumptions before assisted packets are emitted. |
| `rohc_comp_enable_rfc4362_lla()` / `rohc_decomp_enable_rfc4362_lla()` | Opt in only after the embedding layer satisfies the RFC 3243/RFC 3409 contract. |
| `rohc_comp_rfc4362_emit_nhp()` / `rohc_decomp_rfc4362_receive_nhp()` | Represent no-header packet operation through an explicit lower-layer signal rather than ordinary `rohc_decompress4()` bytes. |
| `rohc_comp_rfc4362_emit_csp()` / `rohc_decomp_rfc4362_receive_csp()` | Carry context synchronization packets through the assisting-layer path. |
| `rohc_comp_rfc4362_emit_ccp()` / `rohc_decomp_rfc4362_receive_ccp()` | Carry context check packets and report context mismatch through feedback. |
| `rohc_decomp_rfc4362_report_loss()` / `rohc_decomp_rfc4362_report_residual_error()` | Let the lower layer report loss or residual errors without fabricating ROHC packet bytes. |

Ordinary `rohc_compress4()` and `rohc_decompress4()` continue to reject CSP/CCP/NHP-style inputs unless the embedding layer uses these explicit APIs. This keeps packet identification, ordering, and link-specific error signaling outside the core codec while still making RFC 4362 behavior testable.

## Non-Goals

`rohccxx` does not implement a PPP driver, radio scheduler, link-layer retransmission system, or packet ownership model. Those belong in embedding adapters. The library provides deterministic helpers and negative gates so those adapters can prove they are satisfying the ROHC assumptions before enabling assisted packet families.
