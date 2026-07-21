<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Third-Party Integration HOWTO

This HOWTO describes how a third-party application, driver, modem stack, PPP implementation, or IPsec/IKE stack can integrate `rohccxx` as its ROHC compression/decompression engine.

The stable integration boundary is the installed C API in `rohccxx.h`. The Debian package installs `rohccxx.h` and `rohccxx/version.h`; those are the only external headers required to integrate with `librohccxx.so`.

C++ helper headers under the source-tree `include/rohccxx/` subdirectories and the lightweight `rohccxx::Compressor` / `rohccxx::Decompressor` classes are useful for in-tree adapters and tests, but they are not installed by the Debian package and are not part of the stable ABI contract.

`rohccxx` is a codec and protocol-helper library. It does not own sockets, NIC queues, PPP state machines, radio scheduling, IKEv2 message exchange, kernel SPD/SAD state, or packet lifetime outside a call. The integrating package owns packet I/O, negotiation, ordering policy, retransmission policy, and buffer ownership.

## Build And Link

Install from a local build:

```bash
cmake -B build -S . -DROHCCXX_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
DESTDIR=/tmp/rohccxx-stage cmake --install build
cmake --build build --target package
sudo dpkg -i build/librohccxx-*.deb
```

Include the C API and link the installed library:

```c
#include <rohccxx.h>
```

```bash
cc adapter.c -lrohccxx
```

For CMake consumers, use the installed package config when available:

The exported target points at the installed public include directory and does not expose private source-tree helper headers.

`rohccxx::rohccxx` links the shared library. If static linking is required, use the explicit `rohccxx::rohccxx_static` target and link with a C++ linker/runtime.

```cmake
find_package(rohccxx REQUIRED)
target_link_libraries(my_adapter PRIVATE rohccxx::rohccxx)
```

Adapters can log or enforce the loaded library version at startup:

```c
const char* version = rohccxx_version_string();
unsigned major = rohccxx_version_major();
```

## Ownership Model

A typical adapter owns one compressor per transmit ROHC channel and one decompressor per receive ROHC channel.

- Create handles during channel/session setup.
- Configure mode, CID, MRRU, and optional profile-specific helpers before processing packets.
- Reuse handles for the lifetime of the channel so ROHC context is preserved.
- Free handles only after no other thread can call into them.
- Provide output buffers large enough for the expected ROHC or IP packet.

The public C handles are internally serialized, so separate handles may run concurrently and shared handles serialize calls. The caller still owns buffer lifetime and must not mutate input/output buffers concurrently with a `rohccxx` call.

## Return Values

Most public functions return `0` on success and `-1` on failure. Important exceptions:

- `rohc_decompress4()` returns `0` when an IP packet is produced.
- `rohc_decompress4()` returns `1` when an RFC 5795 non-final segment was accepted and more segments are required.
- `rohc_decomp_has_feedback()` returns `1` when feedback is available and `0` otherwise.
- `rohc_comp_has_segment()` returns `1` when more compressor-generated segments are pending and `0` otherwise.

On output calls, pass `*out_len` as the output buffer capacity. On success, `rohccxx` updates `*out_len` to the produced byte count.

## Core API Entry Points

| API | Service provided |
| --- | --- |
| `rohccxx_version_string()` / `rohccxx_version_major()` / `rohccxx_version_minor()` / `rohccxx_version_patch()` | Report the compile-time release version exported by the installed library. |
| `rohc_profile_is_supported()` / `rohc_profile_is_rohcv2()` | Let adapters verify the active RFC 5225 profile set before advertising or accepting a profile. |
| `rohc_comp_new2(max_cid, direction)` | Creates a compressor for a ROHC channel with a maximum CID and uplink/downlink direction. `max_cid > 15` enables large-CID channel behavior. |
| `rohc_decomp_new2(max_cid, direction)` | Creates a decompressor for the peer channel. Use the negotiated channel `max_cid`. |
| `rohc_comp_free()` / `rohc_decomp_free()` | Destroy handles and release context tables. |
| `rohc_comp_set_cid(comp, cid)` | Selects the compressor context ID used for subsequent packets. Use one CID per flow/context as assigned by the embedding stack. |
| `rohc_compress4(comp, ip_packet, ip_len, rohc_packet, rohc_len)` | Compresses one IP packet into one ROHC packet or first segment. |
| `rohc_decompress4(decomp, rohc_packet, rohc_len, ip_packet, ip_len)` | Decompresses one ROHC packet or accepts one segment. |
| `rohc_comp_set_mode()` / `rohc_decomp_set_mode()` | Select Unidirectional, Optimistic, or Reliable mode for a channel/context. |
| `rohc_comp_get_mode()` / `rohc_decomp_get_mode()` | Query current mode. |
| `rohc_decomp_has_feedback()` / `rohc_decomp_get_feedback()` | Poll decompressor-generated feedback after failed or repair-relevant receive events. |
| `rohc_comp_handle_feedback()` | Deliver a simple feedback event to the compressor. |
| `rohc_comp_deliver_feedback_packet()` | Deliver a serialized ROHC feedback packet or piggybacked feedback prefix to the compressor. |
| `rohc_comp_set_mrru()` / `rohc_decomp_set_mrru()` | Enable or disable RFC 5795 segmentation/reassembly using negotiated MRRU. |
| `rohc_comp_has_segment()` / `rohc_comp_get_segment()` | Drain additional segments after `rohc_compress4()` emits the first segment. |

## Basic ROHC Channel

Use this flow for normal RFC 5225 compressed profiles, including RTP/UDP/IP, UDP/IP, IP-only, ESP/IP, RTP/UDP-Lite/IP, and UDP-Lite/IP.

### Setup

1. Negotiate or configure `max_cid`, direction, mode, and optional MRRU in your third-party protocol.
2. Create one transmit compressor and one receive decompressor for each ROHC channel.
3. If the negotiated channel uses segmentation, call `rohc_comp_set_mrru()` and `rohc_decomp_set_mrru()` with the same negotiated MRRU.
4. If the channel starts in a non-default mode, call `rohc_comp_set_mode()` and `rohc_decomp_set_mode()`.

```c
struct rohc_comp* comp = rohc_comp_new2(max_cid, ROHCCXX_DIRECTION_UPLINK);
struct rohc_decomp* decomp = rohc_decomp_new2(max_cid, ROHCCXX_DIRECTION_UPLINK);

rohc_comp_set_mode(comp, ROHCCXX_MODE_O);
rohc_decomp_set_mode(decomp, ROHCCXX_MODE_O);

if(mrru != 0)
{
    rohc_comp_set_mrru(comp, mrru);
    rohc_decomp_set_mrru(decomp, mrru);
}
```

### Transmit Process

1. Receive or construct a complete IP packet from your networking stack.
2. Choose the CID for the flow and call `rohc_comp_set_cid()` if it changed.
3. Call `rohc_compress4()`.
4. Transmit the produced ROHC bytes using your link protocol.
5. If `rohc_comp_has_segment()` returns `1`, repeatedly call `rohc_comp_get_segment()` and transmit each returned segment in order.

```c
uint8_t rohc_packet[2048];
size_t rohc_len = sizeof(rohc_packet);

rohc_comp_set_cid(comp, cid);
if(rohc_compress4(comp, ip_packet, ip_len, rohc_packet, &rohc_len) == 0)
{
    send_rohc_frame(rohc_packet, rohc_len);

    while(rohc_comp_has_segment(comp) == 1)
    {
        rohc_len = sizeof(rohc_packet);
        if(rohc_comp_get_segment(comp, rohc_packet, &rohc_len) != 0)
            break;
        send_rohc_frame(rohc_packet, rohc_len);
    }
}
```

### Receive Process

1. Receive one ROHC frame from your transport.
2. Call `rohc_decompress4()`.
3. If it returns `0`, deliver the produced IP packet upward.
4. If it returns `1`, wait for more segments and do not deliver an IP packet yet.
5. If it returns `-1`, check `rohc_decomp_has_feedback()` and deliver feedback to the peer compressor if available.

```c
uint8_t ip_packet[4096];
size_t ip_len = sizeof(ip_packet);
int rc = rohc_decompress4(decomp, rohc_packet, rohc_len, ip_packet, &ip_len);

if(rc == 0)
{
    deliver_ip_packet(ip_packet, ip_len);
}
else if(rc == 1)
{
    /* Non-final segment accepted; wait for the next ROHC segment. */
}
else if(rohc_decomp_has_feedback(decomp) == 1)
{
    uint32_t feedback_cid = 0;
    uint8_t feedback_type = 0;
    if(rohc_decomp_get_feedback(decomp, &feedback_cid, &feedback_type) == 0)
        send_feedback_to_peer(feedback_cid, feedback_type);
}
```

### Feedback Process

1. Transport decompressor feedback to the compressor side using your channel's feedback path.
2. For simple feedback, call `rohc_comp_handle_feedback(comp, cid, feedback_type)`.
3. For serialized ROHC feedback packets, call `rohc_comp_deliver_feedback_packet()`.

```c
rohc_comp_handle_feedback(comp, feedback_cid, feedback_type);
```

## RFC 5795 Segmentation/Reassembly

Segmentation is negotiated and opt-in. `rohccxx` will not segment or reassemble unless MRRU is configured.

### Setup

1. Negotiate an MRRU value in the embedding protocol.
2. Call `rohc_comp_set_mrru(comp, mrru)` on the sender.
3. Call `rohc_decomp_set_mrru(decomp, mrru)` on the receiver.
4. Preserve segment ordering in the third-party transport, or reorder before calling the decompressor.

### Transmit Process

1. Call `rohc_compress4()` with the caller's output capacity.
2. If the compressed packet fits, `rohccxx` returns one packet.
3. If it does not fit and MRRU allows segmentation, `rohccxx` returns the first segment.
4. Drain remaining segments with `rohc_comp_get_segment()`.
5. Transmit all segments in order.

### Receive Process

1. Feed each received segment to `rohc_decompress4()` in order.
2. Treat return `1` as ?accepted, no IP packet yet.?
3. Treat return `0` as ?final segment reassembled and decompressed.?
4. Treat return `-1` as malformed, out-of-order, oversized, or unnegotiated segmentation; check feedback and resynchronize through your channel policy.

## RFC 3241 PPP Adapter Integration

`rohccxx` does not implement a PPP driver or PPP negotiation state machine. A PPP package should use the stable installed C API in `rohccxx.h` to validate and serialize ROHC IPCP option payloads, then use the core C API to compress and decompress packets. The source-tree C++ helper API in `include/rohccxx/core/ppp.hpp` remains available for in-repo adapters/tests, but it is not installed by the Debian package.

### Stable C API Entry Points

| API | Service provided |
| --- | --- |
| `rohccxx_ppp_rohc_option_t` | Holds ROHC IPCP option fields: `MAX_CID`, `MRRU`, `MAX_HEADER`, and profile list. |
| `rohc_ppp_validate_rohc_option()` | Validates option limits and profile presence. |
| `rohc_ppp_write_rohc_option()` | Serializes a ROHC IPCP option payload. |
| `rohc_ppp_parse_rohc_option()` | Parses and validates a received ROHC IPCP option payload. |
| `rohc_ppp_merge_rohc_options()` | Merges two adapter-provided ROHC channel configurations. |
| `rohc_ppp_is_rohc_protocol()` | Identifies PPP protocol fields carrying ROHC packets. |
| `rohc_ppp_uses_large_cid_protocol()` | Distinguishes small-CID PPP protocol `0x0003` from large-CID PPP protocol `0x0005`. |

### Setup Process

1. Your PPP stack runs LCP/IPCP/IPV6CP negotiation.
2. Build a `RohcOption` with the ROHC channel parameters your implementation supports.
3. Add profiles with `append_profile()`.
4. Serialize the option with `write_rohc_option()` for Configure-Request or Configure-Ack payloads.
5. Parse peer options with `parse_rohc_option()`.
6. After PPP negotiation completes, create `rohccxx` compressor/decompressor handles with negotiated `max_cid` and `mrru`.
7. Use PPP protocol `0x0003` for small CID channels and `0x0005` for large CID channels.

### PPP Transmit Process

1. Receive an IP packet from the PPP network layer.
2. Compress with `rohc_compress4()`.
3. Emit the returned ROHC packet as a PPP frame using protocol `0x0003` or `0x0005` based on negotiated CID mode.
4. If segmentation is enabled and pending, emit each pending segment as another ROHC PPP frame in order.

### PPP Receive Process

1. When PPP demux sees protocol `0x0003` or `0x0005`, deliver the frame payload to `rohc_decompress4()`.
2. If PPP protocol `0x0005` was negotiated, create/configure the decompressor with `max_cid > 15` so large-CID parsing is active.
3. Deliver produced IP packets upward on return `0`.
4. Preserve return `1` segmentation state by waiting for more ROHC frames.
5. Forward feedback over your PPP feedback path if `rohc_decomp_has_feedback()` reports feedback.

## RFC 4362 Lower-Layer-Assisted ROHC

RFC 4362 lower-layer assistance is explicit. NHP, CSP, and CCP events are not ordinary `rohc_decompress4()` byte streams. Your link layer must identify the event type and dispatch to the matching API.

### API Entry Points

| API | Service provided |
| --- | --- |
| `rohccxx_lla_contract_t` | C contract describing lower-layer services such as packet-type identification, ordering, loss/error reporting, feedback, and context-packet protection. |
| `rohccxx_lla_flow_t` | C flow contract describing whether the assisted flow satisfies RFC 3243 zero-byte assumptions. |
| `rohc_lla_validate_rfc3243_zero_byte_flow()` / `rohc_lla_validate_rfc3409_lower_layer_guidelines()` | Return missing-assumption bitmasks before assisted behavior is enabled. |
| `rohc_comp_enable_rfc4362_lla()` / `rohc_decomp_enable_rfc4362_lla()` | Enable assisted runtime behavior only after contract validation succeeds. |
| `rohc_comp_rfc4362_emit_nhp()` | Advances compressor context for a no-header packet and emits zero ROHC header bytes. The lower layer transmits an NHP event/signal. |
| `rohc_decomp_rfc4362_receive_nhp()` | Reconstructs an IP/RTP packet from an NHP event for CID 0. |
| `rohc_decomp_rfc4362_receive_nhp_for_cid()` | Reconstructs an NHP event when the lower layer supplies a nonzero or large CID out of band. |
| `rohc_comp_rfc4362_emit_csp()` / `rohc_decomp_rfc4362_receive_csp()` | Emit and receive context synchronization packets. |
| `rohc_comp_rfc4362_emit_ccp()` / `rohc_decomp_rfc4362_receive_ccp()` | Emit and verify context check packets for CID 0. |
| `rohc_decomp_rfc4362_receive_ccp_for_cid()` | Verify a CCP when the lower layer supplies a nonzero or large CID out of band. |
| `rohc_decomp_rfc4362_report_loss()` | Tell the decompressor that the lower layer detected loss for a CID. |
| `rohc_decomp_rfc4362_report_residual_error()` | Tell the decompressor that the lower layer detected residual corruption for a CID. |

### Setup Process

1. Verify your lower layer can distinguish normal ROHC packets, NHP events, CSP packets, and CCP packets.
2. Verify it preserves ordering for assisted flows and reports loss/residual errors.
3. Verify it can deliver feedback.
4. Verify it protects CSP/CCP control packets.
5. Populate `rohccxx_lla_contract_t` and `rohccxx_lla_flow_t`.
6. Call `rohc_comp_enable_rfc4362_lla()` and `rohc_decomp_enable_rfc4362_lla()`.
7. Establish ROHC context using ordinary compressed packets or CSP before emitting NHP.

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
contract.supports_reliable_mode = 1;
contract.delivers_ack = 1;
contract.delivers_static_nack = 1;

rohccxx_lla_flow_t flow = {0};
flow.ipv4_udp_rtp = 1;
flow.udp_checksum_disabled = 1;
flow.rtp_sequence_increments_by_one = 1;
flow.compressor_observed_in_order = 1;
flow.synchronized_timing = 1;

rohc_comp_enable_rfc4362_lla(comp, &contract, &flow);
rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow);
```

### Normal Assisted Transmit Process

1. Use `rohc_compress4()` for normal ROHC packets until the dynamic context is established.
2. When the lower layer chooses zero-byte operation for a qualifying RTP packet, call `rohc_comp_rfc4362_emit_nhp()`.
3. On success, transmit an NHP signal/event through your lower layer. The returned ROHC length is `0`.
4. Carry any RTP payload through the lower-layer event if your assisted link separates payload from reconstructed header state.
5. Periodically or when your link policy requires it, call `rohc_comp_rfc4362_emit_csp()` or `rohc_comp_rfc4362_emit_ccp()` and transmit those as explicit CSP/CCP assisted events.

### Assisted Receive Process

1. If the lower layer delivers a normal ROHC packet, call `rohc_decompress4()`.
2. If it delivers an NHP event for CID 0, call `rohc_decomp_rfc4362_receive_nhp()`.
3. If it delivers an NHP event for a nonzero or large CID, call `rohc_decomp_rfc4362_receive_nhp_for_cid()`.
4. If it delivers a CSP event, call `rohc_decomp_rfc4362_receive_csp()` and deliver the produced IP packet upward.
5. If it delivers a CCP event, call `rohc_decomp_rfc4362_receive_ccp()` or `rohc_decomp_rfc4362_receive_ccp_for_cid()`.
6. If the lower layer reports loss or residual error, call `rohc_decomp_rfc4362_report_loss()` or `rohc_decomp_rfc4362_report_residual_error()`.
7. Poll and forward feedback if `rohc_decomp_has_feedback()` returns `1`.

### R-Mode Notes

For Reliable mode, NHP emission is ACK-gated. Deliver ACK and STATIC-NACK events back to the compressor with `rohc_comp_handle_feedback()` or serialized feedback packets. After STATIC-NACK, the compressor returns to context repair and NHP emission is rejected until dynamic context is ACKed again.

## RFC 3243 Zero-Byte Assumption Validation

RFC 3243 is represented by the RFC 4362 enabling contract and by installed C helper functions in `rohccxx.h`. Source-tree C++ helpers in `include/rohccxx/core/lla.hpp` remain available for in-repo tests but are not installed by the Debian package.

### Stable C Helper Entry Points

| API | Service provided |
| --- | --- |
| `rohc_lla_validate_rfc3243_zero_byte_assumptions()` | Checks lower-layer packet identification, ordering, loss indication, residual error indication, and feedback delivery. |
| `rohc_lla_validate_rfc3243_zero_byte_flow()` | Checks the lower-layer contract plus IPv4/UDP/RTP, disabled UDP checksum, RTP sequence progression, compressor-side ordering, and synchronized timing. |
| `rohc_lla_can_emit_no_header_packet()` | Convenience gate for lower-layer assumptions only. |
| `rohc_lla_can_emit_no_header_packet_for_flow()` | Convenience gate for the full lower-layer plus flow assumptions. |

### Third-Party Process

1. Use these helpers in C++ adapters or tests before mapping deployment-specific link capabilities into `rohccxx_lla_contract_t` and `rohccxx_lla_flow_t`.
2. Refuse to enable RFC 4362 NHP if validation fails.
3. Keep link-specific proof and negotiation outside `rohccxx`; only pass true contract fields that the third-party stack actually provides.

## RFC 3408 Reliable-Mode Zero-Byte Support

RFC 3408 extends zero-byte support into R-mode. `rohccxx` exposes the validation helper and enforces R-mode NHP progression in the runtime API.

### API Entry Points

| API | Service provided |
| --- | --- |
| `rohc_lla_validate_rfc3408_r_mode_zero_byte_support()` / `rohccxx::lla::validate_rfc3408_r_mode_zero_byte_support()` | Checks RFC 3243 assumptions plus reliable-mode support, ACK delivery, and STATIC-NACK delivery. |
| `rohc_lla_can_emit_reliable_mode_no_header_packet()` / `rohccxx::lla::can_emit_reliable_mode_no_header_packet()` | Convenience gate for R-mode zero-byte capability. |
| `rohc_comp_set_mode(comp, ROHCCXX_MODE_R)` | Sets compressor mode to Reliable. |
| `rohc_decomp_set_mode(decomp, ROHCCXX_MODE_R)` | Sets decompressor mode to Reliable. |
| `rohc_comp_handle_feedback()` | Delivers ACK/STATIC-NACK feedback that gates NHP progression. |

### Transmit Process

1. Set compressor mode to `ROHCCXX_MODE_R`.
2. Establish static and dynamic context using ordinary ROHC packets or CSP.
3. Do not expect NHP emission to succeed until dynamic context has been ACKed.
4. Deliver decompressor ACK feedback to the compressor.
5. Call `rohc_comp_rfc4362_emit_nhp()` only after dynamic ACK.
6. If STATIC-NACK is received, return to repair packets and wait for ACK before resuming NHP.

### Receive Process

1. Set decompressor mode to `ROHCCXX_MODE_R`.
2. Decompress ordinary packets or assisted CSP/NHP events.
3. Send ACK, NACK, or STATIC-NACK through your lower-layer feedback path.
4. Use `rohc_decomp_rfc4362_report_loss()` and `rohc_decomp_rfc4362_report_residual_error()` when your lower layer detects those conditions.

## RFC 3409 Lower-Layer Guidelines

RFC 3409 is represented by stronger lower-layer contract fields for robust assisted compression.

### API Entry Points

| API | Service provided |
| --- | --- |
| `rohc_lla_validate_rfc3409_lower_layer_guidelines()` / `rohccxx::lla::validate_rfc3409_lower_layer_guidelines()` | Checks RFC 3243 assumptions plus context-packet protection, CSP support, and CCP support. |
| `rohc_lla_can_emit_context_synchronization_packet()` / `rohccxx::lla::can_emit_context_synchronization_packet()` | Convenience gate for CSP capability. |
| `rohc_lla_can_emit_context_check_packet()` / `rohccxx::lla::can_emit_context_check_packet()` | Convenience gate for CCP capability. |

### Third-Party Process

1. Prove that CSP/CCP packets are protected and not confused with ordinary payload.
2. Set `protects_context_packets`, `supports_context_synchronization`, and `supports_context_check` only if the lower layer really provides those services.
3. Enable RFC 4362 LLA.
4. Use CSP/CCP APIs as explicit assisted events.

## ROHCoIPsec: RFC 5856, RFC 5857, And RFC 5858

`rohccxx` provides the ROHCoIPsec codec, negotiation payload, SA, key, ICV, and processing-order seams. Your IKEv2/IPsec stack owns real IKE exchanges, SPD/SAD lifecycle, AH/ESP framing, replay protection, and packet routing.

### API Entry Points

| API | Service provided |
| --- | --- |
| `rohc_rohcoipsec_protocol_number()` | Returns the ROHCoIPsec protocol number, `142`. |
| `rohc_rohcoipsec_write_supported()` | Serializes RFC 5857 ROHC_SUPPORTED attributes from local channel parameters. |
| `rohc_rohcoipsec_parse_supported()` | Parses peer ROHC_SUPPORTED attributes. |
| `rohc_rohcoipsec_negotiate()` | Computes mutually supported ROHCoIPsec channel parameters. |
| `rohc_rohcoipsec_derive_directional_keys()` | Splits IKE KEYMAT into outbound and inbound ROHC integrity keys. |
| `rohc_rohcoipsec_build_sa()` | Builds a `rohccxx_rohcoipsec_sa_t` from negotiated channel parameters and key material. |
| `rohc_comp_apply_rohcoipsec_sa()` / `rohc_decomp_apply_rohcoipsec_sa()` | Applies negotiated ROHCoIPsec SA parameters to compressor/decompressor handles. |
| `rohc_comp_enable_rohcoipsec()` / `rohc_decomp_enable_rohcoipsec()` | Enables ROHCoIPsec with NONE integrity. |
| `rohc_comp_set_rohcoipsec_integrity()` / `rohc_decomp_set_rohcoipsec_integrity()` | Configures keyed ROHCoIPsec integrity. |
| `rohc_rohcoipsec_append_icv()` | Appends a ROHCoIPsec ICV to a compressed packet. |
| `rohc_rohcoipsec_strip_verify_icv()` | Verifies and strips a ROHCoIPsec ICV. |
| `rohc_rohcoipsec_security_next_header()` | Computes AH/ESP Next Header when compressed or uncompressed. |
| `rohc_rohcoipsec_outbound_next_header()` | Returns outbound Next Header value for compressed ROHCoIPsec packets. |
| `rohc_rohcoipsec_inbound_requires_decompression()` | Tests whether inbound AH/ESP payload should be sent to the ROHC decompressor. |
| `rohc_comp_rohcoipsec_next_header()` | Queries compressor ROHCoIPsec Next Header when enabled. |
| `rohc_decomp_rohcoipsec_requires_decompression()` | Decompressor-side Next Header check. |

### IKEv2 Negotiation Process

1. Populate local `rohccxx_rohcoipsec_channel_t` with supported `max_cid`, profiles, integrity algorithms, optional ICV length, and optional MRRU.
2. Call `rohc_rohcoipsec_write_supported()` to produce ROHC_SUPPORTED attribute bytes.
3. Carry those bytes in your IKEv2 notify exchange.
4. Parse peer bytes with `rohc_rohcoipsec_parse_supported()`.
5. Call `rohc_rohcoipsec_negotiate()`.
6. Use your IKEv2 stack to derive KEYMAT.
7. Call `rohc_rohcoipsec_derive_directional_keys()`.
8. Build outbound/inbound SAs with `rohc_rohcoipsec_build_sa()`.
9. Apply SAs to compressor/decompressor handles.

### ROHCoIPsec Transmit Process

1. Receive an outbound IP packet selected by your SPD/policy.
2. Compress it with `rohc_compress4()` using the compressor configured by `rohc_comp_apply_rohcoipsec_sa()`.
3. If you use the integrated compressor SA path, the compressor appends/verifies configured ROHCoIPsec integrity as part of packet processing.
4. If your IPsec stack owns ICV placement separately, use `rohc_rohcoipsec_append_icv()` with the original authenticated packet and compressed packet.
5. Set AH/ESP Next Header using `rohc_rohcoipsec_outbound_next_header(1)` or `rohc_rohcoipsec_security_next_header(original_next_header, 1)`.
6. Hand the result to your AH/ESP encapsulation and replay-protection code.

### ROHCoIPsec Receive Process

1. Your AH/ESP stack validates the outer security association, replay window, and packet ownership.
2. Inspect Next Header.
3. If `rohc_rohcoipsec_inbound_requires_decompression(next_header)` or `rohc_decomp_rohcoipsec_requires_decompression()` returns true, pass the payload to `rohc_decompress4()`.
4. If your IPsec stack owns ICV stripping separately, call `rohc_rohcoipsec_strip_verify_icv()` before `rohc_decompress4()`.
5. Deliver decompressed IP packets upward on return `0`.
6. Handle segmentation return `1` and feedback just like the basic ROHC receive process.

## Native C++ Convenience API

The lightweight C++ classes are useful for source-tree C++ applications and tests that do not need a stable installed ABI boundary. They are not installed by the Debian package.

| API | Service provided |
| --- | --- |
| `rohccxx::Compressor(cid, max_cid)` | Creates a C++ compressor for a single selected CID. |
| `rohccxx::Compressor::compress()` | Compresses an IP packet. |
| `rohccxx::Compressor::enable_rfc4362_lla()` | Enables RFC 4362 assisted behavior for C++ callers. |
| `rohccxx::Compressor::rfc4362_emit_nhp()` | Emits an assisted NHP event. |
| `rohccxx::Compressor::rfc4362_emit_csp()` | Emits a CSP event. |
| `rohccxx::Compressor::rfc4362_emit_ccp()` | Emits a CCP event. |
| `rohccxx::Decompressor(cid, max_cid)` | Creates a C++ decompressor for a single selected CID. |
| `rohccxx::Decompressor::decompress()` | Decompresses a ROHC packet. |
| `rohccxx::Decompressor::enable_rfc4362_lla()` | Enables RFC 4362 assisted behavior for C++ callers. |
| `rohccxx::Decompressor::rfc4362_receive_nhp()` | Receives an assisted NHP event. |
| `rohccxx::Decompressor::rfc4362_receive_csp()` | Receives a CSP event. |
| `rohccxx::Decompressor::rfc4362_receive_ccp()` | Receives a CCP event. |

For full protocol coverage, segmentation, feedback packets, ROHCoIPsec, large-CID assisted receive dispatch, and ABI stability, prefer the C API.

## Shutdown

1. Stop packet I/O for the ROHC channel.
2. Ensure no thread is currently calling into the compressor/decompressor handle.
3. Free the handles.
4. Release any third-party channel, PPP, IKE, IPsec, driver, or queue resources owned by the integrating package.

```c
rohc_decomp_free(decomp);
rohc_comp_free(comp);
```

## Integration Checklist

- The third-party package has a clear ROHC channel lifetime.
- The negotiated `max_cid` matches compressor and decompressor creation.
- Large-CID channels use `max_cid > 15`.
- MRRU is configured on both sides when segmentation is negotiated.
- Feedback has a real return path to the compressor.
- RFC 4362 NHP/CSP/CCP are dispatched through explicit assisted APIs, not `rohc_decompress4()`.
- PPP stacks own PPP negotiation and framing; `rohccxx` only validates ROHC option payloads and compresses/decompresses ROHC packets.
- IPsec/IKE stacks own IKEv2 exchanges, SPD/SAD, AH/ESP framing, and replay protection; `rohccxx` only provides ROHCoIPsec helper seams and codec behavior.
- Handle lifetime is externally synchronized with shutdown.
