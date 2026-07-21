<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Embedding Stack Integration Boundary

`rohccxx` exposes the ROHCoIPsec seams needed by an embedding IPsec/IKE stack, but it does not own kernel or daemon responsibilities.

## Owned By `rohccxx`

- RFC 5857 ROHC_SUPPORTED attribute encode/decode and negotiation helpers.
- Directional KEYMAT split into outbound and inbound ROHC integrity keys.
- ROHCoIPsec SA construction from negotiated channel parameters.
- Compressor/decompressor SA application, including implicit large-CID and MRRU settings.
- RFC 5858 ROHC protocol number and AH/ESP Next Header helper decisions.
- NONE and HMAC-SHA-256 truncated ICV append/verify behavior.
- Compressor-before-IPsec and IPsec-before-decompressor packet processing order.

## Owned By The Embedding Stack

- Real IKEv2 message exchange and notify payload transport.
- SPD/SAD lifecycle and policy ownership.
- Kernel or user-space AH/ESP packet framing and replay protection.
- Lower-layer ordering policy. If the deployment cannot provide in-order segmented ROHC delivery, it should either reorder before calling `rohccxx` or negotiate segmentation off.

The `test_embedding_adapter` compatibility test simulates the expected adapter flow end-to-end with public APIs so downstream integrations have a stable contract to follow.
