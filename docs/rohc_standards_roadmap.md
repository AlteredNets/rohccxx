<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# ROHC Standards Roadmap

This roadmap separates work owned by the `rohccxx` library from work owned by embedding adapters such as PPP, lower-layer-assisted radio/link code, IKEv2, or IPsec packet processing. RFC 3242 is not an active target because RFC 4362 obsoletes it; profile `0x0005` is handled as RFC 4362 lower-layer-assisted RTP.

| RFC | Scope | `rohccxx` responsibility | Adapter responsibility | Current status |
| --- | --- | --- | --- | --- |
| RFC 5225 | ROHCv2 RTP/UDP/IP, UDP/IP, IP-only, ESP/IP, RTP/UDP-Lite/IP, UDP-Lite/IP profiles | Packet grammar, C API behavior, public profile capability discovery, deterministic corpus, decode/encode tests | External oracle can corroborate corpus | Complete for current library boundary; broaden only with future packet families |
| RFC 3241 | ROHC over PPP | Provide C and C++ API helpers for PPP option payload validation and mapping to ROHC channel settings | PPP LCP/IPCP/IPV6CP negotiation, framing, retransmission, and driver behavior | Adapter-seam helpers and tests complete |
| RFC 3243 | 0-byte requirements and assumptions | Executable conformance/acceptance tests for zero-byte assumptions | Lower-layer packet identification, ordering, loss/error signaling | Dedicated conformance helpers and standalone conformance test library complete |
| RFC 3408 | Zero-byte support for R-mode in extended LLA profile | R-mode zero-byte gates layered on RFC 3243 assumptions | Lower layer must deliver reliable-mode ACK/STATIC-NACK signals | R-mode zero-byte contract and ACK/STATIC-NACK progression tests complete |
| RFC 3409 | Lower-layer guidelines for robust RTP/UDP/IP compression | Document and test C/C++ lower-layer missing-bit validation APIs | Link-specific ordering, loss indication, packet type identification, channel policy | Adapter contract helpers and tests complete |
| RFC 4362 | Link-layer-assisted IP/UDP/RTP profile | Profile ID, packet grammar, explicit assisting-layer gate, NHP/CSP/CCP runtime APIs, and zero-byte reconstruction tests | Assisting layer decides when NHP/CCP/CSP can be sent and supplies packet-type/loss signals | Runtime API boundary, large-CID dispatch, C++ wrappers, and oracle corpus complete |
| RFC 5856 | ROHC over IPsec architecture | ROHCoIPsec channel/SA helper boundary | SPD/SAD ownership and packet routing | Complete at library boundary |
| RFC 5857 | IKEv2 extensions for ROHC over IPsec | Strict ROHC_SUPPORTED encode/decode/negotiation helpers | Real IKEv2 exchange/plugin | Complete at library boundary |
| RFC 5858 | IPsec extensions for ROHC packets | protocol number, Next Header helpers, NONE/HMAC ICV append/verify, processing order | AH/ESP framing, replay protection, kernel/user-space packet ownership | Complete at library boundary |
