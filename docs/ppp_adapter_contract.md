<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# PPP Adapter Contract for ROHC

`rohccxx` provides RFC 3241 helper seams for a PPP implementation, but it does not implement PPP NCP negotiation, framing, retransmission, authentication, or driver behavior.

## Library-Owned Helpers

The RFC 3241 helper API in `rohccxx::ppp` and the stable C API covers:

| Helper area | Purpose |
| --- | --- |
| ROHC IPCP option parse/write | Validate and serialize the IP-Compression-Protocol option for ROHC with `rohc_ppp_parse_rohc_option()` and `rohc_ppp_write_rohc_option()`. |
| Channel parameter fields | Preserve `MAX_CID`, `MRRU`, `MAX_HEADER`, and the mandatory PROFILES suboption. |
| Profile list validation | Require at least one profile and reject duplicate or unsorted profile lists with `rohc_ppp_validate_rohc_option()`. |
| PPP protocol demux constants | Distinguish ROHC small-CID (`0x0003`) and large-CID (`0x0005`) PPP protocol fields with `rohc_ppp_is_rohc_protocol()` and `rohc_ppp_uses_large_cid_protocol()`. |
| Option merge helper | Combine adapter-provided ROHC channel options without performing PPP negotiation with `rohc_ppp_merge_rohc_options()`. |

## Adapter-Owned Behavior

A PPP stack or driver owns:

| Adapter responsibility | Reason |
| --- | --- |
| LCP/IPCP/IPV6CP state machines | These are PPP protocol responsibilities, not ROHC codec behavior. |
| Configure-Request/Configure-Ack/Configure-Nak/Configure-Reject exchange | `rohccxx` only validates option payloads. |
| PPP framing, FCS, escaping, MRU enforcement, and retransmission | These depend on the PPP link implementation. |
| Packet ownership and dispatch | The adapter decides when PPP protocol fields `0x0003` and `0x0005` are delivered to `rohccxx`. |

The unit tests exercise the helper boundary so a PPP adapter can use these functions as acceptance checks without making `rohccxx` a PPP driver.
