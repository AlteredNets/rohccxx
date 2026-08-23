<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.4.0

Version 0.4.0 adds context-complete external compressed-optimized (CO)
interoperability coverage and hardens packet classification, context isolation,
bounded private-FO parsing, and transactional decompression failure behavior.
The existing 364-case internal RFC 5225 grammar and CRC corpus remains intact.

## Externally Proven CO Boundary

The mandatory tests establish context with IR and then prove bidirectional
PT-0 interoperability with the pinned rohc-lib for UDP/IPv4, ESP/IPv4, and
IP-only IPv4. The exact tested subset uses small CID 0 without Add-CID,
sequential network-order IP-ID behavior, and forward MSN deltas from 1 through
15.

Within that boundary, each direction performs byte-exact reconstruction. The
suite covers one deliberately lost packet, duplicate and older-packet
rejection, ESP sequence-number wrap, CRC corruption, truncation, missing or
unsupported context, output and context preservation on failure, and a valid
retry after each failed transaction.

## Explicit Limitations

No external CO interoperability claim is made for RTP CO, RTP/UDP-Lite,
UDP-Lite, IPv6, nonzero or large CID modes, non-sequential or byte-swapped
IP-ID behavior, CO-COMMON or CO-REPAIR, RFC 4362, IPv4 options, IPv6 extension
headers, advanced encoding combinations, or other untested profiles and
variants, including advanced options beyond the tested subset.

The result also does not prove general reordering recovery, recovery after a
forward loss of 16 or more packets, or broader burst-loss behavior. The pinned
rohc-lib RTP implementation does not provide a successful external RTP CO path,
so RTP context establishment and private-FO observations are not reported as
external CO success.

## Release Validation

Every supported configuration must report 218 registered tests, 215 passed,
0 failed, and 3 optional external-oracle skips. Both mandatory CO tests must
pass:

- `interop_rfc5225_co_rohccxx_to_rohclib`
- `interop_rfc5225_co_rohclib_to_rohccxx`

The broader baseline RFC 5225 interoperability tests and internal formal
corpora remain separate supporting evidence and do not expand the boundary
stated above.
