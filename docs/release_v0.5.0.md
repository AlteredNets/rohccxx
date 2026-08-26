<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.5.0

Version 0.5.0 adds live standards-based RFC 5225 formal PT-0 selection for
steady-state RTP/UDP/IPv4, UDP/IPv4, ESP/IPv4, and IP-only IPv4 traffic in the
small-CID space. CID 0 uses the one-byte PT-0 base header. CIDs 1 through 15
use Add-CID followed by PT-0 for a two-byte compressed header.

Selection remains conservative. Each profile uses formal PT-0 only when every
omitted field can be reconstructed safely. Existing private first-order
formats remain available where required, and IR or IR-DYN refreshes remain the
fallback for unsupported or unsafe changes. Large-CID behavior is unchanged.

Successful unauthenticated formal compression and decompression paths avoid
per-packet heap allocation and reconstruct only the fixed protocol header
needed for validation. Authenticated ROHCoIPsec traffic retains staged output.
CRC-3 uses an exact-equivalent table-driven implementation while preserving
all existing CRC results and wire bytes.

Decompression remains transactional: CRC failures, malformed or truncated
packets, ambiguous interpretations, and insufficient output capacity do not
commit tentative context or alter caller output. Targeted regression coverage
includes small-CID framing, interleaved flows, wraparound, unsafe-field
fallbacks, corruption recovery, byte-exact reconstruction, and buffer guards.

This release makes no absolute throughput or hardware-performance claim.
