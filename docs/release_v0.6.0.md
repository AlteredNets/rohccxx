<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.6.0

Version 0.6.0 adds a minimal Linux IPv4 TUN-to-UDP tunnel built on the public
ROHCCXX C API. Two symmetric, single-threaded endpoints carry compressed
packets and ROHC feedback in a bounded, versioned UDP envelope. This is a
laboratory example: it makes no production-readiness, operational-deployment,
TRL, encryption, or hardware-performance claim.

The tunnel maintains independent outbound flow-to-CID mappings. IPv4, UDP,
RTP, and ESP fields are parsed with length checks; new flows receive the lowest
available small CID from 0 through 15 deterministically. Established flows keep
their CID. A seventeenth flow safely reuses the least-recently-used CID after
resetting its compressor context, so the replacement begins with context
establishment rather than stale state. Received ROHC CIDs select decompressor
contexts, and feedback is routed to the corresponding compressor context.

UDP private-FO/formal-PT-0 overlap after context reuse is resolved
transactionally using the packet's nonzero UDP checksum. The checksum covers
the IPv4 pseudo-header, UDP header, and payload and selects an interpretation
only when exactly one is valid. Failures preserve context and caller output;
zero-checksum or genuinely ambiguous packets remain rejected. No ROHC wire
format was changed.

The Ubuntu 24.04 Linux CI validation carried byte-exact traffic in both
directions and exercised loss, burst loss, duplication, reordering, corruption,
truncation, endpoint restart, feedback, and bounded recovery. Its mixed-flow
campaign validated 526,005 packets and 561,873,360 bytes over 300 seconds with
1, 4, and 16 flows and 64-, 256-, and 1,200-byte payloads. Client and server
recorded the matching SHA-256 digest
`801842fa6acfb16cd2a4dc64397b2d953738031d6d3bf32e794a8a7c2e864ee2`, with
zero silent corruption. Peak normal endpoint RSS was 4,604 KiB. Reduced-volume
ASan/UBSan stress and leak detection completed without findings, and all Linux
process, TUN, veth, and namespace resources were cleaned up.
