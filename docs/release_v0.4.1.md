<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.4.1

Version 0.4.1 is a corrective patch release for v0.4.0. Valid RFC 5225
CID-0 PT-0 first octets could collide with legacy private-FO markers during
top-level decompression dispatch. The externally validated affected profiles
were UDP/IPv4, ESP/IPv4, and IP-only IPv4. Version 0.4.0 failed safely in
these cases with zero output and rolled-back context; no silent packet
corruption was observed.

Context-aware, independent tentative decoding now selects a unique valid
interpretation and rejects differing dual-valid meanings. Tentative attempts
use isolated context and staged output. Existing fully validated legacy
private FO remains supported, and final failures continue to produce
CID-specific NACK feedback according to the public API contract.

There is an inherent provenance ambiguity in the legacy wire format: when an
identical wire image is valid as legacy private FO, the decoder cannot
distinguish that packet from a corrupted formal packet. The compatibility
policy therefore accepts a private interpretation only when it independently
passes its complete structure and CRC validation. No deliberate encoder wire-
format change was introduced; this release corrects decompressor dispatch.

## Regression And External Validation

The public C API regression suite exercises all 128 PT-0 first-octet values
for each corrected profile. It pins the exact UDP packet 15, ESP packet 48,
and IP-only packet 62 regressions so later compressor changes cannot silently
replace the cases.

The Linux VM correctness comparator passes twice for RTP, UDP, ESP, and
IP-only using rohccxx, the pinned rohc-lib, and control paths, with zero
mismatches and zero guard failures. The mandatory external interoperability
boundary and the three optional-oracle limitations remain unchanged from
v0.4.0; see [`release_v0.4.0.md`](release_v0.4.0.md) for that exact boundary.

Every supported configuration reports 226 registered tests, 223 passed,
0 failed, and 3 optional external-oracle skips. The mandatory RFC 5225 IR and
CO interoperability directions remain required.

Users of the v0.4.0 prerelease should upgrade to v0.4.1.
