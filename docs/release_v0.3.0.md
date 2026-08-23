<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.3.0

Version 0.3.0 changes the emitted ROHCv2 initialization wire format. Releases
through v0.2.2 emitted a private IR/IR-DYN layout. Version 0.3.0 emits
RFC 5225-compliant IR, while its decoder retains guarded legacy decoding for
the earlier private layout.

## Migration

Mixed deployments must upgrade decompressors before compressors. Upgrade and
deploy every receiving/decompressing endpoint to v0.3.0 before enabling v0.3.0
compressors. This order allows the guarded v0.3.0 decoder to accept legacy
traffic during the transition without sending the new RFC 5225-compliant IR to
an older decoder.

## Interoperability Scope

The release suite requires mandatory bidirectional interoperability with the
pinned rohc-lib for deterministic three-packet flows in the tested
RTP/UDP/IP, UDP/IP, ESP/IP, and IP-only profiles. The interoperable subset is
IPv4 with small CID 0 and no IP options: rohccxx-compressed traffic must decode
exactly with rohc-lib, and rohc-lib-compressed traffic must decode exactly with
rohccxx.

This mandatory claim does not extend to RTP/UDP-Lite/IP, UDP-Lite/IP,
RFC 4362, IPv6, nonzero or large CIDs, IP options, extension-header chains, or
other untested variants. Optional oracle hooks and internal corpus coverage for
some of those variants are separate evidence and are not part of the mandatory
bidirectional interoperability claim.

## Release Validation

Each supported CI configuration must report 215 registered tests, 212 passed,
0 failed, and 3 optional external-oracle skips. The two mandatory RFC 5225
rohc-lib tests are `interop_rfc5225_rohccxx_to_rohclib` and
`interop_rfc5225_rohclib_to_rohccxx`.
