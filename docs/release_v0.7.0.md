<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.7.0

Version 0.7.0 adds a versioned, correlated feedback API across the C++ and C
interfaces. Feedback now carries explicit identity and correlation metadata so
callers can associate an accepted feedback item with the compressor operation
that consumes it.

Rejected feedback is transactional: malformed, stale, mismatched, or otherwise
inadmissible input does not partially mutate compressor state. FEEDBACK-2
coverage verifies identity and correlation handling, duplicate and out-of-order
behavior, and the public C compatibility surface.

The release also carries forward the v0.6.1 nonzero small-CID fallback
correction. Uncompressed fallback after CID reuse preserves the selected context
with the standard Add-CID grammar, preventing accidental interpretation through
CID 0.

RFC 5225 IP PT-1 support remains explicitly outside this release. This release
does not claim ANIMAL enrollment, Pi 5 to Pi 4 public-Internet acceptance, or
external interoperability beyond the project’s existing documented gates.
