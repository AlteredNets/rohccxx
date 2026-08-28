<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.6.1

Version 0.6.1 is a correctness and context-isolation hardening release. It adds
four disabled-by-default Clang/libFuzzer targets covering stateless
decompression, stateful decompressor transitions, structured public-API round
trips, and Linux tunnel parsing and flow classification. The initial hardening
campaign completed more than 51 million executions under ASan and UBSan with
leak detection.

That campaign found a nonzero small-CID uncompressed-fallback defect. The
compressor now preserves its selected CID with the existing Add-CID grammar,
preventing fallback packets from being interpreted through stale CID-0 context.
The minimized 17-byte reproducer has deterministic regression coverage.

The correction does not change any ROHC wire format or public API. The existing
Add-CID packet grammar is now applied consistently to this fallback path.

Post-merge validation ran each fuzz target for an additional hour in a clean
Ubuntu 24.04 environment. GCC Debug and Release, Clang ASan/UBSan with leak
detection, the ordinary Release suite, deterministic source and Debian package
generation, installed and linked consumers, and Linux tunnel integration and
stress completed without findings. Accepted structured inputs reconstructed
byte-exactly, malformed input remained transactional, and no crash, hang, leak,
sanitizer finding, guard failure, timeout, or silent corruption was observed.
