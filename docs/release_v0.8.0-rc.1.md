<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.8.0-rc.1

Version 0.8.0-rc.1 is a pre-v1 release candidate. It reconciles the validated
correctness and interoperability composition at
`43f2bb02d48f6800af7fba929864a01d712bdac3` with release metadata and package
verification. It does not claim production readiness or v1 maturity.

The candidate includes the issue #40 unaligned wire-header fix, the issue #45
private-FO context binding and stale-collision behavior, and the issue #47
transactional rejection of the reproduced one-bit ESP PT-0/private-FO
collision. Failed packets in the covered cases leave output and decoder state
unchanged so the next valid packet remains retryable.

The validated composition was exercised on ARM64 and x86_64 components. The
external interoperability gates use the pinned rohc-lib revision and cover the
documented IPv4, small-CID subset in both directions; they do not extend the
claim beyond the limits in `docs/external_oracle.md`. GCC, Clang, ASan, UBSan,
bounded fuzzing, and a 30-minute ARM soak were included in the retained
validation evidence.

The geographic AWS campaign sent deterministic interleaved RTP/UDP/IP, UDP/IP,
ESP/IP, and IP-only flows from a Pi 5 and an x86_64 mini-PC to AWS Ohio. Both
direct paths reconstructed 128 of 128 packets exactly. The Pi 5 -> AWS Ohio ->
mini-PC and mini-PC -> AWS Ohio -> Pi 5 relay paths also reconstructed 128 of
128 exactly. Across that tested campaign, no decode failure, mismatch, silent
mutation, cross-flow error, crash, or packet-capture kernel drop was observed.

These results describe the tested candidate and environments. They do not
establish universal network compatibility, real INE/TME security,
exactly-once transport, or resistance to every corruption or impairment.
