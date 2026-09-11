<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.8.0-rc.3

Version 0.8.0-rc.3 is a pre-v1 release candidate. It addresses the ESP/PT-0
delayed wrap and reorder alias found during the published v0.8.0-rc.2 soak.
The retained RC2 regression reproduces the failure before the fix and passes
with the corrected implementation.

The defect allowed a delayed ESP PT-0 packet crossing a complete four-bit MSN
cycle to be interpreted as a forward delta of one. A CRC-3 collision could then
authenticate a reconstruction with incorrect IPv4 ID and ESP sequence values.
Current ESP traffic now uses PT-0-CRC7, and legacy CRC-3 units are retired
transactionally after a stronger-generation refresh.

The fix lane passed GCC Debug, GCC Release, and Clang ASan/UBSan validation,
with mandatory pinned rohc-lib interoperability at 6/6. Targeted regressions
for issues #32, #40, #45, #47, #49, #51, and #53 passed. Focused fuzzing
completed 1,000,000 executions with no sanitizer findings.

The geographic fix validation attempted 67,584 logical packets. It accepted
52,880 packets, and all 52,880 accepted packets were byte-exact. The campaign
recorded 24 explicit rejects and 1,118 safe recoveries. It observed no silent
mutation, cross-profile acceptance, cross-flow error, crash, or hang.

These results describe the tested candidate, corpus, scenarios, and
environments. They do not establish production readiness, v1 maturity,
universal interoperability, encryption capability, real INE/TME security, or
resistance to every possible network condition or malformed input.
