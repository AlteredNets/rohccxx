<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# rohccxx v0.8.0-rc.2

Version 0.8.0-rc.2 is a pre-v1 release candidate. It incorporates correctness
fixes for defects found while testing v0.8.0-rc.1 under controlled network loss,
reordering, and CID/profile state transitions. It does not claim production
readiness or v1 maturity.

The fixes cover issue #49 silent RTP reconstruction after loss, issue #51 stale
cross-profile context acceptance after CID reuse, issue #53 CID-0
PT-0/uncompressed alias handling, and the issue #32 PT-0 forward-loss and
delayed-reorder alias cases. The corrected paths require exact reconstruction or
explicit transactional rejection and later context recovery.

The validated fix composition attempted 10,485,760 logical packets across the
Pi 5 in El Paso, AWS Ohio, and the x86_64 mini-PC in New York. Of those,
9,101,446 were accepted and all 9,101,446 accepted packets were reconstructed
exactly. The 34-scenario impairment matrix and the 19-scenario deterministic
state matrix both passed.

Focused state fuzzing completed 1,000,000 executions using the retained issue
witnesses and CID/profile transition seeds. ASan and UBSan reported no finding.
Across the validated campaign, no silent mutation, cross-profile acceptance,
cross-flow error, crash, or hang was observed.

These results describe the tested candidate, corpus, scenarios, and
environments. They do not establish universal interoperability, production
readiness, encryption capability, real INE/TME security, or resistance to every
possible network condition or malformed input.
