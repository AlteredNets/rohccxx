# Changelog

## 0.8.0-rc.3 - 2026-09-11

- Prevent delayed ESP PT-0 packets from being accepted after a full four-bit
  MSN wrap with incorrect IPv4 ID and ESP sequence values (#32).
- Emit PT-0-CRC7 for current ESP traffic and transactionally retire legacy
  CRC-3 units after stronger-generation refresh.
- Retain the pre-v1 release-candidate status and the v0.8.0 ABI version.

## 0.8.0-rc.2 - 2026-09-10

- Reject silent RTP reconstruction after loss when the required context is unavailable (#49).
- Prevent stale cross-profile context acceptance after CID reuse and lost replacement context (#51).
- Require explicit context establishment for the CID-0 PT-0/uncompressed alias case (#53).
- Prevent the validated PT-0 forward-loss and delayed-reorder CRC alias cases (#32).
- Retain the pre-v1 release-candidate status and the v0.8.0 ABI version.

## 0.8.0-rc.1 - 2026-09-09

- Reconcile the validated pre-v1 correctness and interoperability composition.
- Make wire header access safe for unaligned byte buffers (#40).
- Bind private FO decoding to established static context and reject stale collisions (#45).
- Reject the tested one-bit ESP PT-0/private FO collision transactionally (#47).
- Add prerelease-aware CMake, package, generated-header, and pkg-config metadata.

## 0.7.0 - 2026-08-31

- Add the versioned and correlated feedback API to the C++ and C surfaces.
- Preserve feedback identity and correlation through FEEDBACK-2 handling.
- Make rejected feedback transactional, including malformed and mismatched input.
- Retain the nonzero small-CID uncompressed-fallback Add-CID correction.

## 0.6.1

- Add fuzzing coverage and correct nonzero small-CID uncompressed fallback.
