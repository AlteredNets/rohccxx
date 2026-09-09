# Changelog

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
