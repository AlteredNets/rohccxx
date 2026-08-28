# Seed corpus provenance

The checked-in seeds are intentionally minimal and contain no laboratory archive,
credentials, captures, addresses, or payload data. They represent boundary bytes
derived from the public unit/interop vectors, RFC 5225 packet discriminators,
Add-CID/PT-0 and private-FO regression shapes, the documented CID-reuse/MSN
ambiguity regression, and tunnel corruption/recovery cases. Structured valid
IPv4/UDP, RTP-like UDP, ESP and IP-only packets are generated deterministically by
the round-trip target from these bounded inputs. The preserved v0.6.0 laboratory
captures were reviewed for packet-shape coverage only; no captured bytes are
committed.
