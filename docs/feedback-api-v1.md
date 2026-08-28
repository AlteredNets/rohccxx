# Versioned correlated feedback API

`rohccxx_feedback_v1_t` is an additive C API record for carrying one complete
ROHCv2 FEEDBACK-2 packet without reducing its standards identity. The record is
bounded and self-describing (`api_version` and `struct_size`) and contains the
channel direction, CID, ACK/NACK/STATIC-NACK type, 14-bit Acknowledgment Number,
ACKNUMBER-NOT-VALID state, feedback CRC state, and the exact received feedback
bytes.

`rohc_decomp_get_feedback_v1` emits standards-compliant bytes.
`rohc_feedback_parse_v1` validates and describes bytes without changing codec
state. `rohc_comp_deliver_feedback_v1` reparses the raw bytes, verifies that the
described fields match them, checks channel and CID, and correlates a valid
Acknowledgment Number with the active context's bounded transmitted-MSN
history. Only then is feedback applied.

The delivery result is one of `ACCEPTED`, `STALE`, `MALFORMED`,
`UNCORRELATED`, or `UNSUPPORTED`. Every result except `ACCEPTED` is
transactional: compressor state is unchanged. `ACKNUMBER-NOT-VALID` is exposed
losslessly but is deliberately uncorrelated and cannot mutate a compressor
context.

The original feedback functions remain available for source and ABI
compatibility. Integrations that reuse CIDs asynchronously should use the v1
API and transport `raw[0..raw_len)` without rewriting it.
