#!/usr/bin/env python3
"""Replay the sealed RC3 Issue #32 witness trajectory through the public C API."""

import argparse
import ctypes
import hashlib
import json
import pathlib
import struct
import sys

MAX_ROHC = 65535


class FeedbackV1(ctypes.Structure):
    _fields_ = [
        ("api_version", ctypes.c_uint32),
        ("struct_size", ctypes.c_size_t),
        ("channel", ctypes.c_int),
        ("cid", ctypes.c_uint32),
        ("feedback_type", ctypes.c_uint8),
        ("acknowledgment_number", ctypes.c_uint16),
        ("acknowledgment_bits", ctypes.c_uint8),
        ("acknowledgment_valid", ctypes.c_int),
        ("crc_present", ctypes.c_int),
        ("crc_valid", ctypes.c_int),
        ("raw_len", ctypes.c_size_t),
        ("raw", ctypes.c_uint8 * 260),
    ]


def put16(buf, offset, value):
    struct.pack_into("!H", buf, offset, value & 0xFFFF)


def put32(buf, offset, value):
    struct.pack_into("!I", buf, offset, value & 0xFFFFFFFF)


def ipv4_checksum(header):
    total = sum((header[i] << 8) | header[i + 1] for i in range(0, 20, 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def crc8(data):
    value = 0xFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = ((value >> 1) ^ 0xE0) if value & 1 else value >> 1
    return value


def feedback2_ack(cid, msn):
    body = bytearray()
    if cid:
        body.append(0xE0 | cid)
    body.extend(((msn >> 8) & 0x3F, msn & 0xFF, 0))
    body[-1] = crc8(body)
    return bytes((0xF0 | len(body),)) + bytes(body)


def packet_state(ordinal, epoch_rounds, flow_count, flow_hold_rounds):
    cid = ordinal & 15
    round_no = ordinal >> 4
    generation = round_no // flow_hold_rounds
    flow_id = (generation * 16 + cid) % flow_count
    profile = ((cid >> 2) + generation) & 3
    return cid, round_no, generation, profile, flow_id


def packet_msn(original, profile, round_no, flow_hold_rounds):
    if profile == 0:
        return struct.unpack_from("!H", original, 30)[0]
    if profile == 2:
        return struct.unpack_from("!I", original, 24)[0] & 0xFFFF
    return (round_no % flow_hold_rounds) + 1


def make_packet(ordinal, seed, size, epoch_rounds, flow_count, flow_hold_rounds,
                wrap_period):
    cid, round_no, generation, profile, flow_id = packet_state(
        ordinal, epoch_rounds, flow_count, flow_hold_rounds)
    progression = round_no % wrap_period if wrap_period else round_no
    key = struct.pack("!QQ", seed & 0xFFFFFFFFFFFFFFFF, ordinal)
    packet = bytearray(hashlib.shake_256(key).digest(size))
    packet[0] = 0x45
    packet[1] = (profile << 4) | (cid & 3)
    put16(packet, 2, size)
    put16(packet, 4, progression)
    packet[6] = 0x40
    packet[7] = 0
    packet[8] = 64 - (cid & 3)
    packet[9] = 50 if profile == 2 else (6 if profile == 3 else 17)
    packet[12:20] = bytes((10, 32 + ((flow_id >> 8) % 192), flow_id & 0xFF, 1,
                           198, 51, (flow_id >> 8) & 0xFF,
                           (flow_id & 0xFF) or 1))
    if profile in (0, 1):
        put16(packet, 20, 12000 + (flow_id % 20000))
        put16(packet, 22, 32000 + (flow_id % 20000))
        put16(packet, 24, size - 20)
        put16(packet, 26, 0)
    if profile == 0:
        packet[28] = 0x80
        packet[29] = 96 + (cid & 3)
        put16(packet, 30, 0xFFF0 + progression)
        put32(packet, 32, 0xFFFFFF00 + progression * 160)
        put32(packet, 36, 0x51000000 + flow_id)
    elif profile == 1:
        packet[28] = 0
    elif profile == 2:
        put32(packet, 20, 0xA0510000 + flow_id)
        put32(packet, 24, 0xFFFFFFF0 + progression)
    put32(packet, 48, ordinal)
    put32(packet, 52, flow_id)
    put32(packet, 56, generation)
    put16(packet, 10, 0)
    put16(packet, 10, ipv4_checksum(packet))
    return bytes(packet)


class Rohc:
    def __init__(self, library, compressor):
        self.lib = ctypes.CDLL(str(library))
        self.lib.rohc_comp_new2.argtypes = [ctypes.c_uint32, ctypes.c_int]
        self.lib.rohc_comp_new2.restype = ctypes.c_void_p
        self.lib.rohc_comp_set_cid.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib.rohc_comp_set_cid.restype = ctypes.c_int
        self.lib.rohc_feedback_parse_v1.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(FeedbackV1)]
        self.lib.rohc_feedback_parse_v1.restype = ctypes.c_int
        self.lib.rohc_comp_deliver_feedback_v1.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(FeedbackV1)]
        self.lib.rohc_comp_deliver_feedback_v1.restype = ctypes.c_int
        self.lib.rohc_compress4.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)]
        self.lib.rohc_compress4.restype = ctypes.c_int
        self.lib.rohc_comp_free.argtypes = [ctypes.c_void_p]
        self.lib.rohc_decomp_new2.argtypes = [ctypes.c_uint32, ctypes.c_int]
        self.lib.rohc_decomp_new2.restype = ctypes.c_void_p
        self.lib.rohc_decompress4.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)]
        self.lib.rohc_decompress4.restype = ctypes.c_int
        self.lib.rohc_decomp_free.argtypes = [ctypes.c_void_p]
        self.compressor = compressor
        self.ptr = (self.lib.rohc_comp_new2(15, 0) if compressor
                    else self.lib.rohc_decomp_new2(15, 0))
        if not self.ptr:
            raise RuntimeError("ROHCCXX allocation failed")

    def close(self):
        if self.ptr:
            (self.lib.rohc_comp_free if self.compressor else
             self.lib.rohc_decomp_free)(self.ptr)
            self.ptr = None

    def ack(self, cid, msn):
        raw_bytes = feedback2_ack(cid, msn)
        raw = (ctypes.c_uint8 * len(raw_bytes)).from_buffer_copy(raw_bytes)
        feedback = FeedbackV1()
        if self.lib.rohc_feedback_parse_v1(0, raw, len(raw_bytes),
                                           ctypes.byref(feedback)) != 0:
            raise RuntimeError("feedback parse failed")
        status = self.lib.rohc_comp_deliver_feedback_v1(
            self.ptr, ctypes.byref(feedback))
        if status not in (0, 1):
            raise RuntimeError(f"feedback correlation failed: {status}")

    def compress(self, cid, original):
        if self.lib.rohc_comp_set_cid(self.ptr, cid) != 0:
            raise RuntimeError("CID selection failed")
        src = (ctypes.c_uint8 * len(original)).from_buffer_copy(original)
        out = (ctypes.c_uint8 * MAX_ROHC)()
        out_len = ctypes.c_size_t(MAX_ROHC)
        if self.lib.rohc_compress4(self.ptr, src, len(original), out,
                                   ctypes.byref(out_len)) != 0:
            raise RuntimeError("compression failed")
        return bytes(out[:out_len.value])

    def decompress(self, compressed):
        src = (ctypes.c_uint8 * len(compressed)).from_buffer_copy(compressed)
        out = (ctypes.c_uint8 * MAX_ROHC)()
        for index in range(MAX_ROHC):
            out[index] = 0xA5
        out_len = ctypes.c_size_t(MAX_ROHC)
        rc = self.lib.rohc_decompress4(self.ptr, src, len(compressed), out,
                                       ctypes.byref(out_len))
        guard_ok = (rc == 0 or
                    (out_len.value == 0 and bytes(out[:64]) == b"\xA5" * 64))
        return rc, bytes(out[:out_len.value]) if rc == 0 else b"", guard_ok


def is_ir(wire, cid):
    pos = 1 if cid else 0
    return len(wire) > pos and (wire[pos] & 0xFE) == 0xFC


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()

    trace = [json.loads(line) for line in pathlib.Path(args.trace).read_text().splitlines()]
    compressor = Rohc(args.library, True)
    decompressor = Rohc(args.library, False)
    exact = rejects = silent_mutations = guard_failures = wire_hash_failures = 0
    witnesses = []
    try:
        wires = {}
        originals = {}
        metadata = {}
        for ordinal in range(8192):
            cid, round_no, generation, profile, flow_id = packet_state(ordinal, 8, 64, 8)
            original = make_packet(ordinal, 8302, 1280, 8, 64, 8, 256)
            wire = compressor.compress(cid, original)
            wires[ordinal] = wire
            originals[ordinal] = original
            metadata[ordinal] = (cid, round_no, generation, profile, flow_id)
        for row in trace:
            ordinal = row["ordinal"]
            cid, round_no, generation, profile, flow_id = metadata[ordinal]
            wire = wires[ordinal]
            if hashlib.sha384(wire).hexdigest() != row["compressed_sha384"]:
                wire_hash_failures += 1
                continue
            rc, output, guard_ok = decompressor.decompress(wire)
            if rc:
                rejects += 1
                if not guard_ok:
                    guard_failures += 1
            elif output == originals[ordinal]:
                exact += 1
                if is_ir(wire, cid):
                    compressor.ack(cid, packet_msn(originals[ordinal], profile, round_no, 8))
            else:
                silent_mutations += 1
                witnesses.append({
                    "arrival_index": row["arrival_index"],
                    "ordinal": ordinal,
                    "cid": cid,
                    "profile": profile,
                    "expected_sha384": hashlib.sha384(originals[ordinal]).hexdigest(),
                    "actual_sha384": hashlib.sha384(output).hexdigest(),
                    "compressed_sha384": hashlib.sha384(wire).hexdigest(),
                    "expected_length": len(originals[ordinal]),
                    "actual_length": len(output),
                })
    finally:
        compressor.close()
        decompressor.close()

    result = {
        "exact": exact,
        "rejects": rejects,
        "silent_mutations": silent_mutations,
        "guard_failures": guard_failures,
        "wire_hash_failures": wire_hash_failures,
        "witnesses": witnesses,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if wire_hash_failures or guard_failures or silent_mutations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
