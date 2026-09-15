#!/usr/bin/env python3
"""Replay preserved RC4 Issue #63 Lane-D witnesses through the public C API."""

import argparse
import hashlib
import json
import pathlib
import sys

from issue32_rc3_replay import Rohc, is_ir, make_packet, packet_msn, packet_state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    parser.add_argument("--mismatches", required=True)
    parser.add_argument("--start-ordinal", type=int, default=40000000)
    parser.add_argument("--seed", type=int, default=920417004)
    parser.add_argument("--packet-size", type=int, default=1280)
    parser.add_argument("--epoch-rounds", type=int, default=256)
    parser.add_argument("--flow-count", type=int, default=1024)
    parser.add_argument("--flow-hold-rounds", type=int, default=8)
    parser.add_argument("--wrap-period", type=int, default=128)
    args = parser.parse_args()

    witnesses = [
        json.loads(line)
        for line in pathlib.Path(args.mismatches).read_text().splitlines()
        if line.strip()
    ]
    if not witnesses:
        raise RuntimeError("no Issue #63 witnesses found")

    replay_ordinals = witnesses[-1]["arrival_history"]
    max_ordinal = max(replay_ordinals)
    expected_by_ordinal = {row["ordinal"]: row for row in witnesses}

    compressor = Rohc(args.library, True)
    decompressor = Rohc(args.library, False)
    exact = rejects = silent_mutations = guard_failures = wire_hash_failures = 0
    reproduced = {}
    observed = []
    try:
        wires = {}
        originals = {}
        metadata = {}
        for ordinal in range(args.start_ordinal, max_ordinal + 1):
            cid, round_no, generation, profile, flow_id = packet_state(
                ordinal, args.epoch_rounds, args.flow_count,
                args.flow_hold_rounds)
            original = make_packet(
                ordinal, args.seed, args.packet_size, args.epoch_rounds,
                args.flow_count, args.flow_hold_rounds, args.wrap_period)
            wire = compressor.compress(cid, original)
            wires[ordinal] = wire
            originals[ordinal] = original
            metadata[ordinal] = (cid, round_no, generation, profile, flow_id)

        for arrival_index, ordinal in enumerate(replay_ordinals):
            cid, round_no, generation, profile, flow_id = metadata[ordinal]
            wire = wires[ordinal]
            expected = expected_by_ordinal.get(ordinal)
            if expected and hashlib.sha384(wire).hexdigest() != expected["compressed_sha384"]:
                wire_hash_failures += 1
                observed.append({
                    "arrival_index": arrival_index,
                    "ordinal": ordinal,
                    "expected_compressed_sha384": expected["compressed_sha384"],
                    "actual_compressed_sha384": hashlib.sha384(wire).hexdigest(),
                })
                continue
            rc, output, guard_ok = decompressor.decompress(wire)
            if rc:
                rejects += 1
                if not guard_ok:
                    guard_failures += 1
            elif output == originals[ordinal]:
                exact += 1
                if is_ir(wire, cid):
                    compressor.ack(
                        cid,
                        packet_msn(originals[ordinal], profile, round_no,
                                   args.flow_hold_rounds))
            else:
                silent_mutations += 1
                record = {
                    "arrival_index": arrival_index,
                    "ordinal": ordinal,
                    "cid": cid,
                    "round": round_no,
                    "generation": generation,
                    "profile": profile,
                    "flow_id": flow_id,
                    "expected_sha384": hashlib.sha384(originals[ordinal]).hexdigest(),
                    "actual_sha384": hashlib.sha384(output).hexdigest(),
                    "compressed_sha384": hashlib.sha384(wire).hexdigest(),
                    "expected_length": len(originals[ordinal]),
                    "actual_length": len(output),
                }
                observed.append(record)
                if ordinal in expected_by_ordinal:
                    reproduced[ordinal] = record
    finally:
        compressor.close()
        decompressor.close()

    result = {
        "exact": exact,
        "rejects": rejects,
        "silent_mutations": silent_mutations,
        "guard_failures": guard_failures,
        "wire_hash_failures": wire_hash_failures,
        "witness_ordinals": [row["ordinal"] for row in witnesses],
        "reproduced_ordinals": sorted(reproduced),
        "observed": observed,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if wire_hash_failures or guard_failures:
        return 2
    if silent_mutations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
