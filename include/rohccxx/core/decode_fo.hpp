// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <iostream>
#include <stdio.h>
#include "rohccxx/core/bit_reader.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/encoding_methods.hpp"
#include "rohccxx/core/bit_crc.hpp"

namespace rohccxx
{

inline bool decode_fo_rtp(const uint8_t* in,
                          size_t len,
                          Context& ctx,
                          uint16_t& seq_out,
                          uint32_t& ts_out,
                          size_t* consumed = nullptr)
{
    using namespace rohccxx;

    if(!in || len == 0)
        return false;
    BitReader br(in, len);

    // FO bit must be 0
    if (br.read_bits(1) != 0 || !br.valid)
        return false;

    br.read_bits(1);             // extension

    const uint8_t embedded_cid = br.read_bits(4);
    if(!br.valid)
        return false;
    if(ctx.large_cid)
    {
        if(embedded_cid != 0)
            return false;
        std::uint32_t wire_cid = 0;
        size_t cid_len = 0;
        if(!cid::read_large(in + 1, len > 1 ? len - 1 : 0, wire_cid, cid_len))
            return false;
        if(wire_cid != ctx.cid)
            return false;
        if(cid_len > len - 1U)
            return false;
        br.bitpos = (1U + cid_len) * 8U;
    }
    else if(embedded_cid != ctx.cid)
    {
        return false;
    }

    uint8_t k = br.read_bits(6); // K
    if(!br.valid || k > 16U)
        return false;

    uint16_t seq_lsb = br.read_bits(k);
    uint32_t ts_lsb  = br.read_bits(8);
    if(!br.valid)
        return false;

    // Align to the CRC byte.
    size_t payload_bits  = br.bitpos;
    size_t payload_bytes = (payload_bits + 7) >> 3;
    if(payload_bytes > len)
        return false;
    br.bitpos = payload_bytes * 8;

    // Read the CRC-7 bits.
    (void) br.read_bits(7);
    if(!br.valid)
        return false;

    size_t total_bits = br.bitpos;
    size_t total_bytes = (total_bits + 7) >> 3;

    if(consumed)
        *consumed = total_bytes;

    if(total_bytes > len || !validate_crc7_bits(in, total_bits))
        return false;

    // Sliding-window reconstruction
    const std::uint16_t previous_seq = ctx.rtp.last_seq;
    uint16_t seq = static_cast<std::uint16_t>(
        encoding::decode_field_lsb(encoding::EncodedField::RtpSequence,
                                   seq_lsb,
                                   ctx.rtp.last_seq,
                                   k));
    uint32_t ts = 0;
    if(ctx.rtp.timer_based_ts)
    {
        const auto decoded = encoding::decode_timer_scaled_lsb(ts_lsb,
                                                               8,
                                                               ctx.rtp.last_ts,
                                                               ctx.rtp.ts_stride,
                                                               ctx.rtp.timer_elapsed_ticks,
                                                               ctx.rtp.ts_residue);
        if(!decoded.valid)
            return false;
        ts = decoded.timestamp;
    }
    else
    {
        const auto seq_delta = static_cast<std::uint16_t>(seq - previous_seq);
        const auto predicted_timestamp = static_cast<std::uint32_t>(
            ctx.rtp.last_ts + ctx.rtp.ts_stride * seq_delta);
        ts = encoding::decode_scaled_lsb_with_timestamp_prediction(
            ts_lsb,
            8,
            predicted_timestamp,
            ctx.rtp.last_ts,
            ctx.rtp.ts_stride,
            ctx.rtp.ts_residue);
    }

    ctx.rtp.seq_window.update(seq);
    ctx.rtp.ts_window.update(ts);
    if(ctx.ip_version == 4 && ctx.ipv4_id_sequential)
    {
        const auto seq_delta = static_cast<std::uint16_t>(seq - previous_seq);
        ctx.ipv4_id = static_cast<std::uint16_t>(ctx.ipv4_id + seq_delta);
    }
    ctx.rtp.last_seq = seq;
    ctx.rtp.last_ts  = ts;

    seq_out = seq;
    ts_out  = ts;

    return true;
}

} // namespace rohccxx
