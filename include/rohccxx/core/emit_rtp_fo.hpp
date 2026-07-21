// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstring>
#include <cstdint>
#include "rohccxx/core/bit_writer.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/encoding_methods.hpp"
#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{

inline bool emit_rtp_fo(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    constexpr uint8_t K_SEQ = 6;
    constexpr uint8_t K_TS  = 8;

    if(!out || !out_len || !cid::is_valid_for_space(ctx.cid, ctx.large_cid))
        return false;

    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U;
    const size_t required_len = 5U + cid_len;
    const size_t capacity = *out_len;
    if(capacity != 0 && capacity < required_len)
        return false;

    if(capacity != 0)
        std::memset(out, 0, capacity);
    BitWriter bw(out);

    // FO header. In large-CID mode, the first octet carries type/body bits,
    // then the SDVL CID starts at octet 1 per the ROHC framework layout.
    bw.write_bits(0, 1);                // FO indicator
    bw.write_bits(0, 1);                // no extension
    bw.write_bits(ctx.large_cid ? 0 : (ctx.cid & 0xF), 4);

    if(ctx.large_cid)
    {
        bw.bitpos = 8;
        uint8_t* cid_pos = out + 1;
        if(!cid::write_large(cid_pos, out + (capacity == 0 ? required_len : capacity), ctx.cid))
            return false;
        bw.bitpos = (1U + cid_len) * 8U;
    }

    bw.write_bits(K_SEQ, 6);

    bw.write_bits(encoding::encode_field_lsb(encoding::EncodedField::RtpSequence,
                                             ctx.rtp.last_seq,
                                             K_SEQ),
                  K_SEQ);
    const auto scaled_ts = encoding::scale_timestamp(ctx.rtp.last_ts, ctx.rtp.ts_stride);
    bw.write_bits(encoding::encode_field_lsb(encoding::EncodedField::RtpTimestamp,
                                             scaled_ts.scaled,
                                             K_TS),
                  K_TS);

    // ✅ FORCE BYTE ALIGNMENT
    size_t payload_bits  = bw.bitpos;
    size_t payload_bytes = (payload_bits + 7) >> 3;

    // CRC‑7 over aligned payload bytes
    uint8_t crc = utils::crc7(out, payload_bytes);

    // Append CRC‑7 bits
    bw.bitpos = payload_bytes * 8;
    bw.write_bits(crc, 7);

    *out_len = (bw.bitpos + 7) >> 3;
    return true;
};

} // namespace rohccxx