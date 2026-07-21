// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{

inline bool emit_udp_fo(uint8_t* out,
                            size_t* out_len,
                            const Context& ctx)
{
    if(!out || !out_len || !cid::is_valid_for_space(ctx.cid, ctx.large_cid))
        return false;

    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U;
    const size_t header_len = 6U + cid_len;
    if(*out_len < header_len)
        return false;

    std::memset(out, 0, *out_len);
    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    *p++ = 0x7A;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    uint8_t* crc_pos = p++;
    *p++ = static_cast<uint8_t>(ctx.ipv4_id >> 8);
    *p++ = static_cast<uint8_t>(ctx.ipv4_id & 0xFF);
    *p++ = static_cast<uint8_t>(ctx.udp_check >> 8);
    *p++ = static_cast<uint8_t>(ctx.udp_check & 0xFF);
    *crc_pos = utils::crc8(out, header_len);
    *out_len = header_len;
    return true;
}

} // namespace rohccxx
