// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/utils/crc.hpp"

#include <cstdint>
#include <cstring>

namespace rohccxx
{

inline bool emit_uncompressed_ir(uint8_t* out,
                                 size_t* out_len,
                                 const Context& ctx,
                                 const uint8_t* in,
                                 size_t in_len) noexcept
{
    if (!out || !out_len || !in)
        return false;

    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid)
        : (ctx.cid > 0U ? 1U : 0U);
    const size_t header_len = cid_len + 3U;
    if((ctx.large_cid && ctx.cid > cid::large_cid_max) ||
       (!ctx.large_cid && !cid::is_small(ctx.cid)) ||
       *out_len < header_len || in_len > *out_len - header_len)
        return false;

    uint8_t* p = out;
    const uint8_t* const end = out + *out_len;
    if(!ctx.large_cid && ctx.cid > 0U)
        *p++ = static_cast<uint8_t>(0xe0U | ctx.cid);
    *p++ = 0xfdU;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x00U;
    uint8_t* const crc = p++;
    *crc = 0U;
    *crc = utils::crc8(out, static_cast<size_t>(p - out));
    std::memcpy(p, in, in_len);

    *out_len = header_len + in_len;
    return true;
}

} // namespace rohccxx
