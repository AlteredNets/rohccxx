// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{




inline bool emit_ir_dyn_esp(uint8_t* out,
                            size_t* out_len,
                            const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x03;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_dyn_ip(uint8_t* out,
                           size_t* out_len,
                           const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x04;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}


inline bool emit_ir_dyn_udp_lite(uint8_t* out,
                                 size_t* out_len,
                                 const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x08;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_lite_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_dyn_udp(uint8_t* out,
                            size_t* out_len,
                            const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x02;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_dyn_rtp_udp_lite(uint8_t* out,
                                     size_t* out_len,
                                     const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x07;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_lite_dynamic(p, ctx);
    if(!rfc5225::write_rtp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_dyn_rtp(uint8_t* out,
                            size_t* out_len,
                            const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xF8;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x01;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_dynamic(p, ctx);
    if(!rfc5225::write_rtp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

} // namespace rohccxx
