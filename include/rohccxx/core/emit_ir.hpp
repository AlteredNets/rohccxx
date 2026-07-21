// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/rfc5225_chains.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{

inline bool emit_add_cid_if_needed(uint8_t*& p, const Context& ctx)
{
    if(!ctx.large_cid && !cid::is_small(ctx.cid))
        return false;
    if(!ctx.large_cid && ctx.cid > 0)
        *p++ = static_cast<uint8_t>(0xE0 | (ctx.cid & 0x0F));
    return true;
}

inline bool emit_ir_esp(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x03;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static_with_protocol(p, ctx, ctx.ipv4_protocol);
    rfc5225::write_ip_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_ip(uint8_t* out,
                       size_t* out_len,
                       const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x04;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static_with_protocol(p, ctx, ctx.ipv4_protocol);
    rfc5225::write_ip_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}


inline bool emit_ir_udp_lite(uint8_t* out,
                             size_t* out_len,
                             const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x08;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static_with_protocol(p, ctx, ctx.ipv4_protocol);
    rfc5225::write_udp_static(p, ctx);
    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_lite_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_udp(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x02;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static(p, ctx);
    rfc5225::write_udp_static(p, ctx);
    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_dynamic(p, ctx);

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}


inline bool emit_ir_rtp_udp_lite(uint8_t* out,
                                 size_t* out_len,
                                 const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x07;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static_with_protocol(p, ctx, ctx.ipv4_protocol);
    rfc5225::write_udp_static(p, ctx);
    rfc5225::write_rtp_static(p, ctx);
    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_lite_dynamic(p, ctx);
    if(!rfc5225::write_rtp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_rtp(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, ctx))
        return false;

    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    *p++ = 0x01;
    uint8_t* crc_pos = p++;

    rfc5225::write_ip_static(p, ctx);
    rfc5225::write_udp_static(p, ctx);
    rfc5225::write_rtp_static(p, ctx);
    rfc5225::write_ip_dynamic(p, ctx);
    rfc5225::write_udp_dynamic(p, ctx);
    if(!rfc5225::write_rtp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<uint8_t>((static_cast<uint8_t>(ctx.mode) & 0x03) << 2);
    *out_len = static_cast<size_t>(p - out);
    return true;
}

} // namespace rohccxx
