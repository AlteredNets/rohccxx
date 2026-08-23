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

inline bool emit_add_cid_if_needed(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(!ctx.large_cid && !cid::is_small(ctx.cid))
        return false;
    if(!ctx.large_cid && ctx.cid > 0)
    {
        if(p >= end)
            return false;
        *p++ = static_cast<uint8_t>(0xE0 | (ctx.cid & 0x0F));
    }
    return true;
}

inline bool emit_ir_prefix(uint8_t*& p,
                           const uint8_t* end,
                           const Context& ctx,
                           uint8_t profile,
                           uint8_t*& crc_pos)
{
    if(!emit_add_cid_if_needed(p, end, ctx) || p >= end)
        return false;
    *p++ = 0xFD;
    if(ctx.large_cid && !cid::write_large(p, end, ctx.cid))
        return false;
    if(static_cast<size_t>(end - p) < 2U)
        return false;
    *p++ = profile;
    crc_pos = p++;
    return true;
}

inline bool emit_ir_esp_into(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    uint8_t* crc_pos = nullptr;
    if(!emit_ir_prefix(p, end, ctx, 0x03, crc_pos))
        return false;

    if(!rfc5225::write_standard_ip_static(p, end, ctx) ||
       !rfc5225::write_standard_esp_static(p, end, ctx) ||
       !rfc5225::write_standard_ip_dynamic(p, end, ctx, false) ||
       !rfc5225::write_standard_esp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

inline bool emit_ir_ip_into(uint8_t* out,
                       size_t* out_len,
                       const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    uint8_t* crc_pos = nullptr;
    if(!emit_ir_prefix(p, end, ctx, 0x04, crc_pos))
        return false;

    if(!rfc5225::write_standard_ip_static(p, end, ctx) ||
       !rfc5225::write_standard_ip_dynamic(p, end, ctx, true))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}


inline bool emit_ir_udp_lite_into(uint8_t* out,
                             size_t* out_len,
                             const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, end, ctx))
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

inline bool emit_ir_udp_into(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    uint8_t* crc_pos = nullptr;
    if(!emit_ir_prefix(p, end, ctx, 0x02, crc_pos))
        return false;

    if(!rfc5225::write_standard_ip_static(p, end, ctx))
        return false;
    if(static_cast<size_t>(end - p) < 4U)
        return false;
    rfc5225::write_udp_static(p, ctx);
    if(!rfc5225::write_standard_ip_dynamic(p, end, ctx, false) ||
       !rfc5225::write_standard_udp_endpoint_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}


inline bool emit_ir_rtp_udp_lite_into(uint8_t* out,
                                 size_t* out_len,
                                 const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    if(!emit_add_cid_if_needed(p, end, ctx))
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

inline bool emit_ir_rtp_into(uint8_t* out,
                        size_t* out_len,
                        const Context& ctx)
{
    std::memset(out, 0, *out_len);

    uint8_t* p = out;
    const uint8_t* end = out + *out_len;
    uint8_t* crc_pos = nullptr;
    if(!emit_ir_prefix(p, end, ctx, 0x01, crc_pos))
        return false;

    if(!rfc5225::write_standard_ip_static(p, end, ctx))
        return false;
    if(static_cast<size_t>(end - p) < 8U)
        return false;
    rfc5225::write_udp_static(p, ctx);
    rfc5225::write_rtp_static(p, ctx);
    if(!rfc5225::write_standard_ip_dynamic(p, end, ctx, false))
        return false;
    rfc5225::write_udp_dynamic(p, ctx);
    if(!rfc5225::write_standard_rtp_dynamic(p, end, ctx))
        return false;

    *crc_pos = utils::crc8(out, static_cast<size_t>(p - out));
    *out_len = static_cast<size_t>(p - out);
    return true;
}

using IrEmitterInto = bool (*)(uint8_t*, size_t*, const Context&);

inline bool emit_ir_atomically(uint8_t* out,
                               size_t* out_len,
                               const Context& ctx,
                               IrEmitterInto emitter)
{
    if(out == nullptr || out_len == nullptr)
        return false;

    uint8_t scratch[2048] = {};
    size_t scratch_len = sizeof(scratch);
    if(!emitter(scratch, &scratch_len, ctx) || scratch_len > *out_len)
        return false;

    std::memcpy(out, scratch, scratch_len);
    *out_len = scratch_len;
    return true;
}

inline bool emit_ir_esp(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_esp_into);
}

inline bool emit_ir_ip(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_ip_into);
}

inline bool emit_ir_udp_lite(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_udp_lite_into);
}

inline bool emit_ir_udp(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_udp_into);
}

inline bool emit_ir_rtp_udp_lite(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_rtp_udp_lite_into);
}

inline bool emit_ir_rtp(uint8_t* out, size_t* out_len, const Context& ctx)
{
    return emit_ir_atomically(out, out_len, ctx, emit_ir_rtp_into);
}

} // namespace rohccxx
