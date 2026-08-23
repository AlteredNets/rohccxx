// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/encoding_methods.hpp"

namespace rohccxx::rfc5225
{

inline constexpr uint8_t ipv4_static_chain_terminal = 0x40;
inline constexpr uint8_t generic_extension_list_empty = encoding::empty_list_marker();
inline constexpr uint8_t ipv4_options_list_marker = 0x40;
inline constexpr uint8_t ipv6_static_chain_terminal = 0x60;
inline constexpr uint8_t ipv6_extensions_list_marker = 0x80;
inline constexpr uint8_t rtp_extras_list_marker = 0x80;
inline constexpr uint8_t rtp_extra_csrc_present = 0x01;
inline constexpr uint8_t rtp_extra_extension_present = 0x02;
inline constexpr uint8_t rtp_extra_padding_present = 0x04;
inline constexpr uint8_t udp_protocol = 17;

inline void write_u16(uint8_t*& p, uint16_t value)
{
    *p++ = static_cast<uint8_t>(value >> 8);
    *p++ = static_cast<uint8_t>(value & 0xFF);
}

inline void write_u32(uint8_t*& p, uint32_t value)
{
    *p++ = static_cast<uint8_t>(value >> 24);
    *p++ = static_cast<uint8_t>(value >> 16);
    *p++ = static_cast<uint8_t>(value >> 8);
    *p++ = static_cast<uint8_t>(value & 0xFF);
}

inline uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
}

inline uint32_t read_u32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline void write_ipv4_static_with_protocol(uint8_t*& p, const Context& ctx, uint8_t protocol)
{
    *p++ = ipv4_static_chain_terminal;
    *p++ = protocol;
    write_u32(p, ctx.ipv4_saddr);
    write_u32(p, ctx.ipv4_daddr);
}

inline void write_ipv4_static(uint8_t*& p, const Context& ctx)
{
    write_ipv4_static_with_protocol(p, ctx, udp_protocol);
}

inline void write_ipv6_static(uint8_t*& p, const Context& ctx)
{
    *p++ = ipv6_static_chain_terminal;
    *p++ = ctx.ipv6_next_header;
    std::memcpy(p, ctx.ipv6_saddr.data(), ctx.ipv6_saddr.size());
    p += ctx.ipv6_saddr.size();
    std::memcpy(p, ctx.ipv6_daddr.data(), ctx.ipv6_daddr.size());
    p += ctx.ipv6_daddr.size();
}

inline void write_ip_static_with_protocol(uint8_t*& p, const Context& ctx, uint8_t protocol)
{
    if(ctx.ip_version == 6)
        write_ipv6_static(p, ctx);
    else
        write_ipv4_static_with_protocol(p, ctx, protocol);
}

inline void write_ip_static(uint8_t*& p, const Context& ctx)
{
    if(ctx.ip_version == 6)
        write_ipv6_static(p, ctx);
    else
        write_ipv4_static(p, ctx);
}

inline void write_udp_static(uint8_t*& p, const Context& ctx)
{
    write_u16(p, ctx.udp_sport);
    write_u16(p, ctx.udp_dport);
}

inline void write_rtp_static(uint8_t*& p, const Context& ctx)
{
    write_u32(p, ctx.rtp.ssrc);
}

// RFC 5225 section 6.7 formal static and dynamic chains.  The older helpers
// below are retained only for the decode-only legacy wire format.
inline bool write_standard_ip_static(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(ctx.ip_version == 4)
    {
        if(ctx.ipv4_options_len != 0 || static_cast<size_t>(end - p) < 10U)
            return false;
        write_ipv4_static_with_protocol(p, ctx, ctx.ipv4_protocol);
        return true;
    }
    if(ctx.ip_version != 6 || ctx.ipv6_extension_len != 0 ||
       ctx.ipv6_flow_label != 0 || static_cast<size_t>(end - p) < 34U)
    {
        return false;
    }

    // version_flag=1, innermost_ip=1, reserved=0, fl_zero=0, reserved=0000
    *p++ = 0xC0;
    *p++ = ctx.ipv6_next_header;
    std::memcpy(p, ctx.ipv6_saddr.data(), ctx.ipv6_saddr.size());
    p += ctx.ipv6_saddr.size();
    std::memcpy(p, ctx.ipv6_daddr.data(), ctx.ipv6_daddr.size());
    p += ctx.ipv6_daddr.size();
    return true;
}

inline bool write_standard_ip_dynamic(uint8_t*& p,
                                      const uint8_t* end,
                                      const Context& ctx,
                                      bool endpoint)
{
    if(ctx.ip_version == 6)
    {
        const size_t required = endpoint ? 5U : 2U;
        if(ctx.ipv6_extension_len != 0 || static_cast<size_t>(end - p) < required)
            return false;
        *p++ = ctx.ipv6_traffic_class;
        *p++ = ctx.ipv6_hop_limit;
        if(endpoint)
        {
            *p++ = static_cast<uint8_t>(ctx.reorder_ratio & 0x03U);
            write_u16(p, ctx.msn);
        }
        return true;
    }
    if(ctx.ip_version != 4 || ctx.ipv4_options_len != 0)
        return false;

    const uint8_t behavior = static_cast<uint8_t>(ctx.ipv4_id_behavior & 0x03U);
    const bool id_present = behavior != 3U;
    const size_t required = 3U + (id_present ? 2U : 0U) + (endpoint ? 2U : 0U);
    if(static_cast<size_t>(end - p) < required)
        return false;
    const uint8_t df = static_cast<uint8_t>((ctx.ipv4_flags >> 1U) & 0x01U);
    if(endpoint)
        *p++ = static_cast<uint8_t>(((ctx.reorder_ratio & 0x03U) << 3U) | (df << 2U) | behavior);
    else
        *p++ = static_cast<uint8_t>((df << 2U) | behavior);
    *p++ = ctx.ipv4_tos;
    *p++ = ctx.ipv4_ttl;
    if(id_present)
        write_u16(p, ctx.ipv4_id);
    if(endpoint)
        write_u16(p, ctx.msn);
    return true;
}

inline bool write_standard_udp_endpoint_dynamic(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(static_cast<size_t>(end - p) < 5U)
        return false;
    write_u16(p, ctx.udp_check);
    write_u16(p, ctx.msn);
    *p++ = static_cast<uint8_t>(ctx.reorder_ratio & 0x03U);
    return true;
}

inline bool write_standard_esp_static(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(static_cast<size_t>(end - p) < 4U)
        return false;
    write_u32(p, ctx.esp_spi);
    return true;
}

inline bool write_standard_esp_dynamic(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(static_cast<size_t>(end - p) < 5U)
        return false;
    write_u32(p, ctx.esp_sequence);
    *p++ = static_cast<uint8_t>(ctx.reorder_ratio & 0x03U);
    return true;
}

inline bool write_standard_rtp_dynamic(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    const uint8_t cc = static_cast<uint8_t>(ctx.rtp.vpxcc & 0x0FU);
    const bool padding = (ctx.rtp.vpxcc & 0x20U) != 0;
    const bool extension = (ctx.rtp.vpxcc & 0x10U) != 0;
    if(cc != 0 || padding || extension || ctx.rtp.csrc_list_len != 0 ||
       ctx.rtp.extension_len != 0 || ctx.rtp.padding_len != 0 ||
       static_cast<size_t>(end - p) < 8U)
    {
        return false;
    }
    *p++ = static_cast<uint8_t>((ctx.reorder_ratio & 0x03U) << 5U);
    *p++ = ctx.rtp.mpt;
    write_u16(p, ctx.rtp.last_seq);
    write_u32(p, ctx.rtp.last_ts);
    return true;
}

inline bool write_ipv4_options_list(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(ctx.ipv4_options_len == 0)
        return encoding::write_empty_list(p, end);
    if(ctx.ipv4_options_len > ctx.ipv4_options.size() ||
       static_cast<size_t>(end - p) < 1U + ctx.ipv4_options_len)
    {
        return false;
    }

    *p++ = static_cast<uint8_t>(ipv4_options_list_marker | ctx.ipv4_options_len);
    std::memcpy(p, ctx.ipv4_options.data(), ctx.ipv4_options_len);
    p += ctx.ipv4_options_len;
    return true;
}

inline void write_ipv4_dynamic(uint8_t*& p, const Context& ctx)
{
    *p++ = ctx.ipv4_tos;
    *p++ = ctx.ipv4_ttl;
    write_u16(p, ctx.ipv4_id);
    *p++ = ctx.ipv4_flags;
    const uint8_t* end = p + 1U + ctx.ipv4_options_len;
    write_ipv4_options_list(p, end, ctx);
}

inline bool write_ipv6_extensions_list(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(ctx.ipv6_extension_len == 0)
        return encoding::write_empty_list(p, end);
    if(ctx.ipv6_extension_len > 127U || ctx.ipv6_extension_len > ctx.ipv6_extensions.size() ||
       static_cast<size_t>(end - p) < 1U + ctx.ipv6_extension_len)
    {
        return false;
    }

    *p++ = static_cast<uint8_t>(ipv6_extensions_list_marker | ctx.ipv6_extension_len);
    std::memcpy(p, ctx.ipv6_extensions.data(), ctx.ipv6_extension_len);
    p += ctx.ipv6_extension_len;
    return true;
}

inline void write_ipv6_dynamic(uint8_t*& p, const Context& ctx)
{
    *p++ = ctx.ipv6_traffic_class;
    *p++ = static_cast<uint8_t>((ctx.ipv6_flow_label >> 16) & 0x0F);
    *p++ = static_cast<uint8_t>((ctx.ipv6_flow_label >> 8) & 0xFF);
    *p++ = static_cast<uint8_t>(ctx.ipv6_flow_label & 0xFF);
    *p++ = ctx.ipv6_hop_limit;
    *p++ = ctx.ipv4_protocol;
    const uint8_t* end = p + 1U + ctx.ipv6_extension_len;
    write_ipv6_extensions_list(p, end, ctx);
}

inline void write_ip_dynamic(uint8_t*& p, const Context& ctx)
{
    if(ctx.ip_version == 6)
        write_ipv6_dynamic(p, ctx);
    else
        write_ipv4_dynamic(p, ctx);
}

inline bool read_ipv4_options_list(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    if(pos >= len)
        return false;

    const uint8_t marker = in[pos++];
    ctx.ipv4_options_len = 0;
    ctx.ipv4_options.fill(0);
    if(encoding::is_empty_list(marker))
        return true;
    if((marker & 0xC0U) != ipv4_options_list_marker)
        return false;

    const uint8_t options_len = static_cast<uint8_t>(marker & 0x3FU);
    if(options_len == 0 || options_len > ctx.ipv4_options.size() || len - pos < options_len)
        return false;

    ctx.ipv4_options_len = options_len;
    std::memcpy(ctx.ipv4_options.data(), in + pos, options_len);
    pos += options_len;
    return true;
}

inline bool read_ipv6_extensions_list(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    if(pos >= len)
        return false;

    const uint8_t marker = in[pos++];
    ctx.ipv6_extension_len = 0;
    ctx.ipv6_extensions.fill(0);
    if(encoding::is_empty_list(marker))
        return true;
    if((marker & 0x80U) != ipv6_extensions_list_marker)
        return false;

    const uint8_t ext_len = static_cast<uint8_t>(marker & 0x7FU);
    if(ext_len == 0 || ext_len > ctx.ipv6_extensions.size() || len - pos < ext_len)
        return false;

    ctx.ipv6_extension_len = ext_len;
    std::memcpy(ctx.ipv6_extensions.data(), in + pos, ext_len);
    pos += ext_len;
    return true;
}

inline bool read_ip_extension_list(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    return ctx.ip_version == 6
        ? read_ipv6_extensions_list(in, len, pos, ctx)
        : read_ipv4_options_list(in, len, pos, ctx);
}

inline bool read_empty_extension_list(const uint8_t* in, size_t len, size_t& pos)
{
    return encoding::read_empty_list(in, len, pos);
}

inline void write_udp_dynamic(uint8_t*& p, const Context& ctx)
{
    write_u16(p, ctx.udp_check);
}

inline void write_udp_lite_dynamic(uint8_t*& p, const Context& ctx)
{
    write_u16(p, ctx.udp_length_or_coverage);
    write_u16(p, ctx.udp_check);
}

inline bool rtp_extension_bytes_valid(const Context& ctx)
{
    if(ctx.rtp.extension_len == 0)
        return true;
    if(ctx.rtp.extension_len < 4U || ctx.rtp.extension_len > ctx.rtp.extension_bytes.size() ||
       (ctx.rtp.extension_len % 4U) != 0U)
    {
        return false;
    }

    const uint16_t extension_words = read_u16(ctx.rtp.extension_bytes.data() + 2U);
    const size_t expected_len = 4U + static_cast<size_t>(extension_words) * 4U;
    return expected_len == ctx.rtp.extension_len;
}

inline bool rtp_extras_body_len(const Context& ctx, uint32_t& body_len)
{
    body_len = 0;
    const uint8_t csrc_count = static_cast<uint8_t>(ctx.rtp.vpxcc & 0x0FU);
    const size_t csrc_len = static_cast<size_t>(csrc_count) * 4U;
    const bool extension_present = (ctx.rtp.vpxcc & 0x10U) != 0;
    const bool padding_present = (ctx.rtp.vpxcc & 0x20U) != 0;

    if(ctx.rtp.csrc_list_len != csrc_len || csrc_len > ctx.rtp.csrc_list.size())
        return false;
    if(extension_present)
    {
        if(ctx.rtp.extension_len == 0 || !rtp_extension_bytes_valid(ctx))
            return false;
    }
    else if(ctx.rtp.extension_len != 0)
    {
        return false;
    }

    if(padding_present)
    {
        if(ctx.rtp.padding_len == 0 || ctx.rtp.padding_len > ctx.rtp.padding_bytes.size() ||
           ctx.rtp.padding_bytes[ctx.rtp.padding_len - 1U] != ctx.rtp.padding_len)
        {
            return false;
        }
    }
    else if(ctx.rtp.padding_len != 0)
    {
        return false;
    }

    if(csrc_len == 0 && ctx.rtp.extension_len == 0 && ctx.rtp.padding_len == 0)
        return true;

    body_len = static_cast<uint32_t>(5U + csrc_len + ctx.rtp.extension_len + ctx.rtp.padding_len);
    return body_len <= cid::large_cid_max;
}

inline bool write_rtp_extras_list(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    uint32_t body_len = 0;
    if(!rtp_extras_body_len(ctx, body_len))
        return false;
    if(body_len == 0)
        return encoding::write_empty_list(p, end);
    if(p >= end)
        return false;

    const uint8_t csrc_count = static_cast<uint8_t>(ctx.rtp.vpxcc & 0x0FU);
    uint8_t flags = 0;
    if(ctx.rtp.csrc_list_len > 0)
        flags |= rtp_extra_csrc_present;
    if(ctx.rtp.extension_len > 0)
        flags |= rtp_extra_extension_present;
    if(ctx.rtp.padding_len > 0)
        flags |= rtp_extra_padding_present;

    *p++ = rtp_extras_list_marker;
    if(!encoding::write_sdvl_14(p, end, body_len) || static_cast<size_t>(end - p) < body_len)
        return false;

    *p++ = flags;
    *p++ = csrc_count;
    write_u16(p, ctx.rtp.extension_len);
    *p++ = ctx.rtp.padding_len;
    if(ctx.rtp.csrc_list_len > 0)
    {
        std::memcpy(p, ctx.rtp.csrc_list.data(), ctx.rtp.csrc_list_len);
        p += ctx.rtp.csrc_list_len;
    }
    if(ctx.rtp.extension_len > 0)
    {
        std::memcpy(p, ctx.rtp.extension_bytes.data(), ctx.rtp.extension_len);
        p += ctx.rtp.extension_len;
    }
    if(ctx.rtp.padding_len > 0)
    {
        std::memcpy(p, ctx.rtp.padding_bytes.data(), ctx.rtp.padding_len);
        p += ctx.rtp.padding_len;
    }
    return true;
}

inline bool read_rtp_extras_list(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    ctx.rtp.csrc_list_len = 0;
    ctx.rtp.csrc_list.fill(0);
    ctx.rtp.extension_len = 0;
    ctx.rtp.extension_bytes.fill(0);
    ctx.rtp.padding_len = 0;
    ctx.rtp.padding_bytes.fill(0);

    if(pos >= len)
        return false;

    const uint8_t marker = in[pos++];
    if(encoding::is_empty_list(marker))
    {
        ctx.rtp.vpxcc = static_cast<uint8_t>(ctx.rtp.vpxcc & 0xC0U);
        return true;
    }
    if(marker != rtp_extras_list_marker)
        return false;

    uint32_t body_len = 0;
    size_t consumed = 0;
    if(!encoding::read_sdvl_14(in + pos, len - pos, body_len, consumed) ||
       body_len < 5U || len - pos - consumed < body_len)
    {
        return false;
    }
    pos += consumed;
    const size_t body_end = pos + body_len;

    const uint8_t flags = in[pos++];
    if((flags & static_cast<uint8_t>(~0x07U)) != 0)
        return false;
    const uint8_t csrc_count = in[pos++];
    const uint16_t extension_len = read_u16(in + pos);
    pos += 2;
    const uint8_t padding_len = in[pos++];

    const size_t csrc_len = static_cast<size_t>(csrc_count) * 4U;
    if(csrc_count != (ctx.rtp.vpxcc & 0x0FU) || csrc_len > ctx.rtp.csrc_list.size())
        return false;
    if(((flags & rtp_extra_csrc_present) != 0) != (csrc_len > 0))
        return false;
    if(((flags & rtp_extra_extension_present) != 0) != ((ctx.rtp.vpxcc & 0x10U) != 0))
        return false;
    if(((flags & rtp_extra_padding_present) != 0) != ((ctx.rtp.vpxcc & 0x20U) != 0))
        return false;
    if(((flags & rtp_extra_extension_present) == 0) != (extension_len == 0))
        return false;
    if(((flags & rtp_extra_padding_present) == 0) != (padding_len == 0))
        return false;
    if(extension_len > ctx.rtp.extension_bytes.size() || padding_len > ctx.rtp.padding_bytes.size())
        return false;
    if(body_end - pos != csrc_len + extension_len + padding_len)
        return false;

    ctx.rtp.csrc_list_len = static_cast<uint8_t>(csrc_len);
    if(csrc_len > 0)
    {
        std::memcpy(ctx.rtp.csrc_list.data(), in + pos, csrc_len);
        pos += csrc_len;
    }
    ctx.rtp.extension_len = extension_len;
    if(extension_len > 0)
    {
        std::memcpy(ctx.rtp.extension_bytes.data(), in + pos, extension_len);
        pos += extension_len;
    }
    ctx.rtp.padding_len = padding_len;
    if(padding_len > 0)
    {
        std::memcpy(ctx.rtp.padding_bytes.data(), in + pos, padding_len);
        pos += padding_len;
    }

    uint32_t validated_body_len = 0;
    if(pos != body_end || !rtp_extras_body_len(ctx, validated_body_len) || validated_body_len != body_len)
        return false;
    return true;
}

inline bool write_rtp_dynamic(uint8_t*& p, const uint8_t* end, const Context& ctx)
{
    if(static_cast<size_t>(end - p) < 8U)
        return false;

    const uint8_t version = static_cast<uint8_t>((ctx.rtp.vpxcc >> 6) & 0x03);
    const uint8_t padding = static_cast<uint8_t>((ctx.rtp.vpxcc >> 5) & 0x01);
    const uint8_t extension = static_cast<uint8_t>((ctx.rtp.vpxcc >> 4) & 0x01);
    const uint8_t csrc_count = static_cast<uint8_t>(ctx.rtp.vpxcc & 0x0F);
    const uint8_t marker = static_cast<uint8_t>((ctx.rtp.mpt >> 7) & 0x01);
    const uint8_t payload_type = static_cast<uint8_t>(ctx.rtp.mpt & 0x7F);

    *p++ = static_cast<uint8_t>((version << 6) | (padding << 5) | (extension << 4) | csrc_count);
    *p++ = static_cast<uint8_t>((marker << 7) | payload_type);
    write_u16(p, ctx.rtp.last_seq);
    write_u32(p, ctx.rtp.last_ts);
    return write_rtp_extras_list(p, end, ctx);
}

inline bool write_rtp_dynamic(uint8_t*& p, const Context& ctx)
{
    const uint8_t* end = p + 8U + 1U + ctx.rtp.csrc_list_len + ctx.rtp.extension_len + ctx.rtp.padding_len + 2U + 5U;
    return write_rtp_dynamic(p, end, ctx);
}

} // namespace rohccxx::rfc5225
