// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/rfc5225_chains.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{
namespace detail
{

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

inline bool read_large_cid_if_present(const uint8_t* in, size_t len, size_t& pos, const Context& ctx)
{
    if(!ctx.large_cid)
        return true;
    uint32_t wire_cid = 0;
    size_t consumed = 0;
    if(pos >= len || !cid::read_large(in + pos, len - pos, wire_cid, consumed))
        return false;
    if(wire_cid != ctx.cid)
        return false;
    pos += consumed;
    return true;
}


inline bool read_legacy_mode(const uint8_t* in, size_t len, size_t pos, Mode& mode)
{
    if(pos >= len || (in[pos] & 0xF3U) != 0)
        return false;
    const uint8_t value = in[pos];
    const uint8_t wire_mode = static_cast<uint8_t>((value >> 2) & 0x03U);
    if(wire_mode < static_cast<uint8_t>(Mode::Optimistic) ||
       wire_mode > static_cast<uint8_t>(Mode::Reliable))
        return false;
    mode = static_cast<Mode>(wire_mode);
    return true;
}

inline bool available(size_t len, size_t pos, size_t required)
{
    return pos <= len && required <= len - pos;
}



inline bool ipv4_options_extra_len(const uint8_t* in,
                                   size_t len,
                                   size_t marker_pos,
                                   size_t& extra_len)
{
    extra_len = 0;
    if(marker_pos >= len)
        return false;

    const uint8_t marker = in[marker_pos];
    if(encoding::is_empty_list(marker))
        return true;
    if((marker & 0xC0U) != rfc5225::ipv4_options_list_marker)
        return false;

    extra_len = static_cast<size_t>(marker & 0x3FU);
    return extra_len > 0 && extra_len <= 40U && len - marker_pos - 1U >= extra_len;
}

inline bool crc8_exact_matches(const uint8_t* in,
                               size_t len,
                               size_t crc_len,
                               size_t crc_index,
                               uint8_t received_crc)
{
    uint8_t crc_buf[1024];
    if(crc_len > sizeof(crc_buf) || len < crc_len || crc_index >= crc_len)
        return false;

    std::memcpy(crc_buf, in, crc_len);
    crc_buf[crc_index] = 0x00;
    return utils::crc8(crc_buf, crc_len) == received_crc;
}


inline bool read_ip_static_chain(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    if(pos >= len)
        return false;

    const uint8_t version = static_cast<uint8_t>(in[pos] >> 4);
    if(version == 4)
    {
        ctx.ip_version = 4;
        ++pos;
        if(pos >= len)
            return false;
        ctx.ipv4_protocol = in[pos++];
        if(len - pos < 8U)
            return false;
        ctx.ipv4_saddr = read_u32(in + pos);
        pos += 4;
        ctx.ipv4_daddr = read_u32(in + pos);
        pos += 4;
        return true;
    }

    if(version == 6)
    {
        ctx.ip_version = 6;
        ++pos;
        if(len - pos < 33U)
            return false;
        ctx.ipv6_next_header = in[pos++];
        std::memcpy(ctx.ipv6_saddr.data(), in + pos, ctx.ipv6_saddr.size());
        pos += ctx.ipv6_saddr.size();
        std::memcpy(ctx.ipv6_daddr.data(), in + pos, ctx.ipv6_daddr.size());
        pos += ctx.ipv6_daddr.size();
        ctx.ipv4_protocol = ctx.ipv6_next_header;
        return true;
    }

    return false;
}

inline bool read_ip_dynamic_chain(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    if(ctx.ip_version == 6)
    {
        if(len - pos < 7U)
            return false;
        ctx.ipv6_traffic_class = in[pos++];
        ctx.ipv6_flow_label = (static_cast<uint32_t>(in[pos++] & 0x0F) << 16);
        ctx.ipv6_flow_label |= static_cast<uint32_t>(in[pos++]) << 8;
        ctx.ipv6_flow_label |= static_cast<uint32_t>(in[pos++]);
        ctx.ipv6_hop_limit = in[pos++];
        ctx.ipv4_protocol = in[pos++];
        return rfc5225::read_ipv6_extensions_list(in, len, pos, ctx);
    }

    if(len - pos < 6U)
        return false;
    ctx.ipv4_tos = in[pos++];
    ctx.ipv4_ttl = in[pos++];
    ctx.ipv4_id = read_u16(in + pos);
    pos += 2;
    ctx.ipv4_flags = in[pos++];
    return rfc5225::read_ipv4_options_list(in, len, pos, ctx);
}

inline bool read_legacy_ip_dynamic_consistent(const uint8_t* in,
                                              size_t len,
                                              size_t& pos,
                                              Context& ctx)
{
    const uint8_t static_terminal = ctx.ip_version == 6U
        ? ctx.ipv6_next_header : ctx.ipv4_protocol;
    if(!read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    return ctx.ip_version != 6U || ctx.ipv4_protocol == static_terminal;
}

inline bool ip_dynamic_extra_len(const uint8_t* in,
                                 size_t len,
                                 size_t dynamic_pos,
                                 const Context& ctx,
                                 size_t& extra_len)
{
    if(ctx.ip_version == 6)
    {
        extra_len = 0;
        const size_t marker_pos = dynamic_pos + 6U;
        if(marker_pos >= len)
            return false;
        const uint8_t marker = in[marker_pos];
        if(encoding::is_empty_list(marker))
            return true;
        if((marker & 0x80U) != rfc5225::ipv6_extensions_list_marker)
            return false;
        extra_len = static_cast<size_t>(marker & 0x7FU);
        return extra_len > 0 && extra_len <= 127U && len - marker_pos - 1U >= extra_len;
    }

    return ipv4_options_extra_len(in, len, dynamic_pos + 5U, extra_len);
}

inline bool rtp_dynamic_extra_len(const uint8_t* in,
                                  size_t len,
                                  size_t marker_pos,
                                  size_t& extra_len)
{
    extra_len = 0;
    if(marker_pos >= len)
        return false;

    const uint8_t marker = in[marker_pos];
    if(encoding::is_empty_list(marker))
        return true;
    if(marker != rfc5225::rtp_extras_list_marker)
        return false;

    uint32_t body_len = 0;
    size_t consumed = 0;
    if(!encoding::read_sdvl_14(in + marker_pos + 1U, len - marker_pos - 1U, body_len, consumed))
        return false;
    if(body_len < 5U || body_len > cid::large_cid_max || len - marker_pos - 1U - consumed < body_len)
        return false;

    extra_len = consumed + body_len;
    return true;
}

} // namespace detail




inline bool decode_ir_esp_legacy(const uint8_t* in,
                          size_t len,
                          Context& ctx,
                          size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t crc_len_no_cid = 19;
    constexpr size_t header_len_no_cid = 20;

    if(len < header_len_no_cid)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x03)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 50)
        return false;

    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::ESP;
    ctx.rohc_state = RohcState::StaticEstablished;
    ctx.legacy_esp_payload_includes_header = true;
    return true;
}

inline bool decode_ir_ip_legacy(const uint8_t* in,
                         size_t len,
                         Context& ctx,
                         size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t crc_len_no_cid = 19;
    constexpr size_t header_len_no_cid = 20;

    if(len < header_len_no_cid)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x04)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;

    if(pos >= len)
        return false;
    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::IP;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}


inline bool decode_ir_udp_lite_legacy(const uint8_t* in,
                               size_t len,
                               Context& ctx,
                               size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t crc_len_no_cid = 27;
    constexpr size_t header_len_no_cid = 28;

    if(len < header_len_no_cid)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x08)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::available(len, pos, 4U))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 136)
        return false;

    if(!detail::available(len, pos, 4U))
        return false;
    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    if(pos >= len)
        return false;
    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::UDP_Lite;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}

inline bool decode_ir_udp_legacy(const uint8_t* in,
                          size_t len,
                          Context& ctx,
                          size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t crc_len_no_cid = 25;
    constexpr size_t header_len_no_cid = 26;

    if(len < header_len_no_cid)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x02)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::available(len, pos, 4U))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 17)
        return false;

    if(!detail::available(len, pos, 2U))
        return false;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    if(pos >= len)
        return false;
    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::UDP;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}


inline bool decode_ir_rtp_udp_lite_legacy(const uint8_t* in,
                                   size_t len,
                                   Context& ctx,
                                   size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t crc_len_no_cid = 40;
    constexpr size_t header_len_no_cid = 41;

    if(len < header_len_no_cid)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x07)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::available(len, pos, 8U))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    ctx.rtp.ssrc = detail::read_u32(in + pos);
    pos += 4;

    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 136)
        return false;

    if(!detail::available(len, pos, 12U))
        return false;
    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    ctx.rtp.vpxcc = in[pos++];
    ctx.rtp.mpt = in[pos++];
    ctx.rtp.last_seq = detail::read_u16(in + pos);
    pos += 2;
    ctx.rtp.last_ts = detail::read_u32(in + pos);
    pos += 4;
    if(!rfc5225::read_rtp_extras_list(in, len, pos, ctx))
        return false;
    if(pos >= len)
        return false;
    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;

    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.ipv4_id_sequential = false;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.profile = Profile::RTP_UDP_Lite;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

inline bool decode_ir_rtp_legacy(const uint8_t* in,
                          size_t len,
                          Context& ctx,
                          size_t* consumed = nullptr)
{
    size_t pos = 0;
    if(len < 4)
        return false;

    const bool has_cid = !ctx.large_cid && ctx.cid > 0;
    if(has_cid)
    {
        if(len < 5)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(!detail::available(len, pos, 1U) || (in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(!detail::available(len, pos, 2U) || in[pos++] != 0x01)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::available(len, pos, 8U))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    ctx.rtp.ssrc = detail::read_u32(in + pos);
    pos += 4;

    if(!detail::read_legacy_ip_dynamic_consistent(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 17)
        return false;

    if(!detail::available(len, pos, 12U))
        return false;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    const uint8_t rtp_first = in[pos++];
    const uint8_t rtp_second = in[pos++];
    ctx.rtp.vpxcc = static_cast<uint8_t>((rtp_first & 0xF0) | (rtp_first & 0x0F));
    ctx.rtp.mpt = rtp_second;

    ctx.rtp.last_seq = detail::read_u16(in + pos);
    pos += 2;
    ctx.rtp.last_ts = detail::read_u32(in + pos);
    pos += 4;
    if(!rfc5225::read_rtp_extras_list(in, len, pos, ctx))
        return false;
    if(pos >= len)
        return false;
    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;

    if(!detail::read_legacy_mode(in, len, pos, ctx.mode))
        return false;
    if(consumed)
        *consumed = pos + 1U;

    ctx.ipv4_id_sequential = false;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.profile = Profile::RTP;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

namespace detail
{

inline bool read_standard_ip_static(const uint8_t* in, size_t len, size_t& pos, Context& ctx)
{
    if(pos >= len)
        return false;
    const uint8_t first = in[pos++];
    const bool ipv6 = (first & 0x80U) != 0;
    if((first & 0x40U) == 0)
        return false; // only an innermost IP header is supported
    if(!ipv6)
    {
        if((first & 0x3FU) != 0 || len - pos < 9U)
            return false;
        ctx.ip_version = 4;
        ctx.ipv4_protocol = in[pos++];
        ctx.ipv4_saddr = read_u32(in + pos); pos += 4;
        ctx.ipv4_daddr = read_u32(in + pos); pos += 4;
        ctx.ipv4_options_len = 0;
        ctx.ipv4_options.fill(0);
        return true;
    }

    // Supported RFC fl_zero form: version=1, innermost=1, reserved=0,
    // discriminator=0, and the four flow-label reserved bits are zero.
    if(first != 0xC0U || len - pos < 33U)
        return false;
    ctx.ip_version = 6;
    ctx.ipv6_flow_label = 0;
    ctx.ipv6_next_header = in[pos++];
    ctx.ipv4_protocol = ctx.ipv6_next_header;
    std::memcpy(ctx.ipv6_saddr.data(), in + pos, ctx.ipv6_saddr.size());
    pos += ctx.ipv6_saddr.size();
    std::memcpy(ctx.ipv6_daddr.data(), in + pos, ctx.ipv6_daddr.size());
    pos += ctx.ipv6_daddr.size();
    ctx.ipv6_extension_len = 0;
    ctx.ipv6_extensions.fill(0);
    return true;
}

inline bool read_standard_ip_dynamic(const uint8_t* in,
                                     size_t len,
                                     size_t& pos,
                                     Context& ctx,
                                     bool endpoint)
{
    if(ctx.ip_version == 6)
    {
        const size_t required = endpoint ? 5U : 2U;
        if(len - pos < required)
            return false;
        ctx.ipv6_traffic_class = in[pos++];
        ctx.ipv6_hop_limit = in[pos++];
        if(endpoint)
        {
            const uint8_t control = in[pos++];
            if((control & 0xFCU) != 0)
                return false;
            ctx.reorder_ratio = static_cast<uint8_t>(control & 0x03U);
            ctx.msn = read_u16(in + pos); pos += 2;
        }
        return true;
    }

    if(len - pos < 3U)
        return false;
    const uint8_t control = in[pos++];
    if(endpoint)
    {
        if((control & 0xE0U) != 0)
            return false;
        ctx.reorder_ratio = static_cast<uint8_t>((control >> 3U) & 0x03U);
    }
    else if((control & 0xF8U) != 0)
    {
        return false;
    }
    ctx.ipv4_flags = static_cast<uint8_t>(((control >> 2U) & 0x01U) << 1U);
    ctx.ipv4_id_behavior = static_cast<uint8_t>(control & 0x03U);
    ctx.ipv4_id_sequential = ctx.ipv4_id_behavior <= 1U;
    ctx.ipv4_tos = in[pos++];
    ctx.ipv4_ttl = in[pos++];
    if(ctx.ipv4_id_behavior != 3U)
    {
        if(len - pos < 2U)
            return false;
        ctx.ipv4_id = read_u16(in + pos); pos += 2;
    }
    else
    {
        ctx.ipv4_id = 0;
    }
    if(endpoint)
    {
        if(len - pos < 2U)
            return false;
        ctx.msn = read_u16(in + pos); pos += 2;
    }
    return true;
}

inline bool read_standard_ir_prefix(const uint8_t* in,
                                    size_t len,
                                    size_t& pos,
                                    const Context& expected,
                                    uint8_t profile_id,
                                    size_t& crc_index,
                                    uint8_t& received_crc)
{
    pos = 0;
    if(!expected.large_cid && expected.cid > 0)
    {
        if(pos >= len || in[pos++] != static_cast<uint8_t>(0xE0U | expected.cid))
            return false;
    }
    if(pos >= len || in[pos++] != 0xFDU)
        return false;
    if(expected.large_cid)
    {
        uint32_t wire_cid = 0;
        size_t cid_len = 0;
        if(!cid::read_large(in + pos, len - pos, wire_cid, cid_len) || wire_cid != expected.cid)
            return false;
        pos += cid_len;
    }
    if(len - pos < 2U || in[pos++] != profile_id)
        return false;
    crc_index = pos;
    received_crc = in[pos++];
    return true;
}

inline bool standard_context_equal(const Context& a, const Context& b)
{
    return a.profile == b.profile && a.mode == b.mode &&
           a.rohc_state == b.rohc_state && a.cid == b.cid &&
           a.large_cid == b.large_cid && a.tx_count == b.tx_count &&
           a.nack_count == b.nack_count && a.static_acked == b.static_acked &&
           a.dynamic_acked == b.dynamic_acked &&
           a.msn == b.msn && a.reorder_ratio == b.reorder_ratio &&
           a.ip_version == b.ip_version && a.ipv4_tos == b.ipv4_tos &&
           a.ipv4_ttl == b.ipv4_ttl && a.ipv4_id == b.ipv4_id &&
           a.ipv4_flags == b.ipv4_flags && a.ipv4_protocol == b.ipv4_protocol &&
           a.ipv4_id_behavior == b.ipv4_id_behavior &&
           a.ipv4_id_sequential == b.ipv4_id_sequential &&
           a.ipv4_saddr == b.ipv4_saddr && a.ipv4_daddr == b.ipv4_daddr &&
           a.ipv4_options_len == b.ipv4_options_len &&
           a.ipv4_options == b.ipv4_options &&
           a.ipv6_traffic_class == b.ipv6_traffic_class &&
           a.ipv6_flow_label == b.ipv6_flow_label &&
           a.ipv6_next_header == b.ipv6_next_header &&
           a.ipv6_hop_limit == b.ipv6_hop_limit &&
           a.ipv6_saddr == b.ipv6_saddr && a.ipv6_daddr == b.ipv6_daddr &&
           a.ipv6_extension_len == b.ipv6_extension_len &&
           a.ipv6_extensions == b.ipv6_extensions &&
           a.udp_sport == b.udp_sport && a.udp_dport == b.udp_dport &&
           a.udp_length_or_coverage == b.udp_length_or_coverage &&
           a.udp_check == b.udp_check &&
           a.udp_checksum_used == b.udp_checksum_used &&
           a.esp_spi == b.esp_spi &&
           a.esp_sequence == b.esp_sequence &&
           a.legacy_esp_payload_includes_header == b.legacy_esp_payload_includes_header &&
           a.rtp.ssrc == b.rtp.ssrc &&
           a.rtp.vpxcc == b.rtp.vpxcc && a.rtp.mpt == b.rtp.mpt &&
           a.rtp.last_seq == b.rtp.last_seq && a.rtp.last_ts == b.rtp.last_ts &&
           a.rtp.initialized == b.rtp.initialized &&
           a.rtp.ts_stride == b.rtp.ts_stride &&
           a.rtp.ts_residue == b.rtp.ts_residue &&
           a.rtp.timer_elapsed_ticks == b.rtp.timer_elapsed_ticks &&
           a.rtp.timer_based_ts == b.rtp.timer_based_ts &&
           a.rtp.csrc_list_len == b.rtp.csrc_list_len &&
           a.rtp.csrc_list == b.rtp.csrc_list &&
           a.rtp.extension_len == b.rtp.extension_len &&
           a.rtp.extension_bytes == b.rtp.extension_bytes &&
           a.rtp.padding_len == b.rtp.padding_len &&
           a.rtp.padding_bytes == b.rtp.padding_bytes &&
           a.rtp.seq_window.ref == b.rtp.seq_window.ref &&
           a.rtp.ts_window.ref == b.rtp.ts_window.ref;
}

inline bool decode_ir_standard(const uint8_t* in,
                               size_t len,
                               Context& ctx,
                               Profile profile,
                               uint8_t profile_id,
                               size_t* consumed)
{
    const bool had_rtp_context = ctx.rtp.initialized != 0;
    const uint16_t previous_rtp_seq = ctx.rtp.last_seq;
    const uint32_t previous_rtp_ts = ctx.rtp.last_ts;
    const bool had_ipv4_context = ctx.ip_version == 4 && ctx.rohc_state != RohcState::NoContext;
    const uint16_t previous_ipv4_id = ctx.ipv4_id;
    size_t pos = 0;
    size_t crc_index = 0;
    uint8_t received_crc = 0;
    if(!read_standard_ir_prefix(in, len, pos, ctx, profile_id, crc_index, received_crc) ||
       !read_standard_ip_static(in, len, pos, ctx))
        return false;

    const uint8_t terminal_protocol = ctx.ip_version == 6 ? ctx.ipv6_next_header : ctx.ipv4_protocol;
    const uint8_t required_protocol = profile == Profile::ESP ? 50U
                                      : (profile == Profile::UDP || profile == Profile::RTP) ? 17U
                                      : terminal_protocol;
    if(terminal_protocol != required_protocol)
        return false;
    ctx.legacy_esp_payload_includes_header = false;

    if(profile == Profile::UDP || profile == Profile::RTP)
    {
        if(len - pos < 4U)
            return false;
        ctx.udp_sport = read_u16(in + pos); pos += 2;
        ctx.udp_dport = read_u16(in + pos); pos += 2;
        ctx.udp_checksum_used = false;
    }
    if(profile == Profile::ESP)
    {
        if(len - pos < 4U)
            return false;
        ctx.esp_spi = read_u32(in + pos); pos += 4;
    }
    if(profile == Profile::RTP)
    {
        if(len - pos < 4U)
            return false;
        ctx.rtp.ssrc = read_u32(in + pos); pos += 4;
    }

    if(!read_standard_ip_dynamic(in, len, pos, ctx, profile == Profile::IP))
        return false;

    if(profile == Profile::UDP)
    {
        if(len - pos < 5U)
            return false;
        ctx.udp_check = read_u16(in + pos); pos += 2;
        ctx.udp_checksum_used = ctx.udp_check != 0;
        ctx.msn = read_u16(in + pos); pos += 2;
        const uint8_t control = in[pos++];
        if((control & 0xFCU) != 0)
            return false;
        ctx.reorder_ratio = static_cast<uint8_t>(control & 0x03U);
    }
    else if(profile == Profile::ESP)
    {
        if(len - pos < 5U)
            return false;
        ctx.esp_sequence = read_u32(in + pos); pos += 4;
        const uint8_t control = in[pos++];
        if((control & 0xFCU) != 0)
            return false;
        ctx.reorder_ratio = static_cast<uint8_t>(control & 0x03U);
        ctx.msn = static_cast<uint16_t>(ctx.esp_sequence);
    }
    else if(profile == Profile::RTP)
    {
        if(len - pos < 10U)
            return false;
        ctx.udp_check = read_u16(in + pos); pos += 2;
        ctx.udp_checksum_used = ctx.udp_check != 0;
        const uint8_t indicators = in[pos++];
        if((indicators & 0x80U) != 0 || (indicators & 0x1CU) != 0)
            return false; // strides and CSRC lists are not yet supported here
        ctx.reorder_ratio = static_cast<uint8_t>((indicators >> 5U) & 0x03U);
        const uint8_t pad_extension = static_cast<uint8_t>(indicators & 0x03U);
        ctx.rtp.vpxcc = static_cast<uint8_t>(0x80U | ((pad_extension & 0x02U) << 4U) |
                                             ((pad_extension & 0x01U) << 4U));
        ctx.rtp.mpt = in[pos++];
        ctx.rtp.last_seq = read_u16(in + pos); pos += 2;
        ctx.rtp.last_ts = read_u32(in + pos); pos += 4;
        if(had_rtp_context)
        {
            uint32_t stride = 0;
            uint32_t residue = 0;
            if(encoding::infer_timestamp_stride(previous_rtp_seq,
                                                previous_rtp_ts,
                                                ctx.rtp.last_seq,
                                                ctx.rtp.last_ts,
                                                stride,
                                                residue))
            {
                ctx.rtp.ts_stride = stride;
                ctx.rtp.ts_residue = residue;
            }
        }
        if(ctx.ip_version == 4 && had_ipv4_context)
        {
            const uint16_t id_delta = static_cast<uint16_t>(ctx.ipv4_id - previous_ipv4_id);
            const uint16_t seq_delta = static_cast<uint16_t>(ctx.rtp.last_seq - previous_rtp_seq);
            ctx.ipv4_id_sequential = id_delta == seq_delta;
        }
        ctx.msn = ctx.rtp.last_seq;
        ctx.rtp.initialized = 1;
        ctx.rtp.seq_window.init(ctx.rtp.last_seq);
        ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    }

    if(!crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    ctx.profile = profile;
    ctx.rohc_state = profile == Profile::RTP ? RohcState::DynamicEstablished
                                             : RohcState::StaticEstablished;
    if(consumed)
        *consumed = pos;
    return true;
}

template<typename LegacyDecoder>
inline bool decode_ir_compatible(const uint8_t* in,
                                 size_t len,
                                 Context& ctx,
                                 Profile profile,
                                 uint8_t profile_id,
                                 LegacyDecoder legacy,
                                 size_t* consumed)
{
    Context standard_ctx = ctx;
    Context legacy_ctx = ctx;
    size_t standard_len = 0;
    size_t legacy_len = 0;
    const bool standard_ok = decode_ir_standard(in, len, standard_ctx, profile, profile_id, &standard_len);
    const bool legacy_ok = legacy(in, len, legacy_ctx, &legacy_len);
    if(standard_ok && legacy_ok &&
       (standard_len != legacy_len || !standard_context_equal(standard_ctx, legacy_ctx)))
        return false;
    if(!standard_ok && !legacy_ok)
        return false;
    ctx = standard_ok ? standard_ctx : legacy_ctx;
    if(consumed)
        *consumed = standard_ok ? standard_len : legacy_len;
    return true;
}

} // namespace detail

inline bool decode_ir_esp(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    return detail::decode_ir_compatible(in, len, ctx, Profile::ESP, 0x03,
                                        decode_ir_esp_legacy, consumed);
}

inline bool decode_ir_ip(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    return detail::decode_ir_compatible(in, len, ctx, Profile::IP, 0x04,
                                        decode_ir_ip_legacy, consumed);
}

inline bool decode_ir_udp(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    return detail::decode_ir_compatible(in, len, ctx, Profile::UDP, 0x02,
                                        decode_ir_udp_legacy, consumed);
}

inline bool decode_ir_rtp(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    return detail::decode_ir_compatible(in, len, ctx, Profile::RTP, 0x01,
                                        decode_ir_rtp_legacy, consumed);
}

inline bool decode_ir_udp_lite(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    Context parsed = ctx;
    size_t parsed_len = 0;
    if(!decode_ir_udp_lite_legacy(in, len, parsed, &parsed_len))
        return false;
    ctx = parsed;
    if(consumed)
        *consumed = parsed_len;
    return true;
}

inline bool decode_ir_rtp_udp_lite(const uint8_t* in, size_t len, Context& ctx, size_t* consumed = nullptr)
{
    Context parsed = ctx;
    size_t parsed_len = 0;
    if(!decode_ir_rtp_udp_lite_legacy(in, len, parsed, &parsed_len))
        return false;
    ctx = parsed;
    if(consumed)
        *consumed = parsed_len;
    return true;
}

} // namespace rohccxx
