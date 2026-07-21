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


inline Mode mode_from_wire(uint8_t value)
{
    const uint8_t mode = static_cast<uint8_t>((value >> 2) & 0x03U);
    return mode <= static_cast<uint8_t>(Mode::Reliable)
        ? static_cast<Mode>(mode)
        : Mode::Optimistic;
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

inline bool find_crc8_len(const uint8_t* in,
                          size_t len,
                          size_t min_crc_len,
                          size_t max_extra_len,
                          size_t crc_index,
                          uint8_t received_crc,
                          size_t& crc_len)
{
    uint8_t crc_buf[1024];
    for(size_t extra = 0; extra <= max_extra_len; ++extra)
    {
        const size_t candidate = min_crc_len + extra;
        if(candidate > sizeof(crc_buf) || len < candidate || crc_index >= candidate)
            continue;

        std::memcpy(crc_buf, in, candidate);
        crc_buf[crc_index] = 0x00;
        if(utils::crc8(crc_buf, candidate) == received_crc)
        {
            crc_len = candidate;
            return true;
        }
    }
    return false;
}

} // namespace detail




inline bool decode_ir_esp(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x03)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 50)
        return false;

    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::ESP;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}

inline bool decode_ir_ip(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x04)
        return false;

    const uint8_t received_crc = in[pos++];
    size_t crc_len = 0;
    const size_t min_crc_len = crc_len_no_cid + (has_cid ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    if(!detail::find_crc8_len(in, len, min_crc_len, 168U, crc_index, received_crc, crc_len))
        return false;
    const size_t header_len = crc_len + 1U;
    if(len < header_len)
        return false;

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::IP;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}


inline bool decode_ir_udp_lite(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x08)
        return false;

    const uint8_t received_crc = in[pos++];
    size_t crc_len = 0;
    const size_t min_crc_len = crc_len_no_cid + (has_cid ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    if(!detail::find_crc8_len(in, len, min_crc_len, 168U, crc_index, received_crc, crc_len))
        return false;
    const size_t header_len = crc_len + 1U;
    if(len < header_len)
        return false;

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 136)
        return false;

    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::UDP_Lite;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}

inline bool decode_ir_udp(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x02)
        return false;

    const uint8_t received_crc = in[pos++];
    size_t crc_len = 0;
    const size_t min_crc_len = crc_len_no_cid + (has_cid ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    if(!detail::find_crc8_len(in, len, min_crc_len, 168U, crc_index, received_crc, crc_len))
        return false;
    const size_t header_len = crc_len + 1U;
    if(len < header_len)
        return false;

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 17)
        return false;

    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    if(!detail::crc8_exact_matches(in, len, pos, crc_index, received_crc))
        return false;
    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.profile = Profile::UDP;
    ctx.rohc_state = RohcState::StaticEstablished;
    return true;
}


inline bool decode_ir_rtp_udp_lite(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x07)
        return false;

    const uint8_t received_crc = in[pos++];
    size_t crc_len = 0;
    const size_t min_crc_len = crc_len_no_cid + (has_cid ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    if(!detail::find_crc8_len(in, len, min_crc_len, 168U, crc_index, received_crc, crc_len))
        return false;
    const size_t header_len = crc_len + 1U;
    if(len < header_len)
        return false;

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    ctx.rtp.ssrc = detail::read_u32(in + pos);
    pos += 4;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 136)
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
    const bool crc_matches = detail::crc8_exact_matches(in, len, pos, crc_index, received_crc) ||
                             detail::crc8_exact_matches(in, len, pos + 1U, crc_index, received_crc);
    if(!crc_matches)
        return false;

    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.profile = Profile::RTP_UDP_Lite;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

inline bool decode_ir_rtp(const uint8_t* in,
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

    if((in[pos] & 0xFE) != 0xFC)
        return false;
    ++pos;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    if(in[pos++] != 0x01)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t crc_index = has_cid ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);

    if(!detail::read_ip_static_chain(in, len, pos, ctx))
        return false;
    ctx.udp_sport = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_dport = detail::read_u16(in + pos);
    pos += 2;

    ctx.rtp.ssrc = detail::read_u32(in + pos);
    pos += 4;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;
    if(ctx.ipv4_protocol != 17)
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
    const bool crc_matches = detail::crc8_exact_matches(in, len, pos, crc_index, received_crc) ||
                             detail::crc8_exact_matches(in, len, pos + 1U, crc_index, received_crc);
    if(!crc_matches)
        return false;

    ctx.mode = detail::mode_from_wire(in[pos]);
    if(consumed)
        *consumed = pos + 1U;

    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.profile = Profile::RTP;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

} // namespace rohccxx
