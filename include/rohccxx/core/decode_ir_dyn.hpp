// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/rfc5225_chains.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/core/encoding_methods.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{




inline bool decode_ir_dyn_esp(const uint8_t* in,
                              size_t len,
                              Context& ctx,
                              size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t header_len_no_cid = 9;

    if(len < header_len_no_cid)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x03)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t ipv6_dynamic_delta = ctx.ip_version == 6 ? 1U : 0U;
    const size_t min_header_len = header_len_no_cid + ipv6_dynamic_delta + (!ctx.large_cid && ctx.cid > 0 ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, pos, ctx, options_extra_len))
        return false;
    const size_t header_len = min_header_len + options_extra_len;
    if(!detail::crc8_exact_matches(in, len, header_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    ctx.profile = Profile::ESP;
    ctx.rohc_state = RohcState::DynamicEstablished;

    if(consumed)
        *consumed = header_len;

    return true;
}

inline bool decode_ir_dyn_ip(const uint8_t* in,
                             size_t len,
                             Context& ctx,
                             size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t header_len_no_cid = 9;

    if(len < header_len_no_cid)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x04)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t ipv6_dynamic_delta = ctx.ip_version == 6 ? 1U : 0U;
    const size_t min_header_len = header_len_no_cid + ipv6_dynamic_delta + (!ctx.large_cid && ctx.cid > 0 ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, pos, ctx, options_extra_len))
        return false;
    const size_t header_len = min_header_len + options_extra_len;
    if(!detail::crc8_exact_matches(in, len, header_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    if(consumed)
        *consumed = header_len;

    ctx.profile = Profile::IP;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}


inline bool decode_ir_dyn_udp_lite(const uint8_t* in,
                                   size_t len,
                                   Context& ctx,
                                   size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t header_len_no_cid = 13;

    if(len < header_len_no_cid)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x08)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t ipv6_dynamic_delta = ctx.ip_version == 6 ? 1U : 0U;
    const size_t min_header_len = header_len_no_cid + ipv6_dynamic_delta + (!ctx.large_cid && ctx.cid > 0 ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, pos, ctx, options_extra_len))
        return false;
    const size_t header_len = min_header_len + options_extra_len;
    if(!detail::crc8_exact_matches(in, len, header_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);

    if(consumed)
        *consumed = header_len;

    ctx.profile = Profile::UDP_Lite;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

inline bool decode_ir_dyn_udp(const uint8_t* in,
                              size_t len,
                              Context& ctx,
                              size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t header_len_no_cid = 11;

    if(len < header_len_no_cid)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if(len < header_len_no_cid + 1U)
            return false;
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x02)
        return false;

    const uint8_t received_crc = in[pos++];
    const size_t ipv6_dynamic_delta = ctx.ip_version == 6 ? 1U : 0U;
    const size_t min_header_len = header_len_no_cid + ipv6_dynamic_delta + (!ctx.large_cid && ctx.cid > 0 ? 1U : 0U) + (ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, pos, ctx, options_extra_len))
        return false;
    const size_t header_len = min_header_len + options_extra_len;
    if(!detail::crc8_exact_matches(in, len, header_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    ctx.udp_check = detail::read_u16(in + pos);

    if(consumed)
        *consumed = header_len;

    ctx.profile = Profile::UDP;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

inline bool decode_ir_dyn_rtp_udp_lite(const uint8_t* in,
                                       size_t len,
                                       Context& ctx,
                                       size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t min_wire_len = 22;
    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U;
    const size_t small_cid_len = (!ctx.large_cid && ctx.cid > 0) ? 1U : 0U;
    if(len < min_wire_len + cid_len + small_cid_len)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x07)
        return false;

    const uint8_t received_crc = in[pos++];

    const size_t min_header_len = 22U + cid_len + small_cid_len + (ctx.ip_version == 6 ? 1U : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    const bool had_ipv4_rtp_context = ctx.ip_version == 4 && ctx.rtp.initialized != 0;
    const std::uint16_t previous_ipv4_id = ctx.ipv4_id;
    const std::uint16_t previous_rtp_seq = ctx.rtp.last_seq;

    const size_t dynamic_pos = pos;
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, dynamic_pos, ctx, options_extra_len))
        return false;
    const size_t ip_dynamic_len = (ctx.ip_version == 6 ? 7U : 6U) + options_extra_len;
    const size_t rtp_marker_pos = dynamic_pos + ip_dynamic_len + 4U + 8U;
    size_t rtp_extra_len = 0;
    if(!detail::rtp_dynamic_extra_len(in, len, rtp_marker_pos, rtp_extra_len))
        return false;
    const size_t candidate_len = min_header_len + options_extra_len + rtp_extra_len;
    if(!detail::crc8_exact_matches(in, len, candidate_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    const uint8_t rtp_first = in[pos++];
    const uint8_t rtp_second = in[pos++];
    ctx.rtp.vpxcc = static_cast<uint8_t>((rtp_first & 0xF0) | (rtp_first & 0x0F));
    ctx.rtp.mpt = rtp_second;

    const std::uint16_t decoded_seq = detail::read_u16(in + pos);
    pos += 2;
    const std::uint32_t decoded_ts = detail::read_u32(in + pos);
    pos += 4;
    if(ctx.rtp.initialized)
    {
        std::uint32_t stride = 0;
        std::uint32_t residue = 0;
        if(encoding::infer_timestamp_stride(ctx.rtp.last_seq,
                                            ctx.rtp.last_ts,
                                            decoded_seq,
                                            decoded_ts,
                                            stride,
                                            residue))
        {
            ctx.rtp.ts_stride = stride;
            ctx.rtp.ts_residue = residue;
        }
    }
    if(ctx.ip_version == 4 && had_ipv4_rtp_context)
    {
        const auto id_delta = static_cast<std::uint16_t>(ctx.ipv4_id - previous_ipv4_id);
        const auto seq_delta = static_cast<std::uint16_t>(decoded_seq - previous_rtp_seq);
        ctx.ipv4_id_sequential = id_delta != 0U && id_delta == seq_delta;
    }
    else
    {
        ctx.ipv4_id_sequential = false;
    }
    ctx.rtp.last_seq = decoded_seq;
    ctx.rtp.last_ts = decoded_ts;
    if(!rfc5225::read_rtp_extras_list(in, candidate_len, pos, ctx) || pos != candidate_len)
        return false;

    if(consumed)
        *consumed = candidate_len;

    ctx.profile = Profile::RTP_UDP_Lite;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

inline bool decode_ir_dyn_rtp(const uint8_t* in,
                              size_t len,
                              Context& ctx,
                              size_t* consumed = nullptr)
{
    size_t pos = 0;
    constexpr size_t min_wire_len = 20;
    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U;
    const size_t small_cid_len = (!ctx.large_cid && ctx.cid > 0) ? 1U : 0U;
    if(len < min_wire_len + cid_len + small_cid_len)
        return false;

    if(!ctx.large_cid && ctx.cid > 0)
    {
        if((in[pos] & 0xF0) != 0xE0 || (in[pos] & 0x0F) != (ctx.cid & 0x0F))
            return false;
        ++pos;
    }

    if(in[pos++] != 0xF8)
        return false;
    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;
    if(in[pos++] != 0x01)
        return false;

    const uint8_t received_crc = in[pos++];

    const bool had_ipv4_rtp_context = ctx.ip_version == 4 && ctx.rtp.initialized != 0;
    const std::uint16_t previous_ipv4_id = ctx.ipv4_id;
    const std::uint16_t previous_rtp_seq = ctx.rtp.last_seq;

    // IR-DYN can also vary by one tail byte in the reference traces.
    const size_t candidate_min_header_len = 20U + cid_len + small_cid_len + (ctx.ip_version == 6 ? 1U : 0U);
    const size_t crc_index = (!ctx.large_cid && ctx.cid > 0) ? 3U : (ctx.large_cid ? (2U + cid::encoded_len(ctx.cid)) : 2U);
    const size_t dynamic_pos = pos;
    size_t options_extra_len = 0;
    if(!detail::ip_dynamic_extra_len(in, len, dynamic_pos, ctx, options_extra_len))
        return false;
    const size_t ip_dynamic_len = (ctx.ip_version == 6 ? 7U : 6U) + options_extra_len;
    const size_t rtp_marker_pos = dynamic_pos + ip_dynamic_len + 2U + 8U;
    size_t rtp_extra_len = 0;
    if(!detail::rtp_dynamic_extra_len(in, len, rtp_marker_pos, rtp_extra_len))
        return false;
    const size_t candidate_len = candidate_min_header_len + options_extra_len + rtp_extra_len;
    if(!detail::crc8_exact_matches(in, len, candidate_len, crc_index, received_crc))
        return false;

    if(!detail::read_ip_dynamic_chain(in, len, pos, ctx))
        return false;

    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;

    const uint8_t rtp_first = in[pos++];
    const uint8_t rtp_second = in[pos++];
    ctx.rtp.vpxcc = static_cast<uint8_t>((rtp_first & 0xF0) | (rtp_first & 0x0F));
    ctx.rtp.mpt = rtp_second;

    const std::uint16_t decoded_seq = detail::read_u16(in + pos);
    pos += 2;
    const std::uint32_t decoded_ts = detail::read_u32(in + pos);
    pos += 4;
    if(ctx.rtp.initialized)
    {
        std::uint32_t stride = 0;
        std::uint32_t residue = 0;
        if(encoding::infer_timestamp_stride(ctx.rtp.last_seq,
                                            ctx.rtp.last_ts,
                                            decoded_seq,
                                            decoded_ts,
                                            stride,
                                            residue))
        {
            ctx.rtp.ts_stride = stride;
            ctx.rtp.ts_residue = residue;
        }
    }
    if(ctx.ip_version == 4 && had_ipv4_rtp_context)
    {
        const auto id_delta = static_cast<std::uint16_t>(ctx.ipv4_id - previous_ipv4_id);
        const auto seq_delta = static_cast<std::uint16_t>(decoded_seq - previous_rtp_seq);
        ctx.ipv4_id_sequential = id_delta != 0U && id_delta == seq_delta;
    }
    else
    {
        ctx.ipv4_id_sequential = false;
    }
    ctx.rtp.last_seq = decoded_seq;
    ctx.rtp.last_ts = decoded_ts;
    if(!rfc5225::read_rtp_extras_list(in, candidate_len, pos, ctx) || pos != candidate_len)
        return false;

    if(consumed)
        *consumed = candidate_len;

    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    ctx.rtp.ts_residue = ctx.rtp.ts_stride == 0 ? 0U : (ctx.rtp.last_ts % ctx.rtp.ts_stride);
    ctx.rtp.initialized = 1;
    ctx.rohc_state = RohcState::DynamicEstablished;
    return true;
}

} // namespace rohccxx
