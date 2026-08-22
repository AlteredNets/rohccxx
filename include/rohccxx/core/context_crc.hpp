// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

#include "rohccxx/core/context.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx::detail
{

inline void write_context_u16(std::uint8_t* data, std::size_t& pos, std::uint16_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 8);
    data[pos++] = static_cast<std::uint8_t>(value & 0xFFU);
}

inline void write_context_u32(std::uint8_t* data, std::size_t& pos, std::uint32_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 24);
    data[pos++] = static_cast<std::uint8_t>(value >> 16);
    data[pos++] = static_cast<std::uint8_t>(value >> 8);
    data[pos++] = static_cast<std::uint8_t>(value & 0xFFU);
}

inline std::uint8_t context_crc7(const Context& ctx)
{
    std::uint8_t data[64] = {};
    std::size_t pos = 0;
    write_context_u16(data, pos, static_cast<std::uint16_t>(ctx.profile));
    write_context_u32(data, pos, ctx.cid);
    data[pos++] = static_cast<std::uint8_t>(ctx.ip_version);
    data[pos++] = ctx.ipv4_tos;
    data[pos++] = ctx.ipv4_ttl;
    write_context_u16(data, pos, ctx.ipv4_id);
    data[pos++] = ctx.ipv4_flags;
    data[pos++] = ctx.ipv4_id_sequential ? 1U : 0U;
    write_context_u32(data, pos, ctx.ipv4_saddr);
    write_context_u32(data, pos, ctx.ipv4_daddr);
    write_context_u16(data, pos, ctx.udp_sport);
    write_context_u16(data, pos, ctx.udp_dport);
    write_context_u16(data, pos, ctx.udp_check);
    data[pos++] = ctx.rtp.vpxcc;
    data[pos++] = ctx.rtp.mpt;
    write_context_u16(data, pos, ctx.rtp.last_seq);
    write_context_u32(data, pos, ctx.rtp.last_ts);
    write_context_u32(data, pos, ctx.rtp.ssrc);
    write_context_u32(data, pos, ctx.rtp.ts_stride);
    return static_cast<std::uint8_t>(utils::crc7(data, pos) & 0x7FU);
}

} // namespace rohccxx::detail
