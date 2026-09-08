// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx::detail
{

inline void append_private_udp_u16(std::array<std::uint8_t, 256>& data,
                                   std::size_t& pos, std::uint16_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 8U);
    data[pos++] = static_cast<std::uint8_t>(value);
}

inline void append_private_udp_u32(std::array<std::uint8_t, 256>& data,
                                   std::size_t& pos, std::uint32_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 24U);
    data[pos++] = static_cast<std::uint8_t>(value >> 16U);
    data[pos++] = static_cast<std::uint8_t>(value >> 8U);
    data[pos++] = static_cast<std::uint8_t>(value);
}

// The private UDP FO form omits the static IP and UDP tuple. Bind its CRC-8
// to every omitted field used during reconstruction so a reused CID cannot
// authenticate against an older same-profile context.
inline std::uint8_t private_udp_fo_crc8(const std::uint8_t* header,
                                        std::size_t header_len,
                                        const Context& context)
{
    std::array<std::uint8_t, 256> data{};
    if(!header || header_len > data.size())
        return 0U;
    std::memcpy(data.data(), header, header_len);
    std::size_t pos = header_len;

    append_private_udp_u16(data, pos,
                           static_cast<std::uint16_t>(context.profile));
    append_private_udp_u32(data, pos, context.cid);
    data[pos++] = context.large_cid ? 1U : 0U;
    data[pos++] = context.ip_version;
    if(context.ip_version == 4U)
    {
        data[pos++] = context.ipv4_tos;
        data[pos++] = context.ipv4_ttl;
        data[pos++] = context.ipv4_flags;
        data[pos++] = context.ipv4_protocol;
        append_private_udp_u32(data, pos, context.ipv4_saddr);
        append_private_udp_u32(data, pos, context.ipv4_daddr);
        const std::size_t options_len =
            context.ipv4_options_len <= context.ipv4_options.size()
                ? context.ipv4_options_len : context.ipv4_options.size();
        data[pos++] = static_cast<std::uint8_t>(options_len);
        std::memcpy(data.data() + pos, context.ipv4_options.data(), options_len);
        pos += options_len;
    }
    else if(context.ip_version == 6U)
    {
        data[pos++] = context.ipv6_traffic_class;
        append_private_udp_u32(data, pos, context.ipv6_flow_label);
        data[pos++] = context.ipv6_next_header;
        data[pos++] = context.ipv6_hop_limit;
        std::memcpy(data.data() + pos, context.ipv6_saddr.data(),
                    context.ipv6_saddr.size());
        pos += context.ipv6_saddr.size();
        std::memcpy(data.data() + pos, context.ipv6_daddr.data(),
                    context.ipv6_daddr.size());
        pos += context.ipv6_daddr.size();
        const std::size_t extension_len =
            context.ipv6_extension_len <= context.ipv6_extensions.size()
                ? context.ipv6_extension_len : context.ipv6_extensions.size();
        data[pos++] = static_cast<std::uint8_t>(extension_len);
        std::memcpy(data.data() + pos, context.ipv6_extensions.data(),
                    extension_len);
        pos += extension_len;
    }

    append_private_udp_u16(data, pos, context.udp_sport);
    append_private_udp_u16(data, pos, context.udp_dport);
    return utils::crc8(data.data(), pos);
}

} // namespace rohccxx::detail
