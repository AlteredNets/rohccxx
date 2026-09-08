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

inline void append_private_fo_u16(std::array<std::uint8_t, 256>& data,
                                 std::size_t& pos, std::uint16_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 8U);
    data[pos++] = static_cast<std::uint8_t>(value);
}

inline void append_private_fo_u32(std::array<std::uint8_t, 256>& data,
                                 std::size_t& pos, std::uint32_t value)
{
    data[pos++] = static_cast<std::uint8_t>(value >> 24U);
    data[pos++] = static_cast<std::uint8_t>(value >> 16U);
    data[pos++] = static_cast<std::uint8_t>(value >> 8U);
    data[pos++] = static_cast<std::uint8_t>(value);
}

inline bool append_private_fo_ip_context(
    std::array<std::uint8_t, 256>& data,
    std::size_t& pos,
    const std::uint8_t* header,
    std::size_t header_len,
    const Context& context,
    std::size_t profile_bytes)
{
    const std::size_t options_len =
        context.ipv4_options_len <= context.ipv4_options.size()
            ? context.ipv4_options_len : context.ipv4_options.size();
    const std::size_t extension_len =
        context.ipv6_extension_len <= context.ipv6_extensions.size()
            ? context.ipv6_extension_len : context.ipv6_extensions.size();
    const std::size_t ip_context_len = context.ip_version == 4U
        ? 21U + options_len
        : context.ip_version == 6U ? 48U + extension_len : 8U;
    if(!header || profile_bytes > data.size() ||
       ip_context_len > data.size() - profile_bytes ||
       header_len > data.size() - profile_bytes - ip_context_len)
    {
        return false;
    }

    std::memcpy(data.data(), header, header_len);
    pos = header_len;

    append_private_fo_u16(data, pos,
                          static_cast<std::uint16_t>(context.profile));
    append_private_fo_u32(data, pos, context.cid);
    data[pos++] = context.large_cid ? 1U : 0U;
    data[pos++] = context.ip_version;
    if(context.ip_version == 4U)
    {
        data[pos++] = context.ipv4_tos;
        data[pos++] = context.ipv4_ttl;
        data[pos++] = context.ipv4_flags;
        data[pos++] = context.ipv4_protocol;
        append_private_fo_u32(data, pos, context.ipv4_saddr);
        append_private_fo_u32(data, pos, context.ipv4_daddr);
        data[pos++] = static_cast<std::uint8_t>(options_len);
        std::memcpy(data.data() + pos, context.ipv4_options.data(), options_len);
        pos += options_len;
    }
    else if(context.ip_version == 6U)
    {
        data[pos++] = context.ipv6_traffic_class;
        append_private_fo_u32(data, pos, context.ipv6_flow_label);
        data[pos++] = context.ipv6_next_header;
        data[pos++] = context.ipv6_hop_limit;
        std::memcpy(data.data() + pos, context.ipv6_saddr.data(),
                    context.ipv6_saddr.size());
        pos += context.ipv6_saddr.size();
        std::memcpy(data.data() + pos, context.ipv6_daddr.data(),
                    context.ipv6_daddr.size());
        pos += context.ipv6_daddr.size();
        data[pos++] = static_cast<std::uint8_t>(extension_len);
        std::memcpy(data.data() + pos, context.ipv6_extensions.data(),
                    extension_len);
        pos += extension_len;
    }

    return true;
}

// Private FO forms omit the reconstruction context carried by IR. Bind their
// CRC-8 to that context so a reused CID cannot authenticate against an older
// same-profile generation.
inline std::uint8_t private_ip_fo_crc8(const std::uint8_t* header,
                                       std::size_t header_len,
                                       const Context& context)
{
    std::array<std::uint8_t, 256> data{};
    std::size_t pos = 0U;
    if(!append_private_fo_ip_context(data, pos, header, header_len, context, 0U))
        return 0U;
    return utils::crc8(data.data(), pos);
}

inline std::uint8_t private_udp_fo_crc8(const std::uint8_t* header,
                                        std::size_t header_len,
                                        const Context& context)
{
    std::array<std::uint8_t, 256> data{};
    std::size_t pos = 0U;
    if(!append_private_fo_ip_context(data, pos, header, header_len, context, 4U))
        return 0U;
    append_private_fo_u16(data, pos, context.udp_sport);
    append_private_fo_u16(data, pos, context.udp_dport);
    return utils::crc8(data.data(), pos);
}

inline std::uint8_t private_udp_lite_fo_crc8(const std::uint8_t* header,
                                             std::size_t header_len,
                                             const Context& context)
{
    return private_udp_fo_crc8(header, header_len, context);
}

inline std::uint8_t private_esp_fo_crc8(const std::uint8_t* header,
                                        std::size_t header_len,
                                        const Context& context)
{
    std::array<std::uint8_t, 256> data{};
    std::size_t pos = 0U;
    if(!append_private_fo_ip_context(data, pos, header, header_len, context, 9U))
        return 0U;
    append_private_fo_u32(data, pos, context.esp_spi);
    append_private_fo_u32(data, pos, context.esp_sequence);
    data[pos++] = context.legacy_esp_payload_includes_header ? 1U : 0U;
    return utils::crc8(data.data(), pos);
}

} // namespace rohccxx::detail
