// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rohccxx::ppp
{

constexpr std::uint8_t ip_compression_option_type = 2;
constexpr std::uint16_t ip_compression_protocol_rohc = 0x0003;
constexpr std::uint16_t protocol_rohc_small_cid = 0x0003;
constexpr std::uint16_t protocol_rohc_large_cid = 0x0005;
constexpr std::uint8_t suboption_profiles = 1;
constexpr std::uint16_t max_cid_limit = 16383;
constexpr std::size_t max_profiles = 16;
constexpr std::uint16_t suggested_max_cid = 15;
constexpr std::uint16_t suggested_mrru = 0;
constexpr std::uint16_t suggested_max_header = 168;

struct RohcOption
{
    std::uint16_t max_cid = suggested_max_cid;
    std::uint16_t mrru = suggested_mrru;
    std::uint16_t max_header = suggested_max_header;
    std::uint16_t profiles[max_profiles] = {};
    std::size_t profile_count = 0;
};

inline bool is_rohc_protocol_field(std::uint16_t protocol)
{
    return protocol == protocol_rohc_small_cid || protocol == protocol_rohc_large_cid;
}

inline bool uses_large_cid_protocol(std::uint16_t protocol)
{
    return protocol == protocol_rohc_large_cid;
}

inline bool append_profile(RohcOption& option, std::uint16_t profile)
{
    if(option.profile_count >= max_profiles)
        return false;
    if(option.profile_count > 0 && option.profiles[option.profile_count - 1] >= profile)
        return false;
    option.profiles[option.profile_count++] = profile;
    return true;
}

inline bool valid(const RohcOption& option)
{
    return option.max_cid <= max_cid_limit && option.profile_count > 0 && option.profile_count <= max_profiles;
}

inline bool read_u16(const std::uint8_t* data, std::size_t len, std::size_t pos, std::uint16_t& value)
{
    if(!data || pos + 2 > len)
        return false;
    value = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8U) | data[pos + 1]);
    return true;
}

inline bool write_u16(std::uint8_t* out, std::size_t capacity, std::size_t& pos, std::uint16_t value)
{
    if(!out || pos + 2 > capacity)
        return false;
    out[pos++] = static_cast<std::uint8_t>(value >> 8);
    out[pos++] = static_cast<std::uint8_t>(value & 0xFFU);
    return true;
}

inline bool parse_rohc_option(const std::uint8_t* data, std::size_t len, RohcOption& option)
{
    option = RohcOption{};
    if(!data || len < 10 || data[0] != ip_compression_option_type || data[1] != len)
        return false;

    std::uint16_t protocol = 0;
    if(!read_u16(data, len, 2, protocol) || protocol != ip_compression_protocol_rohc)
        return false;
    if(!read_u16(data, len, 4, option.max_cid) || option.max_cid > max_cid_limit)
        return false;
    if(!read_u16(data, len, 6, option.mrru) || !read_u16(data, len, 8, option.max_header))
        return false;

    std::size_t pos = 10;
    while(pos < len)
    {
        if(pos + 2 > len)
            return false;
        const std::uint8_t type = data[pos];
        const std::uint8_t sub_len = data[pos + 1];
        if(sub_len < 2 || pos + sub_len > len)
            return false;
        if(type == suboption_profiles)
        {
            if(sub_len < 4 || ((sub_len - 2U) % 2U) != 0)
                return false;
            for(std::size_t profile_pos = pos + 2; profile_pos < pos + sub_len; profile_pos += 2)
            {
                std::uint16_t profile = 0;
                if(!read_u16(data, len, profile_pos, profile) || !append_profile(option, profile))
                    return false;
            }
        }
        pos += sub_len;
    }

    return valid(option);
}

inline bool write_rohc_option(const RohcOption& option, std::uint8_t* out, std::size_t* out_len)
{
    if(!out || !out_len || !valid(option))
        return false;

    const std::size_t needed = 10U + 2U + (option.profile_count * 2U);
    if(needed > 255U || *out_len < needed)
        return false;

    std::size_t pos = 0;
    out[pos++] = ip_compression_option_type;
    out[pos++] = static_cast<std::uint8_t>(needed);
    if(!write_u16(out, *out_len, pos, ip_compression_protocol_rohc) ||
       !write_u16(out, *out_len, pos, option.max_cid) ||
       !write_u16(out, *out_len, pos, option.mrru) ||
       !write_u16(out, *out_len, pos, option.max_header))
    {
        return false;
    }

    out[pos++] = suboption_profiles;
    out[pos++] = static_cast<std::uint8_t>(2U + (option.profile_count * 2U));
    for(std::size_t i = 0; i < option.profile_count; ++i)
    {
        if(!write_u16(out, *out_len, pos, option.profiles[i]))
            return false;
    }

    *out_len = pos;
    return true;
}

inline bool merge_channel_options(const RohcOption& a, const RohcOption& b, RohcOption& merged)
{
    if(!valid(a) || !valid(b))
        return false;
    merged = RohcOption{};
    merged.max_cid = a.max_cid > b.max_cid ? a.max_cid : b.max_cid;
    merged.mrru = a.mrru > b.mrru ? a.mrru : b.mrru;
    merged.max_header = a.max_header > b.max_header ? a.max_header : b.max_header;

    std::size_t ai = 0;
    std::size_t bi = 0;
    while(ai < a.profile_count || bi < b.profile_count)
    {
        std::uint16_t profile = 0;
        if(bi >= b.profile_count || (ai < a.profile_count && a.profiles[ai] < b.profiles[bi]))
            profile = a.profiles[ai++];
        else if(ai >= a.profile_count || b.profiles[bi] < a.profiles[ai])
            profile = b.profiles[bi++];
        else
        {
            profile = a.profiles[ai];
            ++ai;
            ++bi;
        }
        if(!append_profile(merged, profile))
            return false;
    }
    return valid(merged);
}

} // namespace rohccxx::ppp
