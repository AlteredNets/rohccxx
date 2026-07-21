// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rohccxx::cid
{

inline constexpr std::uint32_t small_cid_max = 0x0F;
inline constexpr std::uint32_t large_cid_max = 0x3FFF;

inline bool is_small(std::uint32_t value)
{
    return value <= small_cid_max;
}

inline bool is_valid_for_space(std::uint32_t value, bool large_cid_space)
{
    return large_cid_space ? value <= large_cid_max : is_small(value);
}

inline bool write_large(std::uint8_t*& p, const std::uint8_t* end, std::uint32_t value)
{
    if(value > large_cid_max || !p || !end)
        return false;

    if(value <= 0x7F)
    {
        if(p + 1 > end)
            return false;
        *p++ = static_cast<std::uint8_t>(value);
        return true;
    }

    if(p + 2 > end)
        return false;
    *p++ = static_cast<std::uint8_t>(0x80U | ((value >> 8) & 0x3FU));
    *p++ = static_cast<std::uint8_t>(value & 0xFFU);
    return true;
}

inline bool read_large(const std::uint8_t* p,
                       size_t len,
                       std::uint32_t& value,
                       size_t& consumed)
{
    value = 0;
    consumed = 0;
    if(!p || len == 0)
        return false;

    if((p[0] & 0x80U) == 0)
    {
        value = p[0] & 0x7FU;
        consumed = 1;
        return true;
    }

    if((p[0] & 0xC0U) == 0x80U)
    {
        if(len < 2)
            return false;
        value = (static_cast<std::uint32_t>(p[0] & 0x3FU) << 8) |
                static_cast<std::uint32_t>(p[1]);
        if(value <= 0x7FU)
            return false;
        consumed = 2;
        return true;
    }

    return false;
}

inline size_t encoded_len(std::uint32_t value)
{
    return value <= 0x7F ? 1U : 2U;
}

} // namespace rohccxx::cid
