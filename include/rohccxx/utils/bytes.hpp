// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace rohccxx::utils
{

static inline uint16_t load_be16(const void* p) noexcept
{
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return (uint16_t)((v >> 8) | (v << 8));
}

static inline uint32_t load_be32(const void* p) noexcept
{
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return __builtin_bswap32(v);
}

template<typename T>
static inline bool bounds_check(const uint8_t* base,
                                size_t len,
                                const T* ptr,
                                size_t want = sizeof(T)) noexcept
{
    const auto begin = reinterpret_cast<const uint8_t*>(ptr);
    const auto end   = begin + want;
    return begin >= base && end <= base + len;
}

} // namespace rohccxx::utils