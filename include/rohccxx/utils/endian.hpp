// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>

namespace rohccxx::utils
{

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
    constexpr bool host_is_little_endian =
        (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
#elif defined(_WIN32)
    // Windows is always little-endian
    constexpr bool host_is_little_endian = true;
#else
#   error "Unable to determine host endianness"
#endif

constexpr bool host_is_big_endian = !host_is_little_endian;

} // namespace rohccxx::utils