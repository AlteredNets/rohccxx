// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include <cstring>

namespace rohccxx
{

inline bool emit_uncompressed(uint8_t* out,
                              size_t* out_len,
                              const uint8_t* in,
                              size_t in_len) noexcept
{
    if (!out || !out_len || !in)
        return false;

    // Add-CID (1 byte) + original packet
    if (*out_len < in_len + 1)
        return false;

    out[0] = 0x00; // Add-CID = 0
    std::memcpy(out + 1, in, in_len);

    *out_len = in_len + 1;
    return true;
}

} // namespace rohccxx