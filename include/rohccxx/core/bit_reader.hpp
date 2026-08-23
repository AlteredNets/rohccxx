// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>

namespace rohccxx
{

struct BitReader
{
    const uint8_t* buf;
    size_t bit_len;
    size_t bitpos = 0;
    bool valid = true;

    explicit BitReader(const uint8_t* b,
                       size_t byte_len = std::numeric_limits<size_t>::max() / 8U)
        : buf(b), bit_len(byte_len > std::numeric_limits<size_t>::max() / 8U
                             ? std::numeric_limits<size_t>::max()
                             : byte_len * 8U) {}

    bool can_read(uint8_t bits) const
    {
        return valid && bitpos <= bit_len && static_cast<size_t>(bits) <= bit_len - bitpos;
    }

    uint32_t read_bits(uint8_t bits)
    {
        if(!buf || bits > 32U || !can_read(bits))
        {
            valid = false;
            return 0;
        }
        uint32_t value = 0;

        for (uint8_t i = 0; i < bits; ++i)
        {
            size_t byte = bitpos >> 3;
            uint8_t bit = 7 - (bitpos & 7);

            value <<= 1;
            value |= (buf[byte] >> bit) & 1u;

            ++bitpos;
        }

        return value;
    }
};

} // namespace rohccxx
