// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once
#include <cstdint>
#include <cstring>

namespace rohccxx
{

struct BitWriter
{
    uint8_t* buf;
    size_t bitpos = 0;

    explicit BitWriter(uint8_t* b)
        : buf(b)
    {
        // Caller must zero buffer
    }

    void write_bits(uint32_t value, uint8_t bits)
    {
        for (int i = bits - 1; i >= 0; --i)
        {
            size_t byte = bitpos >> 3;
            uint8_t bit = 7 - (bitpos & 7);

            if (value & (1u << i))
                buf[byte] |= (1u << bit);

            ++bitpos;
        }
    }

    size_t bytes_written() const
    {
        return (bitpos + 7) >> 3;
    }
};

} // namespace rohccxx