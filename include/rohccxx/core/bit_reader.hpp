// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once
#include <cstdint>

namespace rohccxx
{

struct BitReader
{
    const uint8_t* buf;
    size_t bitpos = 0;

    explicit BitReader(const uint8_t* b)
        : buf(b) {}

    uint32_t read_bits(uint8_t bits)
    {
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