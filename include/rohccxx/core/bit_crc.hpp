// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include <cstddef>
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{

/*
 * Validate CRC‑7 when the CRC is bit‑aligned.
 *
 * Buffer layout:
 *   [ payload bits ][ 7 CRC bits ]
 */
inline bool validate_crc7_bits(const uint8_t* buf,
                               size_t total_bits)
{
    if (total_bits < 7)
        return false;

    // Bits before CRC
    size_t data_bits = total_bits - 7;

    // Number of whole bytes that cover the payload bits
    size_t data_bytes = (data_bits + 7) >> 3;

    // Compute expected CRC over payload bytes
    uint8_t expected = utils::crc7(buf, data_bytes) & 0x7F;

    // Extract last 7 bits (MSB-first)
    uint8_t received = 0;
    size_t start = data_bits;

    for (int i = 0; i < 7; ++i)
    {
        size_t bit_index = start + i;
        size_t byte = bit_index >> 3;
        uint8_t bit = 7 - (bit_index & 7);

        received <<= 1;
        received |= (buf[byte] >> bit) & 1u;
    }

    return expected == received;
}

/*
 * CRC‑8 version for IR / IR‑DYN packets
 */
inline bool validate_crc8_bits(const uint8_t* buf,
                               size_t total_bits)
{
    if (total_bits < 8)
        return false;

    size_t data_bits = total_bits - 8;
    size_t data_bytes = (data_bits + 7) >> 3;

    uint8_t expected = utils::crc8(buf, data_bytes);

    uint8_t received = 0;
    size_t start = data_bits;

    for (int i = 0; i < 8; ++i)
    {
        size_t bit_index = start + i;
        size_t byte = bit_index >> 3;
        uint8_t bit = 7 - (bit_index & 7);

        received <<= 1;
        received |= (buf[byte] >> bit) & 1u;
    }

    return expected == received;
}

} // namespace rohccxx