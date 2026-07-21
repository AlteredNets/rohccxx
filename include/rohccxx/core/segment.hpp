// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace rohccxx
{

struct SegmentHeader
{
    bool final = false;
    std::uint16_t sequence = 0;
};

inline bool read_segment_header(const std::uint8_t* in, size_t len, SegmentHeader& segment)
{
    if(!in || len < 2 || (in[0] & 0xFEU) != 0xFEU)
        return false;
    segment.final = (in[0] & 0x01U) != 0;
    segment.sequence = in[1];
    return true;
}

inline bool write_segment_header(std::uint8_t* out, size_t* out_len, const SegmentHeader& segment)
{
    if(!out || !out_len || *out_len < 2)
        return false;
    out[0] = static_cast<std::uint8_t>(0xFEU | (segment.final ? 0x01U : 0x00U));
    out[1] = static_cast<std::uint8_t>(segment.sequence & 0xFFU);
    *out_len = 2;
    return true;
}

inline bool write_segment_packet(std::uint8_t* out,
                                 size_t* out_len,
                                 const SegmentHeader& segment,
                                 const std::uint8_t* payload,
                                 size_t payload_len)
{
    if(!out || !out_len || (!payload && payload_len > 0) || *out_len < 2U + payload_len)
        return false;
    size_t header_len = *out_len;
    if(!write_segment_header(out, &header_len, segment))
        return false;
    if(payload_len > 0)
        std::memcpy(out + header_len, payload, payload_len);
    *out_len = header_len + payload_len;
    return true;
}

} // namespace rohccxx
