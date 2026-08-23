// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/lla.hpp"

namespace rohccxx
{

enum class RohcPacketType : uint8_t
{
    Unknown      = 0xFF,
    Uncompressed = 0x00,
    IR           = 0xFC,
    IR_DYN       = 0xF8,
    FO_RTP       = 0x01,
    FO_UDP       = 0x7A,
    FO_IP        = 0x79,
    FO_ESP       = 0x78,
    FO_UDP_Lite  = 0x77,
    LLA_ContextSync = 0xFA,
    LLA_ContextCheck = 0xFB,
    Feedback     = 0xF0,
    Segment      = 0xFE
};

struct ParsedRohcPacket
{
    const uint8_t* wire = nullptr;
    size_t wire_len = 0;
    const uint8_t* packet = nullptr;
    size_t packet_len = 0;
    uint32_t cid = 0;
    bool has_add_cid = false;
    bool has_large_cid = false;
    size_t cid_len = 0;
    RohcPacketType type = RohcPacketType::Unknown;
    uint8_t profile_id = 0;
};


inline bool is_uncompressed_ip_payload(const std::uint8_t* ip, size_t ip_len)
{
    if(!ip || ip_len == 0)
        return false;

    const std::uint8_t version = static_cast<std::uint8_t>(ip[0] >> 4);
    if(version == 4)
    {
        if(ip_len < 20)
            return false;
        const size_t ihl = static_cast<size_t>(ip[0] & 0x0FU) * 4U;
        const size_t total_len = (static_cast<size_t>(ip[2]) << 8) | ip[3];
        return ihl >= 20U && ihl <= ip_len && total_len == ip_len;
    }

    if(version == 6)
    {
        if(ip_len < 40)
            return false;
        const size_t payload_len = (static_cast<size_t>(ip[4]) << 8) | ip[5];
        return payload_len + 40U == ip_len;
    }

    return false;
}

inline RohcPacketType detect_packet_type(uint8_t b)
{
    if((b & 0xFE) == 0xFE)
        return RohcPacketType::Segment;
    if(b == lla::packet_type_csp)
        return RohcPacketType::LLA_ContextSync;
    if(b == lla::packet_type_ccp)
        return RohcPacketType::LLA_ContextCheck;
    if((b & 0xF8) == 0xF0)
        return RohcPacketType::Feedback;
    if((b & 0xFE) == 0xFC)
        return RohcPacketType::IR;
    if(b == 0xF8)
        return RohcPacketType::IR_DYN;
    if(b == 0x7A)
        return RohcPacketType::FO_UDP;
    if(b == 0x79)
        return RohcPacketType::FO_IP;
    if(b == 0x78)
        return RohcPacketType::FO_ESP;
    if(b == 0x77)
        return RohcPacketType::FO_UDP_Lite;
    if((b & 0x80) == 0x00)
        return RohcPacketType::FO_RTP;
    return RohcPacketType::Unknown;
}

inline bool parse_rohc_packet(const uint8_t* in,
                              size_t len,
                              ParsedRohcPacket& parsed,
                              bool large_cid_space = false)
{
    parsed = {};
    if(!in || len == 0)
        return false;

    parsed.wire = in;
    parsed.wire_len = len;
    parsed.packet = in;
    parsed.packet_len = len;

    if(!large_cid_space && (in[0] & 0xF0) == 0xE0)
    {
        if(len < 2)
            return false;
        parsed.has_add_cid = true;
        parsed.cid = static_cast<uint32_t>(in[0] & 0x0F);
        parsed.packet = in + 1;
        parsed.packet_len = len - 1;
    }

    if(parsed.packet_len == 0)
        return false;

    parsed.type = detect_packet_type(parsed.packet[0]);
    if(parsed.packet[0] == 0x00 && parsed.packet_len > 1 &&
       is_uncompressed_ip_payload(parsed.packet + 1, parsed.packet_len - 1))
    {
        parsed.type = RohcPacketType::Uncompressed;
    }

    if(large_cid_space && parsed.type != RohcPacketType::Uncompressed)
    {
        if(parsed.packet_len < 2)
            return false;
        size_t cid_len = 0;
        uint32_t large_cid = 0;
        if(!cid::read_large(parsed.packet + 1, parsed.packet_len - 1, large_cid, cid_len))
            return false;
        parsed.has_large_cid = true;
        parsed.cid = large_cid;
        parsed.cid_len = cid_len;
    }

    if(parsed.type == RohcPacketType::IR || parsed.type == RohcPacketType::IR_DYN)
    {
        const size_t profile_pos = large_cid_space ? (1U + parsed.cid_len) : 1U;
        if(parsed.packet_len <= profile_pos)
            return false;
        parsed.profile_id = parsed.packet[profile_pos];
    }
    else if(parsed.type == RohcPacketType::FO_RTP && !large_cid_space && !parsed.has_add_cid)
    {
        parsed.cid = static_cast<uint32_t>((parsed.packet[0] >> 2) & 0x0F);
    }

    return parsed.type != RohcPacketType::Unknown;
}

inline const uint8_t* decoder_packet_start(const ParsedRohcPacket& parsed)
{
    if(parsed.has_add_cid &&
       (parsed.type == RohcPacketType::IR || parsed.type == RohcPacketType::IR_DYN))
    {
        return parsed.wire;
    }
    return parsed.packet;
}

inline size_t decoder_packet_len(const ParsedRohcPacket& parsed)
{
    if(parsed.has_add_cid &&
       (parsed.type == RohcPacketType::IR || parsed.type == RohcPacketType::IR_DYN))
    {
        return parsed.wire_len;
    }
    return parsed.packet_len;
}

} // namespace rohccxx
