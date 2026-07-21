// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>

inline std::uint16_t ipv4_checksum(const std::uint8_t* hdr, int len)
{
    std::uint32_t sum = 0;
    for(int i = 0; i < len; i += 2)
    {
        std::uint16_t word = static_cast<std::uint16_t>(hdr[i] << 8);
        if(i + 1 < len)
            word |= hdr[i + 1];
        sum += word;
    }

    while(sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return static_cast<std::uint16_t>(~sum);
}

/*
 * Build a minimal, valid IPv4 + UDP + RTP packet
 * suitable for rohccxx unit tests.
 *
 * All multibyte fields are in network byte order.
 */
inline void make_valid_rtp(uint8_t* pkt,
                           uint16_t seq,
                           uint32_t ts,
                           uint32_t ssrc)
{
    for (int i = 0; i < 64; ++i)
        pkt[i] = 0;

    /* ---- IPv4 ---- */
    pkt[0] = 0x45;        // Version 4, IHL = 5
    pkt[1] = 0x00;        // DSCP/ECN
    pkt[2] = 0x00;        // Total length = 64 bytes
    pkt[3] = 0x40;
    pkt[8] = 64;          // TTL
    pkt[9] = 17;          // Protocol = UDP

    /* ---- UDP (ports arbitrary for test) ---- */
    pkt[20] = 0x12;
    pkt[21] = 0x34;
    pkt[22] = 0x56;
    pkt[23] = 0x78;
    pkt[24] = 0x00;       // UDP length = 44 bytes
    pkt[25] = 0x2C;
    pkt[26] = 0x00;
    pkt[27] = 0x00;       // Zero checksum is allowed

    /* ---- RTP ---- */
    pkt[28] = 0x80;       // RTP version 2, no padding, no extension
    pkt[29] = 0x00;       // Marker = 0, payload type = 0

    // Sequence number
    pkt[30] = static_cast<uint8_t>(seq >> 8);
    pkt[31] = static_cast<uint8_t>(seq & 0xFF);

    // Timestamp
    pkt[32] = static_cast<uint8_t>((ts >> 24) & 0xFF);
    pkt[33] = static_cast<uint8_t>((ts >> 16) & 0xFF);
    pkt[34] = static_cast<uint8_t>((ts >> 8) & 0xFF);
    pkt[35] = static_cast<uint8_t>(ts & 0xFF);

    // SSRC (must be non-zero)
    pkt[36] = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    pkt[37] = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    pkt[38] = static_cast<uint8_t>((ssrc >> 8) & 0xFF);
    pkt[39] = static_cast<uint8_t>(ssrc & 0xFF);

    // IPv4 header checksum over the 20-byte header.
    const std::uint16_t csum = ipv4_checksum(pkt, 20);
    pkt[10] = static_cast<std::uint8_t>(csum >> 8);
    pkt[11] = static_cast<std::uint8_t>(csum & 0xFF);
}
