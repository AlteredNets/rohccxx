// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.


#pragma once

#include "rohccxx/protocols/ipv4.hpp"
#include "rohccxx/protocols/ipv6.hpp"
#include "rohccxx/protocols/udp.hpp"
#include "rohccxx/protocols/rtp.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/wire/convert.hpp"

namespace rohccxx
{

inline Profile classify_packet(const uint8_t* pkt, size_t len)
{
    const uint8_t* transport = nullptr;
    uint8_t protocol = 0;

    const ipv4::Header* ip4;
    size_t ip_hlen = 0;
    if(ipv4::parse(pkt, len, ip4, ip_hlen))
    {
        if(ipv4::is_fragmented(*ip4))
            return Profile::Uncompressed;
        protocol = wire::to_host(ip4->protocol);
        transport = pkt + ip_hlen;
    }
    else
    {
        const ipv6::Header* ip6;
        size_t header_len = 0;
        size_t extension_len = 0;
        if(!ipv6::parse(pkt, len, ip6, header_len, protocol, extension_len))
            return Profile::Uncompressed;
        transport = pkt + header_len;
    }

    if (protocol == 17) // UDP
    {
        const udp::Header* udp;
        if (!udp::parse(pkt, len, transport, udp))
            return Profile::Uncompressed;

        const rtp::Header* rtp;
        if (rtp::parse(pkt, len, transport + sizeof(*udp), rtp))
            return Profile::RTP;

        return Profile::UDP;
    }

    if (protocol == 50) // ESP
        return Profile::ESP;

    if (protocol == 136) // UDP-Lite
    {
        const udp::Header* udp_lite;
        if (!udp::parse(pkt, len, transport, udp_lite))
            return Profile::Uncompressed;

        const rtp::Header* rtp;
        if (rtp::parse(pkt, len, transport + sizeof(*udp_lite), rtp))
            return Profile::RTP_UDP_Lite;

        return Profile::UDP_Lite;
    }

    return Profile::IP;
}

} // namespace rohccxx
