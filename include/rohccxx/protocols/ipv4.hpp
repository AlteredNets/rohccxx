// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/wire/types.hpp"
#include "rohccxx/wire/convert.hpp"

namespace rohccxx::ipv4
{

struct Header
{
    wire::u8   version_ihl;
    wire::u8   tos;
    wire::be16 total_length;
    wire::be16 identification;
    wire::be16 flags_fragment;
    wire::u8   ttl;
    wire::u8   protocol;
    wire::be16 checksum;
    wire::be32 src;
    wire::be32 dst;
};

inline bool is_fragmented(std::uint16_t flags_fragment) noexcept
{
    // RFC 5225 compresses only packets with MF == 0 and fragment offset == 0.
    // The reserved flag is intentionally excluded, preserving existing behavior.
    return (flags_fragment & 0x3FFFU) != 0U;
}

inline bool is_fragmented(const Header& header) noexcept
{
    return is_fragmented(wire::to_host(header.flags_fragment));
}

static inline bool parse(const uint8_t* data,
                         size_t len,
                         const Header*& hdr,
                         size_t& header_len) noexcept
{
    if (len < sizeof(Header))
        return false;

    const auto* ip = reinterpret_cast<const Header*>(data);

    uint8_t vihl = wire::to_host(ip->version_ihl);
   
    if ((vihl >> 4) != 4)
        return false;

    header_len = (vihl & 0x0F) * 4;
    if (header_len < sizeof(Header) || header_len > len)
        return false;

    hdr = ip;
    return true;
}

} // namespace rohccxx::ipv4
