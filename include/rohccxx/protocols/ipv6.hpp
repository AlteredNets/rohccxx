// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/wire/types.hpp"
#include "rohccxx/wire/convert.hpp"

namespace rohccxx::ipv6
{

struct Header
{
    wire::be32 version_tc_flow;
    wire::be16 payload_length;
    wire::u8   next_header;
    wire::u8   hop_limit;
    std::uint8_t src[16];
    std::uint8_t dst[16];
};

inline bool is_extension_header(std::uint8_t next_header) noexcept
{
    return next_header == 0 || next_header == 43 || next_header == 44 || next_header == 60;
}

inline bool extension_header_len(const std::uint8_t* data,
                                 size_t len,
                                 std::uint8_t next_header,
                                 size_t& header_len) noexcept
{
    if(next_header == 44)
    {
        header_len = 8;
        return len >= header_len;
    }

    if(len < 2)
        return false;

    header_len = static_cast<size_t>(data[1] + 1U) * 8U;
    return header_len >= 8U && len >= header_len;
}

inline bool parse(const std::uint8_t* data,
                  size_t len,
                  const Header*& hdr,
                  size_t& header_len,
                  std::uint8_t& terminal_next_header,
                  size_t& extension_len) noexcept
{
    if(len < sizeof(Header))
        return false;

    const auto* ip = reinterpret_cast<const Header*>(data);
    const std::uint32_t first_word = wire::to_host(ip->version_tc_flow);
    if((first_word >> 28) != 6U)
        return false;

    const size_t total_len = sizeof(Header) + wire::to_host(ip->payload_length);
    if(total_len > len)
        return false;

    std::uint8_t next = wire::to_host(ip->next_header);
    size_t pos = sizeof(Header);
    extension_len = 0;
    while(is_extension_header(next))
    {
        size_t ext_len = 0;
        if(!extension_header_len(data + pos, total_len - pos, next, ext_len))
            return false;
        next = data[pos];
        pos += ext_len;
        extension_len += ext_len;
    }

    terminal_next_header = next;
    header_len = pos;
    hdr = ip;
    return true;
}

} // namespace rohccxx::ipv6
