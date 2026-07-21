// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/wire/types.hpp"

namespace rohccxx::udp
{

struct Header
{
    wire::be16 src_port;
    wire::be16 dst_port;
    wire::be16 length;
    wire::be16 checksum;
};

static inline bool parse(const uint8_t* base,
                         size_t total_len,
                         const uint8_t* data,
                         const Header*& hdr) noexcept
{
    if (!utils::bounds_check(base, total_len,
                             reinterpret_cast<const Header*>(data)))
        return false;

    hdr = reinterpret_cast<const Header*>(data);
    return true;
}

} // namespace rohccxx::udp