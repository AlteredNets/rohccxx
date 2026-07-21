// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/wire/types.hpp"
#include "rohccxx/wire/convert.hpp"

namespace rohccxx::rtp
{

struct Header
{
    wire::u8   vpxcc;
    wire::u8   mpt;
    wire::be16 sequence;
    wire::be32 timestamp;
    wire::be32 ssrc;
};

static inline uint8_t version(const Header* h)
{
    return wire::to_host(h->vpxcc) >> 6;
}

static inline bool parse(const uint8_t* base,
                         size_t total_len,
                         const uint8_t* data,
                         const Header*& hdr) noexcept
{
    if (!utils::bounds_check(base, total_len,
                             reinterpret_cast<const Header*>(data)))
        return false;

    const auto* rtp = reinterpret_cast<const Header*>(data);

    if (version(rtp) != 2)
        return false;

    hdr = rtp;
    return true;
}

} // namespace rohccxx::rtp