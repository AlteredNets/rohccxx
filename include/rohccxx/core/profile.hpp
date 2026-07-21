// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/context.hpp"
#include "rohccxx/protocols/ipv4.hpp"
#include "rohccxx/protocols/udp.hpp"
#include "rohccxx/protocols/rtp.hpp"

namespace rohccxx
{

inline Profile select_profile(const ipv4::Header* ip,
                              const udp::Header* udp,
                              const rtp::Header* rtp) noexcept
{
    if (ip && udp && rtp)
        return Profile::RTP;

    if (ip && udp)
        return Profile::UDP;

    return Profile::Uncompressed;
}

} // namespace rohccxx