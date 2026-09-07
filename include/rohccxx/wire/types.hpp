// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>

namespace rohccxx::wire
{
    // These wrappers describe bytes in packet buffers. Packet entry points
    // accept arbitrary byte alignment, so the wire scalars must not impose a
    // stronger alignment on protocol header views.
#pragma pack(push, 1)
    struct be16
    {
        uint16_t v;
    };

    struct be32
    {
        uint32_t v;
    };

    struct u8
    {
        uint8_t v;
    };
#pragma pack(pop)

    static_assert(sizeof(be16) == 2 && alignof(be16) == 1);
    static_assert(sizeof(be32) == 4 && alignof(be32) == 1);
    static_assert(sizeof(u8) == 1 && alignof(u8) == 1);
}
