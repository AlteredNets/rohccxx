// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>

namespace rohccxx::wire
{
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
}