// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/wire/types.hpp"
#include "rohccxx/utils/bytes.hpp"

namespace rohccxx::wire
{
    inline uint16_t to_host(be16 v)
    {
        return utils::load_be16(&v.v);
    }

    inline uint32_t to_host(be32 v)
    {
        return utils::load_be32(&v.v);
    }

    inline uint8_t to_host(u8 v)
    {
        return v.v;
    }
}