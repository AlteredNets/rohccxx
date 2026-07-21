// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include "rohccxx/core/context.hpp"

namespace rohccxx
{

struct ContextTable
{
    Context* table = nullptr;
    uint32_t max_cid = 0;

    bool init(uint32_t max)
    {
        max_cid = max;
        table = new Context[max_cid + 1]();
        return table != nullptr;
    }
    
    void destroy()
    {
        delete[] table;
        table = nullptr;
        max_cid = 0;
    }

    Context* get(uint32_t cid)
    {
        if (cid > max_cid)
            return nullptr;
        return &table[cid];
    }
};

} // namespace rohccxx