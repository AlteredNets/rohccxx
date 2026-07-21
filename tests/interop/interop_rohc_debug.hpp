// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>

#include "interop_debug.hpp"

extern "C" {
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>
#include <rohc/rohc_traces.h>
}

namespace interop_rohc_debug {

inline int random_cb(const struct rohc_comp*, void*)
{
    static std::uint32_t seed = 0x12345678u;
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return static_cast<int>(seed & 0x7fffffffU);
}

inline void trace_cb(void*,
                     const rohc_trace_level_t level,
                     const rohc_trace_entity_t entity,
                     const int profile,
                     const char* format,
                     ...)
{
    if(!interop_debug::trace_enabled() && level < ROHC_TRACE_WARNING)
    {
        return;
    }

    const char* level_str = "UNKNOWN";
    switch(level)
    {
        case ROHC_TRACE_DEBUG:   level_str = "DEBUG"; break;
        case ROHC_TRACE_INFO:    level_str = "INFO"; break;
        case ROHC_TRACE_WARNING: level_str = "WARN"; break;
        case ROHC_TRACE_ERROR:   level_str = "ERROR"; break;
        default: break;
    }

    const char* entity_str = (entity == ROHC_TRACE_COMP) ? "COMP" : "DECOMP";

    std::fprintf(stderr, "[ROHC][%s][%s][%d] ", level_str, entity_str, profile);
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    std::fprintf(stderr, "\n");
}

} // namespace interop_rohc_debug
