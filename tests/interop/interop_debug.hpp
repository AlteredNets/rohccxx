// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace interop_debug {

inline bool enabled()
{
    static const bool value = [] {
        const char* env = std::getenv("ROHCCXX_INTEROP_DEBUG");
        return env != nullptr && *env != '\0' && *env != '0';
    }();
    return value;
}

inline bool trace_enabled()
{
    static const bool value = [] {
        const char* env = std::getenv("ROHCCXX_INTEROP_TRACE");
        return env != nullptr && *env != '\0' && *env != '0';
    }();
    return value;
}

inline void dump_bytes(const char* label, const std::uint8_t* data, std::size_t len)
{
    if(!enabled())
    {
        return;
    }

    std::fprintf(stderr, "[%s] %zu bytes", label, len);
    for(std::size_t i = 0; i < len; ++i)
    {
        if((i % 16U) == 0)
        {
            std::fprintf(stderr, "\n[%s] ", label);
        }
        std::fprintf(stderr, "%02X ", data[i]);
    }
    std::fprintf(stderr, "\n");
}

} // namespace interop_debug
