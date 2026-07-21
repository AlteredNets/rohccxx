// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstdint>
#include <cstddef>

namespace rohccxx
{

template <typename T, size_t WindowSize>
struct LsbWindow
{
    T ref = 0;

    void init(T initial)
    {
        ref = initial;
    }

    void update(T value)
    {
        ref = value;
    }

    static T dist_mod(T a, T b)
    {
        T d = (a >= b) ? (a - b) : (b - a);
        T wrap = (T)(~T(0)) - d + 1;  // 2^N - d
        return (d < wrap) ? d : wrap;
    }

    T decode(T lsb, uint8_t k) const
    {
        const T range = T(1) << k;
        const T half  = range >> 1;

        // interpretation interval base (RFC-correct)
        const T base =
            ((ref + half) / range) * range;

        const T c0 = base + lsb;
        const T c1 = c0 + range;
        const T c2 = c0 - range;

        T best = c0;
        T best_dist = dist_mod(c0, ref);

        T d1 = dist_mod(c1, ref);
        if (d1 < best_dist)
        {
            best = c1;
            best_dist = d1;
        }

        T d2 = dist_mod(c2, ref);
        if (d2 < best_dist)
        {
            best = c2;
        }

        return best;
    }
};

} // namespace rohccxx