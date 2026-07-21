// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// tests/interop/rohccxx_decode.cpp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "interop_debug.hpp"
#include "rohccxx.h"

int main()
{
    uint8_t rohc[512];
    uint8_t out[1500];

    size_t rohc_len = fread(rohc, 1, sizeof(rohc), stdin);
    if (rohc_len == 0)
        return 2;

    interop_debug::dump_bytes("rohccxx_decode input", rohc, rohc_len);

    size_t out_len = sizeof(out);

    rohc_decomp* dec = rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK);
    if (!dec)
        return 3;

    if (rohc_decompress4(dec, rohc, rohc_len, out, &out_len) != 0)
    {
        rohc_decomp_free(dec);
        return 4;
    }

    interop_debug::dump_bytes("rohccxx_decode output", out, out_len);

    rohc_decomp_free(dec);

    uint16_t seq = (out[30] << 8) | out[31];
    if (seq != 2000 && seq != 0x1234)
        return 5;

    return 0;
}
