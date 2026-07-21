// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// tests/interop/rohclib_decode.cpp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "interop_rohc_debug.hpp"
#include "rohc_lib_compat.h"

int main()
{
    uint8_t rohc[512];
    uint8_t out[1500];

    size_t rohc_len = fread(rohc, 1, sizeof(rohc), stdin);
    if (rohc_len == 0)
        return 2;

    interop_debug::dump_bytes("rohclib_decode input", rohc, rohc_len);

    size_t out_len = sizeof(out);

    struct rohc_decomp* dec =
        rohc_decomp_new2(ROHC_SMALL_CID,
                         ROHC_SMALL_CID_MAX,
                         ROHC_U_MODE);
    if (!dec)
        return 3;

    if (!rohc_decomp_set_traces_cb2(dec, interop_rohc_debug::trace_cb, nullptr))
    {
        rohc_decomp_free(dec);
        return 4;
    }

    if (!rohc_decomp_enable_profile(dec, ROHC_PROFILE_RTP))
    {
        rohc_decomp_free(dec);
        return 5;
    }

    rohc_status_t status =
        rohc_decompress_compat(dec,
                                rohc,
                                rohc_len,
                                out,
                                &out_len);

    rohc_decomp_free(dec);

    if (status != ROHC_STATUS_OK)
        return 6;

    interop_debug::dump_bytes("rohclib_decode output", out, out_len);

    uint16_t seq = (out[30] << 8) | out[31];
    if (seq != 1000)
        return 7;

    return 0;
}
