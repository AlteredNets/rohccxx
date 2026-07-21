// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// tests/interop/rohccxx_emit.cpp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "interop_debug.hpp"
#include "rohccxx.h"
#include "test_packet_helpers.hpp"

int main()
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    if (!comp)
        return 2;

#ifdef ROHCCXX_ENABLE_VALIDATION_MODE
    rohccxx_force_u_mode(*comp);
#endif

    uint16_t seq = 1000;
    uint32_t ts  = 100000;
    const uint32_t ssrc = 0x11223344;

    for (int i = 0; i < 40; ++i)
    {
        uint8_t ip[64]   = {};
        uint8_t rohc[512];
        size_t rohc_len = sizeof(rohc);

        if (i < 30)
        {
            make_valid_rtp(ip, seq, ts, ssrc);
        }
        else
        {
            ++seq;
            ts += 160;
            make_valid_rtp(ip, seq, ts, ssrc);
        }

        int rc = rohc_compress4(comp,
                                ip,
                                sizeof(ip),
                                rohc,
                                &rohc_len);

        std::fprintf(stderr,
                     "rohccxx_emit: packet %d, ROHC bytes = %zu\n",
                     i, rohc_len);
        interop_debug::dump_bytes("rohccxx_emit", rohc, rohc_len);

        if (rc != 0)
        {
            rohc_comp_free(comp);
            return 3;
        }

        size_t written = fwrite(rohc, 1, rohc_len, stdout);
        if (written != rohc_len)
        {
            rohc_comp_free(comp);
            return 4;
        }
    }

    fflush(stdout);
    rohc_comp_free(comp);
    return 0;
}
