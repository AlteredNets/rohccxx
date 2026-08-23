// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// tests/interop/rohclib_emit.cpp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "interop_rohc_debug.hpp"
#include "test_packet_helpers.hpp"

static bool is_rtp_packet(const unsigned char*,
                          const unsigned char*,
                          const unsigned char* payload,
                          const unsigned int payload_size,
                          void*)
{
    return payload_size >= 12U && (payload[0] >> 6) == 2;
}

int main()
{
    struct rohc_comp* comp =
        rohc_comp_new2(ROHC_SMALL_CID,
                       ROHC_SMALL_CID_MAX,
                       interop_rohc_debug::random_cb,
                       nullptr);
    if (!comp)
        return 2;

    if (!rohc_comp_set_traces_cb2(comp, interop_rohc_debug::trace_cb, nullptr))
    {
        rohc_comp_free(comp);
        return 3;
    }

    if (!rohc_comp_set_rtp_detection_cb(comp, is_rtp_packet, nullptr))
    {
        rohc_comp_free(comp);
        return 4;
    }

    if (!rohc_comp_enable_profile(comp, ROHCv2_PROFILE_IP_UDP_RTP))
    {
        rohc_comp_free(comp);
        return 5;
    }

    uint16_t seq = 2000;
    uint32_t ts  = 180000;
    const uint32_t ssrc = 0x55667788;

    for (int i = 0; i < 40; ++i)
    {
        uint8_t ip[64]   = {};
        uint8_t rohc[512];

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

        struct rohc_buf ip_input =
            rohc_buf_init_full(ip, sizeof(ip), sizeof(ip));

        struct rohc_buf rohc_output =
            rohc_buf_init_empty(rohc, sizeof(rohc));

        rohc_status_t status =
            rohc_compress4(comp, ip_input, &rohc_output);

        std::fprintf(stderr,
                     "rohclib_emit: packet %d, ROHC bytes = %zu\n",
                     i, rohc_output.len);
        interop_debug::dump_bytes("rohclib_emit", rohc_output.data, rohc_output.len);

        if (status != ROHC_STATUS_OK)
        {
            rohc_comp_free(comp);
            return 6;
        }

        size_t written = fwrite(rohc_output.data, 1, rohc_output.len, stdout);
        if (written != rohc_output.len)
        {
            rohc_comp_free(comp);
            return 7;
        }
    }

    fflush(stdout);
    rohc_comp_free(comp);
    return 0;
}
