// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>
#include "test_packet_helpers.hpp"

namespace
{
struct RohcSession
{
    rohc_comp* comp = nullptr;
    rohc_decomp* dec = nullptr;

    ~RohcSession()
    {
        rohc_decomp_free(dec);
        rohc_comp_free(comp);
    }
};
} // namespace

TEST_CASE("Sprint 6: compress → decompress RTP", "[sprint6][roundtrip]")
{
    RohcSession session{rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK),
                        rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK)};

    uint8_t ip[64];
    uint8_t rohc[64];
    uint8_t out[1500];
    size_t rohc_len;
    size_t out_len = sizeof(out);

    make_valid_rtp(ip, 1000, 1234, 0xCAFEBABE);

    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(session.comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(session.dec, rohc, rohc_len, out, &out_len) == 0);

    // Check reconstructed sequence number, timestamp, SSRC
}
