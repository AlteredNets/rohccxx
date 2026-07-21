// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "test_packet_helpers.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/core/emit_ir_dyn.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/utils/crc.hpp"
#include "rohccxx/wire/convert.hpp"
#include "rohccxx/wire/types.hpp"

TEST_CASE("Sprint 5: First RTP packet emits IR", "[sprint5][ir]")
{
    rohc_comp* c = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);

    uint8_t pkt[64] = {};
    uint8_t out[128];
    size_t out_len = sizeof(out);

    make_valid_rtp(pkt, 1000, 1234, 0x11223344);

    REQUIRE(rohc_compress4(c, pkt, sizeof(pkt), out, &out_len) == 0);

    // ✅ Verify IR semantics by decoding
    rohccxx::Context ctx{};
    REQUIRE(rohccxx::decode_ir_rtp(out, out_len, ctx));

    REQUIRE(ctx.rtp.ssrc == 0x11223344);
    REQUIRE(ctx.rtp.last_seq == 1000);
    REQUIRE(ctx.rtp.last_ts == 1234);
    REQUIRE(ctx.rohc_state == rohccxx::RohcState::DynamicEstablished);

    rohc_comp_free(c);
}

TEST_CASE("Sprint 5: Second RTP packet emits IR-DYN", "[sprint5][ir-dyn]")
{
    rohc_comp* c = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);

    uint8_t pkt[64] = {};
    uint8_t out[128];
    size_t out_len;

    // First packet → IR
    make_valid_rtp(pkt, 1000, 1234, 0x11223344);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(c, pkt, sizeof(pkt), out, &out_len) == 0);

    rohccxx::Context ctx{};
    REQUIRE(rohccxx::decode_ir_rtp(out, out_len, ctx));

    // Second packet → IR‑DYN
    make_valid_rtp(pkt, 1001, 1334, 0x11223344);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(c, pkt, sizeof(pkt), out, &out_len) == 0);

    REQUIRE(rohccxx::decode_ir_dyn_rtp(out, out_len, ctx));

    REQUIRE(ctx.rtp.last_seq == 1001);
    REQUIRE(ctx.rtp.last_ts == 1334);
    REQUIRE(ctx.rohc_state == rohccxx::RohcState::DynamicEstablished);

    rohc_comp_free(c);
}
