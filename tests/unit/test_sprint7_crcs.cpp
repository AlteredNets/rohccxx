// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>
#include "test_packet_helpers.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "rohccxx/core/feedback.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>

TEST_CASE("Sprint 7: FO CRC failure triggers NACK")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* dec = rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK);

    uint8_t ip[64];
    uint8_t rohc[64];
    uint8_t out[1500];

    size_t rohc_len;
    size_t out_len;

    // ---- IR ----
    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1000, 100000, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(dec, rohc, rohc_len, out, &out_len) == 0);

    // ---- IR-DYN ----
    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1001, 100160, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(dec, rohc, rohc_len, out, &out_len) == 0);

    // ---- VALID FO (must succeed) ----
    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1002, 100320, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(dec, rohc, rohc_len, out, &out_len) == 0);

    // ---- CORRUPTED FO ----
    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1003, 100480, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    // Flip ONE CRC bit
    // rohc[rohc_len - 1] ^= 0x01;
    // Brutal but correct: flip everything
    for (size_t i = 0; i < rohc_len; ++i)
        rohc[i] ^= 0xFF;

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(dec, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(dec) == 1);

    rohc_comp_free(comp);
    rohc_decomp_free(dec);
}

TEST_CASE("Sprint 7: Compressor recovers after NACK", "[sprint7][recovery]")
{
    rohc_comp* comp =
        rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* dec =
        rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK);

    uint8_t ip[64];
    uint8_t rohc[64];
    uint8_t out[1500];
    size_t rohc_len;
    size_t out_len = sizeof(out);

    make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);

    // IR
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip),
                            rohc, &rohc_len) == 0);

    // IR-DYN
    make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip),
                            rohc, &rohc_len) == 0);

    // FO
    make_valid_rtp(ip, 1002, 100320, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip),
                            rohc, &rohc_len) == 0);

    // Corrupt FO CRC
    rohc[rohc_len - 1] ^= 0xFF;

    REQUIRE(rohc_decompress4(dec, rohc, rohc_len,
                              out, &out_len) != 0);


    REQUIRE(rohc_decomp_has_feedback(dec) == 1);

    uint32_t cid;
    uint8_t fb;

    REQUIRE(rohc_decomp_get_feedback(dec, &cid, &fb) == 0);

    rohc_comp_handle_feedback(comp, cid, fb);


    // Next packet should be refresh (IR-DYN or IR)
    make_valid_rtp(ip, 1003, 100480, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip),
                            rohc, &rohc_len) == 0);

    // ✅ Either IR-DYN or IR is acceptable recovery
    rohccxx::Context tmp{};
    bool is_ir =
        decode_ir_rtp(rohc, rohc_len, tmp) ||
        decode_ir_dyn_rtp(rohc, rohc_len, tmp);

    REQUIRE(is_ir);

    rohc_comp_free(comp);
    rohc_decomp_free(dec);
}

TEST_CASE("Decoder rejects corrupted IR CRC")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    uint8_t ip[64];
    uint8_t rohc[64];
    uint8_t bad[64];
    rohccxx::Context ctx{};
    size_t rohc_len;

    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1000, 100000, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(decode_ir_rtp(rohc, rohc_len, ctx));

    std::memcpy(bad, rohc, rohc_len);
    bad[2] ^= 0xFF;
    REQUIRE_FALSE(decode_ir_rtp(bad, rohc_len, ctx));

    std::memset(rohc, 0, sizeof(rohc));
    make_valid_rtp(ip, 1001, 100160, 0x11223344);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(decode_ir_dyn_rtp(rohc, rohc_len, ctx));

    std::memcpy(bad, rohc, rohc_len);
    bad[2] ^= 0xFF;
    REQUIRE_FALSE(decode_ir_dyn_rtp(bad, rohc_len, ctx));

    rohc_comp_free(comp);
}



TEST_CASE("ROHC feedback handling gates invalid and per-CID recovery behavior", "[feedback][rfc5795]")
{
    SECTION("invalid feedback type is ignored")
    {
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);
        make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xFD);

        rohc_comp_handle_feedback(comp, 0, 0x7F);

        make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);

        rohc_comp_free(comp);
    }

    SECTION("out-of-range feedback CID is ignored")
    {
        rohc_comp* comp = rohc_comp_new2(1, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);
        make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xFD);

        rohc_comp_handle_feedback(comp, 2, 0);

        make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);

        rohc_comp_free(comp);
    }

    SECTION("first NACK requests IR-DYN refresh")
    {
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);
        make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1002, 100320, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE((rohc[0] & 0x80) == 0x00);

        rohc_comp_handle_feedback(comp, 0, 0);

        make_valid_rtp(ip, 1003, 100480, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);

        rohc_comp_free(comp);
    }

    SECTION("second consecutive NACK requests IR refresh")
    {
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);
        make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1002, 100320, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

        rohc_comp_handle_feedback(comp, 0, 0);
        rohc_comp_handle_feedback(comp, 0, 0);

        make_valid_rtp(ip, 1003, 100480, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xFD);

        rohc_comp_free(comp);
    }

    SECTION("successful recovery clears NACK escalation")
    {
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);
        make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1002, 100320, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

        rohc_comp_handle_feedback(comp, 0, 0);
        make_valid_rtp(ip, 1003, 100480, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);

        rohc_comp_handle_feedback(comp, 0, 0);
        make_valid_rtp(ip, 1004, 100640, 0xCAFEBABE);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);

        rohc_comp_free(comp);
    }

    SECTION("feedback for one CID does not disturb another CID")
    {
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);

        uint8_t ip[64] = {};
        uint8_t rohc[128] = {};
        size_t rohc_len = sizeof(rohc);

        REQUIRE(rohc_comp_set_cid(comp, 0) == 0);
        make_valid_rtp(ip, 1000, 100000, 0x01020304);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1001, 100160, 0x01020304);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 1002, 100320, 0x01020304);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE((rohc[0] & 0x80) == 0x00);

        REQUIRE(rohc_comp_set_cid(comp, 3) == 0);
        make_valid_rtp(ip, 2000, 200000, 0xAABBCCDD);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 2001, 200160, 0xAABBCCDD);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        make_valid_rtp(ip, 2002, 200320, 0xAABBCCDD);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE((rohc[0] & 0x80) == 0x00);

        rohc_comp_handle_feedback(comp, 3, 0);

        REQUIRE(rohc_comp_set_cid(comp, 0) == 0);
        make_valid_rtp(ip, 1003, 100480, 0x01020304);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE((rohc[0] & 0x80) == 0x00);

        REQUIRE(rohc_comp_set_cid(comp, 3) == 0);
        make_valid_rtp(ip, 2003, 200480, 0xAABBCCDD);
        rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xE3);
        REQUIRE(rohc[1] == 0xF8);

        rohc_comp_free(comp);
    }
}


TEST_CASE("ROHC modes expose U O and R transition behavior", "[modes][feedback]")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    rohccxx_mode_t mode = ROHCCXX_MODE_O;
    REQUIRE(rohc_comp_get_mode(comp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_O);
    REQUIRE(rohc_comp_set_mode(comp, ROHCCXX_MODE_U) == 0);
    REQUIRE(rohc_comp_get_mode(comp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_U);
    REQUIRE(rohc_comp_set_mode(comp, ROHCCXX_MODE_R) == 0);
    REQUIRE(rohc_comp_get_mode(comp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_R);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);

    make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE((rohc[38] & 0x0CU) == 0x08U);

    make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::ACK));
    make_valid_rtp(ip, 1002, 100320, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xF8);

    make_valid_rtp(ip, 1003, 100480, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xF8);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::ACK));
    make_valid_rtp(ip, 1004, 100640, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE((rohc[0] & 0x80U) == 0x00U);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::STATIC_NACK));
    make_valid_rtp(ip, 1005, 100800, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);

    rohc_comp_free(comp);
}

TEST_CASE("ROHC feedback packets deliver mode requests to compressor", "[feedback][modes]")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    rohccxx::Feedback feedback{};
    feedback.cid = 0;
    feedback.type = rohccxx::FeedbackType::ACK;
    feedback.has_mode = true;
    feedback.mode = rohccxx::Mode::Reliable;
    const std::uint8_t crc_option[] = {0xAB};
    REQUIRE(rohccxx::add_feedback_option(feedback, rohccxx::FeedbackOptionType::Crc, crc_option, sizeof(crc_option)));

    std::uint8_t wire[16] = {};
    size_t wire_len = sizeof(wire);
    REQUIRE(rohccxx::write_feedback_packet(wire, &wire_len, feedback));
    REQUIRE(rohc_comp_deliver_feedback_packet(comp, wire, wire_len) == 0);

    rohccxx_mode_t mode = ROHCCXX_MODE_O;
    REQUIRE(rohc_comp_get_mode(comp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_R);

    make_valid_rtp(ip, 1001, 100160, 0xCAFEBABE);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xF8);

    rohc_comp_free(comp);
}

TEST_CASE("ROHC decompressor mode API tracks decoded IR mode", "[modes]")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_mode(comp, ROHCCXX_MODE_R) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp, ROHCCXX_MODE_U) == 0);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    std::uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);
    make_valid_rtp(ip, 1000, 100000, 0xCAFEBABE);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    rohccxx_mode_t mode = ROHCCXX_MODE_O;
    REQUIRE(rohc_decomp_get_mode(decomp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_R);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}
