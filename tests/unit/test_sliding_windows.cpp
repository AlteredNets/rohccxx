// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <cmath>

#include "rohccxx/core/lsb_window.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/decode_fo.hpp"

TEST_CASE("Sprint 8: LSB window decodes reordered sequence")
{
    using namespace rohccxx;

    LsbWindow<uint16_t, 8> win;
    win.init(1000);

    uint16_t lsb_1002 = 1002 % 64;
    uint16_t v1 = win.decode(lsb_1002, 6);
    REQUIRE(v1 == 1002);

    win.update(v1);

    uint16_t lsb_1000 = 1000 % 64;
    uint16_t v2 = win.decode(lsb_1000, 6);
    REQUIRE(v2 == 1000);
}

TEST_CASE("Sprint 8: FO decoding survives loss and reordering")
{
    using namespace rohccxx;

    Context ctx{};
    ctx.rohc_state = RohcState::DynamicEstablished;
    ctx.rtp.initialized = 1;

    ctx.rtp.last_seq = 1000;
    ctx.rtp.last_ts  = 50000;

    ctx.rtp.seq_window.init(1000);
    ctx.rtp.ts_window.init(50000);

    uint8_t packet[16];
    size_t len = 0;

    uint16_t seq_out;
    uint32_t ts_out;

    Context txctx{};
    txctx.cid = 0;
    txctx.profile = Profile::RTP;
    txctx.mode = Mode::Optimistic;
    txctx.rohc_state = RohcState::DynamicEstablished;

    txctx.rtp.initialized = 1;
    txctx.rtp.last_seq = 1001;
    txctx.rtp.last_ts  = 50160;

    txctx.rtp.seq_window.init(ctx.rtp.last_seq);
    txctx.rtp.ts_window.init(ctx.rtp.last_ts);

    // FO(seq=1001)
    std::memset(packet, 0, sizeof(packet));
    len = 0;
    emit_rtp_fo(packet, &len, txctx);
    REQUIRE(decode_fo_rtp(packet, len, ctx, seq_out, ts_out));
    REQUIRE(seq_out == 1001);

    // FO(seq=1003)
    std::memset(packet, 0, sizeof(packet));
    len = 0;
    txctx.rtp.last_seq = 1003;
    txctx.rtp.last_ts  = 50320;
    emit_rtp_fo(packet, &len, txctx);
    REQUIRE(decode_fo_rtp(packet, len, ctx, seq_out, ts_out));
    REQUIRE(seq_out == 1003);

    // FO(seq=1002)
    std::memset(packet, 0, sizeof(packet));
    len = 0;
    txctx.rtp.last_seq = 1002;
    txctx.rtp.last_ts  = 50240;
    emit_rtp_fo(packet, &len, txctx);
    REQUIRE(decode_fo_rtp(packet, len, ctx, seq_out, ts_out));
    REQUIRE(seq_out == 1002);
}

TEST_CASE("Sprint 8: FO sequence number wrap-around")
{
    using namespace rohccxx;

    Context ctx{};
    ctx.rohc_state = RohcState::DynamicEstablished;
    ctx.rtp.initialized = 1;

    ctx.rtp.last_seq = 65534;
    ctx.rtp.last_ts  = 100000;

    ctx.rtp.seq_window.init(65534);
    ctx.rtp.ts_window.init(100000);

    uint8_t pkt[16];
    size_t len = 0;

    uint16_t seq;
    uint32_t ts;

    Context txctx{};
    txctx.cid = 0;
    txctx.profile = Profile::RTP;
    txctx.mode = Mode::Optimistic;
    txctx.rohc_state = RohcState::DynamicEstablished;

    txctx.rtp.initialized = 1;
    txctx.rtp.last_seq = 65535;
    txctx.rtp.last_ts  = 100160;

    txctx.rtp.seq_window.init(ctx.rtp.last_seq);
    txctx.rtp.ts_window.init(ctx.rtp.last_ts);

    emit_rtp_fo(pkt, &len, txctx);
    REQUIRE(len > 0);
    REQUIRE(decode_fo_rtp(pkt, len, ctx, seq, ts));
    REQUIRE(seq == 65535);

    txctx.rtp.last_seq = 0;
    txctx.rtp.last_ts  = 100320;
    emit_rtp_fo(pkt, &len, txctx);
    REQUIRE(len > 0);
    REQUIRE(decode_fo_rtp(pkt, len, ctx, seq, ts));
    REQUIRE(seq == 0);
}

TEST_CASE("Sprint 8: FO timestamp drift is reconstructed correctly")
{
    using namespace rohccxx;

    Context ctx{};
    ctx.rohc_state = RohcState::DynamicEstablished;
    ctx.rtp.initialized = 1;

    ctx.rtp.last_seq = 1000;
    ctx.rtp.last_ts  = 100000;

    ctx.rtp.seq_window.init(1000);
    ctx.rtp.ts_window.init(100000);

    uint8_t pkt[16];
    size_t len = 0;

    uint16_t seq;
    uint32_t ts;

    Context txctx{};
    txctx.cid = 0;
    txctx.profile = Profile::RTP;
    txctx.mode = Mode::Optimistic;
    txctx.rohc_state = RohcState::DynamicEstablished;

    txctx.rtp.initialized = 1;
    txctx.rtp.last_seq = 1001;
    txctx.rtp.last_ts  = 200000;

    txctx.rtp.seq_window.init(ctx.rtp.last_seq);
    txctx.rtp.ts_window.init(ctx.rtp.last_ts);

    emit_rtp_fo(pkt, &len, txctx);
    REQUIRE(len > 0);
    REQUIRE(decode_fo_rtp(pkt, len, ctx, seq, ts));
    REQUIRE(std::abs(int(ts) - int(ctx.rtp.last_ts)) <= 128);

    txctx.rtp.last_seq = 1002;
    txctx.rtp.last_ts  = 350000;
    emit_rtp_fo(pkt, &len, txctx);
    REQUIRE(len > 0);
    REQUIRE(decode_fo_rtp(pkt, len, ctx, seq, ts));
    REQUIRE(std::abs(int(ts) - int(ctx.rtp.last_ts)) <= 128);
}