// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "rohccxx/core/context_table.hpp"

TEST_CASE("Context table allocates and retrieves contexts")
{
    rohccxx::ContextTable tbl;
    REQUIRE(tbl.init(8));

    auto* ctx = tbl.get(3);
    REQUIRE(ctx != nullptr);

    ctx->cid     = 3;
    ctx->profile = rohccxx::Profile::RTP;

    auto* ctx2 = tbl.get(3);
    REQUIRE(ctx2->cid == 3);
    REQUIRE(ctx2->profile == rohccxx::Profile::RTP);

    tbl.destroy();
}