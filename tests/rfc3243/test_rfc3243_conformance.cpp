// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "rfc3243_conformance.hpp"

TEST_CASE("RFC 3243 conformance library accepts the complete lower-layer and flow contract")
{
    const auto contract = rohccxx::tests::rfc3243::complete_contract();
    const auto flow = rohccxx::tests::rfc3243::complete_flow();

    auto lower_layer = rohccxx::lla::validate_rfc3243_zero_byte_assumptions(contract);
    REQUIRE(lower_layer.valid);
    REQUIRE(lower_layer.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_no_header_packet(contract));

    auto full_flow = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow);
    REQUIRE(full_flow.valid);
    REQUIRE(full_flow.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_no_header_packet_for_flow(contract, flow));
}

TEST_CASE("RFC 3243 conformance library maps every lower-layer missing bit independently")
{
    const auto flow = rohccxx::tests::rfc3243::complete_flow();
    for(const auto& item : rohccxx::tests::rfc3243::contract_missing_cases())
    {
        CAPTURE(item.name);
        auto lower_layer = rohccxx::lla::validate_rfc3243_zero_byte_assumptions(item.contract);
        REQUIRE_FALSE(lower_layer.valid);
        REQUIRE((lower_layer.missing & item.missing) != 0);
        REQUIRE_FALSE(rohccxx::lla::can_emit_no_header_packet(item.contract));

        auto full_flow = rohccxx::lla::validate_rfc3243_zero_byte_flow(item.contract, flow);
        REQUIRE_FALSE(full_flow.valid);
        REQUIRE((full_flow.missing & item.missing) != 0);
        REQUIRE_FALSE(rohccxx::lla::can_emit_no_header_packet_for_flow(item.contract, flow));
    }
}

TEST_CASE("RFC 3243 conformance library maps every flow missing bit independently")
{
    const auto contract = rohccxx::tests::rfc3243::complete_contract();
    for(const auto& item : rohccxx::tests::rfc3243::flow_missing_cases())
    {
        CAPTURE(item.name);
        auto validation = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, item.flow);
        REQUIRE_FALSE(validation.valid);
        REQUIRE((validation.missing & item.missing) != 0);
        REQUIRE_FALSE(rohccxx::lla::can_emit_no_header_packet_for_flow(contract, item.flow));
    }
}

TEST_CASE("RFC 3243 conformance library reports aggregate missing assumptions")
{
    rohccxx::lla::AssistingLayerContract contract{};
    rohccxx::lla::ZeroByteFlow flow{};

    auto validation = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow);
    REQUIRE_FALSE(validation.valid);
    for(const auto& item : rohccxx::tests::rfc3243::contract_missing_cases())
        REQUIRE((validation.missing & item.missing) != 0);
    for(const auto& item : rohccxx::tests::rfc3243::flow_missing_cases())
        REQUIRE((validation.missing & item.missing) != 0);
}

TEST_CASE("RFC 3243 conformance library keeps obsoleted profile 0x0005 mapped to RFC 4362")
{
    REQUIRE(rohccxx::lla::profile_rfc3242 == 0x0005);
    REQUIRE(rohccxx::lla::profile_rfc4362 == 0x0005);
    REQUIRE(rohccxx::lla::is_legacy_rfc3242_profile(0x0005));
    REQUIRE(rohccxx::lla::maps_to_rfc4362_profile(rohccxx::lla::profile_rfc3242));

    const auto validation = rohccxx::lla::validate_rfc3242_legacy_lla_applicability(
        rohccxx::tests::rfc3243::complete_contract(),
        rohccxx::tests::rfc3243::complete_flow());
    REQUIRE(validation.valid);
}
