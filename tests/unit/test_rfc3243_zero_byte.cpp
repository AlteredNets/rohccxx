// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "rohccxx/core/lla.hpp"

namespace
{

rohccxx::lla::AssistingLayerContract complete_contract()
{
    rohccxx::lla::AssistingLayerContract contract{};
    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;
    return contract;
}

rohccxx::lla::ZeroByteFlow complete_flow()
{
    rohccxx::lla::ZeroByteFlow flow{};
    flow.ipv4_udp_rtp = true;
    flow.udp_checksum_disabled = true;
    flow.rtp_sequence_increments_by_one = true;
    flow.compressor_observed_in_order = true;
    flow.synchronized_timing = true;
    return flow;
}

} // namespace

TEST_CASE("RFC 3243 zero-byte conformance requires both lower-layer and flow assumptions")
{
    const auto contract = complete_contract();
    const auto flow = complete_flow();

    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow);
    REQUIRE(validation.valid);
    REQUIRE(validation.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_no_header_packet_for_flow(contract, flow));
}

TEST_CASE("RFC 3243 zero-byte conformance reports every missing flow assumption")
{
    const auto contract = complete_contract();
    rohccxx::lla::ZeroByteFlow flow{};

    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow);
    REQUIRE_FALSE(validation.valid);
    REQUIRE((validation.missing & rohccxx::lla::MissingIpv4UdpRtpFlow) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingDisabledUdpChecksum) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingRtpSequenceProgression) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingCompressorSideOrdering) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingSynchronizedTiming) != 0);
    REQUIRE_FALSE(rohccxx::lla::can_emit_no_header_packet_for_flow(contract, flow));
}

TEST_CASE("Obsoleted profile 0x0005 remains mapped to the RFC 4362 compatibility boundary")
{
    REQUIRE(rohccxx::lla::profile_rfc3242 == 0x0005);
    REQUIRE(rohccxx::lla::profile_rfc4362 == 0x0005);
    REQUIRE(rohccxx::lla::is_legacy_rfc3242_profile(0x0005));
    REQUIRE(rohccxx::lla::maps_to_rfc4362_profile(rohccxx::lla::profile_rfc3242));

    const auto contract = complete_contract();
    const auto flow = complete_flow();
    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3242_legacy_lla_applicability(contract, flow);
    REQUIRE(validation.valid);
    REQUIRE(validation.missing == 0);
}

TEST_CASE("RFC 3243 zero-byte conformance also rejects incomplete lower-layer contracts")
{
    rohccxx::lla::AssistingLayerContract contract{};
    const auto flow = complete_flow();

    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow);
    REQUIRE_FALSE(validation.valid);
    REQUIRE((validation.missing & rohccxx::lla::MissingPacketTypeIdentification) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingInOrderDelivery) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingLossIndication) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingResidualErrorIndication) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingFeedbackDelivery) != 0);
}
