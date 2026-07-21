// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/lla.hpp"

#include <array>
#include <cstdint>

namespace rohccxx::tests::rfc3243
{

inline lla::AssistingLayerContract complete_contract()
{
    lla::AssistingLayerContract contract{};
    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;
    return contract;
}

inline lla::ZeroByteFlow complete_flow()
{
    lla::ZeroByteFlow flow{};
    flow.ipv4_udp_rtp = true;
    flow.udp_checksum_disabled = true;
    flow.rtp_sequence_increments_by_one = true;
    flow.compressor_observed_in_order = true;
    flow.synchronized_timing = true;
    return flow;
}

struct ContractCase
{
    const char* name;
    std::uint32_t missing;
    lla::AssistingLayerContract contract;
};

struct FlowCase
{
    const char* name;
    std::uint32_t missing;
    lla::ZeroByteFlow flow;
};

inline std::array<ContractCase, 5> contract_missing_cases()
{
    auto packet_types = complete_contract();
    packet_types.identifies_packet_types = false;
    auto order = complete_contract();
    order.preserves_order = false;
    auto loss = complete_contract();
    loss.reports_loss = false;
    auto residual = complete_contract();
    residual.reports_residual_errors = false;
    auto feedback = complete_contract();
    feedback.delivers_feedback = false;
    return {{{"packet type identification", lla::MissingPacketTypeIdentification, packet_types},
             {"in-order delivery", lla::MissingInOrderDelivery, order},
             {"loss indication", lla::MissingLossIndication, loss},
             {"residual error indication", lla::MissingResidualErrorIndication, residual},
             {"feedback delivery", lla::MissingFeedbackDelivery, feedback}}};
}

inline std::array<FlowCase, 5> flow_missing_cases()
{
    auto rtp = complete_flow();
    rtp.ipv4_udp_rtp = false;
    auto checksum = complete_flow();
    checksum.udp_checksum_disabled = false;
    auto sequence = complete_flow();
    sequence.rtp_sequence_increments_by_one = false;
    auto order = complete_flow();
    order.compressor_observed_in_order = false;
    auto timing = complete_flow();
    timing.synchronized_timing = false;
    return {{{"IPv4/UDP/RTP flow", lla::MissingIpv4UdpRtpFlow, rtp},
             {"disabled UDP checksum", lla::MissingDisabledUdpChecksum, checksum},
             {"RTP sequence progression", lla::MissingRtpSequenceProgression, sequence},
             {"compressor-side ordering", lla::MissingCompressorSideOrdering, order},
             {"synchronized timing", lla::MissingSynchronizedTiming, timing}}};
}

} // namespace rohccxx::tests::rfc3243
