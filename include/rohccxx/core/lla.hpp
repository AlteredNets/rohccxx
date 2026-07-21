// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

namespace rohccxx::lla
{

constexpr std::uint16_t profile_rfc3242 = 0x0005;
constexpr std::uint16_t profile_rfc4362 = 0x0005;
constexpr std::uint8_t packet_type_lower_layer_reserved = 0xF9;
constexpr std::uint8_t packet_type_csp = 0xFA;
constexpr std::uint8_t packet_type_ccp = 0xFB;

enum class AssistingLayerPacket : std::uint8_t
{
    Normal = 0x00,
    NoHeaderPacket = packet_type_lower_layer_reserved,
    ContextSynchronization = packet_type_csp,
    ContextCheck = packet_type_ccp
};

struct AssistingLayerContract
{
    bool identifies_packet_types = false;
    bool preserves_order = false;
    bool reports_loss = false;
    bool reports_residual_errors = false;
    bool delivers_feedback = false;
    bool protects_context_packets = false;
    bool supports_context_synchronization = false;
    bool supports_context_check = false;
    bool supports_reliable_mode = false;
    bool delivers_ack = false;
    bool delivers_static_nack = false;
};

enum ContractMissing : std::uint32_t
{
    MissingPacketTypeIdentification = 1U << 0U,
    MissingInOrderDelivery = 1U << 1U,
    MissingLossIndication = 1U << 2U,
    MissingResidualErrorIndication = 1U << 3U,
    MissingFeedbackDelivery = 1U << 4U,
    MissingContextPacketProtection = 1U << 5U,
    MissingContextSynchronization = 1U << 6U,
    MissingContextCheck = 1U << 7U,
    MissingReliableMode = 1U << 8U,
    MissingAckDelivery = 1U << 9U,
    MissingStaticNackDelivery = 1U << 10U,
    MissingIpv4UdpRtpFlow = 1U << 11U,
    MissingDisabledUdpChecksum = 1U << 12U,
    MissingRtpSequenceProgression = 1U << 13U,
    MissingCompressorSideOrdering = 1U << 14U,
    MissingSynchronizedTiming = 1U << 15U
};

struct ContractValidation
{
    bool valid = false;
    std::uint32_t missing = 0;
};

struct ZeroByteFlow
{
    bool ipv4_udp_rtp = false;
    bool udp_checksum_disabled = false;
    bool rtp_sequence_increments_by_one = false;
    bool compressor_observed_in_order = false;
    bool synchronized_timing = false;
};

inline bool is_legacy_rfc3242_profile(std::uint16_t profile)
{
    return profile == profile_rfc3242;
}

inline bool maps_to_rfc4362_profile(std::uint16_t profile)
{
    return is_legacy_rfc3242_profile(profile);
}

inline ContractValidation validate_rfc3243_zero_byte_assumptions(const AssistingLayerContract& contract)
{
    ContractValidation result{};
    if(!contract.identifies_packet_types)
        result.missing |= MissingPacketTypeIdentification;
    if(!contract.preserves_order)
        result.missing |= MissingInOrderDelivery;
    if(!contract.reports_loss)
        result.missing |= MissingLossIndication;
    if(!contract.reports_residual_errors)
        result.missing |= MissingResidualErrorIndication;
    if(!contract.delivers_feedback)
        result.missing |= MissingFeedbackDelivery;
    result.valid = result.missing == 0;
    return result;
}

inline ContractValidation validate_rfc3409_lower_layer_guidelines(const AssistingLayerContract& contract)
{
    ContractValidation result = validate_rfc3243_zero_byte_assumptions(contract);
    if(!contract.protects_context_packets)
        result.missing |= MissingContextPacketProtection;
    if(!contract.supports_context_synchronization)
        result.missing |= MissingContextSynchronization;
    if(!contract.supports_context_check)
        result.missing |= MissingContextCheck;
    result.valid = result.missing == 0;
    return result;
}

inline ContractValidation validate_rfc3408_r_mode_zero_byte_support(const AssistingLayerContract& contract)
{
    ContractValidation result = validate_rfc3243_zero_byte_assumptions(contract);
    if(!contract.supports_reliable_mode)
        result.missing |= MissingReliableMode;
    if(!contract.delivers_ack)
        result.missing |= MissingAckDelivery;
    if(!contract.delivers_static_nack)
        result.missing |= MissingStaticNackDelivery;
    result.valid = result.missing == 0;
    return result;
}

inline ContractValidation validate_rfc3243_zero_byte_flow(const AssistingLayerContract& contract,
                                                          const ZeroByteFlow& flow)
{
    ContractValidation result = validate_rfc3243_zero_byte_assumptions(contract);
    if(!flow.ipv4_udp_rtp)
        result.missing |= MissingIpv4UdpRtpFlow;
    if(!flow.udp_checksum_disabled)
        result.missing |= MissingDisabledUdpChecksum;
    if(!flow.rtp_sequence_increments_by_one)
        result.missing |= MissingRtpSequenceProgression;
    if(!flow.compressor_observed_in_order)
        result.missing |= MissingCompressorSideOrdering;
    if(!flow.synchronized_timing)
        result.missing |= MissingSynchronizedTiming;
    result.valid = result.missing == 0;
    return result;
}

inline ContractValidation validate_rfc3242_legacy_lla_applicability(const AssistingLayerContract& contract,
                                                                    const ZeroByteFlow& flow)
{
    return validate_rfc3243_zero_byte_flow(contract, flow);
}

inline bool can_emit_no_header_packet(const AssistingLayerContract& contract)
{
    return validate_rfc3243_zero_byte_assumptions(contract).valid;
}

inline bool can_emit_no_header_packet_for_flow(const AssistingLayerContract& contract,
                                               const ZeroByteFlow& flow)
{
    return validate_rfc3243_zero_byte_flow(contract, flow).valid;
}

inline bool can_emit_reliable_mode_no_header_packet(const AssistingLayerContract& contract)
{
    return validate_rfc3408_r_mode_zero_byte_support(contract).valid;
}

inline bool can_emit_context_synchronization_packet(const AssistingLayerContract& contract)
{
    const ContractValidation validation = validate_rfc3409_lower_layer_guidelines(contract);
    return validation.valid && contract.supports_context_synchronization;
}

inline bool can_emit_context_check_packet(const AssistingLayerContract& contract)
{
    const ContractValidation validation = validate_rfc3409_lower_layer_guidelines(contract);
    return validation.valid && contract.supports_context_check;
}

struct ContextSynchronizationPacket
{
    std::uint16_t rtp_payload_len = 0;
    const std::uint8_t* rohc_header = nullptr;
    std::size_t rohc_header_len = 0;
};

struct ContextCheckPacket
{
    bool has_crc = false;
    std::uint8_t crc7 = 0;
};

inline bool write_context_synchronization_packet(std::uint8_t* out,
                                                 std::size_t* out_len,
                                                 std::uint16_t rtp_payload_len,
                                                 const std::uint8_t* rohc_header,
                                                 std::size_t rohc_header_len)
{
    if(!out || !out_len || (!rohc_header && rohc_header_len > 0) || *out_len < 3U + rohc_header_len)
        return false;
    out[0] = packet_type_csp;
    out[1] = static_cast<std::uint8_t>(rtp_payload_len >> 8);
    out[2] = static_cast<std::uint8_t>(rtp_payload_len & 0xFFU);
    for(std::size_t i = 0; i < rohc_header_len; ++i)
        out[3U + i] = rohc_header[i];
    *out_len = 3U + rohc_header_len;
    return true;
}

inline bool read_context_synchronization_packet(const std::uint8_t* in,
                                                std::size_t in_len,
                                                ContextSynchronizationPacket& packet)
{
    packet = ContextSynchronizationPacket{};
    if(!in || in_len < 3 || in[0] != packet_type_csp)
        return false;
    packet.rtp_payload_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[1]) << 8U) | in[2]);
    packet.rohc_header = in + 3;
    packet.rohc_header_len = in_len - 3U;
    return true;
}

inline bool write_context_check_packet(std::uint8_t* out,
                                       std::size_t* out_len,
                                       const ContextCheckPacket& packet)
{
    if(!out || !out_len || *out_len < 2)
        return false;
    out[0] = packet_type_ccp;
    out[1] = static_cast<std::uint8_t>((packet.has_crc ? 0x80U : 0x00U) | (packet.crc7 & 0x7FU));
    *out_len = 2;
    return true;
}

inline bool read_context_check_packet(const std::uint8_t* in,
                                      std::size_t in_len,
                                      ContextCheckPacket& packet)
{
    packet = ContextCheckPacket{};
    if(!in || in_len < 2 || in[0] != packet_type_ccp)
        return false;
    packet.has_crc = (in[1] & 0x80U) != 0;
    packet.crc7 = static_cast<std::uint8_t>(in[1] & 0x7FU);
    return true;
}

inline bool packet_type_requires_assisting_layer(std::uint8_t packet_type)
{
    return packet_type == packet_type_lower_layer_reserved || packet_type == packet_type_csp || packet_type == packet_type_ccp;
}

} // namespace rohccxx::lla
