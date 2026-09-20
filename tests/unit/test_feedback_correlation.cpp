// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "rohccxx/core/feedback.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/utils/crc.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
struct DecompDelete { void operator()(rohc_decomp* value) const { rohc_decomp_free(value); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

void put16(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 8U);
    out[1] = static_cast<std::uint8_t>(value);
}

std::uint16_t checksum(const std::uint8_t* bytes)
{
    std::uint32_t sum = 0;
    for(std::size_t pos = 0; pos < 20U; pos += 2U)
        sum += (static_cast<std::uint16_t>(bytes[pos]) << 8U) | bytes[pos + 1U];
    while(sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

std::vector<std::uint8_t> udp_packet(std::uint16_t msn, unsigned flow)
{
    std::vector<std::uint8_t> packet(60U, 0U);
    packet[0] = 0x45U;
    put16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(packet.data() + 4U, msn);
    put16(packet.data() + 6U, 0x4000U);
    packet[8] = 64U;
    packet[9] = 17U;
    packet[12] = 10U;
    packet[15] = static_cast<std::uint8_t>(1U + flow);
    packet[16] = 10U;
    packet[19] = static_cast<std::uint8_t>(101U + flow);
    put16(packet.data() + 20U, static_cast<std::uint16_t>(10000U + flow));
    put16(packet.data() + 22U, static_cast<std::uint16_t>(20000U + flow));
    put16(packet.data() + 24U, 40U);
    for(std::size_t pos = 28U; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(pos + msn + flow);
    put16(packet.data() + 10U, checksum(packet.data()));
    return packet;
}

std::vector<std::uint8_t> compress_packet(rohc_comp* comp,
                                          const std::vector<std::uint8_t>& packet)
{
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(), output.data(), &output_len) == 0);
    return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(output_len)};
}

std::vector<std::uint8_t> legacy_udp_ir_dyn(std::uint16_t ipv4_id,
                                            const std::vector<std::uint8_t>& payload_source)
{
    std::vector<std::uint8_t> wire{
        0xe1U, 0xf8U, 0x02U, 0x00U,
        0x00U, 0x40U,
        static_cast<std::uint8_t>(ipv4_id >> 8U), static_cast<std::uint8_t>(ipv4_id),
        0x02U, 0x00U,
        0x00U, 0x00U,
    };
    wire[3] = rohccxx::utils::crc8(wire.data(), wire.size());
    wire.insert(wire.end(), payload_source.begin() + 28, payload_source.end());
    return wire;
}

std::vector<std::uint8_t> compress(rohc_comp* comp, std::uint16_t msn, unsigned flow)
{
    const auto packet = udp_packet(msn, flow);
    return compress_packet(comp, packet);
}

rohccxx::RohcPacketType packet_type(const std::vector<std::uint8_t>& wire,
                                    bool large_cid = false)
{
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(wire.data(), wire.size(), parsed, large_cid));
    return parsed.type;
}

void require_exact(rohc_decomp* decomp,
                   const std::vector<std::uint8_t>& wire,
                   const std::vector<std::uint8_t>& expected)
{
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, wire.data(), wire.size(), output.data(), &output_len) == 0);
    REQUIRE(output_len == expected.size());
    REQUIRE(std::memcmp(output.data(), expected.data(), expected.size()) == 0);
}

rohccxx_feedback_v1_t require_feedback(rohc_decomp* decomp, rohccxx::FeedbackType type)
{
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);
    rohccxx_feedback_v1_t feedback{};
    REQUIRE(rohc_decomp_get_feedback_v1(decomp, &feedback) == ROHCCXX_FEEDBACK_ACCEPTED);
    REQUIRE(feedback.feedback_type == static_cast<std::uint8_t>(type));
    return feedback;
}

rohccxx_feedback_v1_t make_feedback(std::uint32_t cid,
                                    std::uint16_t acknowledgment,
                                    rohccxx::FeedbackType type,
                                    bool valid = true)
{
    rohccxx::Feedback core{};
    core.cid = cid;
    core.type = type;
    core.acknowledgment_number = acknowledgment;
    core.acknowledgment_bits = 14U;
    core.acknowledgment_valid = valid;
    std::array<std::uint8_t, ROHCCXX_FEEDBACK_RAW_MAX> raw{};
    std::size_t raw_len = raw.size();
    REQUIRE(rohccxx::write_feedback2_v1(raw.data(), &raw_len, core));
    rohccxx_feedback_v1_t parsed{};
    REQUIRE(rohc_feedback_parse_v1(ROHCCXX_DIRECTION_UPLINK, raw.data(), raw_len, &parsed) ==
            ROHCCXX_FEEDBACK_ACCEPTED);
    return parsed;
}

TEST_CASE("Context refresh ACK is disabled by default")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_comp_set_cid(compressor.get(), 1U) == 0);

    const auto expected = udp_packet(1U, 0U);
    const auto wire = compress(compressor.get(), 1U, 0U);
    REQUIRE(packet_type(wire) == rohccxx::RohcPacketType::IR);
    require_exact(decompressor.get(), wire, expected);
    REQUIRE(rohc_decomp_has_feedback(decompressor.get()) == 0);
}

TEST_CASE("Enabled accepted IR produces exactly one correlated ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_comp_set_cid(compressor.get(), 1U) == 0);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    const auto expected = udp_packet(1U, 0U);
    const auto wire = compress(compressor.get(), 1U, 0U);
    REQUIRE(packet_type(wire) == rohccxx::RohcPacketType::IR);
    require_exact(decompressor.get(), wire, expected);
    const auto feedback = require_feedback(decompressor.get(), rohccxx::FeedbackType::ACK);
    REQUIRE(feedback.cid == 1U);
    REQUIRE(feedback.acknowledgment_valid == 1);
    REQUIRE(rohc_comp_deliver_feedback_v1(compressor.get(), &feedback) == ROHCCXX_FEEDBACK_ACCEPTED);
}

TEST_CASE("Enabled accepted IR-DYN produces a correlated ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_comp_set_cid(compressor.get(), 1U) == 0);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    const auto first = udp_packet(1U, 0U);
    require_exact(decompressor.get(), compress_packet(compressor.get(), first), first);

    const auto refresh = udp_packet(2U, 0U);
    const auto wire = legacy_udp_ir_dyn(2U, refresh);
    REQUIRE(packet_type(wire) == rohccxx::RohcPacketType::IR_DYN);
    require_exact(decompressor.get(), wire, refresh);
    const auto feedback = require_feedback(decompressor.get(), rohccxx::FeedbackType::ACK);
    REQUIRE(feedback.acknowledgment_valid == 1);
    REQUIRE(rohc_comp_deliver_feedback_v1(compressor.get(), &feedback) == ROHCCXX_FEEDBACK_ACCEPTED);
}

TEST_CASE("Enabled ordinary compact packet does not produce a refresh ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    bool saw_compact = false;
    for(std::uint16_t msn = 1U; msn <= 32U && !saw_compact; ++msn)
    {
        const auto expected = udp_packet(msn, 0U);
        const auto wire = compress(compressor.get(), msn, 0U);
        const auto type = packet_type(wire);
        require_exact(decompressor.get(), wire, expected);
        if(type == rohccxx::RohcPacketType::IR || type == rohccxx::RohcPacketType::IR_DYN)
        {
            const auto feedback = require_feedback(decompressor.get(), rohccxx::FeedbackType::ACK);
            REQUIRE(rohc_comp_deliver_feedback_v1(compressor.get(), &feedback) == ROHCCXX_FEEDBACK_ACCEPTED);
        }
        else
        {
            saw_compact = true;
            REQUIRE(rohc_decomp_has_feedback(decompressor.get()) == 0);
        }
    }
    REQUIRE(saw_compact);
}

TEST_CASE("Disabling context refresh ACK restores prior behavior")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    auto expected = udp_packet(1U, 0U);
    auto wire = compress(compressor.get(), 1U, 0U);
    require_exact(decompressor.get(), wire, expected);
    (void)require_feedback(decompressor.get(), rohccxx::FeedbackType::ACK);

    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 0) == 0);
    expected = udp_packet(2U, 0U);
    wire = compress(compressor.get(), 2U, 0U);
    REQUIRE(packet_type(wire) == rohccxx::RohcPacketType::IR);
    require_exact(decompressor.get(), wire, expected);
    REQUIRE(rohc_decomp_has_feedback(decompressor.get()) == 0);
}

TEST_CASE("Rejected refresh never produces a positive ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    auto wire = compress(compressor.get(), 1U, 0U);
    REQUIRE(packet_type(wire) == rohccxx::RohcPacketType::IR);
    REQUIRE(wire.size() > 3U);
    wire[2] ^= 0x01U;
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decompressor.get(), wire.data(), wire.size(),
                             output.data(), &output_len) == -1);
    (void)require_feedback(decompressor.get(), rohccxx::FeedbackType::NACK);
}

TEST_CASE("Pending negative feedback is not overwritten by a refresh ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    const std::array<std::uint8_t, 1> malformed{{0xffU}};
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decompressor.get(), malformed.data(), malformed.size(),
                             output.data(), &output_len) == -1);
    const auto pending = require_feedback(decompressor.get(), rohccxx::FeedbackType::NACK);

    const auto expected = udp_packet(1U, 0U);
    const auto wire = compress(compressor.get(), 1U, 0U);
    require_exact(decompressor.get(), wire, expected);
    const auto retained = require_feedback(decompressor.get(), rohccxx::FeedbackType::NACK);
    REQUIRE(retained.cid == pending.cid);
    REQUIRE(retained.acknowledgment_valid == pending.acknowledgment_valid);
}
}

TEST_CASE("Successful context refresh produces a correlated ACK")
{
    CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decompressor(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(compressor);
    REQUIRE(decompressor);
    REQUIRE(rohc_decomp_set_context_refresh_ack_enabled(decompressor.get(), 1) == 0);

    REQUIRE(rohc_comp_set_cid(compressor.get(), 1U) == 0);

    std::size_t acknowledgments = 0;
    std::size_t compact_packets = 0;
    for(std::uint16_t msn = 1U; msn <= 48U; ++msn)
    {
        const auto expected = udp_packet(msn, 0U);
        const auto wire = compress(compressor.get(), msn, 0U);
        if(wire.size() < expected.size())
            ++compact_packets;

        std::array<std::uint8_t, 256> output{};
        std::size_t output_len = output.size();
        REQUIRE(rohc_decompress4(decompressor.get(), wire.data(), wire.size(),
                                 output.data(), &output_len) == 0);
        REQUIRE(output_len == expected.size());
        REQUIRE(std::memcmp(output.data(), expected.data(), expected.size()) == 0);

        if(rohc_decomp_has_feedback(decompressor.get()) == 1)
        {
            rohccxx_feedback_v1_t feedback{};
            REQUIRE(rohc_decomp_get_feedback_v1(decompressor.get(), &feedback) ==
                    ROHCCXX_FEEDBACK_ACCEPTED);
            REQUIRE(feedback.cid == 1U);
            REQUIRE(feedback.feedback_type ==
                    static_cast<std::uint8_t>(rohccxx::FeedbackType::ACK));
            REQUIRE(feedback.acknowledgment_valid == 1);
            REQUIRE(rohc_comp_deliver_feedback_v1(compressor.get(), &feedback) ==
                    ROHCCXX_FEEDBACK_ACCEPTED);
            ++acknowledgments;
        }
    }

    REQUIRE(acknowledgments >= 3U);
    REQUIRE(compact_packets > 24U);
}

TEST_CASE("Feedback v1 rejects retired CID acknowledgments transactionally")
{
    CompPtr retired(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(retired);
    REQUIRE(rohc_comp_set_cid(retired.get(), 3U) == 0);
    for(std::uint16_t msn = 100U; msn < 104U; ++msn)
        (void)compress(retired.get(), msn, 0U);
    const auto delayed_ack = make_feedback(3U, 103U, rohccxx::FeedbackType::ACK);
    const auto delayed_nack = make_feedback(3U, 102U, rohccxx::FeedbackType::NACK);
    const auto delayed_static = make_feedback(3U, 101U, rohccxx::FeedbackType::STATIC_NACK);

    CompPtr replacement(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    CompPtr control(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(replacement);
    REQUIRE(control);
    REQUIRE(rohc_comp_set_cid(replacement.get(), 3U) == 0);
    REQUIRE(rohc_comp_set_cid(control.get(), 3U) == 0);
    for(std::uint16_t msn = 900U; msn < 904U; ++msn)
    {
        REQUIRE(compress(replacement.get(), msn, 9U) == compress(control.get(), msn, 9U));
    }
    REQUIRE(rohc_comp_deliver_feedback_v1(replacement.get(), &delayed_ack) == ROHCCXX_FEEDBACK_STALE);
    REQUIRE(rohc_comp_deliver_feedback_v1(replacement.get(), &delayed_nack) == ROHCCXX_FEEDBACK_STALE);
    REQUIRE(rohc_comp_deliver_feedback_v1(replacement.get(), &delayed_static) == ROHCCXX_FEEDBACK_STALE);
    REQUIRE(compress(replacement.get(), 904U, 9U) == compress(control.get(), 904U, 9U));
}

TEST_CASE("Feedback v1 validates channel acknowledgment and CRC before mutation")
{
    CompPtr subject(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    CompPtr control(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(subject);
    REQUIRE(control);
    REQUIRE(rohc_comp_set_cid(subject.get(), 1U) == 0);
    REQUIRE(rohc_comp_set_cid(control.get(), 1U) == 0);
    for(std::uint16_t msn : {0xfffeU, 0xffffU, 0U, 1U})
        REQUIRE(compress(subject.get(), msn, 1U) == compress(control.get(), msn, 1U));

    auto current = make_feedback(1U, 4U, rohccxx::FeedbackType::ACK);
    REQUIRE(rohc_comp_deliver_feedback_v1(subject.get(), &current) == ROHCCXX_FEEDBACK_ACCEPTED);

    auto invalid_ack = make_feedback(1U, 0U, rohccxx::FeedbackType::NACK, false);
    REQUIRE(rohc_comp_deliver_feedback_v1(subject.get(), &invalid_ack) ==
            ROHCCXX_FEEDBACK_UNCORRELATED);

    auto wrong_channel = current;
    wrong_channel.channel = ROHCCXX_DIRECTION_DOWNLINK;
    REQUIRE(rohc_comp_deliver_feedback_v1(subject.get(), &wrong_channel) ==
            ROHCCXX_FEEDBACK_UNCORRELATED);

    auto corrupt = current;
    corrupt.raw[corrupt.raw_len - 1U] ^= 0x01U;
    REQUIRE(rohc_comp_deliver_feedback_v1(subject.get(), &corrupt) == ROHCCXX_FEEDBACK_MALFORMED);

    auto truncated = current;
    --truncated.raw_len;
    REQUIRE(rohc_comp_deliver_feedback_v1(subject.get(), &truncated) == ROHCCXX_FEEDBACK_MALFORMED);
}

TEST_CASE("Feedback MSN history correlation handles sixteen-bit wraparound")
{
    rohccxx::Context context{};
    rohccxx::record_transmitted_msn(context, 0xfffeU);
    rohccxx::record_transmitted_msn(context, 0xffffU);
    rohccxx::record_transmitted_msn(context, 0U);
    rohccxx::record_transmitted_msn(context, 1U);
    REQUIRE(rohccxx::transmitted_msn_matches(context, 0x3ffeU, 14U));
    REQUIRE(rohccxx::transmitted_msn_matches(context, 0x3fffU, 14U));
    REQUIRE(rohccxx::transmitted_msn_matches(context, 0U, 14U));
    REQUIRE(rohccxx::transmitted_msn_matches(context, 1U, 14U));
    REQUIRE_FALSE(rohccxx::transmitted_msn_matches(context, 2U, 14U));
}
