// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "rohccxx/core/feedback.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;

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

std::vector<std::uint8_t> compress(rohc_comp* comp, std::uint16_t msn, unsigned flow)
{
    const auto packet = udp_packet(msn, flow);
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(), output.data(), &output_len) == 0);
    return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(output_len)};
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
