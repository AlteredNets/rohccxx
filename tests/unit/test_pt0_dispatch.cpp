// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/feedback.hpp"
#include "rohccxx/core/rohcoipsec.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace
{

enum class Pt0Profile { Udp, Esp, Ip };

struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
struct DecompDelete { void operator()(rohc_decomp* value) const { rohc_decomp_free(value); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

std::uint16_t ipv4_checksum(const std::uint8_t* bytes)
{
    std::uint32_t sum = 0;
    for(std::size_t pos = 0; pos < 20; pos += 2)
        sum += (static_cast<std::uint16_t>(bytes[pos]) << 8U) | bytes[pos + 1U];
    while(sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

void put16(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 8U);
    out[1] = static_cast<std::uint8_t>(value);
}

void put32(std::uint8_t* out, std::uint32_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 24U);
    out[1] = static_cast<std::uint8_t>(value >> 16U);
    out[2] = static_cast<std::uint8_t>(value >> 8U);
    out[3] = static_cast<std::uint8_t>(value);
}

std::vector<std::uint8_t> hex_bytes(const char* text)
{
    const auto size = std::strlen(text);
    REQUIRE(size % 2U == 0U);
    std::vector<std::uint8_t> bytes(size / 2U);
    auto nibble = [](char value) -> int
    {
        if(value >= '0' && value <= '9') return value - '0';
        if(value >= 'a' && value <= 'f') return value - 'a' + 10;
        if(value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    for(std::size_t index = 0U; index < bytes.size(); ++index)
    {
        const int high = nibble(text[index * 2U]);
        const int low = nibble(text[index * 2U + 1U]);
        REQUIRE(high >= 0);
        REQUIRE(low >= 0);
        bytes[index] = static_cast<std::uint8_t>((high << 4U) | low);
    }
    return bytes;
}

bool is_ir_packet(const std::vector<std::uint8_t>& packet, std::uint32_t cid)
{
    const std::size_t offset = cid == 0U ? 0U : 1U;
    return packet.size() > offset && (packet[offset] & 0xfeU) == 0xfcU;
}

rohccxx_feedback_v1_t make_ack(std::uint32_t cid, std::uint16_t msn)
{
    rohccxx::Feedback feedback{};
    feedback.cid = cid;
    feedback.type = rohccxx::FeedbackType::ACK;
    feedback.acknowledgment_number = msn;
    feedback.acknowledgment_bits = 14U;
    feedback.acknowledgment_valid = true;
    std::array<std::uint8_t, ROHCCXX_FEEDBACK_RAW_MAX> raw{};
    std::size_t raw_len = raw.size();
    REQUIRE(rohccxx::write_feedback2_v1(raw.data(), &raw_len, feedback));
    rohccxx_feedback_v1_t parsed{};
    REQUIRE(rohc_feedback_parse_v1(ROHCCXX_DIRECTION_UPLINK, raw.data(), raw_len,
                                   &parsed) == ROHCCXX_FEEDBACK_ACCEPTED);
    return parsed;
}

void acknowledge_refresh(rohc_comp* comp, Pt0Profile profile, std::uint32_t cid,
                         std::uint32_t ordinal,
                         const std::vector<std::uint8_t>& packet)
{
    if(ordinal < 2U || !is_ir_packet(packet, cid))
        return;
    const auto parsed = make_ack(cid, static_cast<std::uint16_t>(
        profile == Pt0Profile::Esp ? ordinal : ordinal + 1U));
    REQUIRE(rohc_comp_deliver_feedback_v1(comp, &parsed) ==
            ROHCCXX_FEEDBACK_ACCEPTED);
}

std::vector<std::uint8_t> make_rtp_packet(std::uint16_t sequence,
                                          std::uint32_t timestamp,
                                          std::uint16_t ipv4_id,
                                          unsigned flow = 0U,
                                          std::uint8_t marker_payload_type = 96U)
{
    std::vector<std::uint8_t> packet(40U + 160U);
    auto* ip = packet.data();
    ip[0] = 0x45U;
    put16(ip + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(ip + 4U, ipv4_id);
    put16(ip + 6U, 0x4000U);
    ip[8] = 64U;
    ip[9] = 17U;
    ip[12] = 10U;
    ip[15] = static_cast<std::uint8_t>(1U + flow);
    ip[16] = 10U;
    ip[19] = static_cast<std::uint8_t>(101U + flow);
    put16(ip + 20U, static_cast<std::uint16_t>(10000U + flow));
    put16(ip + 22U, static_cast<std::uint16_t>(20000U + flow));
    put16(ip + 24U, static_cast<std::uint16_t>(packet.size() - 20U));
    put16(ip + 26U, 0U);
    ip[28] = 0x80U;
    ip[29] = marker_payload_type;
    put16(ip + 30U, sequence);
    put32(ip + 32U, timestamp);
    put32(ip + 36U, 0x10203040U + flow);
    for(std::size_t pos = 40U; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(pos + sequence + flow);
    put16(ip + 10U, ipv4_checksum(ip));
    return packet;
}

std::vector<std::uint8_t> make_issue32_fuzz_packet(std::uint32_t ordinal,
                                                    std::uint32_t cid,
                                                    std::uint32_t profile,
                                                    std::uint32_t epoch,
                                                    std::uint32_t round,
                                                    std::uint64_t salt)
{
    constexpr std::size_t packet_size = 96U;
    const std::uint32_t flow = cid & 3U;
    std::vector<std::uint8_t> packet(packet_size);
    auto* ip = packet.data();
    ip[0] = 0x45U;
    put16(ip + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(ip + 4U, static_cast<std::uint16_t>(0xfffcU + round));
    ip[6] = 0x40U;
    ip[8] = static_cast<std::uint8_t>(64U - flow);
    ip[9] = profile == 2U ? 50U : (profile == 3U ? 6U : 17U);
    ip[12] = 10U;
    ip[13] = static_cast<std::uint8_t>(20U + profile + epoch * 8U);
    ip[14] = static_cast<std::uint8_t>(30U + flow);
    ip[15] = 1U;
    ip[16] = 198U;
    ip[17] = 51U;
    ip[18] = static_cast<std::uint8_t>(1U + profile + epoch * 8U);
    ip[19] = static_cast<std::uint8_t>(10U + flow);

    std::uint64_t state = 0x524f484343585354ULL ^
                          (static_cast<std::uint64_t>(ordinal) << 17U) ^ salt;
    for(std::size_t pos = 20U; pos < packet.size(); ++pos)
    {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        packet[pos] = static_cast<std::uint8_t>(state);
    }
    if(profile <= 1U)
    {
        put16(ip + 20U, static_cast<std::uint16_t>(12000U + epoch * 256U +
                                                   profile * 64U + flow));
        put16(ip + 22U, static_cast<std::uint16_t>(22000U + epoch * 256U +
                                                   profile * 64U + flow));
        put16(ip + 24U, static_cast<std::uint16_t>(packet.size() - 20U));
        put16(ip + 26U, 0U);
    }
    if(profile == 0U)
    {
        ip[28] = 0x80U;
        ip[29] = static_cast<std::uint8_t>(96U + flow);
        put16(ip + 30U, static_cast<std::uint16_t>(0xfffcU + round));
        put32(ip + 32U, 0xffffff00U + round * 160U);
        put32(ip + 36U, 0x11223000U + epoch * 16U + flow);
    }
    else if(profile == 2U)
    {
        put32(ip + 20U, 0xa0b00000U + epoch * 16U + flow);
        put32(ip + 24U, 0xfffffff8U + round);
    }
    put32(ip + 48U, ordinal);
    put32(ip + 52U, cid);
    put16(ip + 10U, ipv4_checksum(ip));
    return packet;
}

std::uint16_t issue32_packet_msn(const std::vector<std::uint8_t>& packet,
                                 std::uint32_t profile,
                                 std::uint32_t generation_round)
{
    if(profile == 0U)
        return static_cast<std::uint16_t>((packet[30] << 8U) | packet[31]);
    if(profile == 2U)
        return static_cast<std::uint16_t>((packet[26] << 8U) | packet[27]);
    return static_cast<std::uint16_t>(generation_round + 1U);
}

void require_issue32_fuzz_witness_safe(
    const std::vector<std::uint8_t>& witness, std::uint32_t trigger_round,
    const std::vector<std::uint8_t>& expected_trigger_compressed = {})
{
    REQUIRE(!witness.empty());
    const auto witness_bit = [&](std::size_t offset)
    {
        offset %= witness.size() * 8U;
        return (witness[offset / 8U] & (1U << (offset % 8U))) != 0U;
    };
    std::uint64_t salt = 0x4953535545343955ULL;
    for(const auto byte : witness)
        salt = (salt ^ byte) * 0x100000001b3ULL;
    const std::uint32_t cid = witness[0] & 0x0fU;
    const std::uint32_t starting_profile =
        witness.size() > 1U ? witness[1] & 0x03U : 0U;
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
    rohccxx_feedback_v1_t delayed{};
    bool delayed_valid = false;
    bool trigger_was_safe = false;
    bool recovered_after_trigger = false;

    for(std::uint32_t round = 0U; round < 128U; ++round)
    {
        if(witness_bit(round * 31U + 127U))
        {
            decomp.reset(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(decomp);
            REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
        }
        const std::uint32_t epoch = round / 32U;
        const std::uint32_t profile = (starting_profile + epoch) & 3U;
        const std::uint32_t ordinal = round * 16U + cid;
        if(delayed_valid && witness_bit(round * 13U + 71U))
        {
            const auto status = rohc_comp_deliver_feedback_v1(comp.get(), &delayed);
            REQUIRE((status == ROHCCXX_FEEDBACK_ACCEPTED ||
                     status == ROHCCXX_FEEDBACK_STALE));
            delayed_valid = false;
        }

        const auto packet = make_issue32_fuzz_packet(ordinal, cid, profile,
                                                     epoch, round, salt);
        REQUIRE(rohc_comp_set_cid(comp.get(), cid) == 0);
        std::array<std::uint8_t, 2048> compressed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        if(round == trigger_round && !expected_trigger_compressed.empty())
        {
            REQUIRE(compressed_len == expected_trigger_compressed.size());
            REQUIRE(std::equal(expected_trigger_compressed.begin(),
                               expected_trigger_compressed.end(),
                               compressed.begin()));
        }
        if(witness_bit(round * 17U + 19U))
            continue;

        std::array<std::uint8_t, 256> output{};
        output.fill(0xa5U);
        const auto guard = output;
        std::size_t output_len = output.size();
        const int rc = rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                        output.data(), &output_len);
        if(rc == 0)
        {
            REQUIRE(output_len == packet.size());
            REQUIRE(std::equal(packet.begin(), packet.end(), output.begin()));
            if(round == trigger_round)
                trigger_was_safe = true;
            if(round > trigger_round)
                recovered_after_trigger = true;
            const std::vector<std::uint8_t> frame(
                compressed.begin(), compressed.begin() +
                static_cast<std::ptrdiff_t>(compressed_len));
            if(is_ir_packet(frame, cid))
            {
                const auto feedback = make_ack(
                    cid, issue32_packet_msn(packet, profile, round % 32U));
                if(witness_bit(round * 29U + 113U))
                {
                    const auto status = rohc_comp_deliver_feedback_v1(comp.get(), &feedback);
                    REQUIRE((status == ROHCCXX_FEEDBACK_ACCEPTED ||
                             status == ROHCCXX_FEEDBACK_STALE));
                }
                else
                {
                    delayed = feedback;
                    delayed_valid = true;
                }
            }
        }
        else
        {
            REQUIRE(output_len == 0U);
            REQUIRE(output == guard);
            if(round == trigger_round)
                trigger_was_safe = true;
        }
    }
    REQUIRE(trigger_was_safe);
    REQUIRE(recovered_after_trigger);
}

std::vector<std::uint8_t> make_packet(Pt0Profile profile,
                                      std::uint32_t ordinal,
                                      std::uint8_t tos = 0,
                                      std::uint16_t id_override = 0xffffU,
                                      std::uint16_t udp_checksum = 0U,
                                      unsigned flow = 0U)
{
    const std::size_t header_len = profile == Pt0Profile::Ip ? 20U : 28U;
    std::vector<std::uint8_t> packet(header_len + 160U);
    auto* ip = packet.data();
    ip[0] = 0x45;
    ip[1] = tos;
    put16(ip + 2, static_cast<std::uint16_t>(packet.size()));
    put16(ip + 4, id_override == 0xffffU ? static_cast<std::uint16_t>(ordinal) : id_override);
    put16(ip + 6, 0x4000U);
    ip[8] = 64;
    ip[9] = profile == Pt0Profile::Udp ? 17U : profile == Pt0Profile::Esp ? 50U : 253U;
    ip[12] = 10;
    ip[15] = static_cast<std::uint8_t>(1U + flow);
    ip[16] = 10;
    ip[19] = static_cast<std::uint8_t>(2U + flow);
    if(profile == Pt0Profile::Udp)
    {
        put16(ip + 20, static_cast<std::uint16_t>(10000U + flow));
        put16(ip + 22, static_cast<std::uint16_t>(20000U + flow));
        put16(ip + 24, static_cast<std::uint16_t>(packet.size() - 20U));
        put16(ip + 26, udp_checksum);
    }
    if(profile == Pt0Profile::Esp)
    {
        put32(ip + 20, 0x10203000U);
        put32(ip + 24, ordinal);
    }
    std::uint64_t state = 0x524f484343585832ULL ^ ordinal ^
                          (static_cast<std::uint64_t>(flow) << 32U);
    for(std::size_t pos = header_len; pos < packet.size(); ++pos)
    {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        packet[pos] = static_cast<std::uint8_t>(state);
    }
    if(profile == Pt0Profile::Udp) packet[28] &= 0x3fU;
    put16(ip + 10, ipv4_checksum(ip));
    return packet;
}

std::vector<std::uint8_t> make_rc2_soak_esp_packet(std::uint32_t round,
                                                    std::size_t size = 96U)
{
    REQUIRE(size >= 56U);
    constexpr std::uint32_t cid = 9U;
    std::vector<std::uint8_t> packet(size);
    auto* ip = packet.data();
    ip[0] = 0x45U;
    ip[1] = 0x21U;
    put16(ip + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(ip + 4U, static_cast<std::uint16_t>(round));
    put16(ip + 6U, 0x4000U);
    ip[8] = 63U;
    ip[9] = 50U;
    ip[12] = 10U;
    ip[13] = 32U;
    ip[14] = 25U;
    ip[15] = 1U;
    ip[16] = 198U;
    ip[17] = 51U;
    ip[18] = 3U;
    ip[19] = 19U;
    put32(ip + 20U, 0xa0510000U + cid);
    put32(ip + 24U, 0xfffffff0U + round);
    for(std::size_t pos = 28U; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(pos + round + cid);
    put32(ip + 48U, round * 16U + cid);
    put32(ip + 52U, cid);
    put16(ip + 10U, ipv4_checksum(ip));
    return packet;
}

std::size_t ordinal_for_octet(Pt0Profile profile, std::uint8_t octet)
{
    const std::size_t msn_lsb = static_cast<std::size_t>(octet >> 3U);
    std::size_t ordinal = profile == Pt0Profile::Esp ? msn_lsb : (msn_lsb + 15U) % 16U;
    while(ordinal < 2U) ordinal += 16U;
    return ordinal;
}

bool compress_prefix(Pt0Profile profile,
                     std::uint8_t tos,
                     std::size_t final_ordinal,
                     std::vector<std::uint8_t>& final_rohc,
                     std::uint16_t udp_checksum = 0U)
{
    CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
    if(!comp) return false;
    for(std::size_t ordinal = 0; ordinal <= final_ordinal; ++ordinal)
    {
        const auto ip = make_packet(profile, static_cast<std::uint32_t>(ordinal), tos,
                                    0xffffU, udp_checksum);
        std::array<std::uint8_t, 512> rohc{};
        std::size_t rohc_len = rohc.size();
        if(rohc_compress4(comp.get(), ip.data(), ip.size(), rohc.data(), &rohc_len) != 0)
            return false;
        const std::vector<std::uint8_t> packet(
            rohc.begin(), rohc.begin() + static_cast<std::ptrdiff_t>(rohc_len));
        acknowledge_refresh(comp.get(), profile, 0U,
                            static_cast<std::uint32_t>(ordinal), packet);
        if(ordinal == final_ordinal)
            final_rohc = packet;
    }
    return true;
}

std::uint8_t find_tos_for_octet(Pt0Profile profile, std::uint8_t target,
                                std::uint16_t udp_checksum = 0U)
{
    const std::size_t ordinal = ordinal_for_octet(profile, target);
    for(unsigned tos = 0; tos <= 0xffU; ++tos)
    {
        std::vector<std::uint8_t> rohc;
        if(compress_prefix(profile, static_cast<std::uint8_t>(tos), ordinal, rohc,
                           udp_checksum) &&
           !rohc.empty() && rohc[0] == target)
            return static_cast<std::uint8_t>(tos);
    }
    FAIL("PT-0 octet is structurally reachable but no deterministic TOS witness was found");
    return 0;
}

void require_guarded_decode(rohc_decomp* decomp,
                            const std::vector<std::uint8_t>& rohc,
                            const std::vector<std::uint8_t>& expected)
{
    std::array<std::uint8_t, 514> guarded{};
    guarded.fill(0xa5U);
    guarded.front() = 0x3cU;
    guarded.back() = 0xc3U;
    std::size_t out_len = guarded.size() - 2U;
    REQUIRE(rohc_decompress4(decomp, rohc.data(), rohc.size(), guarded.data() + 1U, &out_len) == 0);
    REQUIRE(out_len == expected.size());
    REQUIRE(guarded.front() == 0x3cU);
    REQUIRE(guarded.back() == 0xc3U);
    REQUIRE(std::memcmp(guarded.data() + 1U, expected.data(), expected.size()) == 0);
    // Successful retry/delivery clears the previous call's pending NACK.
    REQUIRE(rohc_decomp_has_feedback(decomp) == 0);
}

void require_public_round_trip_to(Pt0Profile profile,
                                  std::uint8_t tos,
                                  std::size_t final_ordinal,
                                  std::uint8_t expected_octet)
{
    CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(std::size_t ordinal = 0; ordinal <= final_ordinal; ++ordinal)
    {
        const auto ip = make_packet(profile, static_cast<std::uint32_t>(ordinal), tos);
        std::array<std::uint8_t, 512> compressed_guard{};
        compressed_guard.fill(0xccU);
        compressed_guard.front() = 0xa5U;
        compressed_guard.back() = 0x5aU;
        std::size_t rohc_len = compressed_guard.size() - 2U;
        REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(),
                               compressed_guard.data() + 1U, &rohc_len) == 0);
        REQUIRE(compressed_guard.front() == 0xa5U);
        REQUIRE(compressed_guard.back() == 0x5aU);
        std::vector<std::uint8_t> rohc(compressed_guard.begin() + 1,
                                       compressed_guard.begin() + 1 +
                                           static_cast<std::ptrdiff_t>(rohc_len));
        if(ordinal == final_ordinal) REQUIRE(rohc[0] == expected_octet);
        require_guarded_decode(decomp.get(), rohc, ip);
        acknowledge_refresh(comp.get(), profile, 0U,
                            static_cast<std::uint32_t>(ordinal), rohc);
    }
}

struct CollisionFixture
{
    CompPtr comp{rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK)};
    DecompPtr decomp{rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK)};
    std::vector<std::uint8_t> collision;
    std::vector<std::uint8_t> expected;
};

CollisionFixture establish_before(Pt0Profile profile, std::size_t collision_ordinal,
                                  std::uint8_t tos = 0U,
                                  std::uint16_t udp_checksum = 0U)
{
    CollisionFixture fixture;
    REQUIRE(fixture.comp);
    REQUIRE(fixture.decomp);
    for(std::size_t ordinal = 0; ordinal <= collision_ordinal; ++ordinal)
    {
        auto ip = make_packet(profile, static_cast<std::uint32_t>(ordinal), tos,
                              0xffffU, udp_checksum);
        std::array<std::uint8_t, 512> rohc{};
        std::size_t rohc_len = rohc.size();
        REQUIRE(rohc_compress4(fixture.comp.get(), ip.data(), ip.size(),
                               rohc.data(), &rohc_len) == 0);
        if(ordinal == collision_ordinal)
        {
            fixture.collision.assign(rohc.begin(), rohc.begin() +
                                                    static_cast<std::ptrdiff_t>(rohc_len));
            fixture.expected = std::move(ip);
        }
        else
        {
            require_guarded_decode(fixture.decomp.get(),
                                   std::vector<std::uint8_t>(rohc.begin(), rohc.begin() +
                                       static_cast<std::ptrdiff_t>(rohc_len)), ip);
            acknowledge_refresh(fixture.comp.get(), profile, 0U,
                                static_cast<std::uint32_t>(ordinal),
                                std::vector<std::uint8_t>(
                                    rohc.begin(), rohc.begin() +
                                        static_cast<std::ptrdiff_t>(rohc_len)));
        }
    }
    return fixture;
}

void require_failed_transaction(rohc_decomp* decomp,
                                const std::vector<std::uint8_t>& packet,
                                std::size_t capacity = 510U,
                                bool expect_feedback = true,
                                std::uint32_t expected_cid = 0U)
{
    std::array<std::uint8_t, 512> output{};
    output.fill(0xa5U);
    const auto before = output;
    std::size_t out_len = capacity;
    rohccxx_mode_t mode_before{};
    REQUIRE(rohc_decomp_get_mode(decomp, &mode_before) == 0);
    const std::uint8_t empty_packet = 0;
    const auto* packet_data = packet.empty() ? &empty_packet : packet.data();
    REQUIRE(rohc_decompress4(decomp, packet_data, packet.size(), output.data() + 1U,
                             &out_len) != 0);
    REQUIRE(out_len == 0);
    REQUIRE(output == before);
    rohccxx_mode_t mode_after{};
    REQUIRE(rohc_decomp_get_mode(decomp, &mode_after) == 0);
    REQUIRE(mode_after == mode_before);
    REQUIRE(rohc_decomp_has_feedback(decomp) == (expect_feedback ? 1 : 0));
    std::uint32_t feedback_cid = 0xffffffffU;
    std::uint8_t feedback_type = 0xffU;
    if(expect_feedback)
    {
        REQUIRE(rohc_decomp_get_feedback(decomp, &feedback_cid, &feedback_type) == 0);
        REQUIRE(feedback_cid == expected_cid);
        REQUIRE(feedback_type == 0U); // public NACK value
        // Retrieval is observational, not consuming.
        feedback_cid = 0xffffffffU;
        feedback_type = 0xffU;
        REQUIRE(rohc_decomp_get_feedback(decomp, &feedback_cid, &feedback_type) == 0);
        REQUIRE(feedback_cid == expected_cid);
        REQUIRE(feedback_type == 0U);
    }
    else
    {
        REQUIRE(rohc_decomp_get_feedback(decomp, &feedback_cid, &feedback_type) == -1);
    }
}

std::array<std::uint8_t, rohccxx::rohcoipsec::sha256_digest_len>
sha256(const std::vector<std::uint8_t>& bytes)
{
    std::array<std::uint8_t, rohccxx::rohcoipsec::sha256_digest_len> digest{};
    rohccxx::rohcoipsec::detail::sha256(bytes.data(), bytes.size(), digest.data());
    return digest;
}

std::string hex_digest(const std::array<std::uint8_t, rohccxx::rohcoipsec::sha256_digest_len>& digest)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string text;
    text.reserve(digest.size() * 2U);
    for(const auto byte : digest)
    {
        text.push_back(hex[byte >> 4U]);
        text.push_back(hex[byte & 0x0fU]);
    }
    return text;
}

std::vector<std::uint8_t> compress_rtp(rohc_comp* comp, std::uint32_t cid,
                                       const std::vector<std::uint8_t>& packet)
{
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    std::array<std::uint8_t, 512> output{};
    std::size_t length = output.size();
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(), output.data(), &length) == 0);
    return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(length)};
}

std::vector<std::uint8_t> compress_packet(rohc_comp* comp, std::uint32_t cid,
                                         const std::vector<std::uint8_t>& packet)
{
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    std::array<std::uint8_t, 514> guarded{};
    guarded.fill(0xccU);
    guarded.front() = 0xa5U;
    guarded.back() = 0x5aU;
    std::size_t length = guarded.size() - 2U;
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(), guarded.data() + 1U,
                           &length) == 0);
    REQUIRE(guarded.front() == 0xa5U);
    REQUIRE(guarded.back() == 0x5aU);
    return {guarded.begin() + 1U,
            guarded.begin() + 1U + static_cast<std::ptrdiff_t>(length)};
}

} // namespace

TEST_CASE("public C API round-trips every safely emitted RFC 5225 PT-0 first octet")
{
    // PT-0 is exactly 0 | MSN(4) | CRC-3(3), so all 128 zero-MSB values are
    // structurally decodable.  Each profile's two MSN values used by context
    // establishment are reserved from later wrap emission because that would
    // exceed the unambiguous four-bit forward window. A per-context
    // TOS witness supplies every CRC-3 value for the 14 safe MSN values without
    // fabricating wire packets or bypassing the public encoder.
    // Current ESP emission uses PT-0-CRC7 and has dedicated framing and
    // delayed-unit coverage below. This exhaustive octet test covers the
    // remaining current one-octet CRC-3 emitters.
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Ip})
    {
        for(unsigned value = 0; value <= 0x7fU; ++value)
        {
            const auto octet = static_cast<std::uint8_t>(value);
            const auto msn_lsb = static_cast<std::uint8_t>(octet >> 3U);
            const bool context_interval = profile == Pt0Profile::Esp
                ? (msn_lsb == 0U || msn_lsb == 1U)
                : (msn_lsb == 1U || msn_lsb == 2U);
            if(context_interval)
                continue;
            CAPTURE(static_cast<unsigned>(profile), value);
            const auto tos = find_tos_for_octet(profile, octet);
            require_public_round_trip_to(profile, tos,
                                         ordinal_for_octet(profile, octet), octet);
        }
    }
}

TEST_CASE("public C API resolves every PT-0 private-FO marker for every formal profile")
{
    // Legacy ESP marker overlap remains covered by the Issue 47 witness.
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Ip})
    {
        for(const std::uint8_t marker : {0x77U, 0x78U, 0x79U, 0x7aU})
        {
            CAPTURE(static_cast<unsigned>(profile), static_cast<unsigned>(marker));
            const auto tos = find_tos_for_octet(profile, marker);
            require_public_round_trip_to(profile, tos,
                                         ordinal_for_octet(profile, marker), marker);
        }
    }
}

TEST_CASE("public C API reproduces the scientific comparator collision ordinals")
{
    struct FixturePin
    {
        Pt0Profile profile;
        std::size_t ordinal;
        std::size_t compressed_len;
        std::uint8_t first_octet;
        const char* sha256;
    };
    const FixturePin pins[] = {
        {Pt0Profile::Udp, 14U, 161U, 0x78U,
         "4816fc555718ec1a4f88bec98dcdf0f08323d023954769052095cbaac92f34e7"},
        {Pt0Profile::Esp, 47U, 162U, 0x97U,
         "dba96689be806bd04de2ec60dd783fed18375e376431aaa4c759563d2ba9bee1"},
        {Pt0Profile::Ip, 61U, 161U, 0x77U,
         "cdc4301feabce8de95c830901cf6c575f049cb73729a52f819cf88a6fbfc11df"},
    };
    for(const auto& pin : pins)
    {
        CAPTURE(static_cast<unsigned>(pin.profile), pin.ordinal);
        auto fixture = establish_before(pin.profile, pin.ordinal);
        REQUIRE(fixture.collision.size() == pin.compressed_len);
        REQUIRE(fixture.collision.front() == pin.first_octet);
        REQUIRE(hex_digest(sha256(fixture.collision)) == pin.sha256);
        require_guarded_decode(fixture.decomp.get(), fixture.collision, fixture.expected);
    }
}

TEST_CASE("Issue 47 one-bit ESP PT-0 corruption rejects transactionally")
{
    // rohc-lib 70589cc, randomized interop seed 29, ESP/IP steps 0-4.
    // Steps 0-3 establish the exact decoder context in which changing the
    // step-4 formal PT-0 CRC bit from 0x79 to the private ESP marker 0x78
    // previously returned success with a non-exact 61-byte packet.
    const std::array<const char*, 4> context_packets{{
        "fd038240320a1ba0010a9f3c02e4a0dc2f0036d4da063ef23f8b008000c302a1f1d2acd1a3a1f3978fd7e7a4d7f39aac3adb1b15847a94dc50e2f997ac5e93",
        "fd037740320a1ba0010a9f3c02e4a0dc2f0036d4da073ef23f8c008000c303a1f1d34cd1a3a1f3f4a7b1d44251a858b2a0aa05efdd11b9fc1a9b9b6d994c89",
        "fd03e640320a1ba0010a9f3c02e4a0dc2f0036d4da083ef23f8d008000c304a1f1d3ecd1a3a1f3a09854fdc6d341b8d8d98e989545e5eb6f36de9132818dc6",
        "fd036640320a1ba0010a9f3c02e4a0dc2f0036d4da093ef23f8e008000c305a1f1d48cd1a3a1f365d092957c034b38819fbb343a4e6d6638db170d094f4d03",
    }};
    const std::array<const char*, 4> context_expected{{
        "45360040da060000d4321b920a1ba0010a9f3c02e4a0dc2f3ef23f8b8000c302a1f1d2acd1a3a1f3978fd7e7a4d7f39aac3adb1b15847a94dc50e2f997ac5e93",
        "45360040da070000d4321b910a1ba0010a9f3c02e4a0dc2f3ef23f8c8000c303a1f1d34cd1a3a1f3f4a7b1d44251a858b2a0aa05efdd11b9fc1a9b9b6d994c89",
        "45360040da080000d4321b900a1ba0010a9f3c02e4a0dc2f3ef23f8d8000c304a1f1d3ecd1a3a1f3a09854fdc6d341b8d8d98e989545e5eb6f36de9132818dc6",
        "45360040da090000d4321b8f0a1ba0010a9f3c02e4a0dc2f3ef23f8e8000c305a1f1d48cd1a3a1f365d092957c034b38819fbb343a4e6d6638db170d094f4d03",
    }};
    const auto valid_base = hex_bytes(
        "798000c306a1f1d52cd1a3a1f3890743e751a87ea982e5a551ec73927c16d9748a5b4cf216");
    const auto expected = hex_bytes(
        "45360040da0a0000d4321b8e0a1ba0010a9f3c02e4a0dc2f3ef23f8f8000c306a1f1d52cd1a3a1f3890743e751a87ea982e5a551ec73927c16d9748a5b4cf216");
    auto corrupted_base = valid_base;
    corrupted_base[0] ^= 0x01U;
    REQUIRE(corrupted_base[0] == 0x78U);

    for(const auto direction : {ROHCCXX_DIRECTION_UPLINK, ROHCCXX_DIRECTION_DOWNLINK})
    {
        for(const std::uint32_t cid : {0U, 1U, 15U})
        {
            CAPTURE(direction, cid);
            auto frame = [cid](std::vector<std::uint8_t> packet)
            {
                if(cid != 0U)
                    packet.insert(packet.begin(), static_cast<std::uint8_t>(0xe0U | cid));
                return packet;
            };
            DecompPtr decomp(rohc_decomp_new2(15, direction));
            REQUIRE(decomp);
            if(cid == 0U)
            {
                for(std::size_t index = 0U; index < context_packets.size(); ++index)
                    require_guarded_decode(decomp.get(), hex_bytes(context_packets[index]),
                                           hex_bytes(context_expected[index]));
            }
            else
            {
                CompPtr context_comp(rohc_comp_new2(15, direction));
                REQUIRE(context_comp);
                REQUIRE(rohc_comp_set_mode(context_comp.get(), ROHCCXX_MODE_O) == 0);
                REQUIRE(rohc_comp_set_cid(context_comp.get(), cid) == 0);
                for(const auto* expected_hex : context_expected)
                {
                    const auto context_ip = hex_bytes(expected_hex);
                    std::array<std::uint8_t, 512> context_wire{};
                    std::size_t context_wire_len = context_wire.size();
                    REQUIRE(rohc_compress4(context_comp.get(), context_ip.data(),
                                           context_ip.size(), context_wire.data(),
                                           &context_wire_len) == 0);
                    require_guarded_decode(decomp.get(),
                        std::vector<std::uint8_t>(context_wire.begin(), context_wire.begin() +
                            static_cast<std::ptrdiff_t>(context_wire_len)), context_ip);
                }
            }

            require_failed_transaction(decomp.get(), frame(corrupted_base), 510U, true, cid);
            require_guarded_decode(decomp.get(), frame(valid_base), expected);
        }
    }
}

TEST_CASE("valid private FO packets fall back after failed PT-0 authentication")
{
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        CAPTURE(static_cast<unsigned>(profile));
        CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);

        for(std::uint32_t ordinal = 0; ordinal < 2U; ++ordinal)
        {
            const auto ip = make_packet(profile, ordinal);
            std::array<std::uint8_t, 512> rohc{};
            std::size_t rohc_len = rohc.size();
            REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(), rohc.data(), &rohc_len) == 0);
            require_guarded_decode(decomp.get(),
                std::vector<std::uint8_t>(rohc.begin(), rohc.begin() +
                    static_cast<std::ptrdiff_t>(rohc_len)), ip);
        }

        rohccxx::Context private_context{};
        private_context.profile = profile == Pt0Profile::Udp ? rohccxx::Profile::UDP :
            profile == Pt0Profile::Esp ? rohccxx::Profile::ESP : rohccxx::Profile::IP;
        private_context.mode = rohccxx::Mode::Optimistic;
        private_context.rohc_state = rohccxx::RohcState::DynamicEstablished;
        private_context.cid = 0;
        private_context.ip_version = 4;
        private_context.ipv4_ttl = 64;
        private_context.ipv4_flags = 2;
        private_context.ipv4_protocol = profile == Pt0Profile::Udp ? 17U :
            profile == Pt0Profile::Esp ? 50U : 253U;
        private_context.ipv4_saddr = 0x0a000001U;
        private_context.ipv4_daddr = 0x0a000002U;
        private_context.ipv4_id = 0x2345U;
        private_context.udp_sport = 10000U;
        private_context.udp_dport = 20000U;
        private_context.esp_spi = 0x10203000U;
        private_context.esp_sequence = 1U;

        std::array<std::uint8_t, 512> wire{};
        std::size_t wire_len = wire.size();
        const bool emitted = profile == Pt0Profile::Udp
            ? rohccxx::emit_udp_fo(wire.data(), &wire_len, private_context)
            : profile == Pt0Profile::Esp
                ? rohccxx::emit_esp_fo(wire.data(), &wire_len, private_context)
                : rohccxx::emit_ip_fo(wire.data(), &wire_len, private_context);
        REQUIRE(emitted);
        REQUIRE(wire[0] == (profile == Pt0Profile::Udp ? 0x7aU :
                            profile == Pt0Profile::Esp ? 0x78U : 0x79U));
        // Three ESP payload octets produce a private wire image with no
        // one-bit-valid formal PT-0 neighbor. Four octets are deliberately
        // covered by the Issue 47 transactional-rejection regression above.
        const std::vector<std::uint8_t> payload = profile == Pt0Profile::Esp
            ? std::vector<std::uint8_t>{0x10U, 0x20U, 0x30U}
            : std::vector<std::uint8_t>{0x10U, 0x20U, 0x30U, 0x40U};
        std::memcpy(wire.data() + wire_len, payload.data(), payload.size());
        wire_len += payload.size();

        auto expected = make_packet(profile, 1U, 0, private_context.ipv4_id);
        const std::size_t header_len = profile == Pt0Profile::Ip ? 20U : 28U;
        expected.resize(header_len + payload.size());
        put16(expected.data() + 2, static_cast<std::uint16_t>(expected.size()));
        if(profile == Pt0Profile::Udp)
            put16(expected.data() + 24, static_cast<std::uint16_t>(expected.size() - 20U));
        std::memcpy(expected.data() + header_len, payload.data(), payload.size());
        put16(expected.data() + 10, 0);
        put16(expected.data() + 10, ipv4_checksum(expected.data()));
        require_guarded_decode(decomp.get(),
            std::vector<std::uint8_t>(wire.begin(), wire.begin() +
                static_cast<std::ptrdiff_t>(wire_len)), expected);
    }
}

TEST_CASE("PT-0 collision failures are transactional and retryable")
{
    for(const auto item : {std::pair{Pt0Profile::Udp, 14U},
                           std::pair{Pt0Profile::Esp, 47U},
                           std::pair{Pt0Profile::Ip, 61U}})
    {
        CAPTURE(static_cast<unsigned>(item.first), item.second);

        SECTION("CRC corruption and retry")
        {
            auto fixture = establish_before(item.first, item.second);
            auto corrupt = fixture.collision;
            corrupt[0] ^= 0x01U;
            require_failed_transaction(fixture.decomp.get(), corrupt);
            require_guarded_decode(fixture.decomp.get(), fixture.collision, fixture.expected);
        }

        SECTION("truncation and retry")
        {
            auto fixture = establish_before(item.first, item.second);
            auto truncated = fixture.collision;
            truncated.pop_back();
            require_failed_transaction(fixture.decomp.get(), truncated);
            require_guarded_decode(fixture.decomp.get(), fixture.collision, fixture.expected);
        }

        SECTION("insufficient output and retry")
        {
            auto fixture = establish_before(item.first, item.second);
            require_failed_transaction(fixture.decomp.get(), fixture.collision,
                                       fixture.expected.size() - 1U);
            require_guarded_decode(fixture.decomp.get(), fixture.collision, fixture.expected);
        }

        SECTION("duplicate")
        {
            auto fixture = establish_before(item.first, item.second);
            require_guarded_decode(fixture.decomp.get(), fixture.collision, fixture.expected);
            require_failed_transaction(fixture.decomp.get(), fixture.collision);
        }
    }
}

TEST_CASE("PT-0 collision truncation boundaries preserve public state")
{
    SECTION("zero-byte input is an API precondition failure without feedback")
    {
        DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(decomp);
        require_failed_transaction(decomp.get(), {}, 510U, false);
    }

    SECTION("one-byte PT-0 base without its payload fails transactionally")
    {
        auto fixture = establish_before(Pt0Profile::Udp, 14U);
        fixture.collision.resize(1U);
        require_failed_transaction(fixture.decomp.get(), fixture.collision);
    }

    SECTION("UDP checksum field is truncated at every boundary")
    {
        constexpr std::uint16_t checksum = 0x1234U;
        CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 2U; ++ordinal)
        {
            const auto ip = make_packet(Pt0Profile::Udp, ordinal, 0U, 0xffffU, checksum);
            std::array<std::uint8_t, 512> compressed{};
            std::size_t compressed_len = compressed.size();
            REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(), compressed.data(),
                                   &compressed_len) == 0);
            require_guarded_decode(decomp.get(),
                std::vector<std::uint8_t>(compressed.begin(), compressed.begin() +
                    static_cast<std::ptrdiff_t>(compressed_len)), ip);
        }
        // The decoder expects two checksum octets after the base whenever the
        // established UDP context uses checksums. Lengths one and two exercise
        // each missing-field boundary without reading into payload.
        for(std::size_t length = 1U; length < 3U; ++length)
        {
            CAPTURE(length);
            const std::vector<std::uint8_t> truncated{0x7aU, 0x12U};
            require_failed_transaction(decomp.get(),
                std::vector<std::uint8_t>(truncated.begin(), truncated.begin() +
                    static_cast<std::ptrdiff_t>(length)));
        }
    }
}

TEST_CASE("legacy private FO truncation rejects every header boundary")
{
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        CAPTURE(static_cast<unsigned>(profile));
        CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 2U; ++ordinal)
        {
            const auto ip = make_packet(profile, ordinal, 2U);
            std::array<std::uint8_t, 512> compressed{};
            std::size_t compressed_len = compressed.size();
            REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(), compressed.data(),
                                   &compressed_len) == 0);
            require_guarded_decode(decomp.get(),
                std::vector<std::uint8_t>(compressed.begin(), compressed.begin() +
                    static_cast<std::ptrdiff_t>(compressed_len)), ip);
        }

        rohccxx::Context context{};
        context.profile = profile == Pt0Profile::Udp ? rohccxx::Profile::UDP :
            profile == Pt0Profile::Esp ? rohccxx::Profile::ESP : rohccxx::Profile::IP;
        context.mode = rohccxx::Mode::Optimistic;
        context.rohc_state = rohccxx::RohcState::DynamicEstablished;
        context.cid = 0;
        context.ip_version = 4;
        context.ipv4_tos = 2U;
        context.ipv4_ttl = 64;
        context.ipv4_flags = 2;
        context.ipv4_protocol = profile == Pt0Profile::Udp ? 17U :
            profile == Pt0Profile::Esp ? 50U : 253U;
        context.ipv4_saddr = 0x0a000001U;
        context.ipv4_daddr = 0x0a000002U;
        context.ipv4_id = 0x2345U;
        context.udp_sport = 10000U;
        context.udp_dport = 20000U;
        context.esp_spi = 0x10203000U;
        context.esp_sequence = 1U;

        std::array<std::uint8_t, 32> wire{};
        std::size_t header_len = wire.size();
        const bool emitted = profile == Pt0Profile::Udp
            ? rohccxx::emit_udp_fo(wire.data(), &header_len, context)
            : profile == Pt0Profile::Esp
                ? rohccxx::emit_esp_fo(wire.data(), &header_len, context)
                : rohccxx::emit_ip_fo(wire.data(), &header_len, context);
        REQUIRE(emitted);
        for(std::size_t length = 1U; length < header_len; ++length)
        {
            CAPTURE(length, header_len);
            require_failed_transaction(decomp.get(),
                std::vector<std::uint8_t>(wire.begin(), wire.begin() +
                    static_cast<std::ptrdiff_t>(length)));
        }

        // With this TOS=2 context, two ESP payload octets are an
        // unambiguous private FO image; longer ambiguous images are expected
        // to reject under the Issue 47 rule.
        const std::vector<std::uint8_t> payload = profile == Pt0Profile::Esp
            ? std::vector<std::uint8_t>{0x10U, 0x20U}
            : std::vector<std::uint8_t>{0x10U, 0x20U, 0x30U, 0x40U};
        std::memcpy(wire.data() + header_len, payload.data(), payload.size());
        const std::size_t wire_len = header_len + payload.size();
        auto expected = make_packet(profile, 1U, 2U, context.ipv4_id);
        const std::size_t ip_header_len = profile == Pt0Profile::Ip ? 20U : 28U;
        expected.resize(ip_header_len + payload.size());
        put16(expected.data() + 2U, static_cast<std::uint16_t>(expected.size()));
        if(profile == Pt0Profile::Udp)
            put16(expected.data() + 24U,
                  static_cast<std::uint16_t>(expected.size() - 20U));
        std::memcpy(expected.data() + ip_header_len, payload.data(), payload.size());
        put16(expected.data() + 10U, 0U);
        put16(expected.data() + 10U, ipv4_checksum(expected.data()));
        require_guarded_decode(decomp.get(),
            std::vector<std::uint8_t>(wire.begin(), wire.begin() +
                static_cast<std::ptrdiff_t>(wire_len)), expected);
    }
}

TEST_CASE("PT-0 collision contexts tolerate loss and reject stale reordering")
{
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        std::vector<std::uint8_t> delayed;
        for(std::size_t ordinal = 0; ordinal < 24U; ++ordinal)
        {
            const auto ip = make_packet(profile, static_cast<std::uint32_t>(ordinal));
            std::array<std::uint8_t, 512> bytes{};
            std::size_t length = bytes.size();
            REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(), bytes.data(), &length) == 0);
            std::vector<std::uint8_t> rohc(bytes.begin(), bytes.begin() +
                static_cast<std::ptrdiff_t>(length));
            if(ordinal == 8U) continue; // loss
            if(ordinal == 12U) { delayed = rohc; continue; }
            require_guarded_decode(decomp.get(), rohc, ip);
            if(ordinal == 13U) require_failed_transaction(decomp.get(), delayed);
        }
    }
}

TEST_CASE("PT-0 stale reordering rejects CRC-3 collision witnesses transactionally")
{
    struct Witness
    {
        Pt0Profile profile;
        std::uint8_t tos;
    };
    constexpr std::array<Witness, 3> witnesses{{
        {Pt0Profile::Udp, 148U},
        {Pt0Profile::Esp, 243U},
        {Pt0Profile::Ip, 176U},
    }};
    for(const auto& witness : witnesses)
    {
        DYNAMIC_SECTION("profile " << static_cast<unsigned>(witness.profile))
        {
            CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            REQUIRE(decomp);
            std::vector<std::uint8_t> delayed;
            for(std::size_t ordinal = 0; ordinal < 15U; ++ordinal)
            {
                const auto ip = make_packet(witness.profile,
                                            static_cast<std::uint32_t>(ordinal),
                                            witness.tos);
                std::array<std::uint8_t, 512> bytes{};
                std::size_t length = bytes.size();
                REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(),
                                       bytes.data(), &length) == 0);
                std::vector<std::uint8_t> rohc(bytes.begin(), bytes.begin() +
                    static_cast<std::ptrdiff_t>(length));
                if(ordinal == 12U)
                {
                    delayed = rohc;
                    continue;
                }
                require_guarded_decode(decomp.get(), rohc, ip);
                if(ordinal == 13U) require_failed_transaction(decomp.get(), delayed);
            }
        }
    }
}

TEST_CASE("PT-0 no-reordering interval accepts delta 14 and refreshes before delta 15")
{
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        DYNAMIC_SECTION("maximum forward delta for profile " <<
                        static_cast<unsigned>(profile))
        {
            CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            REQUIRE(decomp);
            for(std::uint32_t ordinal = 0U; ordinal <= 15U; ++ordinal)
            {
                const auto ip = make_packet(profile, ordinal);
                const auto rohc = compress_packet(comp.get(), 0U, ip);
                if(ordinal < 2U || ordinal == 15U)
                    require_guarded_decode(decomp.get(), rohc, ip);
                if(ordinal == 15U)
                    REQUIRE(rohc.size() - 160U ==
                            (profile == Pt0Profile::Esp ? 2U : 1U));
            }
        }

        DYNAMIC_SECTION("ambiguous delta for profile " <<
                        static_cast<unsigned>(profile))
        {
            CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            REQUIRE(decomp);
            for(std::uint32_t ordinal = 0U; ordinal <= 16U; ++ordinal)
            {
                const auto ip = make_packet(profile, ordinal);
                const auto rohc = compress_packet(comp.get(), 0U, ip);
                if(ordinal < 2U)
                    require_guarded_decode(decomp.get(), rohc, ip);
                if(ordinal == 16U)
                {
                    REQUIRE(rohc.size() - 160U > 1U);
                    require_guarded_decode(decomp.get(), rohc, ip);
                }
            }
        }
    }
}

TEST_CASE("PT-0 forward gaps cannot alias a later compressor packet to stale state")
{
    // Four MSN LSBs repeat after 16 values.  Establish the context, lose 16
    // consecutive compressor outputs, and submit the next ordered packet.  A
    // wrong delta-1 reconstruction can collide under CRC-3; it must never be
    // returned as a successful packet.
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        for(unsigned tos = 0U; tos <= 0xffU; ++tos)
        {
            CAPTURE(static_cast<unsigned>(profile), tos);
            CompPtr comp(rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            DecompPtr decomp(rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            REQUIRE(decomp);
            for(std::uint32_t ordinal = 0U; ordinal <= 18U; ++ordinal)
            {
                const auto original = make_packet(profile, ordinal,
                                                  static_cast<std::uint8_t>(tos));
                const auto rohc = compress_packet(comp.get(), 0U, original);
                if(ordinal >= 2U && ordinal < 18U)
                    continue;

                std::array<std::uint8_t, 514> output{};
                output.fill(0xa5U);
                const auto guard_before = output;
                std::size_t output_len = output.size() - 2U;
                const int rc = rohc_decompress4(decomp.get(), rohc.data(), rohc.size(),
                                                output.data() + 1U, &output_len);
                if(rc == 0)
                {
                    REQUIRE(output_len == original.size());
                    REQUIRE(std::memcmp(output.data() + 1U, original.data(),
                                        original.size()) == 0);
                }
                else
                {
                    REQUIRE(output_len == 0U);
                    REQUIRE(output == guard_before);
                }
            }
        }
    }
}

TEST_CASE("Delayed refresh ACK cannot authorize PT-0 beyond its forward window")
{
    CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    rohccxx_feedback_v1_t delayed{};
    for(std::uint32_t ordinal = 0U; ordinal <= 32U; ++ordinal)
    {
        const auto original = make_packet(Pt0Profile::Udp, ordinal, 158U);
        const auto rohc = compress_packet(comp.get(), 0U, original);
        if(ordinal <= 1U || ordinal == 16U)
            require_guarded_decode(decomp.get(), rohc, original);
        if(ordinal == 16U)
        {
            REQUIRE(is_ir_packet(rohc, 0U));
            delayed = make_ack(0U, static_cast<std::uint16_t>(ordinal + 1U));
        }
    }

    REQUIRE(rohc_comp_deliver_feedback_v1(comp.get(), &delayed) ==
            ROHCCXX_FEEDBACK_STALE);
    const auto current = make_packet(Pt0Profile::Udp, 33U, 158U);
    const auto current_rohc = compress_packet(comp.get(), 0U, current);
    REQUIRE(is_ir_packet(current_rohc, 0U));
    require_guarded_decode(decomp.get(), current_rohc, current);
}

TEST_CASE("Issue 32 one-byte fuzz witness cannot silently retain an old RTP IPv4 ID",
          "[issue-32]")
{
    require_issue32_fuzz_witness_safe({0x81U}, 22U);
}

TEST_CASE("Issue 32 private ESP marker fuzz witness cannot consume formal PT-0 payload",
          "[issue-32]")
{
    require_issue32_fuzz_witness_safe(
        {0x01U, 0x02U, 0x00U, 0x08U, 0x39U, 0x89U}, 7U);
}

TEST_CASE("Issue 53 CID-0 IP PT-0 cannot install an uncompressed context after restart",
          "[issue-53]")
{
    require_issue32_fuzz_witness_safe(
        hex_bytes("00000000a5a5a5a5a5a5a5a5a5a50010000000100012"), 111U,
        hex_bytes(
            "004f91004ce8a712b4b32e7ec65371bd3036986f39c32e86cf50783cb8000006f"
            "00000000025bd341820d2d7de8bdafbc25189a85fc5e0a594315d994eec798354c6"
            "cfd447e5d6abc0e5bea9d6"));
}

TEST_CASE("UDP formal PT-0 uses RFC 5225 small-CID framing")
{
    for(const std::uint32_t cid : {0U, 1U, 15U})
    {
        CAPTURE(cid);
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 5U; ++ordinal)
        {
            const auto packet = make_packet(Pt0Profile::Udp, ordinal);
            const auto rohc = compress_packet(comp.get(), cid, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal >= 2U)
            {
                REQUIRE(rohc.size() - 160U == (cid == 0U ? 1U : 2U));
                if(cid != 0U)
                    REQUIRE(rohc[0] == static_cast<std::uint8_t>(0xe0U | cid));
            }
        }
    }
}

TEST_CASE("UDP formal PT-0 round-trips four interleaved small-CID flows")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(std::uint32_t ordinal = 0; ordinal < 512U; ++ordinal)
    {
        for(std::uint32_t flow = 0; flow < 4U; ++flow)
        {
            const auto packet = make_packet(Pt0Profile::Udp, ordinal, 0U, 0xffffU,
                                            0U, flow);
            const auto rohc = compress_packet(comp.get(), flow, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            acknowledge_refresh(comp.get(), Pt0Profile::Udp, flow, ordinal, rohc);
            if(ordinal >= 2U && !is_ir_packet(rohc, flow))
                REQUIRE(rohc.size() - 160U == (flow == 0U ? 1U : 2U));
        }
    }
}

TEST_CASE("unsafe UDP fields retain private FO and PT-0 failures are transactional")
{
    SECTION("unsafe fields use the private fallback")
    {
        for(const unsigned change : {0U, 1U, 2U, 3U})
        {
            CAPTURE(change);
            CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
                (void) compress_packet(comp.get(), 0U,
                                       make_packet(Pt0Profile::Udp, ordinal));
            auto packet = make_packet(Pt0Profile::Udp, 3U);
            if(change == 0U) put16(packet.data() + 20U, 10001U);
            if(change == 1U) packet[8] = 63U;
            if(change == 2U) put16(packet.data() + 26U, 0x1234U);
            if(change == 3U) put16(packet.data() + 4U, 99U);
            put16(packet.data() + 10U, 0U);
            put16(packet.data() + 10U, ipv4_checksum(packet.data()));
            const auto rohc = compress_packet(comp.get(), 0U, packet);
            REQUIRE(rohc.size() - 160U == 6U);
            REQUIRE(rohc[0] == 0x7aU);
        }
    }

    SECTION("malformed packets preserve output and context")
    {
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        std::vector<std::uint8_t> valid;
        std::vector<std::uint8_t> expected;
        for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
        {
            expected = make_packet(Pt0Profile::Udp, ordinal);
            valid = compress_packet(comp.get(), 1U, expected);
            if(ordinal < 2U) require_guarded_decode(decomp.get(), valid, expected);
        }
        REQUIRE(valid.size() - 160U == 2U);
        auto corrupt = valid;
        corrupt[1] ^= 0x01U;
        require_failed_transaction(decomp.get(), corrupt, 510U, true, 1U);
        require_guarded_decode(decomp.get(), valid, expected);

        auto next = make_packet(Pt0Profile::Udp, 3U);
        const auto next_valid = compress_packet(comp.get(), 1U, next);
        require_failed_transaction(decomp.get(), {next_valid.front()}, 510U, true, 0U);
        require_guarded_decode(decomp.get(), next_valid, next);
    }
}

TEST_CASE("ESP formal PT-0-CRC7 uses RFC 5225 small-CID framing")
{
    for(const std::uint32_t cid : {0U, 1U, 15U})
    {
        CAPTURE(cid);
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 5U; ++ordinal)
        {
            const auto packet = make_packet(Pt0Profile::Esp, ordinal);
            const auto rohc = compress_packet(comp.get(), cid, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal >= 2U)
            {
                REQUIRE(rohc.size() - 160U == (cid == 0U ? 2U : 3U));
                if(cid != 0U)
                    REQUIRE(rohc[0] == static_cast<std::uint8_t>(0xe0U | cid));
                const std::size_t base = cid == 0U ? 0U : 1U;
                REQUIRE((rohc[base] & 0xe0U) == 0x80U);
            }
        }
    }
}

TEST_CASE("ESP formal PT-0 round-trips four interleaved small-CID flows")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(std::uint32_t ordinal = 0; ordinal < 128U; ++ordinal)
    {
        for(std::uint32_t flow = 0; flow < 4U; ++flow)
        {
            const auto packet = make_packet(Pt0Profile::Esp, ordinal, 0U, 0xffffU,
                                            0U, flow);
            const auto rohc = compress_packet(comp.get(), flow, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            acknowledge_refresh(comp.get(), Pt0Profile::Esp, flow, ordinal, rohc);
            if(ordinal >= 2U && !is_ir_packet(rohc, flow))
                REQUIRE(rohc.size() - 160U == (flow == 0U ? 2U : 3U));
        }
    }
}

TEST_CASE("ESP PT-0 requires safely reconstructable fields and progression")
{
    for(const unsigned change : {0U, 1U, 2U, 3U})
    {
        CAPTURE(change);
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
            (void) compress_packet(comp.get(), 0U,
                                   make_packet(Pt0Profile::Esp, ordinal));
        auto packet = make_packet(Pt0Profile::Esp, 3U);
        if(change == 0U) put32(packet.data() + 20U, 0x55667788U); // SPI
        if(change == 1U) put32(packet.data() + 24U, 35U); // sequence discontinuity
        if(change == 2U) packet[8] = 63U; // dynamic IPv4 field
        if(change == 3U) put16(packet.data() + 4U, 2U); // non-sequential ID
        put16(packet.data() + 10U, 0U);
        put16(packet.data() + 10U, ipv4_checksum(packet.data()));
        const auto rohc = compress_packet(comp.get(), 0U, packet);
        REQUIRE(rohc[0] == 0xfdU);
    }

    SECTION("ESP sequence wraps while the IPv4 ID remains sequential")
    {
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0U; ordinal < 3U; ++ordinal)
        {
            auto packet = make_packet(Pt0Profile::Esp, ordinal, 0U,
                                      static_cast<std::uint16_t>(100U + ordinal));
            put32(packet.data() + 24U, 0xfffffffeU + ordinal);
            const auto rohc = compress_packet(comp.get(), 0U, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal == 2U) REQUIRE(rohc.size() - 160U == 2U);
        }
    }
}

TEST_CASE("IPv4 ID modulo wrap remains synchronized across formal PT-0 profiles",
          "[issue35]")
{
    for(const auto profile : {Pt0Profile::Esp, Pt0Profile::Udp, Pt0Profile::Ip})
    {
        CAPTURE(static_cast<unsigned>(profile));
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);

        for(std::uint32_t ordinal = 0U; ordinal < 20U; ++ordinal)
        {
            const auto id = static_cast<std::uint16_t>(0xffeeU + ordinal);
            auto packet = make_packet(profile, ordinal, 0U, 0U);
            put16(packet.data() + 4U, id);
            put16(packet.data() + 10U, 0U);
            put16(packet.data() + 10U, ipv4_checksum(packet.data()));
            CAPTURE(ordinal, id);
            const auto rohc = compress_packet(comp.get(), 0U, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
        }
    }
}
TEST_CASE("public decoder accepts rohc-lib ESP PT-1 seq-ID across IPv4 ID wrap",
          "[issue36]")
{
    struct OraclePacket
    {
        const char* expected;
        const char* compressed;
    };
    static constexpr std::array<OraclePacket, 19> packets{{
        {"450f0040ffee0000b53226300a22be010a390d0210b6da7dfc87314180000d160c11b98237eaf3514370df27b91d26b9cabf67a5110f5ef1a4c873dacf213df3", "fd039e40320a22be010a390d0210b6da7d000fb5ffeefc8731410080000d160c11b98237eaf3514370df27b91d26b9cabf67a5110f5ef1a4c873dacf213df3"},
        {"450f0040ffef0000b532262f0a22be010a390d0210b6da7dfc87314280000d170c11ba2237eaf3513bb945af221d0c8cc997544cd79fb633245a7cb751911d38", "fd031e40320a22be010a390d0210b6da7d000fb5ffeffc8731420080000d170c11ba2237eaf3513bb945af221d0c8cc997544cd79fb633245a7cb751911d38"},
        {"450f0040fff00000b532262e0a22be010a390d0210b6da7dfc87314380000d180c11bac237eaf351125cf2b636644e4d31ff666e81bd07dd8788b57f516d3ee2", "fd037d40320a22be010a390d0210b6da7d000fb5fff0fc8731430080000d180c11bac237eaf351125cf2b636644e4d31ff666e81bd07dd8788b57f516d3ee2"},
        {"450f0040fff10000b532262d0a22be010a390d0210b6da7dfc87314480000d190c11bb6237eaf351e74e9bd10e2d66d3e5bb94f1dd6486e21bb769f49f39a4b4", "fd038840320a22be010a390d0210b6da7d000fb5fff1fc8731440080000d190c11bb6237eaf351e74e9bd10e2d66d3e5bb94f1dd6486e21bb769f49f39a4b4"},
        {"450f0040fff20000b532262c0a22be010a390d0210b6da7dfc87314580000d1a0c11bc0237eaf351c5a78c63f9f2de7fb96ce1fb47cb239e43f1adc31bf55c9a", "2e80000d1a0c11bc0237eaf351c5a78c63f9f2de7fb96ce1fb47cb239e43f1adc31bf55c9a"},
        {"450f0040fff30000b532262b0a22be010a390d0210b6da7dfc87314680000d1b0c11bca237eaf351ba76cb0dfc1460db35c464e1543d3eaedff4d03c82711b57", "3080000d1b0c11bca237eaf351ba76cb0dfc1460db35c464e1543d3eaedff4d03c82711b57"},
        {"450f0040fff40000b532262a0a22be010a390d0210b6da7dfc87314780000d1c0c11bd4237eaf3513e03af7da529bf8e5e005ef9f896161497f26fa1db789e1c", "3d80000d1c0c11bd4237eaf3513e03af7da529bf8e5e005ef9f896161497f26fa1db789e1c"},
        {"450f0040fff50000b53226290a22be010a390d0210b6da7dfc87314880000d1d0c11bde237eaf3515e465149e4376890002c1836be17fbd67a8d39132984e77d", "4380000d1d0c11bde237eaf3515e465149e4376890002c1836be17fbd67a8d39132984e77d"},
        {"450f0040fff60000b53226280a22be010a390d0210b6da7dfc87314980000d1e0c11be8237eaf3513db0adb17219834a051c4c6d21b7cc6be53dc2e83af7da72", "4f80000d1e0c11be8237eaf3513db0adb17219834a051c4c6d21b7cc6be53dc2e83af7da72"},
        {"450f0040fff70000b53226270a22be010a390d0210b6da7dfc87314a80000d1f0c11bf2237eaf351cb9509950091702c8fe42761d432ce54c03e313d7eea4ee0", "5080000d1f0c11bf2237eaf351cb9509950091702c8fe42761d432ce54c03e313d7eea4ee0"},
        {"450f0040fff80000b53226260a22be010a390d0210b6da7dfc87314b80000d200c11bfc237eaf351f15f683841ec8177de7889a7ce69fc1620ec8a808d065850", "5f80000d200c11bfc237eaf351f15f683841ec8177de7889a7ce69fc1620ec8a808d065850"},
        {"450f0040fff90000b53226250a22be010a390d0210b6da7dfc87314c80000d210c11c06237eaf3519e7aeeaee6632278f77bacb09189e3c297d50cd9d17b5208", "6580000d210c11c06237eaf3519e7aeeaee6632278f77bacb09189e3c297d50cd9d17b5208"},
        {"450f0040fffa0000b53226240a22be010a390d0210b6da7dfc87314d80000d220c11c10237eaf351f7574812a99f20bb72c1c4d01cdc7f5dfaa2cd3cab14286c", "6980000d220c11c10237eaf351f7574812a99f20bb72c1c4d01cdc7f5dfaa2cd3cab14286c"},
        {"450f0040fffb0000b53226230a22be010a390d0210b6da7dfc87314e80000d230c11c1a237eaf351e7e462d854188883a591455c60043263f5a1e864930da726", "7780000d230c11c1a237eaf351e7e462d854188883a591455c60043263f5a1e864930da726"},
        {"450f0040fffc0000b53226220a22be010a390d0210b6da7dfc87314f80000d240c11c24237eaf351d8836954c43a616eb7fdf59963049a1155e5f2a67df6cbc8", "7a80000d240c11c24237eaf351d8836954c43a616eb7fdf59963049a1155e5f2a67df6cbc8"},
        {"450f0040fffd0000b53226210a22be010a390d0210b6da7dfc87315080000d250c11c2e237eaf351611c52312e488ad9a3a970e0e2fbc0063c4390cfbf08f21c", "0180000d250c11c2e237eaf351611c52312e488ad9a3a970e0e2fbc0063c4390cfbf08f21c"},
        {"450f0040fffe0000b53226200a22be010a390d0210b6da7dfc87315180000d260c11c38237eaf3513eaf59a9134990ed195e06ddd7bcbd64734b7cc3806fe54c", "0d80000d260c11c38237eaf3513eaf59a9134990ed195e06ddd7bcbd64734b7cc3806fe54c"},
        {"450f0040ffff0000b532261f0a22be010a390d0210b6da7dfc87315280000d270c11c42237eaf351fddc6cce2fc8a5a9404ebd5a64728999f3e510628af6c595", "1480000d270c11c42237eaf351fddc6cce2fc8a5a9404ebd5a64728999f3e510628af6c595"},
        {"450f004000000000b532261f0a22be010a390d0210b6da7dfc87315380000d280c11c4c237eaf35139971d3384e4d735b29898749b98bcafcfd509154495d918", "b93d80000d280c11c4c237eaf35139971d3384e4d735b29898749b98bcafcfd509154495d918"},
    }};

    auto wire_packet = [&](const char* compressed, std::uint32_t cid)
    {
        auto wire = hex_bytes(compressed);
        if(cid != 0U)
            wire.insert(wire.begin(), static_cast<std::uint8_t>(0xe0U | cid));
        return wire;
    };
    auto decoder_after = [&](std::uint32_t cid, std::size_t decoded_count)
    {
        CompPtr compressor(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decoder(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(compressor);
        REQUIRE(decoder);
        for(std::size_t step = 0U; step < decoded_count; ++step)
        {
            CAPTURE(step);
            const auto expected = hex_bytes(packets[step].expected);
            const auto compressed = cid == 0U
                ? wire_packet(packets[step].compressed, cid)
                : compress_packet(compressor.get(), cid, expected);
            require_guarded_decode(decoder.get(), compressed, expected);
        }
        return decoder;
    };

    const auto final_expected = hex_bytes(packets.back().expected);
    for(const std::uint32_t cid : {0U, 1U, 15U})
    {
        CAPTURE(cid);
        const auto final_compressed = wire_packet(packets.back().compressed, cid);

        {
            auto decoder = decoder_after(cid, packets.size());
            require_failed_transaction(decoder.get(), final_compressed, 510U, true, cid);
        }

        {
            auto decoder = decoder_after(cid, packets.size() - 1U);
            auto corrupt_crc = final_compressed;
            corrupt_crc[cid == 0U ? 0U : 1U] ^= 0x04U;
            require_failed_transaction(decoder.get(), corrupt_crc, 510U, true, cid);
            require_guarded_decode(decoder.get(), final_compressed, final_expected);
        }

        {
            auto decoder = decoder_after(cid, packets.size() - 1U);
            auto truncated = final_compressed;
            truncated.pop_back();
            truncated.resize(cid == 0U ? 1U : 2U);
            require_failed_transaction(decoder.get(), truncated, 510U, true, cid);
            require_guarded_decode(decoder.get(), final_compressed, final_expected);
        }

        {
            auto decoder = decoder_after(cid, packets.size() - 1U);
            require_failed_transaction(decoder.get(), final_compressed,
                                       final_expected.size() - 1U, true, cid);
            require_guarded_decode(decoder.get(), final_compressed, final_expected);
        }

        DecompPtr no_context(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(no_context);
        require_failed_transaction(no_context.get(), final_compressed, 510U, true, cid);
    }
}

TEST_CASE("malformed ESP PT-0 fails transactionally and remains retryable")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    std::vector<std::uint8_t> valid;
    std::vector<std::uint8_t> expected;
    for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
    {
        expected = make_packet(Pt0Profile::Esp, ordinal);
        valid = compress_packet(comp.get(), 1U, expected);
        if(ordinal < 2U) require_guarded_decode(decomp.get(), valid, expected);
    }
    REQUIRE(valid.size() - 160U == 3U);
    auto corrupt = valid;
    corrupt[1] ^= 0x01U;
    require_failed_transaction(decomp.get(), corrupt, 510U, true, 1U);
    require_guarded_decode(decomp.get(), valid, expected);

    auto next = make_packet(Pt0Profile::Esp, 3U);
    const auto next_valid = compress_packet(comp.get(), 1U, next);
    require_failed_transaction(decomp.get(), {next_valid.front()}, 510U, true, 0U);
    require_guarded_decode(decomp.get(), next_valid, next);
}

TEST_CASE("IP-only formal PT-0 uses RFC 5225 small-CID framing")
{
    for(const std::uint32_t cid : {0U, 1U, 15U})
    {
        CAPTURE(cid);
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 5U; ++ordinal)
        {
            const auto packet = make_packet(Pt0Profile::Ip, ordinal);
            const auto rohc = compress_packet(comp.get(), cid, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal >= 2U)
            {
                REQUIRE(rohc.size() - 160U == (cid == 0U ? 1U : 2U));
                if(cid != 0U)
                    REQUIRE(rohc[0] == static_cast<std::uint8_t>(0xe0U | cid));
            }
        }
    }
}

TEST_CASE("IP-only formal PT-0 round-trips four interleaved small-CID flows")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(std::uint32_t ordinal = 0; ordinal < 128U; ++ordinal)
    {
        for(std::uint32_t flow = 0; flow < 4U; ++flow)
        {
            const auto packet = make_packet(Pt0Profile::Ip, ordinal, 0U, 0xffffU,
                                            0U, flow);
            const auto rohc = compress_packet(comp.get(), flow, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            acknowledge_refresh(comp.get(), Pt0Profile::Ip, flow, ordinal, rohc);
            if(ordinal >= 2U && !is_ir_packet(rohc, flow))
                REQUIRE(rohc.size() - 160U == (flow == 0U ? 1U : 2U));
        }
    }
}

TEST_CASE("unsafe IP-only fields retain private FO fallback")
{
    for(const unsigned change : {0U, 1U, 2U, 3U, 4U})
    {
        CAPTURE(change);
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
        {
            const auto packet = make_packet(Pt0Profile::Ip, ordinal);
            const auto rohc = compress_packet(comp.get(), 0U, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
        }
        auto packet = make_packet(Pt0Profile::Ip, 3U);
        if(change == 0U) packet[1] = 4U;
        if(change == 1U) packet[8] = 63U;
        if(change == 2U) packet[9] = 252U;
        if(change == 3U) packet[19] = 9U;
        if(change == 4U) put16(packet.data() + 4U, 2U);
        put16(packet.data() + 10U, 0U);
        put16(packet.data() + 10U, ipv4_checksum(packet.data()));
        const auto rohc = compress_packet(comp.get(), 0U, packet);
        if(change == 4U)
        {
            REQUIRE(rohc.size() - 160U == 4U);
            REQUIRE(rohc[0] == 0x79U);
        }
        else
        {
            REQUIRE(rohc[0] == 0xfdU);
        }
        require_guarded_decode(decomp.get(), rohc, packet);
    }
}

TEST_CASE("malformed IP-only PT-0 fails transactionally and remains retryable")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    std::vector<std::uint8_t> valid;
    std::vector<std::uint8_t> expected;
    for(std::uint32_t ordinal = 0; ordinal < 3U; ++ordinal)
    {
        expected = make_packet(Pt0Profile::Ip, ordinal);
        valid = compress_packet(comp.get(), 1U, expected);
        if(ordinal < 2U) require_guarded_decode(decomp.get(), valid, expected);
    }
    REQUIRE(valid.size() - 160U == 2U);
    auto corrupt = valid;
    corrupt[1] ^= 0x01U;
    require_failed_transaction(decomp.get(), corrupt, 510U, true, 1U);
    require_guarded_decode(decomp.get(), valid, expected);

    auto next = make_packet(Pt0Profile::Ip, 3U);
    const auto next_valid = compress_packet(comp.get(), 1U, next);
    require_failed_transaction(decomp.get(), {next_valid.front()}, 510U, true, 0U);
    require_guarded_decode(decomp.get(), next_valid, next);
}

TEST_CASE("RTP formal PT-0 round-trips four interleaved small-CID flows")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(unsigned ordinal = 0; ordinal < 4U; ++ordinal)
    {
        for(unsigned flow = 0; flow < 4U; ++flow)
        {
            const auto sequence = static_cast<std::uint16_t>(1000U + ordinal);
            const auto packet = make_rtp_packet(sequence, 90000U + ordinal * 160U,
                                                static_cast<std::uint16_t>(3000U + ordinal), flow);
            const auto rohc = compress_rtp(comp.get(), flow, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal >= 2U)
            {
                REQUIRE(rohc.size() - 160U == (flow == 0U ? 2U : 3U));
                if(flow != 0U) REQUIRE(rohc[0] == static_cast<std::uint8_t>(0xe0U | flow));
            }
        }
    }
}

TEST_CASE("RTP formal PT-0 reconstructs sequence timestamp and IPv4-ID wrap")
{
    for(const bool constant_id : {false, true})
    {
        CAPTURE(constant_id);
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        for(unsigned ordinal = 0; ordinal < 4U; ++ordinal)
        {
            const auto sequence = static_cast<std::uint16_t>(0xfffeU + ordinal);
            const auto timestamp = static_cast<std::uint32_t>(0xffffff00U + ordinal * 160U);
            const auto id = constant_id ? 77U : static_cast<std::uint16_t>(0xfffeU + ordinal);
            const auto packet = make_rtp_packet(sequence, timestamp, id);
            const auto rohc = compress_rtp(comp.get(), 0U, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal >= 2U) REQUIRE(rohc.size() - 160U == 2U);
        }
    }
}

TEST_CASE("Issue 32 delayed legacy RTP PT-0 WAN witness rejects transactionally",
          "[issue32]")
{
    // Preserved from combined-D mini-PC -> AWS Ohio -> Pi5:
    // 300 ms delay, 5% loss, 5% duplication, 10% reorder, seed 531034.
    // The compact ordinal 83 arrived after the ordinal 291 refresh and
    // previously authenticated a reconstruction 16 RTP sequence numbers
    // ahead through a CRC-3 collision.
    const std::array<const char*, 3> context_units{{
        "e3fd013840110a142101c633010d2ee355f31122300406003d2300000000630fa000061a80e7b2f3646a5234c0000000030000000355ef1af6a30824d0533d55114373f54e904f65dbaa5f6dd1aa0b8922a02ff5140eaa05bb6a3ab2cd",
        "e3fd011040110a142101c633010d2ee355f31122300404003d2301000000630fa100061b208fe011894454ac6700000013000000036d91ecd5d8f51e76d6995a7af4578f2458dcf9f0b7f009917868e605f184bb6aacafc899c04b3bff",
        "e3fd01a140110a142101c633010d2ee355f31122300404003d2312000000630fb2000625c01d251f4779c74c640000012300000003da3b55cf1cee37bf6ac06f193f99ac574fb3e04f97e2d5387e1024f6e77ea6edb4395f816ccc93d8",
    }};
    const std::array<const char*, 3> context_packets{{
        "45000060230040003d1128380a142101c633010d2ee355f3004c000080630fa000061a8011223004e7b2f3646a5234c0000000030000000355ef1af6a30824d0533d55114373f54e904f65dbaa5f6dd1aa0b8922a02ff5140eaa05bb6a3ab2cd",
        "45000060230140003d1128370a142101c633010d2ee355f3004c000080630fa100061b20112230048fe011894454ac6700000013000000036d91ecd5d8f51e76d6995a7af4578f2458dcf9f0b7f009917868e605f184bb6aacafc899c04b3bff",
        "45000060231240003d1128260a142101c633010d2ee355f3004c000080630fb2000625c0112230041d251f4779c74c640000012300000003da3b55cf1cee37bf6ac06f193f99ac574fb3e04f97e2d5387e1024f6e77ea6edb4395f816ccc93d8",
    }};
    const auto delayed = hex_bytes(
        "e32e8699a2e5c4afa6fd0000005300000003934ee819dde68dcc5be7fc3763bb42589ad13042940f55d746701a54def10c06420ac44b1b65ef18");
    const auto recovery_unit = hex_bytes(
        "e3fd019240110a142101c633010d2ee355f31122300404003d2313000000630fb3000626607577fdaa57c1d4c30000013300000003e245a3ec67130d19ef64607288bdd63d87207c648a4db178ac734bd1b6d5e893163c92a3c6bd1aea");
    const auto recovery_packet = hex_bytes(
        "45000060231340003d1128250a142101c633010d2ee355f3004c000080630fb300062660112230047577fdaa57c1d4c30000013300000003e245a3ec67130d19ef64607288bdd63d87207c648a4db178ac734bd1b6d5e893163c92a3c6bd1aea");

    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp);
    for(std::size_t index = 0U; index < context_units.size(); ++index)
        require_guarded_decode(decomp.get(), hex_bytes(context_units[index]),
                               hex_bytes(context_packets[index]));
    require_failed_transaction(decomp.get(), delayed, 510U, true, 3U);
    require_failed_transaction(decomp.get(), delayed, 510U, true, 3U);
    require_guarded_decode(decomp.get(), recovery_unit, recovery_packet);
}

TEST_CASE("Issue 32 current RTP PT-0 emission resists delayed CRC aliases",
          "[issue32]")
{
    for(const std::uint32_t cid : {1U, 3U})
    {
        CAPTURE(cid);
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        std::vector<std::uint8_t> delayed;

        for(std::uint32_t ordinal = 0U; ordinal < 22U; ++ordinal)
        {
            const auto packet = make_rtp_packet(
                static_cast<std::uint16_t>(4000U + ordinal),
                400000U + ordinal * 160U,
                static_cast<std::uint16_t>(8000U + ordinal), cid);
            const auto rohc = compress_rtp(comp.get(), cid, packet);
            require_guarded_decode(decomp.get(), rohc, packet);
            if(ordinal == 2U)
            {
                const std::size_t base = cid == 0U ? 0U : 1U;
                REQUIRE(rohc.size() - 160U == (cid == 0U ? 2U : 3U));
                REQUIRE((rohc[base] & 0xf0U) == 0x80U);
                delayed = rohc;
            }
        }

        REQUIRE(!delayed.empty());
        require_failed_transaction(decomp.get(), delayed, 510U, true, cid);
        require_failed_transaction(decomp.get(), delayed, 510U, true, cid);

        const auto recovery = make_rtp_packet(4022U, 403520U, 8022U, cid);
        const auto recovery_rohc = compress_rtp(comp.get(), cid, recovery);
        require_guarded_decode(decomp.get(), recovery_rohc, recovery);
    }
}

TEST_CASE("Issue 32 RC2 delayed ESP PT-0 wrap witness rejects transactionally",
          "[issue32][rc2-wan]")
{
    // Exact compressed witness from the published v0.8.0-rc.2 geographic
    // soak: mini-PC -> AWS Ohio -> Pi5, seed 80200203, CID 9, ordinal 89.
    // The round-5 unit arrived after the live context reached round 20. Its
    // four MSN LSBs decoded as forward delta 1, producing round 21's IPv4 ID
    // and wrapped ESP sequence; CRC-3 authenticated that wrong header.
    // compressed SHA-384: a3f5c2d8de831930d04827f6b312c5298eaee09a79cd908f66b05a2cc37f0931d71157e11b4874fd1b378d4faf1fb667
    // expected SHA-384:   e3a34dcf9d3df649e24f9746fe5c411a02fbcb2d04a74343b5f35f79fb6751004c962c5e5f58e8b72a478f80c6f74025
    // wrong RC2 SHA-384:  eb6c87a119bdf9e7546157f9cbfea2f86c8f608570aa2b4703807e0f606e1dd36dd4dc50b8ff5a96b5823c621b55b361
    constexpr std::uint32_t cid = 9U;
    const auto delayed = hex_bytes(
        "e92f2a9df8076fc05c5f12a0a5a7edaa6e1bf20eb8bc000000590000000900000000c374fbe1307402f853f2a2b97c18"
        "13e20202211dc8976ff51026e0f49a5dd596ddf44369fa005c435ae46d068f9574e14bf0271cd1a2aca876cf1c56f4af"
        "0bfb967adfd7f99a343a8f64d359df1b7c2720ab0801c8ae4767014342297be9da725dc14c9a369ed54c98dd38e81600"
        "3af74d531278371459977f05cbde8cfb9085b00932986a1542032a7902613148c628b7afbf5d5f57daa8f11208281ba9"
        "c8baa58e23281df5abfb339c7abe3573bb4c8312d9fafe0cc5b6e90e8a322d8ce4494f86a46fa3c65e552433fb114c2c"
        "c2eb15cb076a2dd4ec20d487bfa40ae6c1713a90a79cf8b9f30e0fd0b870a5917cd0a3fa19fd0a1f2258048d2d101f87"
        "bd7eb0578675ceaaac254846b932b0b3a956d5f0beed2e03b5c2962558821acaa9c96e39fda11961bdefb05316547310"
        "354fd7620a974638240914156bd2cefbc46c984a6975d1fbd516adf5d1ea14e0f8bb209d8d0bd0be2a82277a1e61c87d"
        "617d9605de0f2e685914b2d7b0c98037a6d145d081f86181f97e77707b443ee98c2e77dd9d76857a2f4c836a96119327"
        "8f3406a567b96d62763447a29c732dcfbfb6c5acf345712be057e20e25a74e26a1f5f651f6b2fcbb6ca820775a69110e"
        "aa152b72381f53099171f2b767447c6134a8a1501e4b881364c353d1d6ea98b716144f3cdcb9e014fa3206e50f62f1fd"
        "0ffea04c4bec1c155934ffaa8a397626875c5e59db312aa57fa52faaf8d4811a13306c822e09e70d50d736add166757c"
        "e0d7e13655213b9913aeb43400a64d9759423f179454c2dd33e71a5fa3333a4b8e6ea65276ab90f856ce9dca304d477b"
        "ab2389373e86369ca6d0c56433b94a249aed913b3322b5abca8fac019754d51fe18012098b8298617bc1959dde3ed9e1"
        "09e961b886a7836ef5e1f3b828d85e7aed508c4773ea37940178323d7741d460f8540624cabe08a78aed42babc0c9525"
        "bc7075b0e627015c3749e55db768ec3500132ec52c9a3622bb14b5a5ff2aa7397ec67915a0f6c357a0aee431b6aa458a"
        "69298e5815870dc665828a4047034965c0541a81b1dc3147d2eb59cdecedb1bf227d3af0a5d368862887ee95b5efeb27"
        "849fdcd67f258d18478e87e1b17abdbb887ff94e2b170a63cb98845324f0faca813b6524870bb68e46b5ab33ef4a05e8"
        "10f112447018ce9e03bd21d9cf03b435af9e61611fcd86aa239941263846aaf15c71b515d15a672aee4dbe2ccaf5ccd9"
        "b23f8850172bc4b0837da089986ed7e84e65cda772f16b08e0147a094486dad9ac51dcfbdcc5ca9c529c8a2a5ae78e57"
        "150392f6677d9a8c375c2cbf10aecad7c9a59ee9f7029d90c98b24b7838262a58da86f55d3206a52e2f071360f1bce4c"
        "b5a678c41f4c04bbc1499e5fac1391c0b3d1db105b7baaf74270eec549405d51988a5f8e9564a0bc39c1adc6a4bf78b8"
        "a660650a4dea8e31a0710e29eec84fb00be94a4166b3731e0c9b732459b001dc1711ae7159978e81b9edc9600ff6a977"
        "eba5202d78475fb3f90193b0d295429ccb028a447944a37766020b8b2375d4196544e2e6be60fd7fcc881fdd870083b7"
        "a0143503352633b1411907b656928d5f7903b9478aa4f464f77fb4d527d9a593c53029bef1561eb0e23d29d586e3aeef"
        "b00b35013c9a8c3408964f69e2221574ea225144159621ca99eaae7e915149a9e507fc3af5ca3950daf0a6e52c09815a"
        "a3671da1a427");
    REQUIRE(delayed.size() == 1254U);
    REQUIRE(delayed[0] == 0xe9U);
    REQUIRE(delayed[1] == 0x2fU);

    auto expected = make_rc2_soak_esp_packet(5U, 1280U);
    REQUIRE(delayed.size() - 2U == expected.size() - 28U);
    std::copy(delayed.begin() + 2U, delayed.end(), expected.begin() + 28U);

    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    for(std::uint32_t round = 0U; round <= 20U; ++round)
    {
        const auto packet = make_rc2_soak_esp_packet(round);
        const auto rohc = compress_packet(comp.get(), cid, packet);
        if(round == 5U)
        {
            REQUIRE(rohc[0] == delayed[0]);
            if((rohc[1] & 0x80U) == 0U)
                REQUIRE(rohc[1] == delayed[1]);
            else
                REQUIRE((rohc[1] & 0xe0U) == 0x80U);
            continue;
        }
        require_guarded_decode(decomp.get(), rohc, packet);
    }

    for(unsigned attempt = 0U; attempt < 2U; ++attempt)
    {
        std::vector<std::uint8_t> output(expected.size() + 2U, 0xa5U);
        output.front() = 0x3cU;
        output.back() = 0xc3U;
        const auto before = output;
        std::size_t output_len = expected.size();
        const int rc = rohc_decompress4(decomp.get(), delayed.data(), delayed.size(),
                                        output.data() + 1U, &output_len);
        INFO("every successful decompression must equal the intended original");
        if(rc == 0)
        {
            REQUIRE(output_len == expected.size());
            REQUIRE(std::memcmp(output.data() + 1U, expected.data(),
                                expected.size()) == 0);
        }
        else
        {
            REQUIRE(output_len == 0U);
            REQUIRE(output == before);
            REQUIRE(rohc_decomp_has_feedback(decomp.get()) == 1);
        }
    }

    const auto recovery = make_rc2_soak_esp_packet(21U);
    const auto recovery_rohc = compress_packet(comp.get(), cid, recovery);
    REQUIRE(is_ir_packet(recovery_rohc, cid));
    require_guarded_decode(decomp.get(), recovery_rohc, recovery);
}

TEST_CASE("unsafe RTP field changes retain the private FO fallback")
{
    enum class Change { Timestamp, Sequence, Marker, PayloadType, Ssrc, Ports,
                        IpAddress, IpTtl, UdpChecksum, Ipv4Id };
    for(const auto change : {Change::Timestamp, Change::Sequence, Change::Marker,
                             Change::PayloadType, Change::Ssrc, Change::Ports,
                             Change::IpAddress, Change::IpTtl, Change::UdpChecksum,
                             Change::Ipv4Id})
    {
        CAPTURE(static_cast<unsigned>(change));
        CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        for(unsigned ordinal = 0; ordinal < 3U; ++ordinal)
        {
            const auto packet = make_rtp_packet(static_cast<std::uint16_t>(100U + ordinal),
                                                10000U + ordinal * 160U,
                                                static_cast<std::uint16_t>(500U + ordinal));
            (void) compress_rtp(comp.get(), 0U, packet);
        }
        auto packet = make_rtp_packet(103U, 10480U, 503U);
        switch(change)
        {
        case Change::Timestamp: put32(packet.data() + 32U, 10481U); break;
        case Change::Sequence:
            put16(packet.data() + 30U, 122U);
            put32(packet.data() + 32U, 13520U);
            put16(packet.data() + 4U, 522U);
            break;
        case Change::Marker: packet[29] |= 0x80U; break;
        case Change::PayloadType: packet[29] = 97U; break;
        case Change::Ssrc: put32(packet.data() + 36U, 0x10203041U); break;
        case Change::Ports: put16(packet.data() + 20U, 10001U); break;
        case Change::IpAddress: packet[19] = 103U; break;
        case Change::IpTtl: packet[8] = 63U; break;
        case Change::UdpChecksum: put16(packet.data() + 26U, 0x1234U); break;
        case Change::Ipv4Id: put16(packet.data() + 4U, 700U); break;
        }
        put16(packet.data() + 10U, 0U);
        put16(packet.data() + 10U, ipv4_checksum(packet.data()));
        const auto rohc = compress_rtp(comp.get(), 0U, packet);
        REQUIRE(rohc.size() - 160U > 1U);
    }
}

TEST_CASE("corrupted RTP PT-0 fails without changing output or context")
{
    CompPtr comp(rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    std::vector<std::uint8_t> valid;
    std::vector<std::uint8_t> expected;
    for(unsigned ordinal = 0; ordinal < 3U; ++ordinal)
    {
        expected = make_rtp_packet(static_cast<std::uint16_t>(200U + ordinal),
                                   20000U + ordinal * 160U,
                                   static_cast<std::uint16_t>(800U + ordinal));
        valid = compress_rtp(comp.get(), 0U, expected);
        if(ordinal < 2U) require_guarded_decode(decomp.get(), valid, expected);
    }
    REQUIRE(valid.size() - 160U == 2U);
    auto corrupt = valid;
    corrupt[1] ^= 0x01U;
    require_failed_transaction(decomp.get(), corrupt);
    require_guarded_decode(decomp.get(), valid, expected);
}

TEST_CASE("IP PT-0 synchronizes IP-ID behavior transitions", "[issue28]")
{
    for(const std::uint32_t cid : {0U, 2U, 15U})
    {
        // Zero/random/sequential transitions occur in real TCP and ICMP flows.
        for(const auto ids : {std::vector<std::uint16_t>{0, 100, 101, 102, 103},
                              std::vector<std::uint16_t>{100, 101, 102, 103, 104, 120, 121, 122, 123},
                              std::vector<std::uint16_t>{100, 101, 105, 106, 107, 108}})
        {
            CompPtr comp(rohc_comp_new2(15, ROHCCXX_DIRECTION_UPLINK));
            DecompPtr decomp(rohc_decomp_new2(15, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(comp);
            REQUIRE(decomp);
            REQUIRE(rohc_comp_set_cid(comp.get(), cid) == 0);
            for(std::size_t ordinal = 0; ordinal < ids.size(); ++ordinal)
            {
                INFO("cid=" << cid << " ordinal=" << ordinal << " id=" << ids[ordinal]);
                auto ip = make_packet(Pt0Profile::Ip, ordinal, 0, ids[ordinal]);
                // A DF change forces a full refresh after the context is warm.
                if(ordinal >= 5) put16(ip.data() + 6, 0);
                put16(ip.data() + 10, 0);
                put16(ip.data() + 10, ipv4_checksum(ip.data()));
                std::array<std::uint8_t, 512> wire{};
                std::size_t length = wire.size();
                REQUIRE(rohc_compress4(comp.get(), ip.data(), ip.size(), wire.data(), &length) == 0);
                require_guarded_decode(decomp.get(),
                    std::vector<std::uint8_t>(wire.begin(), wire.begin() + length), ip);
            }
        }
    }
}
