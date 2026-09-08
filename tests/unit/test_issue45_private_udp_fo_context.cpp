// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/emit_udplite_fo.hpp"
#include "issue45_stale_cid_fixture.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace
{

struct DecompDelete
{
    void operator()(rohc_decomp* value) const { rohc_decomp_free(value); }
};

using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

// Exact Add-CID 1 private UDP FO frame captured when reorder delivered source
// sequence 8 before CID 1's IR. SHA-384:
// 0a460dd004a08a8a1ca43d6f44bfb8fca4dde450c7b02f8388e33063770c61e980c15bf0bc84dd4dea3d2d1c58e63daf
constexpr std::array<std::uint8_t, 135> captured_private_udp_fo{{
    0xe1, 0x7a, 0x07, 0x4e, 0x95, 0x29, 0x02, 0x41, 0x4c, 0x54, 0x45, 0x52,
    0x45, 0x44, 0x4e, 0x45, 0x54, 0x53, 0x2d, 0x49, 0x4d, 0x50, 0x41, 0x49,
    0x52, 0x3a, 0x72, 0x65, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x3a, 0x66, 0x6f,
    0x72, 0x77, 0x61, 0x72, 0x64, 0x3a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38,
    0x3a, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71,
}};

enum class PrivateProfile
{
    Udp,
    Ip,
    Esp,
    UdpLite,
};

std::vector<std::uint8_t> make_private_fo(PrivateProfile profile,
                                          std::uint32_t cid,
                                          std::uint16_t udp_checksum = 0x2902U,
                                          bool established_udp_tuple = false)
{
    rohccxx::Context context{};
    context.profile = profile == PrivateProfile::Udp ? rohccxx::Profile::UDP :
                      profile == PrivateProfile::Ip ? rohccxx::Profile::IP :
                      profile == PrivateProfile::Esp ? rohccxx::Profile::ESP :
                      rohccxx::Profile::UDP_Lite;
    context.rohc_state = rohccxx::RohcState::DynamicEstablished;
    context.cid = cid;
    if(established_udp_tuple)
    {
        context.ipv4_ttl = 64U;
        context.ipv4_protocol = 17U;
        context.ipv4_saddr = 0xc0000201U;
        context.ipv4_daddr = 0xc6336402U;
        context.udp_sport = 0x1234U;
        context.udp_dport = 0x5678U;
    }
    context.ipv4_id = 0x4e95U;
    context.udp_length_or_coverage = 24U;
    context.udp_check = udp_checksum;

    std::array<std::uint8_t, 32> header{};
    std::size_t header_len = header.size();
    const bool emitted = profile == PrivateProfile::Udp ?
        rohccxx::emit_udp_fo(header.data(), &header_len, context) :
        profile == PrivateProfile::Ip ?
        rohccxx::emit_ip_fo(header.data(), &header_len, context) :
        profile == PrivateProfile::Esp ?
        rohccxx::emit_esp_fo(header.data(), &header_len, context) :
        rohccxx::emit_udp_lite_fo(header.data(), &header_len, context);
    REQUIRE(emitted);

    std::vector<std::uint8_t> packet;
    if(cid != 0U)
        packet.push_back(static_cast<std::uint8_t>(0xe0U | cid));
    packet.insert(packet.end(), header.begin(), header.begin() + header_len);
    constexpr std::array<std::uint8_t, 16> payload{{
        0x41, 0x4c, 0x54, 0x45, 0x52, 0x45, 0x44, 0x4e,
        0x45, 0x54, 0x53, 0x2d, 0x46, 0x4f, 0x2d, 0x21,
    }};
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

void require_fresh_context_rejection(const std::vector<std::uint8_t>& packet,
                                     rohccxx_direction_t direction =
                                         ROHCCXX_DIRECTION_UPLINK)
{
    DecompPtr decomp(rohc_decomp_new2(15U, direction));
    REQUIRE(decomp != nullptr);

    std::array<std::uint8_t, 256> output{};
    output.fill(0xa5U);
    const auto original_output = output;
    std::size_t output_len = output.size();

    REQUIRE(rohc_decompress4(decomp.get(), packet.data(), packet.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == original_output);

    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), packet.data(), packet.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == original_output);
}

std::uint16_t ipv4_checksum(const std::uint8_t* header)
{
    std::uint32_t sum = 0U;
    for(std::size_t i = 0U; i < 20U; i += 2U)
    {
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(header[i]) << 8U) | header[i + 1U]);
    }
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

std::vector<std::uint8_t> expected_udp_packet(std::uint16_t ipv4_id,
                                              std::uint16_t udp_checksum)
{
    constexpr std::array<std::uint8_t, 16> payload{{
        0x41, 0x4c, 0x54, 0x45, 0x52, 0x45, 0x44, 0x4e,
        0x45, 0x54, 0x53, 0x2d, 0x46, 0x4f, 0x2d, 0x21,
    }};
    std::vector<std::uint8_t> packet(28U + payload.size(), 0U);
    packet[0] = 0x45U;
    packet[2] = static_cast<std::uint8_t>(packet.size() >> 8U);
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[4] = static_cast<std::uint8_t>(ipv4_id >> 8U);
    packet[5] = static_cast<std::uint8_t>(ipv4_id);
    packet[8] = 64U;
    packet[9] = 17U;
    packet[12] = 192U;
    packet[13] = 0U;
    packet[14] = 2U;
    packet[15] = 1U;
    packet[16] = 198U;
    packet[17] = 51U;
    packet[18] = 100U;
    packet[19] = 2U;
    const auto header_checksum = ipv4_checksum(packet.data());
    packet[10] = static_cast<std::uint8_t>(header_checksum >> 8U);
    packet[11] = static_cast<std::uint8_t>(header_checksum);
    packet[20] = 0x12U;
    packet[21] = 0x34U;
    packet[22] = 0x56U;
    packet[23] = 0x78U;
    packet[24] = 0U;
    packet[25] = static_cast<std::uint8_t>(8U + payload.size());
    packet[26] = static_cast<std::uint8_t>(udp_checksum >> 8U);
    packet[27] = static_cast<std::uint8_t>(udp_checksum);
    std::copy(payload.begin(), payload.end(), packet.begin() + 28);
    return packet;
}

void establish_udp_context(rohc_decomp* decomp,
                           std::uint32_t cid,
                           std::uint16_t udp_checksum)
{
    rohccxx::Context context{};
    context.profile = rohccxx::Profile::UDP;
    context.mode = rohccxx::Mode::Optimistic;
    context.cid = cid;
    context.ipv4_ttl = 64U;
    context.ipv4_protocol = 17U;
    context.ipv4_saddr = 0xc0000201U;
    context.ipv4_daddr = 0xc6336402U;
    context.udp_sport = 0x1234U;
    context.udp_dport = 0x5678U;
    context.udp_length_or_coverage = 8U;
    context.udp_check = udp_checksum;

    std::array<std::uint8_t, 128> ir{};
    std::size_t ir_len = ir.size();
    REQUIRE(rohccxx::emit_ir_udp(ir.data(), &ir_len, context));

    std::array<std::uint8_t, 128> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, ir.data(), ir_len,
                             output.data(), &output_len) == 0);
    REQUIRE(output_len == 28U);
}

std::vector<std::uint8_t> emit_replacement_private_fo()
{
    const auto& packet = issue45_fixture::replacement_flow_expected;
    rohccxx::Context context{};
    context.profile = rohccxx::Profile::UDP;
    context.rohc_state = rohccxx::RohcState::DynamicEstablished;
    context.cid = 12U;
    context.ip_version = 4U;
    context.ipv4_tos = packet[1];
    context.ipv4_ttl = packet[8];
    context.ipv4_protocol = packet[9];
    context.ipv4_saddr = (static_cast<std::uint32_t>(packet[12]) << 24U) |
                         (static_cast<std::uint32_t>(packet[13]) << 16U) |
                         (static_cast<std::uint32_t>(packet[14]) << 8U) |
                         packet[15];
    context.ipv4_daddr = (static_cast<std::uint32_t>(packet[16]) << 24U) |
                         (static_cast<std::uint32_t>(packet[17]) << 16U) |
                         (static_cast<std::uint32_t>(packet[18]) << 8U) |
                         packet[19];
    context.ipv4_id = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[4]) << 8U) | packet[5]);
    context.ipv4_flags = static_cast<std::uint8_t>(packet[6] >> 5U);
    context.udp_sport = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[20]) << 8U) | packet[21]);
    context.udp_dport = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[22]) << 8U) | packet[23]);
    context.udp_length_or_coverage = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[24]) << 8U) | packet[25]);
    context.udp_check = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[26]) << 8U) | packet[27]);
    context.udp_checksum_used = context.udp_check != 0U;

    std::array<std::uint8_t, 32> header{};
    std::size_t header_len = header.size();
    REQUIRE(rohccxx::emit_udp_fo(header.data(), &header_len, context));
    std::vector<std::uint8_t> output;
    output.push_back(0xecU);
    output.insert(output.end(), header.begin(), header.begin() + header_len);
    output.insert(output.end(), packet.begin() + 28, packet.end());
    return output;
}

} // namespace

TEST_CASE("Private UDP FO without an established CID context fails transactionally")
{
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp != nullptr);

    std::array<std::uint8_t, 256> output{};
    output.fill(0xa5U);
    const auto original_output = output;
    std::size_t output_len = output.size();

    REQUIRE(rohc_decompress4(decomp.get(),
                             captured_private_udp_fo.data(),
                             captured_private_udp_fo.size(),
                             output.data(),
                             &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == original_output);
    REQUIRE(rohc_decomp_has_feedback(decomp.get()) == 1);

    // A rejected CO packet must not establish or otherwise mutate its CID.
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(),
                             captured_private_udp_fo.data(),
                             captured_private_udp_fo.size(),
                             output.data(),
                             &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == original_output);
}

TEST_CASE("Generated private UDP FO without static context is rejected")
{
    require_fresh_context_rejection(make_private_fo(PrivateProfile::Udp, 1U));
}

TEST_CASE("Generated private IP FO without static context is rejected")
{
    require_fresh_context_rejection(make_private_fo(PrivateProfile::Ip, 1U));
}

TEST_CASE("Generated private ESP FO without static context is rejected")
{
    require_fresh_context_rejection(make_private_fo(PrivateProfile::Esp, 1U));
}

TEST_CASE("Generated private UDP-Lite FO without static context is rejected")
{
    require_fresh_context_rejection(make_private_fo(PrivateProfile::UdpLite, 1U));
}

TEST_CASE("Private FO missing-context rejection covers small CIDs and directions")
{
    constexpr std::array<std::uint32_t, 3> cids{{0U, 1U, 15U}};
    constexpr std::array<rohccxx_direction_t, 2> directions{{
        ROHCCXX_DIRECTION_UPLINK,
        ROHCCXX_DIRECTION_DOWNLINK,
    }};
    constexpr std::array<PrivateProfile, 4> profiles{{
        PrivateProfile::Udp,
        PrivateProfile::Ip,
        PrivateProfile::Esp,
        PrivateProfile::UdpLite,
    }};

    for(const auto direction : directions)
    {
        for(const auto cid : cids)
        {
            for(const auto profile : profiles)
            {
                CAPTURE(direction, cid, profile);
                require_fresh_context_rejection(
                    make_private_fo(profile, cid), direction);
            }
            require_fresh_context_rejection(
                make_private_fo(PrivateProfile::Udp, cid, 0U), direction);
        }
    }
}

TEST_CASE("Profile-mismatched private FO rejection preserves an established context")
{
    constexpr std::array<std::uint32_t, 3> cids{{0U, 1U, 15U}};
    constexpr std::array<rohccxx_direction_t, 2> directions{{
        ROHCCXX_DIRECTION_UPLINK,
        ROHCCXX_DIRECTION_DOWNLINK,
    }};
    constexpr std::array<std::uint16_t, 2> checksums{{0U, 0x2902U}};

    for(const auto direction : directions)
    {
        for(const auto cid : cids)
        {
            for(const auto checksum : checksums)
            {
                CAPTURE(direction, cid, checksum);
                DecompPtr decomp(rohc_decomp_new2(15U, direction));
                REQUIRE(decomp != nullptr);
                establish_udp_context(decomp.get(), cid, checksum);

                const auto mismatched = make_private_fo(PrivateProfile::Ip, cid);
                std::array<std::uint8_t, 128> output{};
                output.fill(0xa5U);
                const auto original_output = output;
                std::size_t output_len = output.size();
                REQUIRE(rohc_decompress4(decomp.get(), mismatched.data(),
                                         mismatched.size(), output.data(),
                                         &output_len) != 0);
                REQUIRE(output_len == 0U);
                REQUIRE(output == original_output);

                const auto valid = make_private_fo(PrivateProfile::Udp, cid,
                                                   checksum, true);
                output_len = output.size();
                REQUIRE(rohc_decompress4(decomp.get(), valid.data(), valid.size(),
                                         output.data(), &output_len) == 0);
                const auto expected = expected_udp_packet(0x4e95U, checksum);
                REQUIRE(output_len == expected.size());
                REQUIRE(std::equal(expected.begin(), expected.end(), output.begin()));
            }
        }
    }
}

TEST_CASE("Private UDP FO for a reused CID rejects stale same-profile context")
{
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp != nullptr);

    std::array<std::uint8_t, 512> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(),
                             issue45_fixture::prior_flow_ir.data(),
                             issue45_fixture::prior_flow_ir.size(),
                             output.data(), &output_len) == 0);

    output.fill(0xa5U);
    const auto guarded_output = output;
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(),
                             issue45_fixture::replacement_flow_fo.data(),
                             issue45_fixture::replacement_flow_fo.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == guarded_output);
    REQUIRE(rohc_decomp_has_feedback(decomp.get()) == 1);

    // Rejection must be transactional and the later replacement IR must
    // establish the new generation of CID 12 normally.
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(),
                             issue45_fixture::replacement_flow_ir.data(),
                             issue45_fixture::replacement_flow_ir.size(),
                             output.data(), &output_len) == 0);

    const auto current_private_fo = emit_replacement_private_fo();
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), current_private_fo.data(),
                             current_private_fo.size(),
                             output.data(), &output_len) == 0);
    REQUIRE(output_len == issue45_fixture::replacement_flow_expected.size());
    REQUIRE(std::equal(issue45_fixture::replacement_flow_expected.begin(),
                       issue45_fixture::replacement_flow_expected.end(),
                       output.begin()));
}

TEST_CASE("Private UDP FO binds same-profile static context across CIDs and directions")
{
    constexpr std::array<std::uint32_t, 3> cids{{0U, 1U, 15U}};
    constexpr std::array<rohccxx_direction_t, 2> directions{{
        ROHCCXX_DIRECTION_UPLINK,
        ROHCCXX_DIRECTION_DOWNLINK,
    }};
    constexpr std::array<std::uint16_t, 2> checksums{{0U, 0x2902U}};

    for(const auto direction : directions)
    {
        for(const auto cid : cids)
        {
            for(const auto checksum : checksums)
            {
                CAPTURE(direction, cid, checksum);
                DecompPtr decomp(rohc_decomp_new2(15U, direction));
                REQUIRE(decomp != nullptr);
                establish_udp_context(decomp.get(), cid, checksum);

                // make_private_fo deliberately carries the same profile and
                // dynamic values under a different omitted static tuple.
                const auto stale = make_private_fo(PrivateProfile::Udp, cid,
                                                   checksum);
                std::array<std::uint8_t, 256> output{};
                output.fill(0xa5U);
                const auto guarded_output = output;
                std::size_t output_len = output.size();
                REQUIRE(rohc_decompress4(decomp.get(), stale.data(), stale.size(),
                                         output.data(), &output_len) != 0);
                REQUIRE(output_len == 0U);
                REQUIRE(output == guarded_output);
            }
        }
    }
}
