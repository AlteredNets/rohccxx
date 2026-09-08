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

// Exact Add-CID 13 private UDP FO payload captured by the ARM64 full-stack
// reorder soak.  Under the stale CID-13 UDP context below, 0x7a also
// authenticates as formal PT-0 and succeeds with fabricated headers.
// ROHC SHA-384:
// 380a38fef0a69bd07beb67fe81b9c667ca6a1bd2b855990bba5650000b07eae0af9ef590ad0ce45f2706dad695e2bb66
constexpr std::array<std::uint8_t, 135> captured_stale_private_as_formal{{
    0xed, 0x7a, 0xbb, 0xff, 0xd5, 0x06, 0x42, 0x41, 0x4c, 0x54, 0x45, 0x52,
    0x45, 0x44, 0x4e, 0x45, 0x54, 0x53, 0x2d, 0x49, 0x4d, 0x50, 0x41, 0x49,
    0x52, 0x3a, 0x72, 0x65, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2d, 0x6e, 0x30,
    0x33, 0x3a, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x3a, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x35, 0x3a, 0x31, 0x37, 0x38, 0x38, 0x38, 0x39, 0x31,
    0x33, 0x30, 0x31, 0x33, 0x32, 0x38, 0x39, 0x38, 0x30, 0x31, 0x34, 0x32,
    0x3a, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
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

rohccxx::Context private_static_context(PrivateProfile profile,
                                        std::uint32_t cid,
                                        bool replacement)
{
    rohccxx::Context context{};
    context.profile = profile == PrivateProfile::Ip ? rohccxx::Profile::IP :
                      profile == PrivateProfile::Esp ? rohccxx::Profile::ESP :
                      rohccxx::Profile::UDP_Lite;
    context.mode = rohccxx::Mode::Optimistic;
    context.rohc_state = rohccxx::RohcState::DynamicEstablished;
    context.cid = cid;
    context.ip_version = 4U;
    context.ipv4_tos = replacement ? 0x30U : 0x10U;
    context.ipv4_ttl = replacement ? 61U : 63U;
    context.ipv4_id = replacement ? 0x2200U : 0x1200U;
    context.ipv4_flags = 2U;
    context.ipv4_id_behavior = 2U;
    context.ipv4_saddr = replacement ? 0xc0000201U : 0x0a000001U;
    context.ipv4_daddr = replacement ? 0xc6336402U : 0x0a000002U;
    context.msn = 0x2234U;

    if(profile == PrivateProfile::Ip)
    {
        context.ipv4_protocol = 253U;
    }
    else if(profile == PrivateProfile::UdpLite)
    {
        context.ipv4_protocol = 136U;
        context.udp_sport = replacement ? 0x2222U : 0x1111U;
        context.udp_dport = replacement ? 0x4444U : 0x3333U;
        context.udp_length_or_coverage = 24U;
        context.udp_check = 0x2902U;
        context.udp_checksum_used = true;
    }
    else
    {
        context.ipv4_protocol = 50U;
        context.esp_spi = replacement ? 0xa17e2002U : 0xa17e1001U;
        context.esp_sequence = replacement ? 0x10203050U : 0x10203040U;
        context.msn = static_cast<std::uint16_t>(context.esp_sequence);
    }
    return context;
}

std::vector<std::uint8_t> emit_private_ir(PrivateProfile profile,
                                          const rohccxx::Context& context)
{
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    const bool emitted = profile == PrivateProfile::Ip ?
        rohccxx::emit_ir_ip(output.data(), &output_len, context) :
        profile == PrivateProfile::Esp ?
        rohccxx::emit_ir_esp(output.data(), &output_len, context) :
        rohccxx::emit_ir_udp_lite(output.data(), &output_len, context);
    REQUIRE(emitted);
    return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(output_len)};
}

std::vector<std::uint8_t> emit_private_static_fo(
    PrivateProfile profile, const rohccxx::Context& context)
{
    std::array<std::uint8_t, 32> header{};
    std::size_t header_len = header.size();
    const bool emitted = profile == PrivateProfile::Ip ?
        rohccxx::emit_ip_fo(header.data(), &header_len, context) :
        profile == PrivateProfile::Esp ?
        rohccxx::emit_esp_fo(header.data(), &header_len, context) :
        rohccxx::emit_udp_lite_fo(header.data(), &header_len, context);
    REQUIRE(emitted);

    std::vector<std::uint8_t> output;
    if(context.cid != 0U)
        output.push_back(static_cast<std::uint8_t>(0xe0U | context.cid));
    output.insert(output.end(), header.begin(),
                  header.begin() + static_cast<std::ptrdiff_t>(header_len));
    constexpr std::array<std::uint8_t, 16> payload{{
        0x41, 0x4c, 0x54, 0x45, 0x52, 0x45, 0x44, 0x4e,
        0x45, 0x54, 0x53, 0x2d, 0x46, 0x4f, 0x2d, 0x21,
    }};
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

std::vector<std::uint8_t> expected_private_static_packet(
    PrivateProfile profile, const rohccxx::Context& context)
{
    constexpr std::array<std::uint8_t, 16> payload{{
        0x41, 0x4c, 0x54, 0x45, 0x52, 0x45, 0x44, 0x4e,
        0x45, 0x54, 0x53, 0x2d, 0x46, 0x4f, 0x2d, 0x21,
    }};
    const std::size_t upper_header_len = profile == PrivateProfile::Ip ? 0U : 8U;
    std::vector<std::uint8_t> packet(20U + upper_header_len + payload.size(), 0U);
    packet[0] = 0x45U;
    packet[1] = context.ipv4_tos;
    packet[2] = static_cast<std::uint8_t>(packet.size() >> 8U);
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[4] = static_cast<std::uint8_t>(context.ipv4_id >> 8U);
    packet[5] = static_cast<std::uint8_t>(context.ipv4_id);
    packet[6] = static_cast<std::uint8_t>(context.ipv4_flags << 5U);
    packet[8] = context.ipv4_ttl;
    packet[9] = context.ipv4_protocol;
    packet[12] = static_cast<std::uint8_t>(context.ipv4_saddr >> 24U);
    packet[13] = static_cast<std::uint8_t>(context.ipv4_saddr >> 16U);
    packet[14] = static_cast<std::uint8_t>(context.ipv4_saddr >> 8U);
    packet[15] = static_cast<std::uint8_t>(context.ipv4_saddr);
    packet[16] = static_cast<std::uint8_t>(context.ipv4_daddr >> 24U);
    packet[17] = static_cast<std::uint8_t>(context.ipv4_daddr >> 16U);
    packet[18] = static_cast<std::uint8_t>(context.ipv4_daddr >> 8U);
    packet[19] = static_cast<std::uint8_t>(context.ipv4_daddr);

    if(profile == PrivateProfile::UdpLite)
    {
        packet[20] = static_cast<std::uint8_t>(context.udp_sport >> 8U);
        packet[21] = static_cast<std::uint8_t>(context.udp_sport);
        packet[22] = static_cast<std::uint8_t>(context.udp_dport >> 8U);
        packet[23] = static_cast<std::uint8_t>(context.udp_dport);
        packet[24] = static_cast<std::uint8_t>(context.udp_length_or_coverage >> 8U);
        packet[25] = static_cast<std::uint8_t>(context.udp_length_or_coverage);
        packet[26] = static_cast<std::uint8_t>(context.udp_check >> 8U);
        packet[27] = static_cast<std::uint8_t>(context.udp_check);
    }
    else if(profile == PrivateProfile::Esp)
    {
        packet[20] = static_cast<std::uint8_t>(context.esp_spi >> 24U);
        packet[21] = static_cast<std::uint8_t>(context.esp_spi >> 16U);
        packet[22] = static_cast<std::uint8_t>(context.esp_spi >> 8U);
        packet[23] = static_cast<std::uint8_t>(context.esp_spi);
        packet[24] = static_cast<std::uint8_t>(context.esp_sequence >> 24U);
        packet[25] = static_cast<std::uint8_t>(context.esp_sequence >> 16U);
        packet[26] = static_cast<std::uint8_t>(context.esp_sequence >> 8U);
        packet[27] = static_cast<std::uint8_t>(context.esp_sequence);
    }

    const auto header_checksum = ipv4_checksum(packet.data());
    packet[10] = static_cast<std::uint8_t>(header_checksum >> 8U);
    packet[11] = static_cast<std::uint8_t>(header_checksum);
    std::copy(payload.begin(), payload.end(), packet.begin() + 20U + upper_header_len);
    return packet;
}

void establish_private_static_context(rohc_decomp* decomp,
                                      PrivateProfile profile,
                                      const rohccxx::Context& context)
{
    const auto ir = emit_private_ir(profile, context);
    std::array<std::uint8_t, 256> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, ir.data(), ir.size(),
                             output.data(), &output_len) == 0);
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

TEST_CASE("Captured private UDP FO cannot authenticate as formal PT-0 under stale CID context")
{
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp != nullptr);

    // This is the exact stale reconstruction context isolated from the soak.
    // The captured private packet belongs to another UDP tuple.  Interpreting
    // byte 0x7a as formal PT-0 advances MSN 1 -> 15 and IPv4 ID 0xfeea ->
    // 0xfef8, consumes 0xbbff as the UDP checksum, and exposes the private
    // IPv4-ID/checksum bytes as payload.  That 159-byte fabricated packet had
    // SHA-384 4043f87187c0ef2683aad5feaf96b616632e9ff87e518ffb8245b50197ffa7ec5d00a2f52771d8f0b8901f2f083b6c88.
    rohccxx::Context stale{};
    stale.profile = rohccxx::Profile::UDP;
    stale.mode = rohccxx::Mode::Optimistic;
    stale.rohc_state = rohccxx::RohcState::DynamicEstablished;
    stale.cid = 13U;
    stale.msn = 1U;
    stale.reorder_ratio = 0U;
    stale.ip_version = 4U;
    stale.ipv4_tos = 0x20U;
    stale.ipv4_ttl = 64U;
    stale.ipv4_id = 0xfeeaU;
    stale.ipv4_flags = 2U;
    stale.ipv4_id_behavior = 0U;
    stale.ipv4_id_sequential = true;
    stale.ipv4_protocol = 17U;
    stale.ipv4_saddr = 0x0acb0002U;
    stale.ipv4_daddr = 0x0acb0001U;
    stale.udp_sport = 44016U;
    stale.udp_dport = 43100U;
    stale.udp_length_or_coverage = 8U;
    stale.udp_check = 0x0642U;
    stale.udp_checksum_used = true;

    std::array<std::uint8_t, 256> ir{};
    std::size_t ir_len = ir.size();
    REQUIRE(rohccxx::emit_ir_udp(ir.data(), &ir_len, stale));
    std::array<std::uint8_t, 512> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), ir.data(), ir_len,
                             output.data(), &output_len) == 0);

    output.fill(0xa5U);
    const auto guarded_output = output;
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), captured_stale_private_as_formal.data(),
                             captured_stale_private_as_formal.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == guarded_output);
    REQUIRE(rohc_decomp_has_feedback(decomp.get()) == 1);

    // Rejection remains transactional when the same wire image is retried.
    output_len = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), captured_stale_private_as_formal.data(),
                             captured_stale_private_as_formal.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == guarded_output);
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

TEST_CASE("Private IP UDP-Lite and ESP FO bind same-profile reconstruction context")
{
    constexpr std::array<PrivateProfile, 3> profiles{{
        PrivateProfile::Ip,
        PrivateProfile::UdpLite,
        PrivateProfile::Esp,
    }};
    constexpr std::array<std::uint32_t, 3> cids{{0U, 1U, 15U}};
    constexpr std::array<rohccxx_direction_t, 2> directions{{
        ROHCCXX_DIRECTION_UPLINK,
        ROHCCXX_DIRECTION_DOWNLINK,
    }};

    for(const auto profile : profiles)
    {
        for(const auto cid : cids)
        {
            for(const auto direction : directions)
            {
                CAPTURE(static_cast<int>(profile), cid, direction);
                const auto stale_context = private_static_context(profile, cid, false);
                auto current_context = private_static_context(profile, cid, true);
                current_context.ipv4_id = 0x4e95U;

                DecompPtr stale(rohc_decomp_new2(15U, direction));
                DecompPtr current(rohc_decomp_new2(15U, direction));
                REQUIRE(stale != nullptr);
                REQUIRE(current != nullptr);
                establish_private_static_context(stale.get(), profile, stale_context);
                establish_private_static_context(current.get(), profile, current_context);

                const auto private_fo = emit_private_static_fo(profile, current_context);
                std::array<std::uint8_t, 256> stale_output{};
                stale_output.fill(0xa5U);
                const auto guarded_output = stale_output;
                std::size_t stale_len = stale_output.size();
                CHECK(rohc_decompress4(stale.get(), private_fo.data(), private_fo.size(),
                                       stale_output.data(), &stale_len) != 0);
                CHECK(stale_len == 0U);
                CHECK(stale_output == guarded_output);

                std::array<std::uint8_t, 256> current_output{};
                std::size_t current_len = current_output.size();
                REQUIRE(rohc_decompress4(current.get(), private_fo.data(), private_fo.size(),
                                         current_output.data(), &current_len) == 0);
                const auto expected = expected_private_static_packet(profile, current_context);
                REQUIRE(current_len == expected.size());
                REQUIRE(std::equal(expected.begin(), expected.end(), current_output.begin()));
            }
        }
    }
}
