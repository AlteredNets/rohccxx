// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace
{

using Packet = std::array<std::uint8_t, 136>;
constexpr std::array<Packet, 3> issue39_packets{{
    Packet{{
        0x45U, 0x00U, 0x00U, 0x88U, 0xccU, 0x74U, 0x40U, 0x00U, 0x40U, 0x11U, 0x58U, 0x58U,
        0x0aU, 0xcbU, 0x00U, 0x01U, 0x0aU, 0xcbU, 0x00U, 0x02U, 0xdaU, 0xdaU, 0xa8U, 0x5eU,
        0x00U, 0x74U, 0x94U, 0x90U, 0x80U, 0x60U, 0xffU, 0xf8U, 0xffU, 0xffU, 0xffU, 0x00U,
        0x10U, 0x20U, 0x30U, 0x40U, 0x52U, 0x54U, 0x50U, 0x2dU, 0x66U, 0x6fU, 0x72U, 0x77U,
        0x61U, 0x72U, 0x64U, 0x2dU, 0x46U, 0x30U, 0x2dU, 0x53U, 0x30U, 0x30U, 0x30U, 0x30U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U
    }},
    Packet{{
        0x45U, 0x00U, 0x00U, 0x88U, 0xccU, 0x75U, 0x40U, 0x00U, 0x40U, 0x11U, 0x58U, 0x57U,
        0x0aU, 0xcbU, 0x00U, 0x01U, 0x0aU, 0xcbU, 0x00U, 0x02U, 0xdaU, 0xdaU, 0xa8U, 0x5eU,
        0x00U, 0x74U, 0x93U, 0xeeU, 0x80U, 0x60U, 0xffU, 0xf9U, 0xffU, 0xffU, 0xffU, 0xa0U,
        0x10U, 0x20U, 0x30U, 0x40U, 0x52U, 0x54U, 0x50U, 0x2dU, 0x66U, 0x6fU, 0x72U, 0x77U,
        0x61U, 0x72U, 0x64U, 0x2dU, 0x46U, 0x30U, 0x2dU, 0x53U, 0x30U, 0x30U, 0x30U, 0x31U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U
    }},
    Packet{{
        0x45U, 0x00U, 0x00U, 0x88U, 0xccU, 0x76U, 0x40U, 0x00U, 0x40U, 0x11U, 0x58U, 0x56U,
        0x0aU, 0xcbU, 0x00U, 0x01U, 0x0aU, 0xcbU, 0x00U, 0x02U, 0xdaU, 0xdaU, 0xa8U, 0x5eU,
        0x00U, 0x74U, 0x93U, 0x4dU, 0x80U, 0x60U, 0xffU, 0xfaU, 0x00U, 0x00U, 0x00U, 0x40U,
        0x10U, 0x20U, 0x30U, 0x40U, 0x52U, 0x54U, 0x50U, 0x2dU, 0x66U, 0x6fU, 0x72U, 0x77U,
        0x61U, 0x72U, 0x64U, 0x2dU, 0x46U, 0x30U, 0x2dU, 0x53U, 0x30U, 0x30U, 0x30U, 0x32U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U, 0x72U,
        0x72U, 0x72U, 0x72U, 0x72U
    }}
}};

struct CompDelete
{
    void operator()(rohc_comp* value) const { rohc_comp_free(value); }
};
struct DecompDelete
{
    void operator()(rohc_decomp* value) const { rohc_decomp_free(value); }
};
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

std::uint16_t read16(const std::uint8_t* value)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8U) | value[1]);
}

std::uint32_t read32(const std::uint8_t* value)
{
    return (static_cast<std::uint32_t>(value[0]) << 24U) |
           (static_cast<std::uint32_t>(value[1]) << 16U) |
           (static_cast<std::uint32_t>(value[2]) << 8U) | value[3];
}

std::uint16_t udp_checksum_validation(const std::uint8_t* packet, std::size_t length)
{
    REQUIRE(length >= 28U);
    const auto ihl = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
    REQUIRE(packet[0] >> 4U == 4U);
    REQUIRE(packet[9] == 17U);
    REQUIRE(length >= ihl + 8U);
    const auto udp_length = static_cast<std::size_t>(read16(packet + ihl + 4U));
    REQUIRE(length >= ihl + udp_length);

    std::uint32_t sum = 0U;
    auto add_word = [&sum](std::uint16_t word) { sum += word; };
    for(std::size_t pos = 12U; pos < 20U; pos += 2U)
        add_word(read16(packet + pos));
    add_word(17U);
    add_word(static_cast<std::uint16_t>(udp_length));
    for(std::size_t pos = 0U; pos + 1U < udp_length; pos += 2U)
        add_word(read16(packet + ihl + pos));
    if((udp_length & 1U) != 0U)
        add_word(static_cast<std::uint16_t>(packet[ihl + udp_length - 1U]) << 8U);
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

TEST_CASE("RTP timestamp wrap refreshes a changing UDP checksum exactly", "[issue-39]")
{
    REQUIRE(read16(issue39_packets[0].data() + 30U) == 0xfff8U);
    REQUIRE(read16(issue39_packets[1].data() + 30U) == 0xfff9U);
    REQUIRE(read16(issue39_packets[2].data() + 30U) == 0xfffaU);
    REQUIRE(read32(issue39_packets[0].data() + 32U) == 0xffffff00U);
    REQUIRE(read32(issue39_packets[1].data() + 32U) == 0xffffffa0U);
    REQUIRE(read32(issue39_packets[2].data() + 32U) == 0x00000040U);

    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_comp_set_cid(comp.get(), 4U) == 0);

    for(std::size_t index = 0U; index < issue39_packets.size(); ++index)
    {
        const auto& input = issue39_packets[index];
        REQUIRE(udp_checksum_validation(input.data(), input.size()) == 0U);

        std::array<std::uint8_t, 1160> compressed{};
        std::size_t compressed_length = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), input.data(), input.size(),
                               compressed.data(), &compressed_length) == 0);

        std::array<std::uint8_t, 1160> output{};
        output.fill(0xa5U);
        std::size_t output_length = output.size();
        const auto decompress_rc = rohc_decompress4(
            decomp.get(), compressed.data(), compressed_length,
            output.data(), &output_length);
        const auto expected_udp_checksum = read16(input.data() + 26U);
        const auto actual_udp_checksum = output_length >= 28U ? read16(output.data() + 26U) : 0U;
        const auto actual_validation = output_length >= 28U
            ? udp_checksum_validation(output.data(), output_length)
            : 0xffffU;
        CAPTURE(index, compressed_length, decompress_rc, output_length,
                expected_udp_checksum, actual_udp_checksum, actual_validation);

        REQUIRE(decompress_rc == 0);
        REQUIRE(output_length == input.size());
        CHECK(actual_udp_checksum == expected_udp_checksum);
        CHECK(actual_validation == 0U);
        CHECK(std::equal(input.begin(), input.end(), output.begin(),
                         output.begin() + static_cast<std::ptrdiff_t>(output_length)));
    }
}


struct RtpPoint
{
    std::uint16_t sequence;
    std::uint32_t timestamp;
};

void write16(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 8U);
    out[1] = static_cast<std::uint8_t>(value);
}

void write32(std::uint8_t* out, std::uint32_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 24U);
    out[1] = static_cast<std::uint8_t>(value >> 16U);
    out[2] = static_cast<std::uint8_t>(value >> 8U);
    out[3] = static_cast<std::uint8_t>(value);
}

std::uint16_t ipv4_checksum(const std::uint8_t* header)
{
    std::uint32_t sum = 0U;
    for(std::size_t pos = 0U; pos < 20U; pos += 2U)
        sum += read16(header + pos);
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

Packet make_rtp_packet(RtpPoint point, std::uint16_t ipv4_id,
                       unsigned flow, bool checksum_enabled)
{
    Packet packet{};
    packet[0] = 0x45U;
    write16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    write16(packet.data() + 4U, ipv4_id);
    write16(packet.data() + 6U, 0x4000U);
    packet[8] = 64U;
    packet[9] = 17U;
    packet[12] = 10U;
    packet[13] = 203U;
    packet[15] = static_cast<std::uint8_t>(1U + flow);
    packet[16] = 10U;
    packet[17] = 203U;
    packet[19] = static_cast<std::uint8_t>(101U + flow);
    write16(packet.data() + 20U, static_cast<std::uint16_t>(10000U + flow));
    write16(packet.data() + 22U, static_cast<std::uint16_t>(20000U + flow));
    write16(packet.data() + 24U, static_cast<std::uint16_t>(packet.size() - 20U));
    packet[28] = 0x80U;
    packet[29] = 96U;
    write16(packet.data() + 30U, point.sequence);
    write32(packet.data() + 32U, point.timestamp);
    write32(packet.data() + 36U, 0x10203040U + flow);
    for(std::size_t pos = 40U; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(
            pos + point.sequence + (point.timestamp >> 8U) + flow * 17U);
    if(checksum_enabled)
    {
        auto checksum = udp_checksum_validation(packet.data(), packet.size());
        if(checksum == 0U) checksum = 0xffffU;
        write16(packet.data() + 26U, checksum);
        REQUIRE(udp_checksum_validation(packet.data(), packet.size()) == 0U);
    }
    write16(packet.data() + 10U, ipv4_checksum(packet.data()));
    return packet;
}

std::vector<std::uint8_t> compress_packet(rohc_comp* comp, std::uint32_t cid,
                                          const Packet& input)
{
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    std::array<std::uint8_t, 1160> compressed{};
    std::size_t compressed_length = compressed.size();
    REQUIRE(rohc_compress4(comp, input.data(), input.size(),
                           compressed.data(), &compressed_length) == 0);
    return {compressed.begin(), compressed.begin() +
                                static_cast<std::ptrdiff_t>(compressed_length)};
}

void require_exact_decompression(rohc_decomp* decomp,
                                 const std::vector<std::uint8_t>& compressed,
                                 const Packet& input)
{
    std::array<std::uint8_t, 1160> output{};
    output.fill(0xa5U);
    std::size_t output_length = output.size();
    REQUIRE(rohc_decompress4(decomp, compressed.data(), compressed.size(),
                             output.data(), &output_length) == 0);
    REQUIRE(output_length == input.size());
    REQUIRE(std::equal(input.begin(), input.end(), output.begin(),
                       output.begin() + static_cast<std::ptrdiff_t>(output_length)));
}

template<std::size_t Size>
void require_exact_stream(std::uint32_t cid,
                          const std::array<RtpPoint, Size>& points,
                          bool checksum_enabled,
                          unsigned flow = 0U,
                          std::uint16_t initial_ipv4_id = 1000U)
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
    for(std::size_t index = 0U; index < points.size(); ++index)
    {
        const auto input = make_rtp_packet(
            points[index], static_cast<std::uint16_t>(initial_ipv4_id + index),
            flow, checksum_enabled);
        const auto compressed = compress_packet(comp.get(), cid, input);
        require_exact_decompression(decomp.get(), compressed, input);
    }
}

TEST_CASE("RTP checksum refresh covers timestamp and sequence wrap boundaries",
          "[issue-39]")
{
    constexpr std::array<RtpPoint, 4> timestamp_wrap{{
        {100U, 0xffffff00U},
        {101U, 0xffffffa0U},
        {102U, 0x00000040U},
        {103U, 0x000000e0U},
    }};
    constexpr std::array<RtpPoint, 4> sequence_wrap{{
        {0xfffeU, 100000U},
        {0xffffU, 100160U},
        {0x0000U, 100320U},
        {0x0001U, 100480U},
    }};
    constexpr std::array<RtpPoint, 4> combined_wrap{{
        {0xfffeU, 0xffffff00U},
        {0xffffU, 0xffffffa0U},
        {0x0000U, 0x00000040U},
        {0x0001U, 0x000000e0U},
    }};

    for(const std::uint32_t cid : {0U, 1U, 15U})
    {
        CAPTURE(cid);
        require_exact_stream(cid, timestamp_wrap, true);
    }
    require_exact_stream(1U, sequence_wrap, true);
    require_exact_stream(15U, combined_wrap, true);
    require_exact_stream(1U, timestamp_wrap, false);
}

TEST_CASE("RTP checksum refresh isolates interleaved flows and restarts",
          "[issue-39]")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
    for(unsigned ordinal = 0U; ordinal < 5U; ++ordinal)
    {
        for(unsigned flow = 0U; flow < 2U; ++flow)
        {
            const std::uint32_t cid = flow == 0U ? 1U : 15U;
            const auto input = make_rtp_packet(
                {static_cast<std::uint16_t>(0xfffdU + ordinal),
                 static_cast<std::uint32_t>(0xfffffe60U + ordinal * 160U)},
                static_cast<std::uint16_t>(3000U + ordinal), flow, true);
            const auto compressed = compress_packet(comp.get(), cid, input);
            require_exact_decompression(decomp.get(), compressed, input);
        }
    }

    constexpr std::array<RtpPoint, 3> after_restart{{
        {0xfff9U, 0xffffffa0U},
        {0xfffaU, 0x00000040U},
        {0xfffbU, 0x000000e0U},
    }};
    for(unsigned restart = 0U; restart < 2U; ++restart)
    {
        CAPTURE(restart);
        require_exact_stream(1U, after_restart, true, restart,
                             static_cast<std::uint16_t>(4000U + restart * 10U));
    }
}

TEST_CASE("corrupted RTP checksum refresh is transactional", "[issue-39]")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);

    constexpr std::array<RtpPoint, 3> points{{
        {0xfff8U, 0xffffff00U},
        {0xfff9U, 0xffffffa0U},
        {0xfffaU, 0x00000040U},
    }};
    std::vector<std::uint8_t> refresh;
    Packet final_input{};
    for(std::size_t index = 0U; index < points.size(); ++index)
    {
        const auto input = make_rtp_packet(
            points[index], static_cast<std::uint16_t>(5000U + index), 0U, true);
        const auto compressed = compress_packet(comp.get(), 4U, input);
        if(index + 1U == points.size())
        {
            refresh = compressed;
            final_input = input;
        }
        else
        {
            require_exact_decompression(decomp.get(), compressed, input);
        }
    }

    REQUIRE(refresh.size() > 4U);
    REQUIRE(refresh[0] == 0xe4U);
    REQUIRE(refresh[1] == 0xfdU);
    auto corrupted = refresh;
    corrupted[3] ^= 0x01U;
    std::array<std::uint8_t, 1160> output{};
    output.fill(0xa5U);
    const auto before = output;
    std::size_t output_length = output.size();
    REQUIRE(rohc_decompress4(decomp.get(), corrupted.data(), corrupted.size(),
                             output.data(), &output_length) != 0);
    REQUIRE(output_length == 0U);
    REQUIRE(output == before);
    require_exact_decompression(decomp.get(), refresh, final_input);
}

} // namespace
