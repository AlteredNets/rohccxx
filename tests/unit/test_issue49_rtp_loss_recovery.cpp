// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using Packet = std::array<std::uint8_t, 96>;

struct DecompDelete
{
    void operator()(rohc_decomp* value) const { rohc_decomp_free(value); }
};

using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

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
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(header[pos]) << 8U) | header[pos + 1U]);
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

Packet make_issue49_packet(std::uint32_t ordinal)
{
    constexpr std::uint32_t packet_seed = 786057685U;
    constexpr std::uint32_t round_offset = 1000U;
    constexpr std::uint32_t cid = 1U;
    constexpr std::uint32_t flow = 1U;
    const std::uint32_t round = ordinal / 16U;
    Packet packet{};
    packet[0] = 0x45U;
    write16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    write16(packet.data() + 4U, static_cast<std::uint16_t>(0x2000U + cid * 0x100U + round));
    packet[6] = 0x40U;
    packet[8] = 63U;
    packet[9] = 17U;
    packet[12] = 10U;
    packet[13] = 20U;
    packet[14] = 31U;
    packet[15] = 1U;
    packet[16] = 198U;
    packet[17] = 51U;
    packet[18] = 1U;
    packet[19] = 11U;

    std::uint64_t state = 0x524f484343585857ULL ^
                          (static_cast<std::uint64_t>(ordinal) << 17U) ^ packet_seed;
    for(std::size_t pos = 20U; pos < packet.size(); ++pos)
    {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        packet[pos] = static_cast<std::uint8_t>(state);
    }

    write16(packet.data() + 20U, static_cast<std::uint16_t>(12000U + flow));
    write16(packet.data() + 22U, static_cast<std::uint16_t>(22000U + flow));
    write16(packet.data() + 24U, static_cast<std::uint16_t>(packet.size() - 20U));
    write16(packet.data() + 26U, 0U);
    packet[28] = 0x80U;
    packet[29] = static_cast<std::uint8_t>(96U + flow);
    write16(packet.data() + 30U,
            static_cast<std::uint16_t>(round_offset + flow * 1000U + round));
    write32(packet.data() + 32U, 100000U + flow * 100000U + round * 160U);
    write32(packet.data() + 36U, 0x11223000U + flow + 1U);
    write32(packet.data() + 48U, ordinal);
    write32(packet.data() + 52U, cid);
    write16(packet.data() + 10U, 0U);
    write16(packet.data() + 10U, ipv4_checksum(packet.data()));
    return packet;
}

std::vector<std::uint8_t> decode_hex(std::string_view text)
{
    auto nibble = [](char value) -> std::uint8_t
    {
        if(value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
        if(value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
        return 0xffU;
    };
    REQUIRE((text.size() % 2U) == 0U);
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() / 2U);
    for(std::size_t pos = 0U; pos < text.size(); pos += 2U)
    {
        const auto high = nibble(text[pos]);
        const auto low = nibble(text[pos + 1U]);
        REQUIRE(high <= 0x0fU);
        REQUIRE(low <= 0x0fU);
        bytes.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }
    return bytes;
}

struct CapturedUnit
{
    std::uint32_t ordinal;
    std::string_view hex;
};

constexpr std::array<CapturedUnit, 14> issue49_corpus{{
    {17U, "e1fd01c440110a141f01c633010b2ee155f11122300204003f21010000006107d100030de0475f63ef148469770000001100000001d7009861b3821f174baf4e04c45be37a22e897d83b8dca1d85ba05dbee2fad5e0622901f510f836c"},
    {33U, "e112a1c43f0b756701c50000002100000001d3003ce265c582778d92f3ea8dd0c1ba7fed761a64702a1c3ab07db78ecd2ed2a998b3702a923923"},
    {49U, "e11ec996dde65b6199620000003100000001eb7ecac11e38b8d10836fc813af4bbd0b77eea3179df4e5ce8d31290df6660ac0b9d7e5280e3b011"},
    {65U, "e1242674326eba79fb4a000000410000000111a16a8ecd6cb60b4375e722e493546c2876c24105ddf21b69c196ad90f1544c4a8251ef2050deb9"},
    {81U, "e12b4e26d083947f63ed000000510000000129df9cadb6918cadc6d1e84953b72e06e0e55e6a1872965bbba2f98ac15a1a32e8879ccd8a21578b"},
    {97U, "e132a8bd8c67f59c0b5f00000061000000012ddf382e60d611cd00ec55a71a3c0cc6bde0bfa8478f765a04a881e6a1b899be473dbfa2f1bcedc4"},
    {113U, "e138c0ef6e8adb9a93f8000000710000000115a1ce0d1b2b2b6b85485accad1876ac757323835a20121ad6cbeec1f013d7c0e53872805bcd64f6"},
    {129U, "e1434f9722e8dbba3575000000810000000162360c0622acdd70dc8f6ed8d5f85fd5f21d35add8658522ee81747e883f9bca19275d3531a782cf"},
    {145U, "e14b27c5c005f5bcadd200000091000000015a48fa255951e7d6592b61b362dc25bf3a8ea986c5cae1623ce21b59d994d5b4bb2290179bd60bfd"},
    {161U, "e152c15e9ce1945fc560000000a1000000015e485ea68f167ab69f16dc5d2b57077f678b48449a37016383e86335b97656381498b378e04bb1b2"},
    {177U, "e15aa90c7e0cba595dc7000000b1000000016636a885f4eb40101ab2d3369c737d15af18d46f87986523518b0c12e8dd1846b69d7e5a4a3a3880"},
    {193U, "e16046ee91845b413fef000000c1000000019ce908ca27bf4eca51f1c895421492a93010fc1ffb9ad964d099882fa74a2ca6f78251e7ea895628"},
    {209U, "e16a2ebc73697547a748000000d100000001a497fee95c42746cd455c7fef530e8c3f8836034e635bd2402fae708f6e162d855879cc540f8df1a"},
    {225U, "e1fd01d240110a141f01c633010b2ee155f11122300204003f210e0000006107de00031600c8272f8d14a4cffa000000e100000001a0975a6a8a05e90c12687a10bcbbca03a58681f6b9c85d25bdf09f649603e154fa3dbfaa3b656555"},
}};

} // namespace

TEST_CASE("RTP PT-0 after initial context loss never returns a stale timestamp", "[issue-49]")
{
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);

    std::size_t exact = 0U;
    std::size_t rejected = 0U;
    for(const auto& item : issue49_corpus)
    {
        const auto compressed = decode_hex(item.hex);
        const auto expected = make_issue49_packet(item.ordinal);
        std::array<std::uint8_t, 160> output{};
        output.fill(0xa5U);
        std::size_t output_len = output.size();
        const auto rc = rohc_decompress4(decomp.get(), compressed.data(), compressed.size(),
                                         output.data(), &output_len);
        CAPTURE(item.ordinal, compressed.size(), rc, output_len);
        if(rc == 0)
        {
            ++exact;
            REQUIRE(output_len == expected.size());
            CHECK(std::equal(expected.begin(), expected.end(), output.begin()));
        }
        else
        {
            ++rejected;
            CHECK(output_len == 0U);
            CHECK(std::all_of(output.begin(), output.end(),
                              [](std::uint8_t value) { return value == 0xa5U; }));
        }
    }

    CHECK(exact == 2U);
    CHECK(rejected == 12U);
}
