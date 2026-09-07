// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "rohccxx/protocols/ipv4.hpp"
#include "rohccxx/protocols/ipv6.hpp"
#include "rohccxx/protocols/rtp.hpp"
#include "rohccxx/protocols/udp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

static_assert(sizeof(rohccxx::ipv4::Header) == 20U);
static_assert(sizeof(rohccxx::ipv6::Header) == 40U);
static_assert(sizeof(rohccxx::udp::Header) == 8U);
static_assert(sizeof(rohccxx::rtp::Header) == 12U);

TEST_CASE("IPv4 wire headers support arbitrary byte-buffer alignment", "[issue-40]")
{
    REQUIRE(alignof(rohccxx::ipv4::Header) == 1U);
    alignas(8) std::array<std::uint8_t, sizeof(rohccxx::ipv4::Header) + 1U> storage{};
    auto* packet = storage.data() + 1U;
    packet[0] = 0x45U;
    packet[2] = 0x00U;
    packet[3] = 0x14U;
    const rohccxx::ipv4::Header* header = nullptr;
    std::size_t header_length = 0U;
    REQUIRE(rohccxx::ipv4::parse(packet, sizeof(rohccxx::ipv4::Header),
                                 header, header_length));
    REQUIRE(header == reinterpret_cast<const rohccxx::ipv4::Header*>(packet));
    REQUIRE(header_length == sizeof(rohccxx::ipv4::Header));
}

TEST_CASE("IPv6 wire headers support arbitrary byte-buffer alignment", "[issue-40]")
{
    REQUIRE(alignof(rohccxx::ipv6::Header) == 1U);
    alignas(8) std::array<std::uint8_t, sizeof(rohccxx::ipv6::Header) + 1U> storage{};
    auto* packet = storage.data() + 1U;
    packet[0] = 0x60U;
    packet[6] = 59U;
    const rohccxx::ipv6::Header* header = nullptr;
    std::size_t header_length = 0U;
    std::size_t extension_length = 0U;
    std::uint8_t terminal_next_header = 0U;
    REQUIRE(rohccxx::ipv6::parse(packet, sizeof(rohccxx::ipv6::Header),
                                 header, header_length, terminal_next_header,
                                 extension_length));
    REQUIRE(header == reinterpret_cast<const rohccxx::ipv6::Header*>(packet));
    REQUIRE(header_length == sizeof(rohccxx::ipv6::Header));
    REQUIRE(extension_length == 0U);
}

TEST_CASE("UDP wire headers support arbitrary byte-buffer alignment", "[issue-40]")
{
    REQUIRE(alignof(rohccxx::udp::Header) == 1U);
    alignas(8) std::array<std::uint8_t, sizeof(rohccxx::udp::Header) + 1U> storage{};
    const auto* base = storage.data() + 1U;
    const rohccxx::udp::Header* header = nullptr;
    REQUIRE(rohccxx::udp::parse(base, sizeof(rohccxx::udp::Header), base, header));
    REQUIRE(header == reinterpret_cast<const rohccxx::udp::Header*>(base));
}

TEST_CASE("RTP wire headers support arbitrary byte-buffer alignment", "[issue-40]")
{
    REQUIRE(alignof(rohccxx::rtp::Header) == 1U);
    alignas(8) std::array<std::uint8_t, sizeof(rohccxx::rtp::Header) + 1U> storage{};
    auto* packet = storage.data() + 1U;
    packet[0] = 0x80U;
    const rohccxx::rtp::Header* header = nullptr;
    REQUIRE(rohccxx::rtp::parse(packet, sizeof(rohccxx::rtp::Header), packet, header));
    REQUIRE(header == reinterpret_cast<const rohccxx::rtp::Header*>(packet));
}
