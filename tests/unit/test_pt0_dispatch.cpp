// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
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

std::vector<std::uint8_t> make_packet(Pt0Profile profile,
                                      std::uint32_t ordinal,
                                      std::uint8_t tos = 0,
                                      std::uint16_t id_override = 0xffffU,
                                      std::uint16_t udp_checksum = 0U)
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
    ip[15] = 1;
    ip[16] = 10;
    ip[19] = 2;
    if(profile == Pt0Profile::Udp)
    {
        put16(ip + 20, 10000U);
        put16(ip + 22, 20000U);
        put16(ip + 24, static_cast<std::uint16_t>(packet.size() - 20U));
        put16(ip + 26, udp_checksum);
    }
    if(profile == Pt0Profile::Esp)
    {
        put32(ip + 20, 0x10203000U);
        put32(ip + 24, ordinal);
    }
    std::uint64_t state = 0x524f484343585832ULL ^ ordinal;
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
        if(ordinal == final_ordinal)
            final_rohc.assign(rohc.begin(), rohc.begin() + static_cast<std::ptrdiff_t>(rohc_len));
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
        }
    }
    return fixture;
}

void require_failed_transaction(rohc_decomp* decomp,
                                const std::vector<std::uint8_t>& packet,
                                std::size_t capacity = 510U,
                                bool expect_feedback = true)
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
        REQUIRE(feedback_cid == 0U);
        REQUIRE(feedback_type == 0U); // public NACK value
        // Retrieval is observational, not consuming.
        feedback_cid = 0xffffffffU;
        feedback_type = 0xffU;
        REQUIRE(rohc_decomp_get_feedback(decomp, &feedback_cid, &feedback_type) == 0);
        REQUIRE(feedback_cid == 0U);
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

} // namespace

TEST_CASE("public C API round-trips every RFC 5225 PT-0 first octet")
{
    // PT-0 is exactly 0 | MSN(4) | CRC-3(3), so all 128 zero-MSB values are
    // structurally reachable.  A per-context TOS witness supplies each CRC-3
    // value without fabricating wire packets or bypassing the public encoder.
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
    {
        for(unsigned value = 0; value <= 0x7fU; ++value)
        {
            const auto octet = static_cast<std::uint8_t>(value);
            CAPTURE(static_cast<unsigned>(profile), value);
            const auto tos = find_tos_for_octet(profile, octet);
            require_public_round_trip_to(profile, tos,
                                         ordinal_for_octet(profile, octet), octet);
        }
    }
}

TEST_CASE("public C API resolves every PT-0 private-FO marker for every formal profile")
{
    for(const auto profile : {Pt0Profile::Udp, Pt0Profile::Esp, Pt0Profile::Ip})
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
        {Pt0Profile::Esp, 47U, 161U, 0x78U,
         "98d3a21878eceb5108366f581e6b2d378f19dfe045e07de2bc4fdf959865746f"},
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
        const std::array<std::uint8_t, 4> payload{{0x10U, 0x20U, 0x30U, 0x40U}};
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

        const std::array<std::uint8_t, 4> payload{{0x10U, 0x20U, 0x30U, 0x40U}};
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
