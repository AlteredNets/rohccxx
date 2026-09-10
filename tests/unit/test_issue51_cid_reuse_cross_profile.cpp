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
#include <vector>

namespace
{
constexpr std::size_t packet_size = 96U;
using Packet = std::array<std::uint8_t, packet_size>;
using ScalePacket = std::array<std::uint8_t, 1024U>;

struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
struct DecompDelete { void operator()(rohc_decomp* value) const { rohc_decomp_free(value); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
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

std::uint16_t checksum(const std::uint8_t* data, std::size_t size)
{
    std::uint32_t sum = 0U;
    for(std::size_t pos = 0U; pos < size; pos += 2U)
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(data[pos]) << 8U) | data[pos + 1U]);
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

std::uint64_t issue51_salt()
{
    constexpr std::array<std::uint8_t, 19> control{{
        0x49U, 0x92U, 0x24U, 0x49U, 0x24U, 0x49U, 0x12U, 0x24U,
        0x53U, 0x92U, 0x81U, 0x38U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U,
    }};
    std::uint64_t salt = 0x4953535545343955ULL;
    for(const auto byte : control)
        salt = (salt ^ byte) * 0x100000001b3ULL;
    return salt;
}

Packet make_packet(std::uint32_t ordinal, std::uint32_t cid,
                   std::uint32_t profile, std::uint32_t epoch,
                   std::uint32_t round, std::uint64_t salt)
{
    const std::uint32_t flow = cid & 3U;
    Packet packet{};
    packet[0] = 0x45U;
    write16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    write16(packet.data() + 4U, static_cast<std::uint16_t>(0xfffcU + round));
    packet[6] = 0x40U;
    packet[8] = 64U;
    packet[9] = profile == 2U ? 50U : (profile == 3U ? 6U : 17U);
    packet[12] = 10U;
    packet[13] = static_cast<std::uint8_t>(20U + profile + epoch * 8U);
    packet[14] = 30U;
    packet[15] = 1U;
    packet[16] = 198U;
    packet[17] = 51U;
    packet[18] = static_cast<std::uint8_t>(1U + profile + epoch * 8U);
    packet[19] = 10U;

    std::uint64_t state = 0x524f484343585354ULL ^
                          (static_cast<std::uint64_t>(ordinal) << 17U) ^
                          salt;
    for(std::size_t pos = 20U; pos < packet.size(); ++pos)
    {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        packet[pos] = static_cast<std::uint8_t>(state);
    }

    if(profile <= 1U)
    {
        write16(packet.data() + 20U,
                static_cast<std::uint16_t>(12000U + epoch * 256U + profile * 64U));
        write16(packet.data() + 22U,
                static_cast<std::uint16_t>(22000U + epoch * 256U + profile * 64U));
        write16(packet.data() + 24U,
                static_cast<std::uint16_t>(packet.size() - 20U));
        write16(packet.data() + 26U, 0U);
    }
    if(profile == 0U)
    {
        packet[28] = 0x80U;
        packet[29] = 96U;
        write16(packet.data() + 30U,
                static_cast<std::uint16_t>(0xfffcU + round));
        write32(packet.data() + 32U, 0xffffff00U + round * 160U);
        write32(packet.data() + 36U, 0x11223000U + epoch * 16U);
    }
    else if(profile == 1U)
    {
        // Keep the UDP payload from accidentally satisfying the RTP version
        // discriminator used by automatic profile classification.
        packet[28] = 0U;
    }
    else if(profile == 2U)
    {
        write32(packet.data() + 20U, 0xa0b00000U + epoch * 16U);
        write32(packet.data() + 24U, 0xfffffff8U + round);
    }
    write32(packet.data() + 48U, ordinal);
    write32(packet.data() + 52U, cid);
    write16(packet.data() + 10U, 0U);
    write16(packet.data() + 10U, checksum(packet.data(), 20U));
    return packet;
}

ScalePacket make_issue52_packet(std::uint32_t cid, std::uint32_t profile,
                                std::uint32_t generation, std::uint32_t round)
{
    ScalePacket packet{};
    for(std::size_t pos = 0; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(pos * 37U + 1U + round);
    packet[0] = 0x45U;
    packet[1] = static_cast<std::uint8_t>((profile << 4U) | (cid & 3U));
    write16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    write16(packet.data() + 4U, static_cast<std::uint16_t>(round));
    packet[6] = 0x40U;
    packet[7] = 0U;
    packet[8] = static_cast<std::uint8_t>(64U - (cid & 3U));
    packet[9] = profile == 2U ? 50U : (profile == 3U ? 6U : 17U);
    packet[12] = 10U;
    packet[13] = static_cast<std::uint8_t>(32U + generation % 192U);
    packet[14] = static_cast<std::uint8_t>(16U + cid);
    packet[15] = 1U;
    packet[16] = 198U;
    packet[17] = 51U;
    packet[18] = static_cast<std::uint8_t>(1U + profile);
    packet[19] = static_cast<std::uint8_t>(10U + cid);
    if(profile <= 1U)
    {
        write16(packet.data() + 20U,
                static_cast<std::uint16_t>(12000U + generation * 64U + cid));
        write16(packet.data() + 22U,
                static_cast<std::uint16_t>(22000U + generation * 64U + cid));
        write16(packet.data() + 24U,
                static_cast<std::uint16_t>(packet.size() - 20U));
        write16(packet.data() + 26U, 0U);
    }
    if(profile == 0U)
    {
        packet[28] = 0x80U;
        packet[29] = static_cast<std::uint8_t>(96U + (cid & 3U));
        write16(packet.data() + 30U,
                static_cast<std::uint16_t>(0xfff0U + round));
        write32(packet.data() + 32U, 0xffffff00U + round * 160U);
        write32(packet.data() + 36U, 0x51000000U + generation * 16U + cid);
    }
    else if(profile == 1U)
    {
        packet[28] = 0U;
    }
    else if(profile == 2U)
    {
        write32(packet.data() + 20U, 0xa0510000U + generation * 16U + cid);
        write32(packet.data() + 24U, 0xfffffff0U + round);
    }
    write32(packet.data() + 48U, round * 16U + cid);
    write32(packet.data() + 52U, cid);
    write32(packet.data() + 56U, generation);
    write16(packet.data() + 10U, 0U);
    write16(packet.data() + 10U, checksum(packet.data(), 20U));
    return packet;
}

template<std::size_t Size>
std::vector<std::uint8_t> compress_array(rohc_comp* comp, std::uint32_t cid,
                                         const std::array<std::uint8_t, Size>& packet)
{
    std::array<std::uint8_t, 2048> bytes{};
    std::size_t length = bytes.size();
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(),
                           bytes.data(), &length) == 0);
    return {bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)};
}

template<std::size_t Size>
void require_exact_array(rohc_decomp* decomp,
                         const std::vector<std::uint8_t>& compressed,
                         const std::array<std::uint8_t, Size>& expected)
{
    std::array<std::uint8_t, 2048> output{};
    output.fill(0xa5U);
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, compressed.data(), compressed.size(),
                             output.data(), &output_len) == 0);
    REQUIRE(output_len == expected.size());
    REQUIRE(std::equal(expected.begin(), expected.end(), output.begin()));
}

std::vector<std::uint8_t> compress(rohc_comp* comp, std::uint32_t cid,
                                   const Packet& packet)
{
    std::array<std::uint8_t, 2048> bytes{};
    std::size_t length = bytes.size();
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(),
                           bytes.data(), &length) == 0);
    return {bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)};
}

void require_exact(rohc_decomp* decomp, const std::vector<std::uint8_t>& compressed,
                   const Packet& expected)
{
    std::array<std::uint8_t, 256> output{};
    output.fill(0xa5U);
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, compressed.data(), compressed.size(),
                             output.data(), &output_len) == 0);
    REQUIRE(output_len == expected.size());
    REQUIRE(std::equal(expected.begin(), expected.end(), output.begin()));
}

void require_transactional_reject(rohc_decomp* decomp,
                                  const std::vector<std::uint8_t>& compressed)
{
    std::array<std::uint8_t, 2048> output{};
    output.fill(0xa5U);
    const auto guard = output;
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp, compressed.data(), compressed.size(),
                             output.data(), &output_len) != 0);
    REQUIRE(output_len == 0U);
    REQUIRE(output == guard);
}

std::vector<std::uint8_t> captured_issue51_pt0()
{
    constexpr std::array<std::uint8_t, 58> witness{{
        0xecU, 0x17U, 0xaaU, 0xb5U, 0x42U, 0x44U, 0x70U, 0xb6U,
        0x81U, 0x30U, 0x00U, 0x00U, 0x00U, 0x6cU, 0x00U, 0x00U,
        0x00U, 0x0cU, 0x3eU, 0x40U, 0x32U, 0xd8U, 0x23U, 0xb1U,
        0x7cU, 0x58U, 0x98U, 0x51U, 0xe9U, 0x2eU, 0x2aU, 0xbcU,
        0x85U, 0xd4U, 0x0dU, 0x9fU, 0xc2U, 0x73U, 0x0bU, 0x33U,
        0x51U, 0x91U, 0x6cU, 0x50U, 0x6eU, 0xb0U, 0x55U, 0x61U,
        0x65U, 0xa1U, 0x22U, 0x6aU, 0x5eU, 0x40U, 0x88U, 0xe5U,
        0x3cU, 0x66U,
    }};
    return {witness.begin(), witness.end()};
}
}

TEST_CASE("Issue 51 exact control sequence stays exact and refresh rejection is transactional",
          "[issue-51]")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr generated(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr captured(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(generated);
    REQUIRE(captured);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(generated.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(captured.get(), ROHCCXX_MODE_O) == 0);

    std::vector<std::uint8_t> replacement_refresh;
    Packet replacement_refresh_packet{};
    const auto sealed_witness = captured_issue51_pt0();
    for(std::uint32_t round = 0U; round <= 6U; ++round)
    {
        const std::uint32_t ordinal = round * 16U + 12U;
        const std::uint32_t epoch = round / 4U;
        const std::uint32_t profile = (3U + epoch) & 3U;
        const auto packet = make_packet(ordinal, 12U, profile, epoch, round,
                                        issue51_salt());
        const auto compressed = compress(comp.get(), 12U, packet);

        if(round == 0U || round == 4U || round == 5U)
        {
            if(round == 4U)
            {
                replacement_refresh = compressed;
                replacement_refresh_packet = packet;
            }
            continue;
        }
        if(round <= 3U)
        {
            require_exact(generated.get(), compressed, packet);
            require_exact(captured.get(), compressed, packet);
            continue;
        }

        // The affected compressor emitted the sealed 58-byte PT-0 witness here.
        // A corrected compressor may instead retain explicit context framing.
        INFO("sealed_witness_reproduced=" << (compressed == sealed_witness));
        std::array<std::uint8_t, 256> output{};
        output.fill(0xa5U);
        const auto guard = output;
        std::size_t output_len = output.size();
        const int rc = rohc_decompress4(generated.get(), compressed.data(),
                                        compressed.size(), output.data(), &output_len);
        CAPTURE(rc, output_len, compressed.size());
        if(rc == 0)
        {
            REQUIRE(output_len == packet.size());
            REQUIRE(std::equal(packet.begin(), packet.end(), output.begin()));
        }
        else
        {
            REQUIRE(output_len == 0U);
            REQUIRE(output == guard);
        }
    }

    // A failed replacement refresh must leave both the caller buffer and the
    // retired context unchanged, and a subsequent intact refresh must recover.
    auto corrupted_refresh = replacement_refresh;
    REQUIRE(corrupted_refresh.size() > 3U);
    corrupted_refresh[3] ^= 0x01U;
    require_transactional_reject(captured.get(), corrupted_refresh);
    require_transactional_reject(captured.get(), corrupted_refresh);
    require_exact(captured.get(), replacement_refresh, replacement_refresh_packet);

    // A correlated acknowledgment releases only this replacement generation;
    // ordinary compact encoding resumes after its dynamic refresh.
    rohc_comp_handle_feedback(comp.get(), 12U, 2U);
    for(std::uint32_t round : {7U, 8U})
    {
        const auto packet = make_packet(round * 16U + 12U, 12U, 0U, 1U,
                                        round, issue51_salt());
        const auto compressed = compress(comp.get(), 12U, packet);
        require_exact(generated.get(), compressed, packet);
        if(round == 8U)
        {
            REQUIRE(compressed.size() == 58U);
            REQUIRE(compressed[0] == 0xecU);
            REQUIRE((compressed[1] & 0x80U) == 0U);
        }
    }
}

TEST_CASE("Issue 51 profile replacement matrix keeps compact units behind acknowledgment",
          "[issue-51]")
{
    constexpr std::array<std::uint32_t, 4> profiles{{0U, 1U, 2U, 3U}};
    for(std::uint32_t cid = 0U; cid <= 15U; ++cid)
    {
        for(const auto old_profile : profiles)
        {
            for(const auto replacement_profile : profiles)
            {
                if(old_profile == replacement_profile)
                    continue;
                CAPTURE(cid, old_profile, replacement_profile);
                CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
                DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
                REQUIRE(comp);
                REQUIRE(decomp);
                REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
                REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);

                const std::uint64_t salt = 0x5100000000000000ULL ^
                    (static_cast<std::uint64_t>(cid) << 24U) ^
                    (static_cast<std::uint64_t>(old_profile) << 12U) ^
                    replacement_profile;
                for(std::uint32_t step = 0U; step < 3U; ++step)
                {
                    const auto packet = make_packet(step * 16U + cid, cid,
                                                    old_profile, 0U, step, salt);
                    require_exact(decomp.get(), compress(comp.get(), cid, packet), packet);
                }

                if(((cid + old_profile + replacement_profile) % 5U) == 0U)
                {
                    decomp.reset(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
                    REQUIRE(decomp);
                    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
                }

                const std::uint32_t lost = 1U +
                    ((cid + old_profile + replacement_profile) & 1U);
                for(std::uint32_t step = 0U; step <= lost; ++step)
                {
                    const auto round = 3U + step;
                    const auto packet = make_packet(round * 16U + cid, cid,
                                                    replacement_profile, 1U,
                                                    round, salt);
                    const auto wire = compress(comp.get(), cid, packet);
                    if(step < lost)
                        continue;
                    // Even after every earlier replacement unit is lost, the
                    // first delivered unit remains an explicit profile-bearing IR.
                    const std::size_t type_offset = cid == 0U ? 0U : 1U;
                    REQUIRE(wire.size() > type_offset + 1U);
                    REQUIRE(wire[type_offset] == 0xfdU);
                    require_exact(decomp.get(), wire, packet);
                }

                rohc_comp_handle_feedback(comp.get(), cid, 2U);
                for(std::uint32_t tail = 0U; tail < 2U; ++tail)
                {
                    const auto round = 4U + lost + tail;
                    const auto packet = make_packet(round * 16U + cid, cid,
                                                    replacement_profile, 1U,
                                                    round, salt);
                    require_exact(decomp.get(), compress(comp.get(), cid, packet),
                                  packet);
                }
            }
        }
    }
}

TEST_CASE("Profile replacement clears retired RTP dynamics before compact recovery",
          "[issue-51][issue-52]")
{
    constexpr std::uint32_t cid = 4U;
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);
    REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);
    // Establish an older RTP generation so retired RTP timestamp dynamics exist.
    for(std::uint32_t round : {248U, 249U, 250U})
    {
        const auto packet = make_issue52_packet(cid, 0U, 31U, round);
        require_exact_array(decomp.get(), compress_array(comp.get(), cid, packet), packet);
        if(round == 248U)
            rohc_comp_handle_feedback(comp.get(), cid, 2U);
    }

    // Reuse the CID for IP-only and establish its sequential IPv4-ID behavior.
    for(std::uint32_t round : {272U, 273U, 274U})
    {
        const auto packet = make_issue52_packet(cid, 3U, 34U, round);
        require_exact_array(decomp.get(), compress_array(comp.get(), cid, packet), packet);
        if(round == 272U)
            rohc_comp_handle_feedback(comp.get(), cid, 2U);
    }

    // Reuse the CID for RTP again. The replacement IR arrives, but the next
    // state-changing IR-DYN is deliberately lost. The following compact unit
    // must never authenticate using RTP dynamics retired before the IP phase.
    const auto replacement = make_issue52_packet(cid, 0U, 35U, 280U);
    require_exact_array(decomp.get(), compress_array(comp.get(), cid, replacement),
                        replacement);
    rohc_comp_handle_feedback(comp.get(), cid, 2U);

    const auto lost_refresh = make_issue52_packet(cid, 0U, 35U, 281U);
    const auto lost_wire = compress_array(comp.get(), cid, lost_refresh);
    REQUIRE(lost_wire.size() > 2U);

    const auto ambiguous = make_issue52_packet(cid, 0U, 35U, 282U);
    const auto ambiguous_wire = compress_array(comp.get(), cid, ambiguous);
    CAPTURE(lost_wire.size(), ambiguous_wire.size(), ambiguous_wire[0],
            ambiguous_wire[1]);
    REQUIRE(ambiguous_wire.size() == 986U);
    REQUIRE(ambiguous_wire[0] == 0xe4U);
    REQUIRE((ambiguous_wire[1] & 0x80U) == 0U);
    require_transactional_reject(decomp.get(), ambiguous_wire);
    require_transactional_reject(decomp.get(), ambiguous_wire);

    // NACK-driven refresh recovers without a stale-context commit.
    rohc_comp_handle_feedback(comp.get(), cid, 0U);
    const auto recovery = make_issue52_packet(cid, 0U, 35U, 283U);
    require_exact_array(decomp.get(), compress_array(comp.get(), cid, recovery), recovery);
}
