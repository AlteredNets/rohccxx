// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include <rohccxx.h>

#include "tunnel_protocol.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
struct FakeCodec
{
    bool fail_compress = false;
    bool fail_decompress = false;
    std::uint32_t feedback_cid = 99U;
    std::uint8_t feedback_type = 99U;
};

int fake_compress(void* opaque, const std::uint8_t* input, std::size_t input_len,
                  std::uint8_t* output, std::size_t* output_len)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    if(fake.fail_compress || !output_len || *output_len < input_len)
        return -1;
    std::memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
}

int fake_decompress(void* opaque, const std::uint8_t* input, std::size_t input_len,
                    std::uint8_t* output, std::size_t* output_len)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    if(fake.fail_decompress || !output_len || *output_len < input_len)
        return -1;
    std::memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
}

void fake_feedback(void* opaque, std::uint32_t cid, std::uint8_t type)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    fake.feedback_cid = cid;
    fake.feedback_type = type;
}

std::array<std::uint8_t, 20> ipv4_packet()
{
    std::array<std::uint8_t, 20> packet{};
    packet[0] = 0x45U;
    packet[2] = 0U;
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[8] = 64U;
    packet[9] = 253U;
    return packet;
}

void put16(std::uint8_t* output, std::uint16_t value)
{
    output[0] = static_cast<std::uint8_t>(value >> 8U);
    output[1] = static_cast<std::uint8_t>(value);
}

std::uint16_t internet_checksum(const std::uint8_t* data, std::size_t length,
                                std::uint32_t initial = 0U)
{
    std::uint32_t sum = initial;
    for(std::size_t pos = 0U; pos < length; pos += 2U)
    {
        sum += static_cast<std::uint16_t>(data[pos] << 8U) |
               (pos + 1U < length ? data[pos + 1U] : 0U);
    }
    while((sum >> 16U) != 0U)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

std::vector<std::uint8_t> kernel_style_packet(std::uint8_t protocol,
                                              std::uint16_t ipv4_id)
{
    const std::size_t transport_length = protocol == 17U ? 40U : 8U;
    std::vector<std::uint8_t> packet(20U + transport_length);
    packet[0] = 0x45U;
    put16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(packet.data() + 4U, ipv4_id);
    put16(packet.data() + 6U, 0x4000U);
    packet[8] = 64U;
    packet[9] = protocol;
    packet[12] = 10U; packet[15] = 1U;
    packet[16] = 10U; packet[19] = 2U;
    if(protocol == 17U)
    {
        put16(packet.data() + 20U, 31000U);
        put16(packet.data() + 22U, 32123U);
        put16(packet.data() + 24U, static_cast<std::uint16_t>(transport_length));
        for(std::size_t pos = 28U; pos < packet.size(); ++pos)
            packet[pos] = static_cast<std::uint8_t>(pos * 7U);
        std::uint32_t pseudo = 0U;
        pseudo += 0x0a00U + 0x0001U + 0x0a00U + 0x0002U;
        pseudo += 17U + static_cast<std::uint16_t>(transport_length);
        put16(packet.data() + 26U,
              internet_checksum(packet.data() + 20U, transport_length, pseudo));
    }
    else
    {
        for(std::size_t pos = 20U; pos < packet.size(); ++pos)
            packet[pos] = static_cast<std::uint8_t>(pos);
    }
    put16(packet.data() + 10U, internet_checksum(packet.data(), 20U));
    return packet;
}

std::vector<std::uint8_t> stress_udp_packet(std::uint64_t sequence,
                                            std::uint16_t ipv4_id = 0U,
                                            bool reverse = false,
                                            std::size_t payload_size = 64U,
                                            std::uint16_t source_port = 34000U,
                                            std::uint8_t flow = 0U)
{
    std::vector<std::uint8_t> packet(28U + payload_size);
    packet[0] = 0x45U;
    put16(packet.data() + 2U, static_cast<std::uint16_t>(packet.size()));
    put16(packet.data() + 4U, ipv4_id);
    put16(packet.data() + 6U, 0x4000U);
    packet[8] = 64U; packet[9] = 17U;
    packet[12] = 10U; packet[15] = reverse ? 2U : 1U;
    packet[16] = 10U; packet[19] = reverse ? 1U : 2U;
    put16(packet.data() + 20U, reverse ? 33221U : source_port);
    put16(packet.data() + 22U, reverse ? source_port : 33221U);
    put16(packet.data() + 24U, 8U + payload_size);
    const std::array<std::uint8_t, 4> magic{{'R', 'T', 'S', 'T'}};
    std::memcpy(packet.data() + 28U, magic.data(), magic.size());
    for(std::size_t pos = 0U; pos < 8U; ++pos)
        packet[32U + pos] = static_cast<std::uint8_t>(sequence >> (56U - pos * 8U));
    packet[40U] = flow;
    put16(packet.data() + 41U, payload_size);
    for(std::size_t pos = 43U; pos < packet.size(); ++pos)
        packet[pos] = static_cast<std::uint8_t>(sequence + flow * 17U + pos - 43U);
    std::uint32_t pseudo = 0x0a00U + 0x0001U + 0x0a00U + 0x0002U +
                           17U + static_cast<std::uint16_t>(8U + payload_size);
    put16(packet.data() + 26U,
          internet_checksum(packet.data() + 20U, 8U + payload_size, pseudo));
    put16(packet.data() + 10U, internet_checksum(packet.data(), 20U));
    return packet;
}

struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
struct DecompDelete { void operator()(rohc_decomp* value) const { rohc_decomp_free(value); } };
}

TEST_CASE("Linux TUN transport envelope round-trips exact versioned frames")
{
    const std::array<std::uint8_t, 3> payload{{1U, 2U, 3U}};
    std::array<std::uint8_t, 32> wire{};
    std::size_t wire_len = 0U;
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Compressed,
        payload.data(), payload.size(), wire.data(), wire.size(), wire_len) ==
        rohccxx::tun::Result::Ok);
    REQUIRE(wire_len == rohccxx::tun::envelope_size + payload.size());
    REQUIRE(wire[0] == 'R'); REQUIRE(wire[1] == 'H');
    REQUIRE(wire[2] == 'C'); REQUIRE(wire[3] == 'T');
    REQUIRE(wire[4] == rohccxx::tun::transport_version);
    rohccxx::tun::FrameView decoded{};
    REQUIRE(rohccxx::tun::decode_frame(wire.data(), wire_len, decoded) ==
            rohccxx::tun::Result::Ok);
    REQUIRE(decoded.type == rohccxx::tun::MessageType::Compressed);
    REQUIRE(decoded.payload_len == payload.size());
    REQUIRE(std::memcmp(decoded.payload, payload.data(), payload.size()) == 0);
}

TEST_CASE("Linux TUN transport envelope rejects malformed inputs")
{
    std::array<std::uint8_t, 16> wire{{'R','H','C','T',1U,1U,0U,1U,0xaaU}};
    rohccxx::tun::FrameView frame{};
    for(std::size_t len = 0U; len < rohccxx::tun::envelope_size; ++len)
        REQUIRE(rohccxx::tun::decode_frame(wire.data(), len, frame) == rohccxx::tun::Result::Malformed);
    auto bad = wire;
    bad[0] ^= 1U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
    bad = wire; bad[4] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::UnknownVersion);
    bad = wire; bad[5] = 9U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::UnknownType);
    bad = wire; bad[7] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
    bad = wire; bad[5] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
}

TEST_CASE("Linux TUN pump helpers validate packets and surface codec errors")
{
    FakeCodec fake{};
    const rohccxx::tun::Codec codec{&fake, fake_compress, fake_decompress, fake_feedback};
    auto packet = ipv4_packet();
    std::array<std::uint8_t, 128> compressed{}, datagram{}, output{};
    std::size_t compressed_len = 0U, datagram_len = 0U;
    REQUIRE(rohccxx::tun::prepare_compressed_datagram(codec, packet.data(), packet.size(),
        64U, compressed.data(), compressed.size(), datagram.data(), datagram.size(),
        compressed_len, datagram_len) == rohccxx::tun::Result::Ok);
    REQUIRE(compressed_len == packet.size());
    std::size_t output_len = 0U;
    rohccxx::tun::MessageType type{};
    REQUIRE(rohccxx::tun::consume_datagram(codec, datagram.data(), datagram_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::Ok);
    REQUIRE(type == rohccxx::tun::MessageType::Compressed);
    REQUIRE(output_len == packet.size());
    REQUIRE(std::memcmp(output.data(), packet.data(), packet.size()) == 0);

    fake.fail_compress = true;
    REQUIRE(rohccxx::tun::prepare_compressed_datagram(codec, packet.data(), packet.size(),
        64U, compressed.data(), compressed.size(), datagram.data(), datagram.size(),
        compressed_len, datagram_len) == rohccxx::tun::Result::CodecFailure);
    fake.fail_compress = false; fake.fail_decompress = true;
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Compressed,
        packet.data(), packet.size(), datagram.data(), datagram.size(), datagram_len) == rohccxx::tun::Result::Ok);
    REQUIRE(rohccxx::tun::consume_datagram(codec, datagram.data(), datagram_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::CodecFailure);
    REQUIRE(output_len == 0U);

    packet[0] = 0x60U;
    REQUIRE(rohccxx::tun::validate_ipv4_packet(packet.data(), packet.size(), 64U) ==
            rohccxx::tun::Result::UnknownVersion);
}

TEST_CASE("Linux TUN feedback frames validate CID and public feedback type")
{
    FakeCodec fake{};
    const rohccxx::tun::Codec codec{&fake, fake_compress, fake_decompress, fake_feedback};
    std::array<std::uint8_t, 32> payload{}, wire{}, output{};
    std::size_t payload_len = 0U, wire_len = 0U, output_len = 0U;
    REQUIRE(rohccxx::tun::encode_feedback(15U, 1U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::Ok);
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Feedback,
        payload.data(), payload_len, wire.data(), wire.size(), wire_len) == rohccxx::tun::Result::Ok);
    rohccxx::tun::MessageType type{};
    REQUIRE(rohccxx::tun::consume_datagram(codec, wire.data(), wire_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::Ok);
    REQUIRE(type == rohccxx::tun::MessageType::Feedback);
    REQUIRE(fake.feedback_cid == 15U);
    REQUIRE(fake.feedback_type == 1U);
    REQUIRE(rohccxx::tun::encode_feedback(16U, 0U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::InvalidArgument);
    REQUIRE(rohccxx::tun::encode_feedback(0U, 3U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::InvalidArgument);
}

TEST_CASE("Linux TUN automatic profile changes establish new decompressor state")
{
    std::unique_ptr<rohc_comp, CompDelete> comp(
        rohc_comp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    std::unique_ptr<rohc_decomp, DecompDelete> decomp(
        rohc_decomp_new2(0U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);

    auto round_trip = [&](const std::vector<std::uint8_t>& packet,
                          bool expect_ir) {
        std::array<std::uint8_t, 256> compressed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        if(expect_ir)
            REQUIRE((compressed[0] & 0xfeU) == 0xfcU);
        std::array<std::uint8_t, 256> reconstructed{};
        std::size_t reconstructed_len = reconstructed.size();
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 reconstructed.data(), &reconstructed_len) == 0);
        REQUIRE(reconstructed_len == packet.size());
        REQUIRE(std::memcmp(reconstructed.data(), packet.data(), packet.size()) == 0);
    };

    round_trip(kernel_style_packet(253U, 1U), true);
    round_trip(kernel_style_packet(253U, 2U), false);
    round_trip(kernel_style_packet(17U, 3U), true);
}

TEST_CASE("Linux TUN flow mapping assigns stable deterministic small CIDs")
{
    rohccxx::tun::FlowTable table;
    for(std::uint16_t flow = 0U; flow < 16U; ++flow)
    {
        auto packet = kernel_style_packet(17U, static_cast<std::uint16_t>(flow + 1U));
        put16(packet.data() + 20U, static_cast<std::uint16_t>(31000U + flow));
        rohccxx::tun::FlowAssignment assignment{};
        REQUIRE(table.select(packet.data(), packet.size(), assignment) == rohccxx::tun::Result::Ok);
        REQUIRE(assignment.cid == flow);
        REQUIRE(assignment.newly_assigned);
        REQUIRE_FALSE(assignment.evicted);
        rohccxx::tun::FlowAssignment repeated{};
        REQUIRE(table.select(packet.data(), packet.size(), repeated) == rohccxx::tun::Result::Ok);
        REQUIRE(repeated.cid == flow);
        REQUIRE_FALSE(repeated.newly_assigned);
    }
    REQUIRE(table.active_contexts() == 16U);
    REQUIRE(table.assignments() == 16U);
    REQUIRE(table.evictions() == 0U);
}

TEST_CASE("Linux TUN flow mappings are directional and reuse the LRU CID safely")
{
    rohccxx::tun::FlowTable outbound_a, outbound_b;
    for(std::uint16_t flow = 0U; flow < 16U; ++flow)
    {
        auto packet = kernel_style_packet(17U, static_cast<std::uint16_t>(flow));
        put16(packet.data() + 20U, static_cast<std::uint16_t>(20000U + flow));
        rohccxx::tun::FlowAssignment a{}, b{};
        REQUIRE(outbound_a.select(packet.data(), packet.size(), a) == rohccxx::tun::Result::Ok);
        REQUIRE(outbound_b.select(packet.data(), packet.size(), b) == rohccxx::tun::Result::Ok);
        REQUIRE(a.cid == flow);
        REQUIRE(b.cid == flow);
    }
    auto newest = kernel_style_packet(17U, 99U);
    put16(newest.data() + 20U, 45000U);
    rohccxx::tun::FlowAssignment replacement{};
    REQUIRE(outbound_a.select(newest.data(), newest.size(), replacement) == rohccxx::tun::Result::Ok);
    REQUIRE(replacement.cid == 0U);
    REQUIRE(replacement.newly_assigned);
    REQUIRE(replacement.evicted);
    REQUIRE(outbound_a.evictions() == 1U);
    REQUIRE(outbound_b.evictions() == 0U);
}

TEST_CASE("Linux TUN flow mapping validates UDP ESP RTP and fragment boundaries")
{
    rohccxx::tun::FlowTable table;
    rohccxx::tun::FlowAssignment assignment{};
    auto udp = kernel_style_packet(17U, 1U);
    REQUIRE(table.select(udp.data(), 27U, assignment) == rohccxx::tun::Result::Malformed);
    udp[24] = 0U; udp[25] = 7U;
    REQUIRE(table.select(udp.data(), udp.size(), assignment) == rohccxx::tun::Result::Malformed);

    auto esp = kernel_style_packet(50U, 2U);
    REQUIRE(table.select(esp.data(), 27U, assignment) == rohccxx::tun::Result::Malformed);

    auto fragment = kernel_style_packet(17U, 0x1234U);
    put16(fragment.data() + 6U, 0x2000U);
    REQUIRE(table.select(fragment.data(), fragment.size(), assignment) == rohccxx::tun::Result::Ok);
    REQUIRE(assignment.newly_assigned);

    auto rtp_a = kernel_style_packet(17U, 3U);
    rtp_a[28] = 0x80U; rtp_a[29] = 96U;
    rtp_a[36] = 1U; rtp_a[37] = 2U; rtp_a[38] = 3U; rtp_a[39] = 4U;
    auto rtp_b = rtp_a;
    rtp_b[39] = 5U;
    rohccxx::tun::FlowAssignment first{}, second{};
    REQUIRE(table.select(rtp_a.data(), rtp_a.size(), first) == rohccxx::tun::Result::Ok);
    REQUIRE(table.select(rtp_b.data(), rtp_b.size(), second) == rohccxx::tun::Result::Ok);
    REQUIRE(first.cid != second.cid);
    REQUIRE(table.mapping_failures() == 3U);
}

TEST_CASE("Linux TUN mapped compressors round-trip interleaved flows and LRU IR refresh")
{
    std::array<std::unique_ptr<rohc_comp, CompDelete>, 16> compressors{};
    std::unique_ptr<rohc_decomp, DecompDelete> decomp(
        rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    rohccxx::tun::FlowTable table;
    REQUIRE(decomp);

    auto round_trip = [&](std::vector<std::uint8_t> packet, bool expect_new,
                          std::uint8_t expected_cid) {
        rohccxx::tun::FlowAssignment assignment{};
        REQUIRE(table.select(packet.data(), packet.size(), assignment) == rohccxx::tun::Result::Ok);
        REQUIRE(assignment.cid == expected_cid);
        REQUIRE(assignment.newly_assigned == expect_new);
        if(assignment.newly_assigned)
        {
            compressors[assignment.cid].reset(
                rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(compressors[assignment.cid]);
            REQUIRE(rohc_comp_set_cid(compressors[assignment.cid].get(), assignment.cid) == 0);
        }
        std::array<std::uint8_t, 256> compressed{}, output{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(compressors[assignment.cid].get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        if(expect_new)
        {
            const std::size_t offset = assignment.cid == 0U ? 0U : 1U;
            REQUIRE((compressed[offset] & 0xfeU) == 0xfcU);
        }
        std::size_t output_len = output.size();
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 output.data(), &output_len) == 0);
        REQUIRE(output_len == packet.size());
        REQUIRE(std::memcmp(output.data(), packet.data(), packet.size()) == 0);
    };

    for(std::uint16_t flow = 0U; flow < 16U; ++flow)
    {
        auto packet = kernel_style_packet(17U, static_cast<std::uint16_t>(flow + 1U));
        put16(packet.data() + 20U, static_cast<std::uint16_t>(30000U + flow));
        round_trip(std::move(packet), true, static_cast<std::uint8_t>(flow));
    }
    for(std::uint16_t flow = 0U; flow < 4U; ++flow)
    {
        auto packet = kernel_style_packet(17U, static_cast<std::uint16_t>(flow + 100U));
        put16(packet.data() + 20U, static_cast<std::uint16_t>(30000U + flow));
        round_trip(std::move(packet), false, static_cast<std::uint8_t>(flow));
    }
    auto seventeenth = kernel_style_packet(17U, 500U);
    put16(seventeenth.data() + 20U, 50000U);
    round_trip(std::move(seventeenth), true, 4U);
    REQUIRE(table.evictions() == 1U);
}

TEST_CASE("Linux TUN mapped codec round-trips first three fixed-size UDP packets")
{
    std::array<std::unique_ptr<rohc_comp, CompDelete>, 16> compressors{};
    std::unique_ptr<rohc_decomp, DecompDelete> decomp(
        rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    rohccxx::tun::FlowTable flows;
    REQUIRE(decomp);

    // The integration establishes an ICMP mapping before starting UDP stress.
    auto icmp = kernel_style_packet(1U, 0U);
    rohccxx::tun::FlowAssignment icmp_assignment{};
    REQUIRE(flows.select(icmp.data(), icmp.size(), icmp_assignment) == rohccxx::tun::Result::Ok);
    REQUIRE(icmp_assignment.cid == 0U);

    for(std::uint64_t sequence = 0U; sequence < 3U; ++sequence)
    {
        auto packet = stress_udp_packet(sequence);
        rohccxx::tun::FlowAssignment assignment{};
        REQUIRE(flows.select(packet.data(), packet.size(), assignment) == rohccxx::tun::Result::Ok);
        REQUIRE(assignment.cid == 1U);
        if(assignment.newly_assigned)
        {
            compressors[assignment.cid].reset(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
            REQUIRE(compressors[assignment.cid]);
            REQUIRE(rohc_comp_set_cid(compressors[assignment.cid].get(), assignment.cid) == 0);
        }
        std::array<std::uint8_t, 256> compressed{}, reconstructed{};
        std::size_t compressed_len = compressed.size();
        const int compress_status = rohc_compress4(
            compressors[assignment.cid].get(), packet.data(), packet.size(),
            compressed.data(), &compressed_len);
        INFO("sequence=" << sequence << " cid=" << unsigned(assignment.cid)
             << " compress_status=" << compress_status
             << " compressed_len=" << compressed_len);
        REQUIRE(compress_status == 0);
        std::size_t reconstructed_len = reconstructed.size();
        const int decompress_status = rohc_decompress4(
            decomp.get(), compressed.data(), compressed_len,
            reconstructed.data(), &reconstructed_len);
        INFO("decompress_status=" << decompress_status
             << " reconstructed_len=" << reconstructed_len
             << " feedback=" << rohc_decomp_has_feedback(decomp.get()));
        REQUIRE(decompress_status == 0);
        REQUIRE(reconstructed_len == packet.size());
        REQUIRE(std::memcmp(reconstructed.data(), packet.data(), packet.size()) == 0);
    }
}

TEST_CASE("Linux TUN fixed UDP sequence remains byte exact across formal overlap")
{
    std::unique_ptr<rohc_comp, CompDelete> comp(
        rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    std::unique_ptr<rohc_decomp, DecompDelete> decomp(
        rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp); REQUIRE(decomp);
    REQUIRE(rohc_comp_set_cid(comp.get(), 1U) == 0);
    for(std::size_t index = 0U; index < 10U; ++index)
    {
        auto packet = stress_udp_packet(index, static_cast<std::uint16_t>(0x4000U + index));
        std::array<std::uint8_t, 256> compressed{}, reconstructed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        std::size_t reconstructed_len = reconstructed.size();
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 reconstructed.data(), &reconstructed_len) == 0);
    }
    comp.reset(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(rohc_comp_set_cid(comp.get(), 1U) == 0);
    const std::array<std::uint16_t, 10> ids{{
        0x9568U, 0x9569U, 0x956aU, 0x956bU, 0x956cU,
        0x956dU, 0x956eU, 0x956fU, 0x9570U, 0x9571U}};
    for(std::size_t index = 0U; index < ids.size(); ++index)
    {
        auto packet = stress_udp_packet(index, ids[index], true);
        std::array<std::uint8_t, 256> compressed{}, reconstructed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        REQUIRE(compressed[0] == 0xe1U);
        if(index < 2U)
        {
            REQUIRE(compressed_len == packet.size());
            REQUIRE(compressed[1] == 0xfdU);
        }
        INFO("index=" << index << " checksum=" << std::hex
             << unsigned(packet[26]) << unsigned(packet[27])
             << " compressed_len=" << std::dec << compressed_len
             << " first=" << std::hex << unsigned(compressed[0]) << ":"
             << unsigned(compressed[1]) << ":" << unsigned(compressed[2]));
        std::size_t reconstructed_len = reconstructed.size();
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 reconstructed.data(), &reconstructed_len) == 0);
        REQUIRE(reconstructed_len == packet.size());
        REQUIRE(std::memcmp(reconstructed.data(), packet.data(), packet.size()) == 0);
    }
}

TEST_CASE("Linux TUN UDP private FO avoids PT-0 ambiguity after CID reuse and loss")
{
    std::unique_ptr<rohc_comp, CompDelete> comp(
        rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    std::unique_ptr<rohc_decomp, DecompDelete> decomp(
        rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp); REQUIRE(decomp);
    REQUIRE(rohc_comp_set_cid(comp.get(), 15U) == 0);

    for(std::size_t index = 0U; index < 3U; ++index)
    {
        auto old_flow = stress_udp_packet(index,
            static_cast<std::uint16_t>(0x9000U + index), true, 1200U);
        std::array<std::uint8_t, 1400> compressed{}, reconstructed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), old_flow.data(), old_flow.size(),
                               compressed.data(), &compressed_len) == 0);
        std::size_t reconstructed_len = reconstructed.size();
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 reconstructed.data(), &reconstructed_len) == 0);
        REQUIRE(reconstructed_len == old_flow.size());
        REQUIRE(std::memcmp(reconstructed.data(), old_flow.data(), old_flow.size()) == 0);
    }
    comp.reset(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(rohc_comp_set_cid(comp.get(), 15U) == 0);

    // This is the second generation for CID 15. Its first IR replaces the
    // evicted flow, then packet 37 is lost. Private FO subsequently refreshes
    // the peer IPv4 ID while its MSN remains one behind the local MSN. The UDP
    // checksum distinguishes that private packet from an accidental PT-0.
    for(std::size_t index = 0U; index <= 39U; ++index)
    {
        auto packet = stress_udp_packet(241112U + index,
                                        static_cast<std::uint16_t>(14U + index),
                                        false, 1200U, 34143U, 15U);
        std::array<std::uint8_t, 1400> compressed{}, reconstructed{};
        std::size_t compressed_len = compressed.size();
        REQUIRE(rohc_compress4(comp.get(), packet.data(), packet.size(),
                               compressed.data(), &compressed_len) == 0);
        if(index == 37U)
        {
            REQUIRE(compressed[0] == 0xefU);
            REQUIRE(compressed[1] == 0x7aU);
            continue;
        }
        if(index == 38U)
        {
            REQUIRE(compressed[0] == 0xefU);
            REQUIRE(compressed[1] == 0x7aU);
        }
        std::size_t reconstructed_len = reconstructed.size();
        INFO("generation=2 cid=15 sequence=" << 241112U + index
             << " local_msn=" << index + 1U
             << " peer_msn_after_decode=" << index + 1U
             << " ipv4_id=" << 14U + index
             << " compressed_len=" << compressed_len);
        REQUIRE(rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                 reconstructed.data(), &reconstructed_len) == 0);
        REQUIRE(reconstructed_len == packet.size());
        REQUIRE(std::memcmp(reconstructed.data(), packet.data(), packet.size()) == 0);
        REQUIRE(rohc_decomp_has_feedback(decomp.get()) == 0);
    }
}
