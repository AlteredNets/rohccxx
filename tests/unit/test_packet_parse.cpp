// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>
#include "../../src/core/compressor.h"
#include "../../src/core/decompressor.h"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/context_crc.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/core/emit_ir_dyn.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/emit_udplite_fo.hpp"
#include "rohccxx/core/decode_esp_fo.hpp"
#include "rohccxx/core/decode_ip_fo.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/decode_udp_fo.hpp"
#include "rohccxx/core/decode_udplite_fo.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/core/lla.hpp"
#include "rohccxx/core/ppp.hpp"
#include "rohccxx/core/feedback.hpp"
#include "rohccxx/core/segment.hpp"
#include "rohccxx/core/rohcoipsec.hpp"
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>

#include "test_packet_helpers.hpp"

#include "rohccxx/protocols/ipv4.hpp"
#include "rohccxx/protocols/udp.hpp"
#include "rohccxx/protocols/rtp.hpp"
#include "rohccxx/wire/types.hpp"
#include "rohccxx/wire/convert.hpp"


namespace
{

std::uint16_t checksum_ipv4_header(const std::uint8_t* hdr, int len)
{
    std::uint32_t sum = 0;
    for(int i = 0; i < len; i += 2)
    {
        std::uint16_t word = static_cast<std::uint16_t>(hdr[i] << 8);
        if(i + 1 < len)
            word |= hdr[i + 1];
        sum += word;
    }

    while(sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return static_cast<std::uint16_t>(~sum);
}



void prepend_add_cid(std::uint8_t cid, std::uint8_t* packet, size_t& len)
{
    std::memmove(packet + 1, packet, len);
    packet[0] = static_cast<std::uint8_t>(0xE0 | (cid & 0x0F));
    ++len;
}

void require_ip_header_id(const std::uint8_t* packet, std::uint16_t id)
{
    REQUIRE(packet[4] == static_cast<std::uint8_t>(id >> 8));
    REQUIRE(packet[5] == static_cast<std::uint8_t>(id & 0xFF));
}

void finish_ipv4_checksum(std::uint8_t* packet)
{
    packet[10] = 0;
    packet[11] = 0;
    const std::uint16_t csum = checksum_ipv4_header(packet, 20);
    packet[10] = static_cast<std::uint8_t>(csum >> 8);
    packet[11] = static_cast<std::uint8_t>(csum & 0xFF);
}

std::vector<std::uint8_t> make_collision_regression_packet(std::uint32_t ordinal,
                                                           bool zero_payload)
{
    constexpr std::size_t header_size = 40;
    constexpr std::size_t payload_size = 1200;
    constexpr std::uint64_t seed = 0x524F484343585832ULL;
    std::vector<std::uint8_t> packet(header_size + payload_size);
    auto* p = packet.data();
    p[0] = 0x45;
    p[2] = static_cast<std::uint8_t>(packet.size() >> 8U);
    p[3] = static_cast<std::uint8_t>(packet.size());
    p[4] = static_cast<std::uint8_t>(ordinal >> 8U);
    p[5] = static_cast<std::uint8_t>(ordinal);
    p[6] = 0x40;
    p[8] = 64;
    p[9] = 17;
    p[12] = 10;
    p[15] = 1;
    p[16] = 10;
    p[19] = 2;
    p[20] = 0x27;
    p[21] = 0x10;
    p[22] = 0x4E;
    p[23] = 0x20;
    p[24] = 0x04;
    p[25] = 0xC4;
    p[28] = 0x80;
    p[29] = 96;
    const std::uint16_t sequence = static_cast<std::uint16_t>(0x1000U + ordinal);
    p[30] = static_cast<std::uint8_t>(sequence >> 8U);
    p[31] = static_cast<std::uint8_t>(sequence);
    const std::uint32_t timestamp = 0x01000000U + ordinal * 160U;
    p[32] = static_cast<std::uint8_t>(timestamp >> 24U);
    p[33] = static_cast<std::uint8_t>(timestamp >> 16U);
    p[34] = static_cast<std::uint8_t>(timestamp >> 8U);
    p[35] = static_cast<std::uint8_t>(timestamp);
    p[36] = 0x10;
    p[37] = 0x20;
    p[38] = 0x30;
    p[39] = 0x40;

    std::uint64_t state = seed ^ ordinal;
    for(std::size_t i = header_size; i < packet.size(); ++i)
    {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        p[i] = zero_payload ? 0 : static_cast<std::uint8_t>(state);
    }
    finish_ipv4_checksum(p);
    return packet;
}

void require_collision_regression_round_trips(bool zero_payload)
{
    constexpr std::size_t packet_count = 49017;
    rohc_comp* comp = rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 0) == 0);

    std::vector<std::uint8_t> compressed(2048);
    std::vector<std::uint8_t> output(2048);
    std::uint64_t incorrect_round_trips = 0;
    std::uint64_t guard_failures = 0;
    for(std::uint32_t i = 0; i < packet_count; ++i)
    {
        const auto input = make_collision_regression_packet(i, zero_payload);
        std::size_t compressed_len = compressed.size();
        const int compress_status = rohc_compress4(comp,
                                                   input.data(),
                                                   input.size(),
                                                   compressed.data(),
                                                   &compressed_len);
        if(compress_status != 0)
        {
            ++guard_failures;
            continue;
        }

        if(!zero_payload && (i == 41095U || i == 49016U))
        {
            REQUIRE(compressed_len == 1205);
            REQUIRE(compressed[0] == 0x00);
        }

        std::size_t output_len = output.size();
        const int api_status = rohc_decompress4(decomp,
                                                compressed.data(),
                                                compressed_len,
                                                output.data(),
                                                &output_len);
        if(api_status != 0)
            ++guard_failures;
        if(api_status != 0 || output_len != input.size() ||
           std::memcmp(output.data(), input.data(), input.size()) != 0)
        {
            ++incorrect_round_trips;
        }

        if(!zero_payload && (i == 41095U || i == 49016U))
        {
            REQUIRE(api_status == 0);
            REQUIRE(output_len == 1240);
            REQUIRE(std::memcmp(output.data(), input.data(), input.size()) == 0);
        }
    }

    REQUIRE(incorrect_round_trips == 0);
    REQUIRE(guard_failures == 0);
    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

void set_ipv4_id_and_flags(std::uint8_t* packet,
                           std::uint16_t id,
                           std::uint16_t flags_fragment)
{
    packet[4] = static_cast<std::uint8_t>(id >> 8);
    packet[5] = static_cast<std::uint8_t>(id & 0xFF);
    packet[6] = static_cast<std::uint8_t>(flags_fragment >> 8);
    packet[7] = static_cast<std::uint8_t>(flags_fragment & 0xFF);
    finish_ipv4_checksum(packet);
}


rohccxx_lla_contract_t complete_c_lla_contract()
{
    rohccxx_lla_contract_t contract{};
    contract.identifies_packet_types = 1;
    contract.preserves_order = 1;
    contract.reports_loss = 1;
    contract.reports_residual_errors = 1;
    contract.delivers_feedback = 1;
    contract.protects_context_packets = 1;
    contract.supports_context_synchronization = 1;
    contract.supports_context_check = 1;
    contract.supports_reliable_mode = 1;
    contract.delivers_ack = 1;
    contract.delivers_static_nack = 1;
    return contract;
}

rohccxx_lla_flow_t complete_c_lla_flow()
{
    rohccxx_lla_flow_t flow{};
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;
    return flow;
}

rohccxx::lla::AssistingLayerContract complete_cpp_lla_contract()
{
    rohccxx::lla::AssistingLayerContract contract{};
    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;
    contract.protects_context_packets = true;
    contract.supports_context_synchronization = true;
    contract.supports_context_check = true;
    contract.supports_reliable_mode = true;
    contract.delivers_ack = true;
    contract.delivers_static_nack = true;
    return contract;
}

rohccxx::lla::ZeroByteFlow complete_cpp_lla_flow()
{
    rohccxx::lla::ZeroByteFlow flow{};
    flow.ipv4_udp_rtp = true;
    flow.udp_checksum_disabled = true;
    flow.rtp_sequence_increments_by_one = true;
    flow.compressor_observed_in_order = true;
    flow.synchronized_timing = true;
    return flow;
}


void make_valid_ipv6_udp_without_transport(std::uint8_t* packet, size_t packet_len)
{
    REQUIRE(packet_len >= 40);
    std::memset(packet, 0, packet_len);
    packet[0] = 0x60;
    const std::uint16_t payload_len = static_cast<std::uint16_t>(packet_len - 40U);
    packet[4] = static_cast<std::uint8_t>(payload_len >> 8);
    packet[5] = static_cast<std::uint8_t>(payload_len & 0xFF);
    packet[6] = 17;
    packet[7] = 64;
    packet[8] = 0x20;
    packet[9] = 0x01;
    packet[10] = 0x0D;
    packet[11] = 0xB8;
    packet[24] = 0x20;
    packet[25] = 0x01;
    packet[26] = 0x0D;
    packet[27] = 0xB8;
    for(size_t i = 40; i < packet_len; ++i)
        packet[i] = static_cast<std::uint8_t>(0xA0U + (i & 0x0FU));
}

void make_valid_ip_packet(std::uint8_t* packet, std::uint8_t protocol, std::uint16_t ip_id)
{
    std::memset(packet, 0, 64);
    packet[0] = 0x45;
    packet[2] = 0x00;
    packet[3] = 0x40;
    packet[4] = static_cast<std::uint8_t>(ip_id >> 8);
    packet[5] = static_cast<std::uint8_t>(ip_id & 0xFF);
    packet[8] = 64;
    packet[9] = protocol;
    packet[12] = 192;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    for(size_t i = 20; i < 64; ++i)
        packet[i] = static_cast<std::uint8_t>(0xA0U + (i & 0x0FU));
    finish_ipv4_checksum(packet);
}

void make_valid_udp_family_packet(std::uint8_t* packet,
                                  std::uint8_t protocol,
                                  std::uint16_t ip_id,
                                  std::uint16_t check_or_coverage,
                                  bool with_rtp)
{
    std::memset(packet, 0, 64);
    packet[0] = 0x45;
    packet[2] = 0x00;
    packet[3] = 0x40;
    packet[4] = static_cast<std::uint8_t>(ip_id >> 8);
    packet[5] = static_cast<std::uint8_t>(ip_id & 0xFF);
    packet[8] = 64;
    packet[9] = protocol;
    packet[12] = 192;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x2C;
    packet[26] = static_cast<std::uint8_t>(check_or_coverage >> 8);
    packet[27] = static_cast<std::uint8_t>(check_or_coverage & 0xFF);
    if(with_rtp)
    {
        packet[28] = 0x80;
        packet[29] = 0x60;
        packet[30] = static_cast<std::uint8_t>(ip_id >> 8);
        packet[31] = static_cast<std::uint8_t>(ip_id & 0xFF);
        packet[32] = 0x01;
        packet[33] = 0x02;
        packet[34] = static_cast<std::uint8_t>(ip_id >> 8);
        packet[35] = static_cast<std::uint8_t>(ip_id & 0xFF);
        packet[36] = 0x11;
        packet[37] = 0x22;
        packet[38] = 0x33;
        packet[39] = 0x44;
    }
    else
    {
        packet[28] = static_cast<std::uint8_t>(0x40U | (ip_id & 0x3FU));
    }
    finish_ipv4_checksum(packet);
}

} // namespace

TEST_CASE("Parse minimal IPv4/UDP/RTP packet")
{
    uint8_t packet[64] = {};

    packet[0] = 0x45;            // IPv4, IHL=5
    packet[9] = 17;              // UDP
    packet[20] = 0x12;           // UDP src port
    packet[21] = 0x34;
    packet[28] = 0x80;           // RTP v=2

    const rohccxx::ipv4::Header* ip;
    size_t ip_hlen;

    REQUIRE(rohccxx::ipv4::parse(packet, sizeof(packet), ip, ip_hlen));
    REQUIRE(rohccxx::wire::to_host(ip->protocol)  == 17);

    const rohccxx::udp::Header* udp;
    REQUIRE(rohccxx::udp::parse(packet, sizeof(packet),
                                packet + ip_hlen, udp));

    const rohccxx::rtp::Header* rtp;
    REQUIRE(rohccxx::rtp::parse(packet, sizeof(packet),
                                packet + ip_hlen + sizeof(*udp),
                                rtp));
}

TEST_CASE("ROHC RTP profile round-trips CSRC extension and padding through C API")
{
    auto make_packet = [](std::uint8_t* packet, std::uint16_t seq, std::uint32_t ts)
    {
        constexpr size_t total_len = 68;
        std::memset(packet, 0, total_len);
        packet[0] = 0x45;
        packet[2] = 0x00;
        packet[3] = static_cast<std::uint8_t>(total_len);
        packet[4] = static_cast<std::uint8_t>(seq >> 8);
        packet[5] = static_cast<std::uint8_t>(seq & 0xFFU);
        packet[8] = 64;
        packet[9] = 17;
        packet[12] = 192;
        packet[13] = 0;
        packet[14] = 2;
        packet[15] = 1;
        packet[16] = 198;
        packet[17] = 51;
        packet[18] = 100;
        packet[19] = 2;

        packet[20] = 0x12;
        packet[21] = 0x34;
        packet[22] = 0x56;
        packet[23] = 0x78;
        const std::uint16_t udp_len = static_cast<std::uint16_t>(total_len - 20U);
        packet[24] = static_cast<std::uint8_t>(udp_len >> 8);
        packet[25] = static_cast<std::uint8_t>(udp_len & 0xFFU);

        constexpr size_t rtp = 28;
        packet[rtp + 0] = 0xB2;
        packet[rtp + 1] = 0x60;
        packet[rtp + 2] = static_cast<std::uint8_t>(seq >> 8);
        packet[rtp + 3] = static_cast<std::uint8_t>(seq & 0xFFU);
        packet[rtp + 4] = static_cast<std::uint8_t>(ts >> 24);
        packet[rtp + 5] = static_cast<std::uint8_t>(ts >> 16);
        packet[rtp + 6] = static_cast<std::uint8_t>(ts >> 8);
        packet[rtp + 7] = static_cast<std::uint8_t>(ts & 0xFFU);
        packet[rtp + 8] = 0x11;
        packet[rtp + 9] = 0x22;
        packet[rtp + 10] = 0x33;
        packet[rtp + 11] = 0x44;

        const std::uint8_t csrcs[] = {0xCA, 0xFE, 0x00, 0x01, 0xCA, 0xFE, 0x00, 0x02};
        std::memcpy(packet + rtp + 12, csrcs, sizeof(csrcs));
        const std::uint8_t extension[] = {0xBE, 0xDE, 0x00, 0x01, 0xC0, 0xFF, 0xEE, 0x00};
        std::memcpy(packet + rtp + 20, extension, sizeof(extension));
        for(size_t i = 0; i < 8; ++i)
            packet[rtp + 28 + i] = static_cast<std::uint8_t>(0xA0U + i);
        const std::uint8_t padding[] = {0x91, 0x92, 0x93, 0x04};
        std::memcpy(packet + rtp + 36, padding, sizeof(padding));
        finish_ipv4_checksum(packet);
    };

    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    for(std::uint16_t i = 0; i < 2; ++i)
    {
        std::uint8_t packet[68] = {};
        make_packet(packet, static_cast<std::uint16_t>(0x2000U + i), 0x01020304U + static_cast<std::uint32_t>(i) * 160U);

        std::uint8_t rohc[256] = {};
        std::size_t rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);

        std::uint8_t out[96] = {};
        std::size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(packet));
        REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC packet parser identifies current RFC 5225 packet families")
{
    uint8_t ir[] = {0xFD, 0x02, 0x00};
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(ir, sizeof(ir), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::IR);
    REQUIRE(parsed.profile_id == 0x02);
    REQUIRE(parsed.cid == 0);
    REQUIRE_FALSE(parsed.has_add_cid);
    REQUIRE(parsed.packet == ir);

    uint8_t ir_dyn[] = {0xF8, 0x07, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(ir_dyn, sizeof(ir_dyn), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::IR_DYN);
    REQUIRE(parsed.profile_id == 0x07);

    uint8_t udp_fo[] = {0x7A, 0x00, 0x00, 0x01, 0x00, 0x02};
    REQUIRE(rohccxx::parse_rohc_packet(udp_fo, sizeof(udp_fo), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_UDP);

    uint8_t rtp_fo[] = {0x06, 0x00, 0x00, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(rtp_fo, sizeof(rtp_fo), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.cid == 1);

    uint8_t zero_prefixed_rtp_fo[] = {0x00, 0x40, 0x00, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(zero_prefixed_rtp_fo, sizeof(zero_prefixed_rtp_fo), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.cid == 0);

    rohccxx::Context rtp_ctx{};
    rtp_ctx.cid = 3;
    rtp_ctx.rtp.last_seq = 0x1235;
    rtp_ctx.rtp.last_ts = 0x01020305;
    uint8_t generated_rtp_fo[16] = {};
    size_t generated_rtp_fo_len = sizeof(generated_rtp_fo);
    REQUIRE(rohccxx::emit_rtp_fo(generated_rtp_fo, &generated_rtp_fo_len, rtp_ctx));
    REQUIRE(rohccxx::parse_rohc_packet(generated_rtp_fo, generated_rtp_fo_len, parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.cid == 3);
    REQUIRE_FALSE(parsed.has_add_cid);

    uint8_t feedback[] = {0xF2, 0x00, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(feedback, sizeof(feedback), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::Feedback);

    uint8_t lla_csp[] = {0xFA, 0x00, 0x10, 0xFD, 0x05};
    REQUIRE(rohccxx::parse_rohc_packet(lla_csp, sizeof(lla_csp), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::LLA_ContextSync);

    uint8_t lla_ccp[] = {0xFB, 0x85};
    REQUIRE(rohccxx::parse_rohc_packet(lla_ccp, sizeof(lla_ccp), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::LLA_ContextCheck);

    uint8_t segment[] = {0xFE, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(segment, sizeof(segment), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::Segment);

    uint8_t add_cid_segment[] = {0xE3, 0xFE, 0x00};
    REQUIRE(rohccxx::parse_rohc_packet(add_cid_segment, sizeof(add_cid_segment), parsed));
    REQUIRE(parsed.has_add_cid);
    REQUIRE(parsed.cid == 3);
    REQUIRE(parsed.type == rohccxx::RohcPacketType::Segment);

    uint8_t uncompressed[21] = {};
    uncompressed[0] = 0x00;
    uncompressed[1] = 0x45;
    uncompressed[3] = 0x00;
    uncompressed[4] = 0x14;
    REQUIRE(rohccxx::parse_rohc_packet(uncompressed, sizeof(uncompressed), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::Uncompressed);

    uint8_t malformed_uncompressed[21] = {};
    malformed_uncompressed[0] = 0x00;
    malformed_uncompressed[1] = 0x45;
    malformed_uncompressed[3] = 0x00;
    malformed_uncompressed[4] = 0x18;
    REQUIRE(rohccxx::parse_rohc_packet(malformed_uncompressed, sizeof(malformed_uncompressed), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
}

TEST_CASE("CID 0 FO-RTP packets cannot be mistaken for uncompressed IPv6")
{
    SECTION("patterned payload crosses both known collision indices")
    {
        require_collision_regression_round_trips(false);
    }

    SECTION("zero-filled payload remains correct")
    {
        require_collision_regression_round_trips(true);
    }
}

TEST_CASE("CID 0 genuine uncompressed IPv6 works without an RTP context")
{
    std::array<std::uint8_t, 48> rohc{};
    rohc[0] = 0x00;
    make_valid_ipv6_udp_without_transport(rohc.data() + 1, rohc.size() - 1);

    rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);
    std::array<std::uint8_t, 64> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_decompress4(decomp,
                             rohc.data(),
                             rohc.size(),
                             output.data(),
                             &output_len) == 0);
    REQUIRE(output_len == rohc.size() - 1);
    REQUIRE(std::memcmp(output.data(), rohc.data() + 1, output_len) == 0);
    rohc_decomp_free(decomp);
}


TEST_CASE("RTP FO round-trips sequential IPv4 IDs and DF flags")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_DOWNLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 0) == 0);

    for(std::uint16_t i = 0; i < 4; ++i)
    {
        std::uint8_t ip[64] = {};
        make_valid_rtp(ip,
                       static_cast<std::uint16_t>(1000U + i),
                       160000U + static_cast<std::uint32_t>(i) * 160U,
                       0x11223344U);
        set_ipv4_id_and_flags(ip, i, 0x4000U);

        std::uint8_t rohc[128] = {};
        std::size_t rohc_len = sizeof(rohc);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

        rohccxx::ParsedRohcPacket parsed{};
        REQUIRE(rohccxx::parse_rohc_packet(rohc, rohc_len, parsed));
        if(i >= 2)
            REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);

        std::uint8_t out[128] = {};
        std::size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(ip));
        REQUIRE(out[4] == ip[4]);
        REQUIRE(out[5] == ip[5]);
        REQUIRE(out[6] == ip[6]);
        REQUIRE(out[7] == ip[7]);
        REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHC uncompressed profile round-trips IPv4 and IPv6 packets")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    std::uint8_t ipv4[20] = {};
    ipv4[0] = 0x45;
    ipv4[2] = 0x00;
    ipv4[3] = sizeof(ipv4);
    ipv4[4] = 0x60;
    ipv4[5] = 0x01;
    ipv4[8] = 64;
    ipv4[9] = 17;
    ipv4[12] = 192;
    ipv4[13] = 0;
    ipv4[14] = 2;
    ipv4[15] = 1;
    ipv4[16] = 198;
    ipv4[17] = 51;
    ipv4[18] = 100;
    ipv4[19] = 2;
    finish_ipv4_checksum(ipv4);

    std::uint8_t ipv6[40] = {};
    make_valid_ipv6_udp_without_transport(ipv6, sizeof(ipv6));

    for(const auto* packet : {ipv4, ipv6})
    {
        const size_t packet_len = packet == ipv4 ? sizeof(ipv4) : sizeof(ipv6);
        std::uint8_t rohc[80] = {};
        std::size_t rohc_len = sizeof(rohc);
        std::uint8_t out[80] = {};
        std::size_t out_len = sizeof(out);
        REQUIRE(rohc_compress4(comp, packet, packet_len, rohc, &rohc_len) == 0);
        REQUIRE(rohc_len == packet_len + 1U);
        REQUIRE(rohc[0] == 0x00);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == packet_len);
        REQUIRE(std::memcmp(out, packet, packet_len) == 0);
    }

    rohccxx_mode_t mode = ROHCCXX_MODE_O;
    REQUIRE(rohc_decomp_get_mode(decomp, &mode) == 0);
    REQUIRE(mode == ROHCCXX_MODE_U);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC uncompressed profile rejects malformed packets and reports feedback")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t malformed[21] = {};
    malformed[0] = 0x00;
    malformed[1] = 0x45;
    malformed[3] = 0x00;
    malformed[4] = 0x18;
    std::uint8_t out[32] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, malformed, sizeof(malformed), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    std::uint8_t valid[21] = {};
    valid[0] = 0x00;
    valid[1] = 0x45;
    valid[3] = 0x00;
    valid[4] = 0x14;
    out_len = 4;
    REQUIRE(rohc_decompress4(decomp, valid, sizeof(valid), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC uncompressed profile preserves Add-CID context isolation")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t packet[22] = {};
    packet[0] = 0xE3;
    packet[1] = 0x00;
    packet[2] = 0x45;
    packet[4] = 0x00;
    packet[5] = 0x14;

    std::uint8_t out[32] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, packet, sizeof(packet), out, &out_len) == 0);
    REQUIRE(out_len == 20);
    REQUIRE(out[0] == 0x45);

    std::uint8_t other_cid_packet[22] = {};
    other_cid_packet[0] = 0xE2;
    other_cid_packet[1] = 0x00;
    other_cid_packet[2] = 0x45;
    other_cid_packet[4] = 0x00;
    other_cid_packet[5] = 0x14;

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, other_cid_packet, sizeof(other_cid_packet), out, &out_len) == 0);
    REQUIRE(out_len == 20);
    REQUIRE(out[0] == 0x45);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC RFC 3243 zero-byte assumptions are validated before NHP use")
{
    rohccxx::lla::AssistingLayerContract contract{};
    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3243_zero_byte_assumptions(contract);
    REQUIRE_FALSE(validation.valid);
    REQUIRE((validation.missing & rohccxx::lla::MissingPacketTypeIdentification) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingInOrderDelivery) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingLossIndication) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingResidualErrorIndication) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingFeedbackDelivery) != 0);
    REQUIRE_FALSE(rohccxx::lla::can_emit_no_header_packet(contract));

    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;
    validation = rohccxx::lla::validate_rfc3243_zero_byte_assumptions(contract);
    REQUIRE(validation.valid);
    REQUIRE(validation.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_no_header_packet(contract));
}

TEST_CASE("ROHC RFC 3408 R-mode zero-byte support requires reliable feedback delivery")
{
    rohccxx::lla::AssistingLayerContract contract{};
    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;

    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3408_r_mode_zero_byte_support(contract);
    REQUIRE_FALSE(validation.valid);
    REQUIRE((validation.missing & rohccxx::lla::MissingReliableMode) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingAckDelivery) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingStaticNackDelivery) != 0);
    REQUIRE_FALSE(rohccxx::lla::can_emit_reliable_mode_no_header_packet(contract));

    contract.supports_reliable_mode = true;
    contract.delivers_ack = true;
    contract.delivers_static_nack = true;
    validation = rohccxx::lla::validate_rfc3408_r_mode_zero_byte_support(contract);
    REQUIRE(validation.valid);
    REQUIRE(validation.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_reliable_mode_no_header_packet(contract));
}

TEST_CASE("ROHC RFC 3241 PPP option helpers parse write and merge ROHC channel settings")
{
    rohccxx::ppp::RohcOption option{};
    option.max_cid = 31;
    option.mrru = 1500;
    option.max_header = 168;
    REQUIRE(rohccxx::ppp::append_profile(option, static_cast<std::uint16_t>(rohccxx::Profile::LLA_RTP)));
    REQUIRE(rohccxx::ppp::append_profile(option, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));

    std::uint8_t wire[32] = {};
    std::size_t wire_len = sizeof(wire);
    REQUIRE(rohccxx::ppp::write_rohc_option(option, wire, &wire_len));
    REQUIRE(wire_len == 16);
    REQUIRE(wire[0] == rohccxx::ppp::ip_compression_option_type);
    REQUIRE(wire[1] == wire_len);
    REQUIRE(wire[2] == 0x00);
    REQUIRE(wire[3] == rohccxx::ppp::ip_compression_protocol_rohc);

    rohccxx::ppp::RohcOption parsed{};
    REQUIRE(rohccxx::ppp::parse_rohc_option(wire, wire_len, parsed));
    REQUIRE(parsed.max_cid == option.max_cid);
    REQUIRE(parsed.mrru == option.mrru);
    REQUIRE(parsed.max_header == option.max_header);
    REQUIRE(parsed.profile_count == 2);
    REQUIRE(parsed.profiles[0] == static_cast<std::uint16_t>(rohccxx::Profile::LLA_RTP));
    REQUIRE(parsed.profiles[1] == static_cast<std::uint16_t>(rohccxx::Profile::RTP));

    REQUIRE(rohccxx::ppp::is_rohc_protocol_field(rohccxx::ppp::protocol_rohc_small_cid));
    REQUIRE(rohccxx::ppp::is_rohc_protocol_field(rohccxx::ppp::protocol_rohc_large_cid));
    REQUIRE_FALSE(rohccxx::ppp::uses_large_cid_protocol(rohccxx::ppp::protocol_rohc_small_cid));
    REQUIRE(rohccxx::ppp::uses_large_cid_protocol(rohccxx::ppp::protocol_rohc_large_cid));

    rohccxx::ppp::RohcOption extra{};
    extra.max_cid = 15;
    extra.mrru = 2048;
    extra.max_header = 128;
    REQUIRE(rohccxx::ppp::append_profile(extra, static_cast<std::uint16_t>(rohccxx::Profile::UDP)));

    rohccxx::ppp::RohcOption merged{};
    REQUIRE(rohccxx::ppp::merge_channel_options(option, extra, merged));
    REQUIRE(merged.max_cid == 31);
    REQUIRE(merged.mrru == 2048);
    REQUIRE(merged.max_header == 168);
    REQUIRE(merged.profile_count == 3);
    REQUIRE(merged.profiles[0] == static_cast<std::uint16_t>(rohccxx::Profile::LLA_RTP));
    REQUIRE(merged.profiles[1] == static_cast<std::uint16_t>(rohccxx::Profile::RTP));
    REQUIRE(merged.profiles[2] == static_cast<std::uint16_t>(rohccxx::Profile::UDP));
}

TEST_CASE("ROHC RFC 3241 C API exposes PPP option acceptance helpers")
{
    rohccxx_ppp_rohc_option_t option{};
    option.max_cid = 31;
    option.mrru = 1500;
    option.max_header = 168;
    option.profiles[0] = ROHCCXX_PROFILE_RTP;
    option.profiles[1] = ROHCCXX_PROFILE_UDP;
    option.profile_count = 2;

    REQUIRE(rohc_ppp_validate_rohc_option(&option) == 1);
    REQUIRE(rohc_ppp_is_rohc_protocol(rohccxx::ppp::protocol_rohc_small_cid) == 1);
    REQUIRE(rohc_ppp_is_rohc_protocol(rohccxx::ppp::protocol_rohc_large_cid) == 1);
    REQUIRE(rohc_ppp_uses_large_cid_protocol(rohccxx::ppp::protocol_rohc_small_cid) == 0);
    REQUIRE(rohc_ppp_uses_large_cid_protocol(rohccxx::ppp::protocol_rohc_large_cid) == 1);

    std::uint8_t wire[32] = {};
    std::size_t wire_len = sizeof(wire);
    REQUIRE(rohc_ppp_write_rohc_option(&option, wire, &wire_len) == 0);

    rohccxx_ppp_rohc_option_t parsed{};
    REQUIRE(rohc_ppp_parse_rohc_option(wire, wire_len, &parsed) == 0);
    REQUIRE(parsed.max_cid == option.max_cid);
    REQUIRE(parsed.mrru == option.mrru);
    REQUIRE(parsed.max_header == option.max_header);
    REQUIRE(parsed.profile_count == option.profile_count);
    REQUIRE(parsed.profiles[0] == ROHCCXX_PROFILE_RTP);
    REQUIRE(parsed.profiles[1] == ROHCCXX_PROFILE_UDP);

    rohccxx_ppp_rohc_option_t extra{};
    extra.max_cid = 63;
    extra.mrru = 0;
    extra.max_header = 200;
    extra.profiles[0] = ROHCCXX_PROFILE_ESP;
    extra.profile_count = 1;

    rohccxx_ppp_rohc_option_t merged{};
    REQUIRE(rohc_ppp_merge_rohc_options(&option, &extra, &merged) == 0);
    REQUIRE(merged.max_cid == 63);
    REQUIRE(merged.max_header == 200);
    REQUIRE(merged.profile_count == 3);
    REQUIRE(merged.profiles[0] == ROHCCXX_PROFILE_RTP);
    REQUIRE(merged.profiles[1] == ROHCCXX_PROFILE_UDP);
    REQUIRE(merged.profiles[2] == ROHCCXX_PROFILE_ESP);

    option.profiles[1] = ROHCCXX_PROFILE_RTP;
    REQUIRE(rohc_ppp_validate_rohc_option(&option) == 0);
    REQUIRE(rohc_ppp_write_rohc_option(&option, wire, &wire_len) == -1);
}

TEST_CASE("ROHC RFC 3241 PPP option helpers reject malformed negotiation payloads")
{
    rohccxx::ppp::RohcOption parsed{};
    const std::uint8_t wrong_type[] = {0x01, 0x0E, 0x00, 0x03, 0x00, 0x0F, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x04, 0x01, 0x01};
    REQUIRE_FALSE(rohccxx::ppp::parse_rohc_option(wrong_type, sizeof(wrong_type), parsed));

    const std::uint8_t wrong_protocol[] = {0x02, 0x0E, 0x00, 0x04, 0x00, 0x0F, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x04, 0x01, 0x01};
    REQUIRE_FALSE(rohccxx::ppp::parse_rohc_option(wrong_protocol, sizeof(wrong_protocol), parsed));

    const std::uint8_t no_profiles[] = {0x02, 0x0A, 0x00, 0x03, 0x00, 0x0F, 0x00, 0x00, 0x00, 0xA8};
    REQUIRE_FALSE(rohccxx::ppp::parse_rohc_option(no_profiles, sizeof(no_profiles), parsed));

    const std::uint8_t duplicate_profiles[] = {0x02, 0x10, 0x00, 0x03, 0x00, 0x0F, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x06, 0x01, 0x01, 0x01, 0x01};
    REQUIRE_FALSE(rohccxx::ppp::parse_rohc_option(duplicate_profiles, sizeof(duplicate_profiles), parsed));

    rohccxx::ppp::RohcOption invalid{};
    invalid.max_cid = rohccxx::ppp::max_cid_limit + 1U;
    invalid.profile_count = 1;
    invalid.profiles[0] = static_cast<std::uint16_t>(rohccxx::Profile::RTP);
    std::uint8_t wire[16] = {};
    std::size_t wire_len = sizeof(wire);
    REQUIRE_FALSE(rohccxx::ppp::write_rohc_option(invalid, wire, &wire_len));
}

TEST_CASE("ROHC RFC 3409 lower-layer guidelines gate LLA context packets")
{
    rohccxx::lla::AssistingLayerContract contract{};
    contract.identifies_packet_types = true;
    contract.preserves_order = true;
    contract.reports_loss = true;
    contract.reports_residual_errors = true;
    contract.delivers_feedback = true;

    rohccxx::lla::ContractValidation validation = rohccxx::lla::validate_rfc3409_lower_layer_guidelines(contract);
    REQUIRE_FALSE(validation.valid);
    REQUIRE((validation.missing & rohccxx::lla::MissingContextPacketProtection) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingContextSynchronization) != 0);
    REQUIRE((validation.missing & rohccxx::lla::MissingContextCheck) != 0);
    REQUIRE_FALSE(rohccxx::lla::can_emit_context_synchronization_packet(contract));
    REQUIRE_FALSE(rohccxx::lla::can_emit_context_check_packet(contract));

    contract.protects_context_packets = true;
    contract.supports_context_synchronization = true;
    contract.supports_context_check = true;
    validation = rohccxx::lla::validate_rfc3409_lower_layer_guidelines(contract);
    REQUIRE(validation.valid);
    REQUIRE(validation.missing == 0);
    REQUIRE(rohccxx::lla::can_emit_context_synchronization_packet(contract));
    REQUIRE(rohccxx::lla::can_emit_context_check_packet(contract));
}

TEST_CASE("ROHC RFC 3243 3408 and 3409 C API exposes missing assumption masks")
{
    rohccxx_lla_contract_t contract{};
    uint32_t missing = 0;
    REQUIRE(rohc_lla_validate_rfc3243_zero_byte_assumptions(&contract, &missing) == 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_PACKET_TYPE_IDENTIFICATION) != 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_IN_ORDER_DELIVERY) != 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_LOSS_INDICATION) != 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_RESIDUAL_ERROR_INDICATION) != 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_FEEDBACK_DELIVERY) != 0);
    REQUIRE(rohc_lla_can_emit_no_header_packet(&contract) == 0);

    contract = complete_c_lla_contract();
    rohccxx_lla_flow_t flow = complete_c_lla_flow();
    REQUIRE(rohc_lla_validate_rfc3243_zero_byte_assumptions(&contract, &missing) == 1);
    REQUIRE(missing == 0);
    REQUIRE(rohc_lla_validate_rfc3243_zero_byte_flow(&contract, &flow, &missing) == 1);
    REQUIRE(missing == 0);
    REQUIRE(rohc_lla_validate_rfc3408_r_mode_zero_byte_support(&contract, &missing) == 1);
    REQUIRE(missing == 0);
    REQUIRE(rohc_lla_validate_rfc3409_lower_layer_guidelines(&contract, &missing) == 1);
    REQUIRE(missing == 0);
    REQUIRE(rohc_lla_can_emit_no_header_packet(&contract) == 1);
    REQUIRE(rohc_lla_can_emit_no_header_packet_for_flow(&contract, &flow) == 1);
    REQUIRE(rohc_lla_can_emit_reliable_mode_no_header_packet(&contract) == 1);
    REQUIRE(rohc_lla_can_emit_context_synchronization_packet(&contract) == 1);
    REQUIRE(rohc_lla_can_emit_context_check_packet(&contract) == 1);

    flow.udp_checksum_disabled = 0;
    REQUIRE(rohc_lla_validate_rfc3243_zero_byte_flow(&contract, &flow, &missing) == 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_DISABLED_UDP_CHECKSUM) != 0);
    REQUIRE(rohc_lla_can_emit_no_header_packet_for_flow(&contract, &flow) == 0);

    contract.delivers_ack = 0;
    REQUIRE(rohc_lla_validate_rfc3408_r_mode_zero_byte_support(&contract, &missing) == 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_ACK_DELIVERY) != 0);
    contract.delivers_ack = 1;
    contract.supports_context_check = 0;
    REQUIRE(rohc_lla_validate_rfc3409_lower_layer_guidelines(&contract, &missing) == 0);
    REQUIRE((missing & ROHCCXX_LLA_MISSING_CONTEXT_CHECK) != 0);
}

TEST_CASE("ROHC RFC 4362 LLA profile skeleton exposes assisting-layer packet helpers")
{
    REQUIRE(static_cast<std::uint16_t>(rohccxx::Profile::LLA_RTP) == rohccxx::lla::profile_rfc4362);
    REQUIRE(rohccxx::lla::profile_rfc4362 == 0x0005);

    const std::uint8_t rohc_header[] = {0xFD, 0x05, 0xA5};
    std::uint8_t csp_wire[16] = {};
    std::size_t csp_len = sizeof(csp_wire);
    REQUIRE(rohccxx::lla::write_context_synchronization_packet(csp_wire,
                                                              &csp_len,
                                                              0x1234,
                                                              rohc_header,
                                                              sizeof(rohc_header)));
    REQUIRE(csp_len == 3U + sizeof(rohc_header));
    REQUIRE(csp_wire[0] == rohccxx::lla::packet_type_csp);
    REQUIRE(csp_wire[1] == 0x12);
    REQUIRE(csp_wire[2] == 0x34);
    REQUIRE(std::memcmp(csp_wire + 3, rohc_header, sizeof(rohc_header)) == 0);

    rohccxx::lla::ContextSynchronizationPacket csp{};
    REQUIRE(rohccxx::lla::read_context_synchronization_packet(csp_wire, csp_len, csp));
    REQUIRE(csp.rtp_payload_len == 0x1234);
    REQUIRE(csp.rohc_header == csp_wire + 3);
    REQUIRE(csp.rohc_header_len == sizeof(rohc_header));

    rohccxx::lla::ContextCheckPacket ccp{};
    ccp.has_crc = true;
    ccp.crc7 = 0x45;
    std::uint8_t ccp_wire[4] = {};
    std::size_t ccp_len = sizeof(ccp_wire);
    REQUIRE(rohccxx::lla::write_context_check_packet(ccp_wire, &ccp_len, ccp));
    REQUIRE(ccp_len == 2);
    REQUIRE(ccp_wire[0] == rohccxx::lla::packet_type_ccp);
    REQUIRE(ccp_wire[1] == 0xC5);

    rohccxx::lla::ContextCheckPacket parsed_ccp{};
    REQUIRE(rohccxx::lla::read_context_check_packet(ccp_wire, ccp_len, parsed_ccp));
    REQUIRE(parsed_ccp.has_crc);
    REQUIRE(parsed_ccp.crc7 == 0x45);

    REQUIRE(rohccxx::lla::packet_type_requires_assisting_layer(rohccxx::lla::packet_type_lower_layer_reserved));
    REQUIRE(rohccxx::lla::packet_type_requires_assisting_layer(rohccxx::lla::packet_type_csp));
    REQUIRE(rohccxx::lla::packet_type_requires_assisting_layer(rohccxx::lla::packet_type_ccp));
    REQUIRE_FALSE(rohccxx::lla::packet_type_requires_assisting_layer(0xF0));
}

TEST_CASE("ROHC framework packets expose feedback and segmentation helpers")
{
    std::uint8_t feedback_wire[16] = {};
    size_t feedback_len = sizeof(feedback_wire);
    rohccxx::Feedback static_nack{};
    static_nack.cid = 3;
    static_nack.type = rohccxx::FeedbackType::STATIC_NACK;
    REQUIRE(rohccxx::write_feedback_packet(feedback_wire, &feedback_len, static_nack));
    REQUIRE(feedback_len == 4);
    REQUIRE(feedback_wire[0] == 0xF3);
    REQUIRE(feedback_wire[1] == 0xE3);
    REQUIRE(feedback_wire[2] == 0x80);
    REQUIRE(feedback_wire[3] == 0x00);

    rohccxx::Feedback feedback{};
    REQUIRE(rohccxx::read_feedback_packet(feedback_wire, feedback_len, feedback));
    REQUIRE(feedback.cid == 3);
    REQUIRE(feedback.type == rohccxx::FeedbackType::STATIC_NACK);

    rohccxx::Feedback rich{};
    rich.cid = 2;
    rich.type = rohccxx::FeedbackType::ACK;
    rich.has_mode = true;
    rich.mode = rohccxx::Mode::Reliable;
    const std::uint8_t sn_option[] = {0x12, 0x34};
    REQUIRE(rohccxx::add_feedback_option(rich,
                                         rohccxx::FeedbackOptionType::SequenceNumber,
                                         sn_option,
                                         sizeof(sn_option)));
    feedback_len = sizeof(feedback_wire);
    REQUIRE(rohccxx::write_feedback_packet(feedback_wire, &feedback_len, rich));
    REQUIRE(feedback_len == 10);
    REQUIRE(feedback_wire[0] == 0xF0);
    REQUIRE(feedback_wire[1] == 8);
    REQUIRE(feedback_wire[2] == 0xE2);
    REQUIRE((feedback_wire[3] & 0xC0U) == 0x00U);
    REQUIRE((feedback_wire[3] & 0x20U) == 0x20U);
    REQUIRE((feedback_wire[3] & 0x10U) == 0x10U);
    REQUIRE((feedback_wire[3] & 0x03U) == static_cast<std::uint8_t>(rohccxx::Mode::Reliable));
    REQUIRE(feedback_wire[4] == 0x00);

    size_t consumed = 0;
    REQUIRE(rohccxx::read_feedback_packet(feedback_wire, feedback_len, feedback, &consumed));
    REQUIRE(consumed == feedback_len);
    REQUIRE(feedback.cid == 2);
    REQUIRE(feedback.type == rohccxx::FeedbackType::ACK);
    REQUIRE(feedback.has_mode);
    REQUIRE(feedback.mode == rohccxx::Mode::Reliable);
    REQUIRE(feedback.option_count == 1);
    REQUIRE(feedback.options[0].type == rohccxx::FeedbackOptionType::SequenceNumber);
    REQUIRE(feedback.options[0].len == 2);
    REQUIRE(feedback.options[0].value[0] == 0x12);
    REQUIRE(feedback.options[0].value[1] == 0x34);
    const size_t rich_feedback_len = feedback_len;

    rohccxx::Feedback max_cid{};
    max_cid.cid = 15;
    max_cid.type = rohccxx::FeedbackType::NACK;
    feedback_len = sizeof(feedback_wire);
    REQUIRE(rohccxx::write_feedback_packet(feedback_wire, &feedback_len, max_cid));
    REQUIRE(feedback_wire[0] == 0xF3);
    REQUIRE(feedback_wire[1] == 0xEF);
    REQUIRE((feedback_wire[2] & 0xC0U) == 0x40U);
    REQUIRE(rohccxx::read_feedback_packet(feedback_wire, feedback_len, feedback, &consumed));
    REQUIRE(consumed == feedback_len);
    REQUIRE(feedback.cid == 15);
    REQUIRE(feedback.type == rohccxx::FeedbackType::NACK);

    const std::uint8_t tiny_packet[] = {0x00, 0x45, 0x00, 0x00, 0x14};
    std::uint8_t piggybacked[16] = {};
    size_t piggybacked_len = sizeof(piggybacked);
    REQUIRE(rohccxx::write_piggybacked_feedback(piggybacked,
                                                &piggybacked_len,
                                                rich,
                                                tiny_packet,
                                                sizeof(tiny_packet)));
    REQUIRE(piggybacked_len == rich_feedback_len + sizeof(tiny_packet));
    REQUIRE(rohccxx::read_feedback_prefix(piggybacked, piggybacked_len, feedback, consumed));
    REQUIRE(consumed == rich_feedback_len);

    std::uint8_t segment_wire[4] = {};
    size_t segment_len = sizeof(segment_wire);
    REQUIRE(rohccxx::write_segment_header(segment_wire, &segment_len, {true, 0x0042}));
    REQUIRE(segment_len == 2);
    REQUIRE(segment_wire[0] == 0xFF);
    REQUIRE(segment_wire[1] == 0x42);

    rohccxx::SegmentHeader segment{};
    REQUIRE(rohccxx::read_segment_header(segment_wire, segment_len, segment));
    REQUIRE(segment.final);
    REQUIRE(segment.sequence == 0x42);

    const std::uint8_t segment_payload[] = {0xAA, 0xBB, 0xCC};
    std::uint8_t segment_packet[8] = {};
    segment_len = sizeof(segment_packet);
    REQUIRE(rohccxx::write_segment_packet(segment_packet,
                                          &segment_len,
                                          {false, 0x0043},
                                          segment_payload,
                                          sizeof(segment_payload)));
    REQUIRE(segment_len == 5);
    REQUIRE(segment_packet[0] == 0xFE);
    REQUIRE(segment_packet[1] == 0x43);
    REQUIRE(std::memcmp(segment_packet + 2, segment_payload, sizeof(segment_payload)) == 0);
}

TEST_CASE("ROHC packet parser preserves Add-CID framing for IR-family CRC coverage")
{
    uint8_t packet[] = {0xE3, 0xF8, 0x01, 0x00};
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(packet, sizeof(packet), parsed));
    REQUIRE(parsed.has_add_cid);
    REQUIRE(parsed.cid == 3);
    REQUIRE(parsed.type == rohccxx::RohcPacketType::IR_DYN);
    REQUIRE(parsed.profile_id == 0x01);
    REQUIRE(parsed.packet == packet + 1);
    REQUIRE(rohccxx::decoder_packet_start(parsed) == packet);
    REQUIRE(rohccxx::decoder_packet_len(parsed) == sizeof(packet));
}

TEST_CASE("ROHC packet parser rejects malformed packet starts")
{
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(nullptr, 1, parsed));

    uint8_t add_cid_only[] = {0xE1};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(add_cid_only, sizeof(add_cid_only), parsed));

    uint8_t unknown[] = {0x80};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(unknown, sizeof(unknown), parsed));

    uint8_t truncated_ir[] = {0xFD};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(truncated_ir, sizeof(truncated_ir), parsed));
}

TEST_CASE("ROHC RFC 4362 assisting-layer API gates opt-in configuration")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    rohccxx_lla_contract_t contract{};
    rohccxx_lla_flow_t flow{};
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) != 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) != 0);

    contract.identifies_packet_types = 1;
    contract.preserves_order = 1;
    contract.reports_loss = 1;
    contract.reports_residual_errors = 1;
    contract.delivers_feedback = 1;
    contract.protects_context_packets = 1;
    contract.supports_context_synchronization = 1;
    contract.supports_context_check = 1;
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;

    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 4362 NHP reconstructs RTP packets through assisting-layer API")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    rohccxx_lla_contract_t contract{};
    contract.identifies_packet_types = 1;
    contract.preserves_order = 1;
    contract.reports_loss = 1;
    contract.reports_residual_errors = 1;
    contract.delivers_feedback = 1;
    contract.protects_context_packets = 1;
    contract.supports_context_synchronization = 1;
    contract.supports_context_check = 1;
    rohccxx_lla_flow_t flow{};
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    std::uint8_t ip1[64] = {};
    std::uint8_t ip2[64] = {};
    std::uint8_t ip3[64] = {};
    make_valid_rtp(ip1, 1000, 16000, 0x01020304U);
    make_valid_rtp(ip2, 1001, 16160, 0x01020304U);
    make_valid_rtp(ip3, 1002, 16320, 0x01020304U);
    ip1[26] = ip2[26] = ip3[26] = 0;
    ip1[27] = ip2[27] = ip3[27] = 0;

    std::uint8_t rohc[128] = {};
    std::size_t rohc_len = sizeof(rohc);
    std::uint8_t out[128] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip1, sizeof(ip1), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip2, sizeof(ip2), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    std::uint8_t nhp[1] = {0xAA};
    std::size_t nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) == 0);
    REQUIRE(nhp_len == 0);

    out_len = sizeof(out);
    REQUIRE(rohc_decomp_rfc4362_receive_nhp(decomp, ip3 + 40, sizeof(ip3) - 40, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip3));
    REQUIRE(out[30] == ip3[30]);
    REQUIRE(out[31] == ip3[31]);
    REQUIRE(out[32] == ip3[32]);
    REQUIRE(out[35] == ip3[35]);
    REQUIRE(std::memcmp(out + 40, ip3 + 40, sizeof(ip3) - 40) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 4362 CSP and CCP synchronize and verify context")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    rohccxx_lla_contract_t contract{};
    contract.identifies_packet_types = 1;
    contract.preserves_order = 1;
    contract.reports_loss = 1;
    contract.reports_residual_errors = 1;
    contract.delivers_feedback = 1;
    contract.protects_context_packets = 1;
    contract.supports_context_synchronization = 1;
    contract.supports_context_check = 1;
    rohccxx_lla_flow_t flow{};
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 2000, 32000, 0xAABBCCDDU);
    ip[26] = 0;
    ip[27] = 0;

    std::uint8_t csp[160] = {};
    std::size_t csp_len = sizeof(csp);
    REQUIRE(rohc_comp_rfc4362_emit_csp(comp, ip, sizeof(ip), csp, &csp_len) == 0);
    REQUIRE(csp[0] == ROHCCXX_LLA_PACKET_CSP);

    std::uint8_t out[128] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decomp_rfc4362_receive_csp(decomp, csp, csp_len, out, &out_len) == 0);

    std::uint8_t ccp[8] = {};
    std::size_t ccp_len = sizeof(ccp);
    REQUIRE(rohc_comp_rfc4362_emit_ccp(comp, ccp, &ccp_len) == 0);
    REQUIRE(ccp[0] == ROHCCXX_LLA_PACKET_CCP);
    REQUIRE(rohc_decomp_rfc4362_receive_ccp(decomp, ccp, ccp_len) == 0);

    ccp[1] ^= 0x01;
    REQUIRE(rohc_decomp_rfc4362_receive_ccp(decomp, ccp, ccp_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("Context CRC covers IPv4 reconstruction state")
{
    rohccxx::Context baseline{};
    baseline.profile = rohccxx::Profile::RTP;
    baseline.cid = 4;
    baseline.ip_version = 4;
    baseline.ipv4_id = 0x1234;
    baseline.rtp.last_seq = 0x4321;

    auto changed = baseline;
    changed.ipv4_flags = 0x02;
    REQUIRE(rohccxx::detail::context_crc7(changed) !=
            rohccxx::detail::context_crc7(baseline));

    changed = baseline;
    changed.ipv4_id_sequential = true;
    REQUIRE(rohccxx::detail::context_crc7(changed) !=
            rohccxx::detail::context_crc7(baseline));
}

TEST_CASE("IPv4 fragments use uncompressed fallback and round-trip exactly")
{
    constexpr std::uint16_t cases[] = {
        0x0001, 0x2001, 0x4001, 0x6001,
        0x1FFF, 0x3FFF, 0x5FFF, 0x7FFF,
        0x2000
    };

    for(const auto flags_fragment : cases)
    {
        CAPTURE(flags_fragment);
        rohc_comp* comp = rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK);
        rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);
        REQUIRE(decomp != nullptr);

        std::uint8_t ip[64] = {};
        make_valid_rtp(ip, 100, 16000, 0x12345678U);
        set_ipv4_id_and_flags(ip, 7, flags_fragment);
        std::uint8_t rohc[128] = {};
        std::size_t rohc_len = sizeof(rohc);
        std::uint8_t out[128] = {};
        std::size_t out_len = sizeof(out);

        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0x00);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(ip));
        REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

        rohc_decomp_free(decomp);
        rohc_comp_free(comp);
    }
}

TEST_CASE("DF-only IPv4 RTP remains compressible")
{
    rohc_comp* comp = rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 100, 16000, 0x12345678U);
    set_ipv4_id_and_flags(ip, 7, 0x4000);
    std::uint8_t rohc[128] = {};
    std::size_t rohc_len = sizeof(rohc);
    std::uint8_t out[128] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] != 0x00);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("RTP-only C++ compressor rejects IPv4 fragments")
{
    constexpr std::uint16_t cases[] = {0x0001, 0x1FFF, 0x2000, 0x2001, 0x3FFF};
    for(const auto flags_fragment : cases)
    {
        CAPTURE(flags_fragment);
        rohccxx::Compressor comp(0);
        std::uint8_t ip[64] = {};
        make_valid_rtp(ip, 100, 16000, 0x12345678U);
        set_ipv4_id_and_flags(ip, 7, flags_fragment);
        std::uint8_t rohc[128] = {};
        std::size_t rohc_len = sizeof(rohc);
        REQUIRE(comp.compress(ip, sizeof(ip), rohc, &rohc_len) != 0);
    }
}

TEST_CASE("RTP sequence boundaries and wraparound round-trip exactly")
{
    const std::vector<std::vector<std::uint16_t>> runs = {
        {0xEFFF, 0xF000},
        {0xFFFE, 0xFFFF, 0x0000}
    };
    for(const auto& sequences : runs)
    {
        rohc_comp* comp = rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK);
        rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);
        REQUIRE(decomp != nullptr);
        std::uint32_t timestamp = 16000;
        for(const auto sequence : sequences)
        {
            CAPTURE(sequence);
            std::uint8_t ip[64] = {};
            make_valid_rtp(ip, sequence, timestamp, 0x12345678U);
            set_ipv4_id_and_flags(ip, sequence, 0x4000);
            std::uint8_t rohc[128] = {};
            std::size_t rohc_len = sizeof(rohc);
            std::uint8_t out[128] = {};
            std::size_t out_len = sizeof(out);
            REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
            REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
            REQUIRE(out_len == sizeof(ip));
            REQUIRE((static_cast<std::uint16_t>(out[30]) << 8U | out[31]) == sequence);
            REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);
            timestamp += 160;
        }
        rohc_decomp_free(decomp);
        rohc_comp_free(comp);
    }
}

TEST_CASE("RTP timestamps cross the high boundary and wrap with zero SSRC")
{
    constexpr std::uint32_t timestamps[] = {
        0xFFFFFE00U,
        0xFFFFFEA0U,
        0xFFFFFF40U,
        0xFFFFFFE0U,
        0x00000080U
    };
    rohc_comp* comp = rohc_comp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(0, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    std::uint16_t sequence = 0x4000;
    for(const auto timestamp : timestamps)
    {
        CAPTURE(sequence, timestamp);
        std::uint8_t ip[64] = {};
        make_valid_rtp(ip, sequence, timestamp, 0x00000000U);
        set_ipv4_id_and_flags(ip, sequence, 0x4000);
        std::uint8_t rohc[128] = {};
        std::size_t rohc_len = sizeof(rohc);
        std::uint8_t out[128] = {};
        std::size_t out_len = sizeof(out);

        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(ip));
        const auto reconstructed_timestamp =
            (static_cast<std::uint32_t>(out[32]) << 24U) |
            (static_cast<std::uint32_t>(out[33]) << 16U) |
            (static_cast<std::uint32_t>(out[34]) << 8U) |
            static_cast<std::uint32_t>(out[35]);
        const auto reconstructed_ssrc =
            (static_cast<std::uint32_t>(out[36]) << 24U) |
            (static_cast<std::uint32_t>(out[37]) << 16U) |
            (static_cast<std::uint32_t>(out[38]) << 8U) |
            static_cast<std::uint32_t>(out[39]);
        REQUIRE(reconstructed_timestamp == timestamp);
        REQUIRE(reconstructed_ssrc == 0x00000000U);
        REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);
        ++sequence;
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHC RFC 4362 assisting-layer APIs reject malformed calls and packet bodies")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    auto contract = complete_c_lla_contract();
    auto flow = complete_c_lla_flow();
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 2400, 38400, 0x0A0B0C0DU);
    ip[26] = 0;
    ip[27] = 0;

    std::uint8_t csp[160] = {};
    std::size_t csp_len = 2;
    REQUIRE(rohc_comp_rfc4362_emit_csp(comp, ip, sizeof(ip), csp, &csp_len) != 0);

    csp_len = sizeof(csp);
    REQUIRE(rohc_comp_rfc4362_emit_csp(comp, ip, sizeof(ip), csp, &csp_len) == 0);

    std::uint8_t out[128] = {};
    std::size_t out_len = sizeof(out);
    const std::uint8_t short_csp[] = {ROHCCXX_LLA_PACKET_CSP, 0x00};
    REQUIRE(rohc_decomp_rfc4362_receive_csp(decomp, short_csp, sizeof(short_csp), out, &out_len) != 0);

    out_len = sizeof(out);
    const std::uint8_t short_ccp[] = {ROHCCXX_LLA_PACKET_CCP};
    REQUIRE(rohc_decomp_rfc4362_receive_ccp(decomp, short_ccp, sizeof(short_ccp)) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    out_len = sizeof(out);
    REQUIRE(rohc_decomp_rfc4362_receive_nhp(decomp, nullptr, 1, out, &out_len) != 0);
    REQUIRE(rohc_decomp_rfc4362_receive_nhp(nullptr, nullptr, 0, out, &out_len) != 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 4362 assisted-layer APIs preserve large CID context identity")
{
    constexpr std::uint32_t cid = 31;
    rohc_comp* comp = rohc_comp_new2(cid, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(cid, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);

    auto contract = complete_c_lla_contract();
    auto flow = complete_c_lla_flow();
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    std::uint8_t ip1[64] = {};
    std::uint8_t ip2[64] = {};
    std::uint8_t ip3[64] = {};
    make_valid_rtp(ip1, 3000, 48000, 0x11121314U);
    make_valid_rtp(ip2, 3001, 48160, 0x11121314U);
    make_valid_rtp(ip3, 3002, 48320, 0x11121314U);
    ip1[26] = ip2[26] = ip3[26] = 0;
    ip1[27] = ip2[27] = ip3[27] = 0;

    std::uint8_t rohc[160] = {};
    std::size_t rohc_len = sizeof(rohc);
    std::uint8_t out[160] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip1, sizeof(ip1), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip2, sizeof(ip2), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    std::uint8_t nhp[1] = {};
    std::size_t nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) == 0);
    REQUIRE(nhp_len == 0);

    out_len = sizeof(out);
    REQUIRE(rohc_decomp_rfc4362_receive_nhp_for_cid(decomp, cid, ip3 + 40, sizeof(ip3) - 40, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip3));
    REQUIRE(out[30] == ip3[30]);
    REQUIRE(out[31] == ip3[31]);
    REQUIRE(std::memcmp(out + 40, ip3 + 40, sizeof(ip3) - 40) == 0);

    rohc_comp* csp_comp = rohc_comp_new2(cid, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* csp_decomp = rohc_decomp_new2(cid, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(csp_comp != nullptr);
    REQUIRE(csp_decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(csp_comp, cid) == 0);
    REQUIRE(rohc_comp_enable_rfc4362_lla(csp_comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(csp_decomp, &contract, &flow) == 0);

    std::uint8_t csp[200] = {};
    std::size_t csp_len = sizeof(csp);
    REQUIRE(rohc_comp_rfc4362_emit_csp(csp_comp, ip3, sizeof(ip3), csp, &csp_len) == 0);
    out_len = sizeof(out);
    REQUIRE(rohc_decomp_rfc4362_receive_csp(csp_decomp, csp, csp_len, out, &out_len) == 0);

    std::uint8_t ccp[8] = {};
    std::size_t ccp_len = sizeof(ccp);
    REQUIRE(rohc_comp_rfc4362_emit_ccp(csp_comp, ccp, &ccp_len) == 0);
    REQUIRE(rohc_decomp_rfc4362_receive_ccp_for_cid(csp_decomp, cid, ccp, ccp_len) == 0);
    REQUIRE(rohc_decomp_rfc4362_receive_ccp_for_cid(csp_decomp, 0, ccp, ccp_len) != 0);

    rohc_comp_free(csp_comp);
    rohc_decomp_free(csp_decomp);
    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 4362 R-mode NHP emission follows ACK and STATIC-NACK progression")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    auto contract = complete_c_lla_contract();
    auto flow = complete_c_lla_flow();
    REQUIRE(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) == 0);
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);
    REQUIRE(rohc_comp_set_mode(comp, ROHCCXX_MODE_R) == 0);
    REQUIRE(rohc_decomp_set_mode(decomp, ROHCCXX_MODE_R) == 0);

    std::uint8_t ip1[64] = {};
    std::uint8_t ip2[64] = {};
    std::uint8_t ip3[64] = {};
    make_valid_rtp(ip1, 4000, 64000, 0x51525354U);
    make_valid_rtp(ip2, 4001, 64160, 0x51525354U);
    make_valid_rtp(ip3, 4002, 64320, 0x51525354U);
    ip1[26] = ip2[26] = ip3[26] = 0;
    ip1[27] = ip2[27] = ip3[27] = 0;

    std::uint8_t rohc[160] = {};
    std::size_t rohc_len = sizeof(rohc);
    std::uint8_t out[160] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip1, sizeof(ip1), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    std::uint8_t nhp[1] = {};
    std::size_t nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip2, sizeof(ip2), nhp, &nhp_len) != 0);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::ACK));
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip2, sizeof(ip2), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) != 0);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::ACK));
    nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) == 0);

    rohc_comp_handle_feedback(comp, 0, static_cast<std::uint8_t>(rohccxx::FeedbackType::STATIC_NACK));
    nhp_len = sizeof(nhp);
    REQUIRE(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) != 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 4362 native C++ wrappers expose assisted runtime operations")
{
    rohccxx::Compressor comp(0, 4);
    rohccxx::Decompressor decomp(0, 4);
    const auto contract = complete_cpp_lla_contract();
    const auto flow = complete_cpp_lla_flow();
    REQUIRE(comp.enable_rfc4362_lla(contract, flow));
    REQUIRE(decomp.enable_rfc4362_lla(contract, flow));

    std::uint8_t ip1[64] = {};
    std::uint8_t ip2[64] = {};
    std::uint8_t ip3[64] = {};
    make_valid_rtp(ip1, 5000, 80000, 0x61626364U);
    make_valid_rtp(ip2, 5001, 80160, 0x61626364U);
    make_valid_rtp(ip3, 5002, 80320, 0x61626364U);
    ip1[26] = ip2[26] = ip3[26] = 0;
    ip1[27] = ip2[27] = ip3[27] = 0;

    std::uint8_t rohc[160] = {};
    std::size_t rohc_len = sizeof(rohc);
    std::uint8_t out[160] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(comp.compress(ip1, sizeof(ip1), rohc, &rohc_len) == 0);
    REQUIRE(decomp.decompress(rohc, rohc_len, out, &out_len) == 0);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(comp.compress(ip2, sizeof(ip2), rohc, &rohc_len) == 0);
    REQUIRE(decomp.decompress(rohc, rohc_len, out, &out_len) == 0);

    std::uint8_t nhp[1] = {};
    std::size_t nhp_len = sizeof(nhp);
    REQUIRE(comp.rfc4362_emit_nhp(ip3, sizeof(ip3), nhp, &nhp_len) == 0);
    REQUIRE(nhp_len == 0);
    out_len = sizeof(out);
    REQUIRE(decomp.rfc4362_receive_nhp(ip3 + 40, sizeof(ip3) - 40, out, &out_len) == 0);
    REQUIRE(out[30] == ip3[30]);
    REQUIRE(out[31] == ip3[31]);

    std::uint8_t ccp[8] = {};
    std::size_t ccp_len = sizeof(ccp);
    REQUIRE(comp.rfc4362_emit_ccp(ccp, &ccp_len) == 0);
    REQUIRE(decomp.rfc4362_receive_ccp(ccp, ccp_len) == 0);
}

TEST_CASE("ROHC RFC 4362 lower-layer loss and residual error signals produce feedback")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    rohccxx_lla_contract_t contract{};
    contract.identifies_packet_types = 1;
    contract.preserves_order = 1;
    contract.reports_loss = 1;
    contract.reports_residual_errors = 1;
    contract.delivers_feedback = 1;
    contract.protects_context_packets = 1;
    contract.supports_context_synchronization = 1;
    contract.supports_context_check = 1;
    rohccxx_lla_flow_t flow{};
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;
    REQUIRE(rohc_decomp_enable_rfc4362_lla(decomp, &contract, &flow) == 0);

    REQUIRE(rohc_decomp_rfc4362_report_loss(decomp, 0) == 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);
    std::uint32_t cid = 99;
    std::uint8_t type = 99;
    REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &type) == 0);
    REQUIRE(cid == 0);
    REQUIRE(type == 0);

    REQUIRE(rohc_decomp_rfc4362_report_residual_error(decomp, 0) == 0);
    REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &type) == 0);
    REQUIRE(type == 1);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor rejects RFC 4362 LLA packets without assisting-layer negotiation")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    const std::uint8_t csp[] = {rohccxx::lla::packet_type_csp, 0x00, 0x10, 0xFD, 0x05};
    REQUIRE(rohc_decompress4(decomp, csp, sizeof(csp), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    out_len = sizeof(out);
    const std::uint8_t ccp[] = {rohccxx::lla::packet_type_ccp, 0x85};
    REQUIRE(rohc_decompress4(decomp, ccp, sizeof(ccp), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor gates framework feedback and segmentation packets")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    rohccxx::Feedback feedback{};
    feedback.type = rohccxx::FeedbackType::ACK;
    std::uint8_t feedback_wire[8] = {};
    size_t feedback_len = sizeof(feedback_wire);
    REQUIRE(rohccxx::write_feedback_packet(feedback_wire, &feedback_len, feedback));
    REQUIRE(rohc_decompress4(decomp, feedback_wire, feedback_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 0);

    const std::uint8_t segment[] = {0xFE, 0x00};
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, segment, sizeof(segment), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC RFC 5795 segmentation requires negotiated MRRU")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 5100, 90000, 0xA0B0C0D0U);

    std::uint8_t rohc[8] = {};
    std::size_t rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) != 0);

    REQUIRE(rohc_comp_set_mrru(comp, 256) == 0);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFE);

    std::uint8_t out[64] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 5795 segmentation reassembles negotiated streams")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_mrru(comp, 256) == 0);
    REQUIRE(rohc_decomp_set_mrru(decomp, 256) == 0);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 5200, 90160, 0x10293847U);

    std::vector<std::vector<std::uint8_t>> segments;
    std::uint8_t first_segment[8] = {};
    std::size_t first_segment_len = sizeof(first_segment);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), first_segment, &first_segment_len) == 0);
    REQUIRE(first_segment[0] == 0xFE);
    segments.emplace_back(first_segment, first_segment + first_segment_len);

    while(rohc_comp_has_segment(comp) == 1)
    {
        std::uint8_t segment[8] = {};
        std::size_t segment_len = sizeof(segment);
        REQUIRE(rohc_comp_get_segment(comp, segment, &segment_len) == 0);
        segments.emplace_back(segment, segment + segment_len);
    }
    REQUIRE(segments.size() > 2);

    std::uint8_t out[64] = {};
    for(std::size_t i = 0; i + 1 < segments.size(); ++i)
    {
        std::size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, segments[i].data(), segments[i].size(), out, &out_len) == 1);
        REQUIRE(rohc_decomp_has_feedback(decomp) == 0);
    }

    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, segments.back().data(), segments.back().size(), out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC RFC 5795 segmentation rejects malformed streams and recovers")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_mrru(comp, 256) == 0);
    REQUIRE(rohc_decomp_set_mrru(decomp, 256) == 0);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 5300, 90320, 0x31415926U);

    std::vector<std::vector<std::uint8_t>> segments;
    std::uint8_t first_segment[8] = {};
    std::size_t first_segment_len = sizeof(first_segment);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), first_segment, &first_segment_len) == 0);
    segments.emplace_back(first_segment, first_segment + first_segment_len);
    while(rohc_comp_has_segment(comp) == 1)
    {
        std::uint8_t segment[8] = {};
        std::size_t segment_len = sizeof(segment);
        REQUIRE(rohc_comp_get_segment(comp, segment, &segment_len) == 0);
        segments.emplace_back(segment, segment + segment_len);
    }
    REQUIRE(segments.size() > 2);

    std::uint8_t out[64] = {};
    std::size_t out_len = sizeof(out);
    auto bad_first = segments.front();
    bad_first[1] = 1;
    REQUIRE(rohc_decompress4(decomp, bad_first.data(), bad_first.size(), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, segments[0].data(), segments[0].size(), out, &out_len) == 1);
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, segments[2].data(), segments[2].size(), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    REQUIRE(rohc_decomp_set_mrru(decomp, 4) == 0);
    const std::uint8_t oversized[] = {0xFF, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, oversized, sizeof(oversized), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);
    REQUIRE(rohc_decomp_set_mrru(decomp, 256) == 0);

    for(std::size_t i = 0; i + 1 < segments.size(); ++i)
    {
        out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, segments[i].data(), segments[i].size(), out, &out_len) == 1);
    }
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, segments.back().data(), segments.back().size(), out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHC decompressor skips interspersed feedback before compressed payload")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    rohccxx::Feedback feedback{};
    feedback.cid = 0;
    feedback.type = rohccxx::FeedbackType::ACK;
    feedback.has_mode = true;
    feedback.mode = rohccxx::Mode::Reliable;

    std::uint8_t uncompressed[21] = {};
    uncompressed[0] = 0x00;
    uncompressed[1] = 0x45;
    uncompressed[3] = 0x00;
    uncompressed[4] = 0x14;

    std::uint8_t packet[64] = {};
    size_t packet_len = sizeof(packet);
    REQUIRE(rohccxx::write_piggybacked_feedback(packet, &packet_len, feedback, uncompressed, sizeof(uncompressed)));

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, packet, packet_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(uncompressed) - 1U);
    REQUIRE(out[0] == 0x45);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor selects Add-CID context for IR packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::UDP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_tos = 0x22;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x1234;
    ctx.ipv4_flags = 0;
    ctx.ipv4_protocol = 17;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 12;
    ctx.udp_check = 0x9ABC;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_udp(rohc, &rohc_len, ctx));
    REQUIRE(rohc[0] == 0xE3);

    const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    REQUIRE(rohc_len + sizeof(payload) <= sizeof(rohc));
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 32);

    std::uint8_t expected[32] = {};
    expected[0] = 0x45;
    expected[1] = ctx.ipv4_tos;
    expected[2] = 0x00;
    expected[3] = 0x20;
    expected[4] = 0x12;
    expected[5] = 0x34;
    expected[8] = ctx.ipv4_ttl;
    expected[9] = ctx.ipv4_protocol;
    expected[12] = 192;
    expected[13] = 0;
    expected[14] = 2;
    expected[15] = 1;
    expected[16] = 198;
    expected[17] = 51;
    expected[18] = 100;
    expected[19] = 2;
    const std::uint16_t csum = checksum_ipv4_header(expected, 20);
    expected[10] = static_cast<std::uint8_t>(csum >> 8);
    expected[11] = static_cast<std::uint8_t>(csum & 0xFF);
    expected[20] = 0x12;
    expected[21] = 0x34;
    expected[22] = 0x56;
    expected[23] = 0x78;
    expected[24] = 0x00;
    expected[25] = 0x0C;
    expected[26] = 0x9A;
    expected[27] = 0xBC;
    std::memcpy(expected + 28, payload, sizeof(payload));

    REQUIRE(std::memcmp(out, expected, sizeof(expected)) == 0);

    rohc_decomp_free(decomp);
}




TEST_CASE("ROHC decompressor selects Add-CID context for IR-DYN packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::UDP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_protocol = 17;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 12;
    ctx.udp_check = 0x9ABC;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_udp(rohc, &rohc_len, ctx));

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    ctx.ipv4_tos = 0x11;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x2345;
    ctx.udp_check = 0x4567;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_dyn_udp(rohc, &rohc_len, ctx));
    REQUIRE(rohc[0] == 0xE3);
    REQUIRE(rohc[1] == 0xF8);

    const std::uint8_t payload[] = {0xAA, 0xBB, 0xCC, 0xDD};
    REQUIRE(rohc_len + sizeof(payload) <= sizeof(rohc));
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 32);
    REQUIRE(out[1] == 0x11);
    REQUIRE(out[4] == 0x23);
    REQUIRE(out[5] == 0x45);
    REQUIRE(out[8] == 63);
    REQUIRE(out[26] == 0x45);
    REQUIRE(out[27] == 0x67);
    REQUIRE(std::memcmp(out + 28, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor rejects Add-CID outside configured context table")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::UDP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_protocol = 17;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 8;
    ctx.udp_check = 0x9ABC;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_udp(rohc, &rohc_len, ctx));
    REQUIRE(rohc[0] == 0xE3);

    rohc_decomp* decomp = rohc_decomp_new2(1, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    std::uint32_t cid = 0;
    std::uint8_t feedback = 0;
    REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &feedback) == 0);
    REQUIRE(cid == 3);
    REQUIRE(feedback == 0);

    rohc_decomp_free(decomp);
}




TEST_CASE("ROHC packet parser identifies Add-CID FO packet families")
{
    rohccxx::ParsedRohcPacket parsed{};

    std::uint8_t udp[] = {0xE3, 0x7A, 0x00, 0x00, 0x01, 0x00, 0x02};
    REQUIRE(rohccxx::parse_rohc_packet(udp, sizeof(udp), parsed));
    REQUIRE(parsed.has_add_cid);
    REQUIRE(parsed.cid == 3);
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_UDP);
    REQUIRE(parsed.packet == udp + 1);
    REQUIRE(rohccxx::decoder_packet_start(parsed) == udp + 1);

    std::uint8_t ip[] = {0xE3, 0x79, 0x00, 0x00, 0x01};
    REQUIRE(rohccxx::parse_rohc_packet(ip, sizeof(ip), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_IP);

    std::uint8_t esp[] = {0xE3, 0x78, 0x00, 0x00, 0x01};
    REQUIRE(rohccxx::parse_rohc_packet(esp, sizeof(esp), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_ESP);

    std::uint8_t udp_lite[] = {0xE3, 0x77, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x02};
    REQUIRE(rohccxx::parse_rohc_packet(udp_lite, sizeof(udp_lite), parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_UDP_Lite);
}

TEST_CASE("ROHC decompressor selects Add-CID context for UDP FO packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::UDP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_protocol = 17;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_check = 0x1111;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_udp(rohc, &rohc_len, ctx));

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);
    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    ctx.ipv4_id = 0x3456;
    ctx.udp_check = 0x789A;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_udp_fo(rohc, &rohc_len, ctx));
    prepend_add_cid(3, rohc, rohc_len);
    const std::uint8_t payload[] = {0xCA, 0xFE, 0xBA, 0xBE};
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 32);
    require_ip_header_id(out, 0x3456);
    REQUIRE(out[26] == 0x78);
    REQUIRE(out[27] == 0x9A);
    REQUIRE(std::memcmp(out + 28, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor selects Add-CID context for IP-only FO packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::IP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_protocol = 6;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_ip(rohc, &rohc_len, ctx));

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);
    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    ctx.ipv4_id = 0x4567;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ip_fo(rohc, &rohc_len, ctx));
    prepend_add_cid(3, rohc, rohc_len);
    const std::uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 24);
    require_ip_header_id(out, 0x4567);
    REQUIRE(std::memcmp(out + 20, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor selects Add-CID context for ESP FO packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::ESP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_protocol = 50;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_esp(rohc, &rohc_len, ctx));

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);
    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    ctx.ipv4_id = 0x5678;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_esp_fo(rohc, &rohc_len, ctx));
    prepend_add_cid(3, rohc, rohc_len);
    const std::uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 24);
    require_ip_header_id(out, 0x5678);
    REQUIRE(out[9] == 50);
    REQUIRE(std::memcmp(out + 20, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor selects Add-CID context for UDP-Lite FO packets")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::UDP_Lite;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_protocol = 136;
    ctx.ipv4_ttl = 64;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 0x0010;
    ctx.udp_check = 0x1111;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_udp_lite(rohc, &rohc_len, ctx));

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);
    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    ctx.ipv4_id = 0x6789;
    ctx.udp_length_or_coverage = 0x0014;
    ctx.udp_check = 0x89AB;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_udp_lite_fo(rohc, &rohc_len, ctx));
    prepend_add_cid(3, rohc, rohc_len);
    const std::uint8_t payload[] = {0x55, 0x66, 0x77, 0x88};
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 32);
    require_ip_header_id(out, 0x6789);
    REQUIRE(out[24] == 0x00);
    REQUIRE(out[25] == 0x14);
    REQUIRE(out[26] == 0x89);
    REQUIRE(out[27] == 0xAB);
    REQUIRE(std::memcmp(out + 28, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor rejects out-of-range Add-CID FO packets")
{
    std::uint8_t rohc[] = {0xE3, 0x79, 0x00, 0x12, 0x34};
    rohc_decomp* decomp = rohc_decomp_new2(1, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, sizeof(rohc), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    std::uint32_t cid = 0;
    std::uint8_t feedback = 0;
    REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &feedback) == 0);
    REQUIRE(cid == 3);
    REQUIRE(feedback == 0);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC decompressor reports Add-CID context on malformed FO feedback")
{
    std::uint8_t rohc[] = {0xE3, 0x7A, 0x00, 0x12, 0x34, 0x56};
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, sizeof(rohc), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    std::uint32_t cid = 0;
    std::uint8_t feedback = 0xFF;
    REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &feedback) == 0);
    REQUIRE(cid == 3);
    REQUIRE(feedback == 0);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC decompressor explicitly rejects unsupported framework packet starts")
{
    const std::uint8_t segment[] = {0xFE, 0x00};
    const std::uint8_t feedback_packet[] = {0xF2, 0x00, 0x00};
    const std::uint8_t add_cid_segment[] = {0xE3, 0xFE, 0x00};
    const std::uint8_t add_cid_feedback[] = {0xF3, 0xE3, 0x00, 0x00};

    struct Case
    {
        const char* name;
        const std::uint8_t* packet;
        size_t len;
        std::uint32_t expected_cid;
        bool expect_feedback;
    };

    const Case cases[] = {
        {"segment", segment, sizeof(segment), 0, true},
        {"feedback", feedback_packet, sizeof(feedback_packet), 0, false},
        {"add-cid segment", add_cid_segment, sizeof(add_cid_segment), 3, true},
        {"add-cid feedback", add_cid_feedback, sizeof(add_cid_feedback), 3, false},
    };

    for(const Case& item : cases)
    {
        CAPTURE(item.name);
        rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(decomp != nullptr);

        std::uint8_t out[64] = {};
        size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, item.packet, item.len, out, &out_len) != 0);
        REQUIRE(rohc_decomp_has_feedback(decomp) == (item.expect_feedback ? 1 : 0));

        if(item.expect_feedback)
        {
            std::uint32_t cid = 0xFFFFFFFFu;
            std::uint8_t feedback = 0xFF;
            REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &feedback) == 0);
            REQUIRE(cid == item.expected_cid);
            REQUIRE(feedback == 0);
        }

        rohc_decomp_free(decomp);
    }
}

TEST_CASE("ROHC decompressor clears stale feedback after successful packet")
{
    std::uint8_t bad[] = {0xE3, 0x7A, 0x00, 0x12, 0x34, 0x56};
    std::uint8_t good[21] = {};
    good[0] = 0x00;
    good[1] = 0x45;
    good[3] = 0x00;
    good[4] = 0x14;

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, bad, sizeof(bad), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, good, sizeof(good), out, &out_len) == 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 0);
    REQUIRE(out_len == sizeof(good) - 1U);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC decompressor reports feedback on output buffer exhaustion")
{
    struct Case
    {
        const char* name;
        std::uint32_t expected_cid;
        std::uint8_t packet[128];
        size_t len;
    };

    Case cases[6] = {
        {"uncompressed", 0, {}, 0},
        {"rtp", 3, {}, 0},
        {"udp", 3, {}, 0},
        {"ip", 3, {}, 0},
        {"esp", 3, {}, 0},
        {"udp-lite", 3, {}, 0},
    };

    cases[0].packet[0] = 0x00;
    cases[0].packet[1] = 0x45;
    cases[0].packet[3] = 0x00;
    cases[0].packet[4] = 0x14;
    cases[0].len = 21;

    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_tos = 0x22;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x1234;
    ctx.ipv4_flags = 0;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 0x0010;
    ctx.udp_check = 0x9ABC;
    ctx.rtp.vpxcc = 0x80;
    ctx.rtp.mpt = 0x60;
    ctx.rtp.last_seq = 0x2234;
    ctx.rtp.last_ts = 0x01020304;
    ctx.rtp.ssrc = 0x11223344;

    ctx.profile = rohccxx::Profile::RTP;
    ctx.ipv4_protocol = 17;
    cases[1].len = sizeof(cases[1].packet);
    REQUIRE(rohccxx::emit_ir_rtp(cases[1].packet, &cases[1].len, ctx));

    ctx.profile = rohccxx::Profile::UDP;
    ctx.ipv4_protocol = 17;
    cases[2].len = sizeof(cases[2].packet);
    REQUIRE(rohccxx::emit_ir_udp(cases[2].packet, &cases[2].len, ctx));

    ctx.profile = rohccxx::Profile::IP;
    ctx.ipv4_protocol = 6;
    cases[3].len = sizeof(cases[3].packet);
    REQUIRE(rohccxx::emit_ir_ip(cases[3].packet, &cases[3].len, ctx));

    ctx.profile = rohccxx::Profile::ESP;
    ctx.ipv4_protocol = 50;
    cases[4].len = sizeof(cases[4].packet);
    REQUIRE(rohccxx::emit_ir_esp(cases[4].packet, &cases[4].len, ctx));

    ctx.profile = rohccxx::Profile::UDP_Lite;
    ctx.ipv4_protocol = 136;
    cases[5].len = sizeof(cases[5].packet);
    REQUIRE(rohccxx::emit_ir_udp_lite(cases[5].packet, &cases[5].len, ctx));

    for(const Case& item : cases)
    {
        CAPTURE(item.name);
        rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(decomp != nullptr);

        std::uint8_t out[1] = {};
        size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, item.packet, item.len, out, &out_len) != 0);
        REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

        std::uint32_t cid = 0xFFFFFFFFu;
        std::uint8_t feedback = 0xFF;
        REQUIRE(rohc_decomp_get_feedback(decomp, &cid, &feedback) == 0);
        REQUIRE(cid == item.expected_cid);
        REQUIRE(feedback == 0);

        rohc_decomp_free(decomp);
    }
}



TEST_CASE("ROHC decompressor selects embedded RTP FO CID context")
{
    rohccxx::Context ctx{};
    ctx.cid = 3;
    ctx.profile = rohccxx::Profile::RTP;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_tos = 0x22;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x1234;
    ctx.ipv4_flags = 0;
    ctx.ipv4_protocol = 17;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_check = 0x9ABC;
    ctx.rtp.vpxcc = 0x80;
    ctx.rtp.mpt = 0x60;
    ctx.rtp.last_seq = 0x2234;
    ctx.rtp.last_ts = 0x01020304;
    ctx.rtp.ssrc = 0x11223344;

    std::uint8_t rohc[128] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_ir_rtp(rohc, &rohc_len, ctx));
    REQUIRE(rohc[0] == 0xE3);
    REQUIRE(rohc[1] == 0xFD);

    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[128] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 40);
    REQUIRE(out[30] == 0x22);
    REQUIRE(out[31] == 0x34);
    REQUIRE(out[32] == 0x01);
    REQUIRE(out[33] == 0x02);
    REQUIRE(out[34] == 0x03);
    REQUIRE(out[35] == 0x04);

    ctx.rtp.last_seq = 0x2235;
    ctx.rtp.last_ts = 0x01020318;
    rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_rtp_fo(rohc, &rohc_len, ctx));
    REQUIRE(((rohc[0] >> 2) & 0x0F) == 3);
    const std::uint8_t payload[] = {0xCA, 0xFE, 0xBA, 0xBE};
    std::memcpy(rohc + rohc_len, payload, sizeof(payload));
    rohc_len += sizeof(payload);

    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == 44);
    REQUIRE(out[30] == 0x22);
    REQUIRE(out[31] == 0x35);
    REQUIRE(out[32] == 0x01);
    REQUIRE(out[33] == 0x02);
    REQUIRE(out[34] == 0x03);
    REQUIRE(out[35] == 0x18);
    REQUIRE(std::memcmp(out + 40, payload, sizeof(payload)) == 0);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC FO decoders reject short profile-specific packets")
{
    rohccxx::Context ctx{};
    size_t consumed = 0;

    const std::uint8_t short_udp[] = {0x7A, 0x00, 0x12, 0x34, 0x56};
    REQUIRE_FALSE(rohccxx::decode_udp_fo(short_udp, sizeof(short_udp), ctx, &consumed));

    const std::uint8_t short_ip[] = {0x79, 0x00, 0x12};
    REQUIRE_FALSE(rohccxx::decode_ip_fo(short_ip, sizeof(short_ip), ctx, &consumed));

    const std::uint8_t short_esp[] = {0x78, 0x00, 0x12};
    REQUIRE_FALSE(rohccxx::decode_esp_fo(short_esp, sizeof(short_esp), ctx, &consumed));

    const std::uint8_t short_udp_lite[] = {0x77, 0x00, 0x12, 0x34, 0x00, 0x10, 0x56};
    REQUIRE_FALSE(rohccxx::decode_udp_lite_fo(short_udp_lite, sizeof(short_udp_lite), ctx, &consumed));
}

TEST_CASE("ROHC decompressor rejects malformed FO packet families with feedback")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    const std::uint8_t packets[][7] = {
        {0x7A, 0x00, 0x12, 0x34, 0x56, 0x00, 0x00},
        {0x79, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00},
        {0x78, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00},
        {0x77, 0x00, 0x12, 0x34, 0x00, 0x10, 0x56},
        {0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00}
    };
    const size_t lengths[] = {5, 3, 3, 7, 4};

    for(size_t i = 0; i < 5; ++i)
    {
        std::uint8_t out[64] = {};
        size_t out_len = sizeof(out);
        REQUIRE(rohc_decompress4(decomp, packets[i], lengths[i], out, &out_len) != 0);
        REQUIRE(rohc_decomp_has_feedback(decomp) == 1);
    }

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC packet parser rejects malformed Add-CID FO starts")
{
    rohccxx::ParsedRohcPacket parsed{};

    const std::uint8_t add_cid_only[] = {0xE3};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(add_cid_only, sizeof(add_cid_only), parsed));

    const std::uint8_t add_cid_unknown[] = {0xE3, 0x80};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(add_cid_unknown, sizeof(add_cid_unknown), parsed));
}

TEST_CASE("ROHC decompressor rejects unknown IR profile identifiers")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);

    const std::uint8_t unknown_ir[] = {0xFD, 0x09, 0x00, 0x00};
    REQUIRE(rohc_decompress4(decomp, unknown_ir, sizeof(unknown_ir), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
}

TEST_CASE("ROHC decompressor rejects unknown IR-DYN profile identifiers")
{
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(decomp != nullptr);

    std::uint8_t out[64] = {};
    size_t out_len = sizeof(out);

    const std::uint8_t unknown_ir_dyn[] = {0xF8, 0x09, 0x00, 0x00};
    REQUIRE(rohc_decompress4(decomp, unknown_ir_dyn, sizeof(unknown_ir_dyn), out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
}


TEST_CASE("ROHC compressor emits selected nonzero CID across UDP IR IR-DYN and FO")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 3) == 0);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    std::uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    ip[0] = 0x45;
    ip[2] = 0x00;
    ip[3] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[20] = 0x12;
    ip[21] = 0x34;
    ip[22] = 0x56;
    ip[23] = 0x78;
    ip[24] = 0x00;
    ip[25] = 0x2C;
    ip[26] = 0x11;
    ip[27] = 0x11;
    ip[28] = 0x11;
    std::uint16_t csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xE3);
    REQUIRE(rohc[1] == 0xFD);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    ip[4] = 0x12;
    ip[5] = 0x34;
    ip[26] = 0x22;
    ip[27] = 0x22;
    ip[28] = 0x22;
    ip[10] = 0x00;
    ip[11] = 0x00;
    csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xE3);
    REQUIRE(rohc[1] == 0xF8);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    ip[4] = 0x23;
    ip[5] = 0x45;
    ip[26] = 0x33;
    ip[27] = 0x33;
    ip[28] = 0x33;
    ip[10] = 0x00;
    ip[11] = 0x00;
    csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xE3);
    REQUIRE(rohc[1] == 0x7A);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC compressor rejects CID selection outside configured context table")
{
    rohc_comp* comp = rohc_comp_new2(1, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 2) != 0);
    REQUIRE(rohc_comp_set_cid(comp, 1) == 0);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC compressor accepts large CID selection when channel is configured for large CIDs")
{
    rohc_comp* comp = rohc_comp_new2(16, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 15) == 0);
    REQUIRE(rohc_comp_set_cid(comp, 16) == 0);
    REQUIRE(rohc_comp_set_cid(comp, rohccxx::cid::large_cid_max) != 0);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC large CID SDVL helper encodes one and two octet channel CIDs")
{
    std::uint8_t out[4] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::cid::write_large(p, out + sizeof(out), 0x7F));
    REQUIRE(static_cast<size_t>(p - out) == 1);
    REQUIRE(out[0] == 0x7F);

    std::uint32_t value = 0;
    size_t consumed = 0;
    REQUIRE(rohccxx::cid::read_large(out, 1, value, consumed));
    REQUIRE(value == 0x7F);
    REQUIRE(consumed == 1);

    p = out;
    REQUIRE(rohccxx::cid::write_large(p, out + sizeof(out), 0x1234));
    REQUIRE(static_cast<size_t>(p - out) == 2);
    REQUIRE(out[0] == 0x92);
    REQUIRE(out[1] == 0x34);
    REQUIRE(rohccxx::cid::read_large(out, 2, value, consumed));
    REQUIRE(value == 0x1234);
    REQUIRE(consumed == 2);

    const std::uint8_t invalid_too_long[] = {0xC0, 0x00, 0x00};
    REQUIRE_FALSE(rohccxx::cid::read_large(invalid_too_long, sizeof(invalid_too_long), value, consumed));

    const std::uint8_t truncated_two_octet[] = {0x92};
    REQUIRE_FALSE(rohccxx::cid::read_large(truncated_two_octet, sizeof(truncated_two_octet), value, consumed));
}

TEST_CASE("ROHC packet parser identifies large-CID IR and FO framing")
{
    std::uint8_t ir[] = {0xFD, 0x92, 0x34, 0x02, 0x00};
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(ir, sizeof(ir), parsed, true));
    REQUIRE(parsed.has_large_cid);
    REQUIRE(parsed.cid == 0x1234);
    REQUIRE(parsed.cid_len == 2);
    REQUIRE(parsed.type == rohccxx::RohcPacketType::IR);
    REQUIRE(parsed.profile_id == 0x02);
    REQUIRE(parsed.packet == ir);

    std::uint8_t fo[] = {0x7A, 0x92, 0x34, 0x00, 0x12, 0x34, 0x56, 0x78};
    REQUIRE(rohccxx::parse_rohc_packet(fo, sizeof(fo), parsed, true));
    REQUIRE(parsed.has_large_cid);
    REQUIRE(parsed.cid == 0x1234);
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_UDP);

    std::uint8_t truncated_ir_cid[] = {0xFD, 0x92};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(truncated_ir_cid, sizeof(truncated_ir_cid), parsed, true));

    std::uint8_t invalid_ir_cid[] = {0xFD, 0xC0, 0x00, 0x02};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(invalid_ir_cid, sizeof(invalid_ir_cid), parsed, true));

    std::uint8_t truncated_fo_cid[] = {0x7A, 0x92};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(truncated_fo_cid, sizeof(truncated_fo_cid), parsed, true));
}


TEST_CASE("ROHC large-CID RTP channel round-trips IR IR-DYN and FO packets")
{
    rohc_comp* comp = rohc_comp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 0x1234) == 0);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    std::uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(ip, 0x2345, 0x01020304, 0x11223344);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc[3] == 0x01);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    make_valid_rtp(ip, 0x2346, 0x01020305, 0x11223344);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc[3] == 0x01);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    make_valid_rtp(ip, 0x2347, 0x01020306, 0x11223344);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE((rohc[0] & 0x80) == 0x00);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ROHC large-CID UDP channel round-trips IR IR-DYN and FO packets")
{
    rohc_comp* comp = rohc_comp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 0x1234) == 0);

    std::uint8_t ip[64] = {};
    std::uint8_t rohc[128] = {};
    std::uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    ip[0] = 0x45;
    ip[2] = 0x00;
    ip[3] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[12] = 192;
    ip[15] = 1;
    ip[16] = 198;
    ip[17] = 51;
    ip[18] = 100;
    ip[19] = 2;
    ip[20] = 0x12;
    ip[21] = 0x34;
    ip[22] = 0x56;
    ip[23] = 0x78;
    ip[24] = 0x00;
    ip[25] = 0x2C;
    ip[26] = 0x11;
    ip[27] = 0x11;
    ip[28] = 0x11;
    std::uint16_t csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc[3] == 0x02);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    ip[4] = 0x12;
    ip[5] = 0x34;
    ip[26] = 0x22;
    ip[27] = 0x22;
    ip[28] = 0x22;
    ip[10] = 0x00;
    ip[11] = 0x00;
    csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc[3] == 0x02);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    ip[4] = 0x23;
    ip[5] = 0x45;
    ip[26] = 0x33;
    ip[27] = 0x33;
    ip[28] = 0x33;
    ip[10] = 0x00;
    ip[11] = 0x00;
    csum = checksum_ipv4_header(ip, 20);
    ip[10] = static_cast<std::uint8_t>(csum >> 8);
    ip[11] = static_cast<std::uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0x7A);
    REQUIRE(rohc[1] == 0x92);
    REQUIRE(rohc[2] == 0x34);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHC large-CID channels round-trip remaining compressed profiles")
{
    struct Case
    {
        const char* name;
        rohccxx::Profile profile;
        std::uint8_t ir_profile_id;
        std::uint8_t fo_type;
        bool with_udp;
        bool with_rtp;
        std::uint8_t protocol;
    };

    const Case cases[] = {
        {"ip", rohccxx::Profile::IP, 0x04, 0x79, false, false, 6},
        {"esp", rohccxx::Profile::ESP, 0x03, 0x78, false, false, 50},
        {"udp-lite", rohccxx::Profile::UDP_Lite, 0x08, 0x77, true, false, 136},
        {"rtp-udp-lite", rohccxx::Profile::RTP_UDP_Lite, 0x07, 0x00, true, true, 136},
    };

    for(const auto& item : cases)
    {
        CAPTURE(item.name);
        rohc_comp* comp = rohc_comp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
        rohc_decomp* decomp = rohc_decomp_new2(0x1234, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);
        REQUIRE(decomp != nullptr);
        REQUIRE(rohc_comp_set_cid(comp, 0x1234) == 0);

        std::uint8_t ip[64] = {};
        std::uint8_t rohc[128] = {};
        std::uint8_t out[128] = {};
        size_t rohc_len = sizeof(rohc);
        size_t out_len = sizeof(out);

        if(item.with_udp)
            make_valid_udp_family_packet(ip, item.protocol, 0x1201, 0x1111, item.with_rtp);
        else
            make_valid_ip_packet(ip, item.protocol, 0x1201);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xFD);
        REQUIRE(rohc[1] == 0x92);
        REQUIRE(rohc[2] == 0x34);
        REQUIRE(rohc[3] == item.ir_profile_id);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(ip));
        REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

        if(item.with_udp)
            make_valid_udp_family_packet(ip, item.protocol, 0x1202, item.with_rtp ? 0x1111 : 0x2222, item.with_rtp);
        else
            make_valid_ip_packet(ip, item.protocol, 0x1202);
        rohc_len = sizeof(rohc);
        out_len = sizeof(out);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        REQUIRE(rohc[0] == 0xF8);
        REQUIRE(rohc[1] == 0x92);
        REQUIRE(rohc[2] == 0x34);
        REQUIRE(rohc[3] == item.ir_profile_id);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

        if(item.with_udp)
        {
            make_valid_udp_family_packet(ip, item.protocol, 0x1203, item.with_rtp ? 0x1111 : 0x3333, item.with_rtp);
            if(item.with_rtp)
            {
                ip[4] = 0x12;
                ip[5] = 0x02;
                finish_ipv4_checksum(ip);
            }
        }
        else
        {
            make_valid_ip_packet(ip, item.protocol, 0x1203);
        }
        rohc_len = sizeof(rohc);
        out_len = sizeof(out);
        REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
        if(item.with_rtp)
        {
            // This packet changes IP-ID behavior, so IR-DYN must refresh context.
            REQUIRE(rohc[0] == 0xF8);
        }
        else
            REQUIRE(rohc[0] == item.fo_type);
        REQUIRE(rohc[1] == 0x92);
        REQUIRE(rohc[2] == 0x34);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        size_t first_diff = sizeof(ip);
        for(size_t i = 0; i < sizeof(ip); ++i)
        {
            if(out[i] != ip[i])
            {
                first_diff = i;
                break;
            }
        }
        INFO("first_diff=" << first_diff << " expected=" << static_cast<unsigned>(first_diff < sizeof(ip) ? ip[first_diff] : 0) << " actual=" << static_cast<unsigned>(first_diff < sizeof(ip) ? out[first_diff] : 0));
        REQUIRE(first_diff == sizeof(ip));

        rohc_decomp_free(decomp);
        rohc_comp_free(comp);
    }
}


TEST_CASE("ROHCoIPsec encodes and parses RFC 5857 ROHC_SUPPORTED attributes")
{
    rohccxx::rohcoipsec::ChannelParameters params{};
    params.max_cid = 63;
    REQUIRE(rohccxx::rohcoipsec::append_profile(params, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));
    REQUIRE(rohccxx::rohcoipsec::append_profile(params, static_cast<std::uint16_t>(rohccxx::Profile::UDP)));
    REQUIRE(rohccxx::rohcoipsec::append_integrity(
        params, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None)));
    params.icv_len = 0;
    params.has_icv_len = true;
    params.mrru = 0;
    params.has_mrru = true;

    std::uint8_t payload[32] = {};
    std::size_t payload_len = sizeof(payload);
    REQUIRE(rohccxx::rohcoipsec::write_supported_notify_payload(params, payload, &payload_len));
    const std::uint8_t expected[] = {
        0x80, 0x01, 0x00, 0x3F,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x02, 0x01, 0x02,
        0x80, 0x03, 0x00, 0x00,
        0x80, 0x04, 0x00, 0x00,
        0x80, 0x05, 0x00, 0x00,
    };
    REQUIRE(payload_len == sizeof(expected));
    REQUIRE(std::memcmp(payload, expected, sizeof(expected)) == 0);

    rohccxx::rohcoipsec::ChannelParameters parsed{};
    REQUIRE(rohccxx::rohcoipsec::parse_supported_notify_payload(payload, payload_len, parsed));
    REQUIRE(parsed.max_cid == 63);
    REQUIRE(parsed.large_cids());
    REQUIRE(parsed.profile_count == 2);
    REQUIRE(rohccxx::rohcoipsec::supports_profile(parsed, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));
    REQUIRE(rohccxx::rohcoipsec::supports_profile(parsed, static_cast<std::uint16_t>(rohccxx::Profile::UDP)));
    REQUIRE(parsed.integrity_algorithm_count == 1);
    REQUIRE(rohccxx::rohcoipsec::supports_integrity(
        parsed, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None)));
    REQUIRE(parsed.has_icv_len);
    REQUIRE(parsed.icv_len == 0);
    REQUIRE(parsed.has_mrru);
    REQUIRE(parsed.mrru == 0);
}

TEST_CASE("ROHCoIPsec rejects malformed mandatory RFC 5857 attributes")
{
    const std::uint8_t missing_profile[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x03, 0x00, 0x00,
    };
    rohccxx::rohcoipsec::ChannelParameters parsed{};
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        missing_profile, sizeof(missing_profile), parsed));

    const std::uint8_t duplicate_max_cid[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x01, 0x00, 0x05,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x00,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        duplicate_max_cid, sizeof(duplicate_max_cid), parsed));

    const std::uint8_t max_cid_too_large[] = {
        0x80, 0x01, 0x40, 0x00,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x00,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        max_cid_too_large, sizeof(max_cid_too_large), parsed));
}

TEST_CASE("ROHCoIPsec rejects duplicate unsupported and incoherent RFC 5857 attributes")
{
    rohccxx::rohcoipsec::ChannelParameters params{};
    params.max_cid = 4;
    REQUIRE(rohccxx::rohcoipsec::append_profile(params, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::append_profile(params, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::append_profile(params, static_cast<std::uint16_t>(rohccxx::Profile::LLA_RTP)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::append_profile(params, 0x0105));
    REQUIRE(rohccxx::rohcoipsec::append_integrity(
        params, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::append_integrity(
        params, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::append_integrity(params, 0x7777));
    params.has_icv_len = true;
    params.icv_len = 0;
    REQUIRE_FALSE(params.valid());
    params.icv_len = 12;
    REQUIRE(params.valid());
    REQUIRE(rohccxx::rohcoipsec::icv_length_is_valid_for_algorithm(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256), 12));
    REQUIRE_FALSE(rohccxx::rohcoipsec::icv_length_is_valid_for_algorithm(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None), 12));

    rohccxx::rohcoipsec::ChannelParameters none_only{};
    none_only.max_cid = 4;
    REQUIRE(rohccxx::rohcoipsec::append_profile(none_only, static_cast<std::uint16_t>(rohccxx::Profile::IP)));
    REQUIRE(rohccxx::rohcoipsec::append_integrity(
        none_only, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None)));
    none_only.has_icv_len = true;
    none_only.icv_len = 4;
    REQUIRE_FALSE(none_only.valid());
    none_only.icv_len = 0;
    REQUIRE(none_only.valid());

    const std::uint8_t duplicate_profile[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x00,
    };
    rohccxx::rohcoipsec::ChannelParameters parsed{};
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        duplicate_profile, sizeof(duplicate_profile), parsed));

    const std::uint8_t unknown_profile[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x02, 0x01, 0x05,
        0x80, 0x03, 0x00, 0x00,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        unknown_profile, sizeof(unknown_profile), parsed));

    const std::uint8_t duplicate_integrity[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        duplicate_integrity, sizeof(duplicate_integrity), parsed));

    const std::uint8_t hmac_zero_icv[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x0C,
        0x80, 0x04, 0x00, 0x00,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        hmac_zero_icv, sizeof(hmac_zero_icv), parsed));

    const std::uint8_t none_nonzero_icv[] = {
        0x80, 0x01, 0x00, 0x04,
        0x80, 0x02, 0x01, 0x01,
        0x80, 0x03, 0x00, 0x00,
        0x80, 0x04, 0x00, 0x04,
    };
    REQUIRE_FALSE(rohccxx::rohcoipsec::parse_supported_notify_payload(
        none_nonzero_icv, sizeof(none_nonzero_icv), parsed));

    rohccxx_rohcoipsec_channel_t c_params{};
    c_params.max_cid = 4;
    c_params.profiles[0] = ROHCCXX_PROFILE_RTP;
    c_params.profile_count = 1;
    c_params.integrity_algorithms[0] = ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256;
    c_params.integrity_algorithm_count = 1;
    c_params.has_icv_len = 1;
    c_params.icv_len = 0;
    std::uint8_t wire[32] = {};
    std::size_t wire_len = sizeof(wire);
    REQUIRE(rohc_rohcoipsec_write_supported(&c_params, wire, &wire_len) == -1);
    c_params.icv_len = 12;
    REQUIRE(rohc_rohcoipsec_write_supported(&c_params, wire, &wire_len) == 0);
}

TEST_CASE("ROHCoIPsec negotiation derives usable channel parameters")
{
    rohccxx::rohcoipsec::ChannelParameters local{};
    local.max_cid = 4;
    REQUIRE(rohccxx::rohcoipsec::append_profile(local, static_cast<std::uint16_t>(rohccxx::Profile::RTP)));
    REQUIRE(rohccxx::rohcoipsec::append_profile(local, static_cast<std::uint16_t>(rohccxx::Profile::IP)));
    REQUIRE(rohccxx::rohcoipsec::append_integrity(
        local, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None)));

    rohccxx::rohcoipsec::ChannelParameters peer{};
    peer.max_cid = 20;
    REQUIRE(rohccxx::rohcoipsec::append_profile(peer, static_cast<std::uint16_t>(rohccxx::Profile::IP)));
    REQUIRE(rohccxx::rohcoipsec::append_profile(peer, static_cast<std::uint16_t>(rohccxx::Profile::UDP)));
    REQUIRE(rohccxx::rohcoipsec::append_integrity(
        peer, static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None)));
    peer.icv_len = 0;
    peer.has_icv_len = true;
    peer.mrru = 0;
    peer.has_mrru = true;

    rohccxx::rohcoipsec::ChannelParameters negotiated{};
    REQUIRE(rohccxx::rohcoipsec::negotiate(local, peer, negotiated));
    REQUIRE(negotiated.max_cid == 20);
    REQUIRE(negotiated.large_cids());
    REQUIRE(negotiated.profile_count == 1);
    REQUIRE(negotiated.profiles[0] == static_cast<std::uint16_t>(rohccxx::Profile::IP));
    REQUIRE(negotiated.integrity_algorithm_count == 1);
    REQUIRE(negotiated.integrity_algorithms[0] ==
            static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None));
    REQUIRE(negotiated.icv_len == 0);
    REQUIRE(negotiated.has_mrru);
    REQUIRE(negotiated.mrru == 0);

    peer.profile_count = 0;
    REQUIRE(rohccxx::rohcoipsec::append_profile(peer, static_cast<std::uint16_t>(rohccxx::Profile::ESP)));
    REQUIRE_FALSE(rohccxx::rohcoipsec::negotiate(local, peer, negotiated));
}

TEST_CASE("ROHCoIPsec pins RFC 5858 protocol number and NONE ICV behavior")
{
    REQUIRE(rohccxx::rohcoipsec::protocol_number == 142);
    REQUIRE(rohccxx::rohcoipsec::is_rohc_next_header(142));
    REQUIRE_FALSE(rohccxx::rohcoipsec::is_rohc_next_header(50));

    const std::uint8_t rohc_packet[] = {0xFD, 0x01, 0x02, 0x03};
    std::uint8_t out[8] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohccxx::rohcoipsec::append_none_icv(rohc_packet, sizeof(rohc_packet), out, &out_len));
    REQUIRE(out_len == sizeof(rohc_packet));
    REQUIRE(std::memcmp(out, rohc_packet, sizeof(rohc_packet)) == 0);

    const std::uint8_t* stripped = nullptr;
    std::size_t stripped_len = 0;
    REQUIRE(rohccxx::rohcoipsec::strip_none_icv(out, out_len, &stripped, &stripped_len));
    REQUIRE(stripped == out);
    REQUIRE(stripped_len == out_len);
}


TEST_CASE("ROHCoIPsec C API wraps supported-notify negotiation helpers")
{
    rohccxx_rohcoipsec_channel_t local{};
    local.max_cid = 4;
    local.profiles[0] = static_cast<std::uint16_t>(rohccxx::Profile::RTP);
    local.profiles[1] = static_cast<std::uint16_t>(rohccxx::Profile::IP);
    local.profile_count = 2;
    local.integrity_algorithms[0] = ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE;
    local.integrity_algorithm_count = 1;

    rohccxx_rohcoipsec_channel_t peer{};
    peer.max_cid = 31;
    peer.profiles[0] = static_cast<std::uint16_t>(rohccxx::Profile::IP);
    peer.profile_count = 1;
    peer.integrity_algorithms[0] = ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE;
    peer.integrity_algorithm_count = 1;
    peer.has_icv_len = 1;
    peer.icv_len = 0;
    peer.has_mrru = 1;
    peer.mrru = 0;

    REQUIRE(rohc_rohcoipsec_protocol_number() == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);

    std::uint8_t wire[32] = {};
    std::size_t wire_len = sizeof(wire);
    REQUIRE(rohc_rohcoipsec_write_supported(&peer, wire, &wire_len) == 0);

    rohccxx_rohcoipsec_channel_t parsed{};
    REQUIRE(rohc_rohcoipsec_parse_supported(wire, wire_len, &parsed) == 0);
    REQUIRE(parsed.max_cid == peer.max_cid);
    REQUIRE(parsed.profile_count == peer.profile_count);
    REQUIRE(parsed.profiles[0] == peer.profiles[0]);
    REQUIRE(parsed.integrity_algorithm_count == peer.integrity_algorithm_count);
    REQUIRE(parsed.integrity_algorithms[0] == ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE);
    REQUIRE(parsed.has_mrru == 1);
    REQUIRE(parsed.mrru == 0);

    rohccxx_rohcoipsec_channel_t negotiated{};
    REQUIRE(rohc_rohcoipsec_negotiate(&local, &parsed, &negotiated) == 0);
    REQUIRE(negotiated.max_cid == 31);
    REQUIRE(negotiated.profile_count == 1);
    REQUIRE(negotiated.profiles[0] == static_cast<std::uint16_t>(rohccxx::Profile::IP));
    REQUIRE(negotiated.integrity_algorithm_count == 1);
    REQUIRE(negotiated.integrity_algorithms[0] == ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE);
}


TEST_CASE("ROHCoIPsec keyed ICV uses HMAC-SHA-256 and verifies truncation")
{
    const std::uint8_t key[] = {'k', 'e', 'y'};
    const std::uint8_t data[] = {
        'T','h','e',' ','q','u','i','c','k',' ','b','r','o','w','n',' ',
        'f','o','x',' ','j','u','m','p','s',' ','o','v','e','r',' ',
        't','h','e',' ','l','a','z','y',' ','d','o','g'
    };
    std::uint8_t digest[32] = {};
    std::size_t digest_len = sizeof(digest);
    REQUIRE(rohccxx::rohcoipsec::compute_icv(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256),
        key,
        sizeof(key),
        data,
        sizeof(data),
        digest,
        &digest_len));
    const std::uint8_t expected[] = {
        0xF7, 0xBC, 0x83, 0xF4, 0x30, 0x53, 0x84, 0x24,
        0xB1, 0x32, 0x98, 0xE6, 0xAA, 0x6F, 0xB1, 0x43,
        0xEF, 0x4D, 0x59, 0xA1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9D, 0xBC, 0x2D, 0x1A, 0x3C, 0xD8,
    };
    REQUIRE(std::memcmp(digest, expected, sizeof(expected)) == 0);

    const std::uint8_t rohc[] = {0xFD, 0x01, 0x02};
    std::uint8_t packet[16] = {};
    std::size_t packet_len = sizeof(packet);
    REQUIRE(rohccxx::rohcoipsec::append_icv(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256),
        key,
        sizeof(key),
        data,
        sizeof(data),
        rohc,
        sizeof(rohc),
        packet,
        &packet_len,
        8));
    REQUIRE(packet_len == sizeof(rohc) + 8);
    REQUIRE(std::memcmp(packet, rohc, sizeof(rohc)) == 0);
    REQUIRE(std::memcmp(packet + sizeof(rohc), expected, 8) == 0);

    const std::uint8_t* stripped = nullptr;
    std::size_t stripped_len = 0;
    REQUIRE(rohccxx::rohcoipsec::strip_and_verify_icv(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256),
        key,
        sizeof(key),
        data,
        sizeof(data),
        packet,
        packet_len,
        &stripped,
        &stripped_len,
        8));
    REQUIRE(stripped == packet);
    REQUIRE(stripped_len == sizeof(rohc));

    packet[packet_len - 1] ^= 0x01;
    REQUIRE_FALSE(rohccxx::rohcoipsec::strip_and_verify_icv(
        static_cast<std::uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::HmacSha256),
        key,
        sizeof(key),
        data,
        sizeof(data),
        packet,
        packet_len,
        &stripped,
        &stripped_len,
        8));
}

TEST_CASE("ROHCoIPsec C API appends verifies and routes AH ESP next headers")
{
    const std::uint8_t key[] = {0x10, 0x20, 0x30, 0x40};
    const std::uint8_t ip[] = {0x45, 0x00, 0x00, 0x14};
    const std::uint8_t rohc[] = {0xFD, 0x00, 0x01};
    std::uint8_t packet[32] = {};
    std::size_t packet_len = sizeof(packet);
    REQUIRE(rohc_rohcoipsec_append_icv(ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                       key,
                                       sizeof(key),
                                       ip,
                                       sizeof(ip),
                                       rohc,
                                       sizeof(rohc),
                                       packet,
                                       &packet_len,
                                       12) == 0);
    REQUIRE(packet_len == sizeof(rohc) + 12);
    REQUIRE(rohc_rohcoipsec_outbound_next_header(1) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_rohcoipsec_inbound_requires_decompression(ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER) == 1);
    REQUIRE(rohc_rohcoipsec_inbound_requires_decompression(50) == 0);

    std::uint8_t stripped[32] = {};
    std::size_t stripped_len = sizeof(stripped);
    REQUIRE(rohc_rohcoipsec_strip_verify_icv(ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                            key,
                                            sizeof(key),
                                            ip,
                                            sizeof(ip),
                                            packet,
                                            packet_len,
                                            stripped,
                                            &stripped_len,
                                            12) == 0);
    REQUIRE(stripped_len == sizeof(rohc));
    REQUIRE(std::memcmp(stripped, rohc, sizeof(rohc)) == 0);

    packet[packet_len - 2] ^= 0x01;
    stripped_len = sizeof(stripped);
    REQUIRE(rohc_rohcoipsec_strip_verify_icv(ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                            key,
                                            sizeof(key),
                                            ip,
                                            sizeof(ip),
                                            packet,
                                            packet_len,
                                            stripped,
                                            &stripped_len,
                                            12) == -1);
}

TEST_CASE("ROHCoIPsec enabled C API appends ICV after compression and verifies after decompression")
{
    const std::uint8_t key[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4};
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_set_rohcoipsec_integrity(comp,
                                               ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                               key,
                                               sizeof(key),
                                               12) == 0);
    REQUIRE(rohc_decomp_set_rohcoipsec_integrity(decomp,
                                                 ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                                 key,
                                                 sizeof(key),
                                                 12) == 0);
    REQUIRE(rohc_comp_rohcoipsec_next_header(comp) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_decomp_rohcoipsec_requires_decompression(decomp, ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER) == 1);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 1000, 1234, 0xCAFEBABE);
    std::uint8_t rohc[128] = {};
    std::size_t rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len > 12);

    std::uint8_t out[64] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc[rohc_len - 1] ^= 0x80;
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHCoIPsec SA helpers derive KEYMAT and apply negotiated channel state")
{
    std::uint8_t keymat[32] = {};
    for(std::size_t i = 0; i < sizeof(keymat); ++i)
        keymat[i] = static_cast<std::uint8_t>(0x40U + i);

    std::uint8_t outbound_key[16] = {};
    std::uint8_t inbound_key[16] = {};
    std::size_t outbound_key_len = sizeof(outbound_key);
    std::size_t inbound_key_len = sizeof(inbound_key);
    REQUIRE(rohc_rohcoipsec_derive_directional_keys(keymat,
                                                    sizeof(keymat),
                                                    16,
                                                    outbound_key,
                                                    &outbound_key_len,
                                                    inbound_key,
                                                    &inbound_key_len) == 0);
    REQUIRE(outbound_key_len == 16);
    REQUIRE(inbound_key_len == 16);
    REQUIRE(std::memcmp(outbound_key, keymat, 16) == 0);
    REQUIRE(std::memcmp(inbound_key, keymat + 16, 16) == 0);

    rohccxx_rohcoipsec_channel_t negotiated{};
    negotiated.max_cid = 31;
    negotiated.profiles[0] = static_cast<std::uint16_t>(rohccxx::Profile::RTP);
    negotiated.profile_count = 1;
    negotiated.integrity_algorithms[0] = ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256;
    negotiated.integrity_algorithm_count = 1;
    negotiated.has_icv_len = 1;
    negotiated.icv_len = 12;
    negotiated.has_mrru = 1;
    negotiated.mrru = 0;

    rohccxx_rohcoipsec_sa_t outbound_sa{};
    rohccxx_rohcoipsec_sa_t inbound_sa{};
    REQUIRE(rohc_rohcoipsec_build_sa(&negotiated,
                                     ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                     outbound_key,
                                     outbound_key_len,
                                     9,
                                     1,
                                     &outbound_sa) == 0);
    REQUIRE(rohc_rohcoipsec_build_sa(&negotiated,
                                     ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                     outbound_key,
                                     outbound_key_len,
                                     9,
                                     1,
                                     &inbound_sa) == 0);
    REQUIRE(outbound_sa.large_cids == 1);
    REQUIRE(outbound_sa.icv_len == 12);
    REQUIRE(outbound_sa.has_mrru == 1);
    REQUIRE(outbound_sa.mrru == 0);
    REQUIRE(outbound_sa.has_feedback_for == 1);
    REQUIRE(outbound_sa.feedback_for == 9);
    REQUIRE(outbound_sa.key_len == outbound_key_len);
    REQUIRE(std::memcmp(outbound_sa.key, outbound_key, outbound_key_len) == 0);

    REQUIRE(rohc_rohcoipsec_security_next_header(ROHCCXX_IPPROTO_ESP, 1) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_rohcoipsec_security_next_header(ROHCCXX_IPPROTO_ESP, 0) == ROHCCXX_IPPROTO_ESP);
    REQUIRE(rohc_rohcoipsec_security_next_header(ROHCCXX_IPPROTO_AH, 0) == ROHCCXX_IPPROTO_AH);

    rohc_comp* comp = rohc_comp_new2(31, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(31, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_apply_rohcoipsec_sa(comp, &outbound_sa) == 0);
    REQUIRE(rohc_decomp_apply_rohcoipsec_sa(decomp, &inbound_sa) == 0);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 2000, 32000, 0x10203040);
    std::uint8_t rohc[128] = {};
    std::size_t rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) == 0);

    std::uint8_t out[64] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ROHC C API supports independent instances on concurrent threads")
{
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    for(int worker = 0; worker < 8; ++worker)
    {
        workers.emplace_back([worker, &failures]() {
            rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
            rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
            if(!comp || !decomp)
            {
                failures.fetch_add(1);
                if(decomp)
                    rohc_decomp_free(decomp);
                if(comp)
                    rohc_comp_free(comp);
                return;
            }

            for(int packet_index = 0; packet_index < 8; ++packet_index)
            {
                std::uint8_t ip[64] = {};
                make_valid_rtp(ip,
                               static_cast<std::uint16_t>(1000 + worker * 32 + packet_index),
                               static_cast<std::uint32_t>(1234 + packet_index * 160),
                               static_cast<std::uint32_t>(0xCAFE0000U + worker));
                std::uint8_t rohc[128] = {};
                std::size_t rohc_len = sizeof(rohc);
                std::uint8_t out[64] = {};
                std::size_t out_len = sizeof(out);
                if(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) != 0 ||
                   rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0 ||
                   out_len != sizeof(ip) || std::memcmp(out, ip, sizeof(ip)) != 0)
                {
                    failures.fetch_add(1);
                    break;
                }
            }

            rohc_decomp_free(decomp);
            rohc_comp_free(comp);
        });
    }

    for(auto& worker : workers)
        worker.join();
    REQUIRE(failures.load() == 0);
}

TEST_CASE("ROHC C API serializes shared instance configuration and compression")
{
    std::atomic<int> failures{0};
    rohc_comp* comp = rohc_comp_new2(31, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(rohc_comp_set_cid(comp, 1) == 0);

    std::vector<std::thread> workers;
    for(int worker = 0; worker < 6; ++worker)
    {
        workers.emplace_back([worker, comp, &failures]() {
            for(int i = 0; i < 10; ++i)
            {
                const auto mode = (i % 2) == 0 ? ROHCCXX_MODE_O : ROHCCXX_MODE_R;
                rohccxx_mode_t observed = ROHCCXX_MODE_U;
                std::uint8_t ip[64] = {};
                make_valid_rtp(ip,
                               static_cast<std::uint16_t>(2000 + worker * 64 + i),
                               static_cast<std::uint32_t>(32000 + i * 160),
                               0x10203040U);
                std::uint8_t rohc[128] = {};
                std::size_t rohc_len = sizeof(rohc);
                if(rohc_comp_set_mode(comp, mode) != 0 || rohc_comp_get_mode(comp, &observed) != 0 ||
                   rohc_comp_enable_rohcoipsec(comp) != 0 ||
                   rohc_comp_rohcoipsec_next_header(comp) != ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER ||
                   rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) != 0)
                {
                    failures.fetch_add(1);
                    break;
                }
            }
        });
    }

    for(auto& worker : workers)
        worker.join();
    REQUIRE(failures.load() == 0);
    rohc_comp_free(comp);
}


TEST_CASE("ROHCCXX C++ API supports independent instances on concurrent threads")
{
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    for(int worker = 0; worker < 8; ++worker)
    {
        workers.emplace_back([worker, &failures]() {
            rohccxx::Compressor comp(0);
            rohccxx::Decompressor decomp(0);
            for(int packet_index = 0; packet_index < 8; ++packet_index)
            {
                std::uint8_t ip[64] = {};
                make_valid_rtp(ip,
                               static_cast<std::uint16_t>(3000 + worker * 32 + packet_index),
                               static_cast<std::uint32_t>(48000 + packet_index * 160),
                               static_cast<std::uint32_t>(0xABCD0000U + worker));
                std::uint8_t rohc[128] = {};
                std::size_t rohc_len = sizeof(rohc);
                std::uint8_t out[64] = {};
                std::size_t out_len = sizeof(out);
                if(comp.compress(ip, sizeof(ip), rohc, &rohc_len) != 0 ||
                   decomp.decompress(rohc, rohc_len, out, &out_len) != 0 ||
                   out_len != 40 || std::memcmp(out + 28, ip + 28, 12) != 0)
                {
                    failures.fetch_add(1);
                    break;
                }
            }
        });
    }

    for(auto& worker : workers)
        worker.join();
    REQUIRE(failures.load() == 0);
}

TEST_CASE("ROHCCXX C++ API serializes shared compressor and decompressor instances")
{
    std::atomic<int> failures{0};
    rohccxx::Compressor comp(0);
    rohccxx::Decompressor decomp(0);

    std::uint8_t seed_ip[64] = {};
    make_valid_rtp(seed_ip, 4000, 64000, 0x55667788U);
    std::uint8_t seed_rohc[128] = {};
    std::size_t seed_rohc_len = sizeof(seed_rohc);
    std::uint8_t seed_out[64] = {};
    std::size_t seed_out_len = sizeof(seed_out);
    REQUIRE(comp.compress(seed_ip, sizeof(seed_ip), seed_rohc, &seed_rohc_len) == 0);
    REQUIRE(decomp.decompress(seed_rohc, seed_rohc_len, seed_out, &seed_out_len) == 0);

    std::vector<std::thread> workers;
    for(int worker = 0; worker < 6; ++worker)
    {
        workers.emplace_back([worker, &comp, &decomp, &failures]() {
            for(int i = 0; i < 10; ++i)
            {
                std::uint8_t ip[64] = {};
                make_valid_rtp(ip,
                               static_cast<std::uint16_t>(4100 + worker * 64 + i),
                               static_cast<std::uint32_t>(65000 + i * 160),
                               0x55667788U);
                std::uint8_t rohc[128] = {};
                std::size_t rohc_len = sizeof(rohc);
                std::uint8_t out[64] = {};
                std::size_t out_len = sizeof(out);
                if(comp.compress(ip, sizeof(ip), rohc, &rohc_len) != 0 ||
                   decomp.decompress(rohc, rohc_len, out, &out_len) != 0 ||
                   out_len != 40)
                {
                    failures.fetch_add(1);
                    break;
                }
            }
        });
    }

    for(auto& worker : workers)
        worker.join();
    REQUIRE(failures.load() == 0);
}


TEST_CASE("ROHC thread safety handles one independent traffic source per CPU core")
{
    const unsigned detected_cores = std::thread::hardware_concurrency();
    const unsigned worker_count = std::max(1U, std::min(detected_cores == 0 ? 2U : detected_cores, 32U));
    constexpr int packets_per_worker = 24;

    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for(unsigned worker = 0; worker < worker_count; ++worker)
    {
        workers.emplace_back([worker, &failures]() {
            rohc_comp* c_comp = rohc_comp_new2(7, ROHCCXX_DIRECTION_UPLINK);
            rohc_decomp* c_decomp = rohc_decomp_new2(7, ROHCCXX_DIRECTION_UPLINK);
            if(!c_comp || !c_decomp)
            {
                failures.fetch_add(1);
                if(c_decomp)
                    rohc_decomp_free(c_decomp);
                if(c_comp)
                    rohc_comp_free(c_comp);
                return;
            }

            rohccxx::Compressor cpp_comp(0);
            rohccxx::Decompressor cpp_decomp(0);
            for(int packet_index = 0; packet_index < packets_per_worker; ++packet_index)
            {
                std::uint8_t ip[64] = {};
                const auto seq = static_cast<std::uint16_t>(5000 + worker * 128 + packet_index);
                const auto ts = static_cast<std::uint32_t>(90000 + worker * 4096 + packet_index * 160);
                const auto ssrc = static_cast<std::uint32_t>(0x71000000U + worker);
                make_valid_rtp(ip, seq, ts, ssrc);

                std::uint8_t c_rohc[128] = {};
                std::size_t c_rohc_len = sizeof(c_rohc);
                std::uint8_t c_out[64] = {};
                std::size_t c_out_len = sizeof(c_out);
                const bool c_ok = rohc_compress4(c_comp, ip, sizeof(ip), c_rohc, &c_rohc_len) == 0 &&
                                  rohc_decompress4(c_decomp, c_rohc, c_rohc_len, c_out, &c_out_len) == 0 &&
                                  c_out_len == sizeof(ip) && std::memcmp(c_out, ip, sizeof(ip)) == 0;

                std::uint8_t cpp_rohc[128] = {};
                std::size_t cpp_rohc_len = sizeof(cpp_rohc);
                std::uint8_t cpp_out[64] = {};
                std::size_t cpp_out_len = sizeof(cpp_out);
                const bool cpp_ok = cpp_comp.compress(ip, sizeof(ip), cpp_rohc, &cpp_rohc_len) == 0 &&
                                    cpp_decomp.decompress(cpp_rohc, cpp_rohc_len, cpp_out, &cpp_out_len) == 0 &&
                                    cpp_out_len == 40 && std::memcmp(cpp_out + 28, ip + 28, 12) == 0;

                if(!c_ok || !cpp_ok)
                {
                    failures.fetch_add(1);
                    break;
                }
            }

            rohc_decomp_free(c_decomp);
            rohc_comp_free(c_comp);
        });
    }

    for(auto& worker : workers)
        worker.join();

    REQUIRE(worker_count >= 1);
    REQUIRE(failures.load() == 0);
}
