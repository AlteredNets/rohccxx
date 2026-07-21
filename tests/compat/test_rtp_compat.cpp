// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include <cstdint>
#include <cstring>

#include "rohccxx/core/classify.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "test_packet_helpers.hpp"
#include "protocols/ip_numbers.h"

namespace
{

void set_ipv4_protocol(uint8_t* pkt, uint8_t proto)
{
    pkt[0] = 0x45;
    pkt[2] = 0x00;
    pkt[3] = 64;
    pkt[9] = proto;
}

void set_ipv6_version(uint8_t* pkt)
{
    std::memset(pkt, 0, 64);
    pkt[0] = 0x60;
}


void make_valid_ipv6_rtp(uint8_t* pkt,
                         size_t packet_len,
                         uint16_t seq,
                         uint32_t ts,
                         uint32_t ssrc,
                         bool hop_by_hop_extension = false)
{
    std::memset(pkt, 0, packet_len);
    const size_t ext_len = hop_by_hop_extension ? 8U : 0U;
    const size_t udp_offset = 40U + ext_len;
    const size_t rtp_offset = udp_offset + 8U;
    const uint16_t payload_len = static_cast<uint16_t>(packet_len - 40U);
    const uint16_t udp_len = static_cast<uint16_t>(packet_len - udp_offset);

    pkt[0] = 0x60;
    pkt[4] = static_cast<uint8_t>(payload_len >> 8);
    pkt[5] = static_cast<uint8_t>(payload_len & 0xFF);
    pkt[6] = hop_by_hop_extension ? 0 : 17;
    pkt[7] = 64;
    for(size_t i = 0; i < 16; ++i)
    {
        pkt[8 + i] = static_cast<uint8_t>(0x20 + i);
        pkt[24 + i] = static_cast<uint8_t>(0x40 + i);
    }

    if(hop_by_hop_extension)
    {
        pkt[40] = 17;
        pkt[41] = 0;
    }

    pkt[udp_offset + 0] = 0x12;
    pkt[udp_offset + 1] = 0x34;
    pkt[udp_offset + 2] = 0x56;
    pkt[udp_offset + 3] = 0x78;
    pkt[udp_offset + 4] = static_cast<uint8_t>(udp_len >> 8);
    pkt[udp_offset + 5] = static_cast<uint8_t>(udp_len & 0xFF);
    pkt[udp_offset + 6] = 0x00;
    pkt[udp_offset + 7] = 0x00;

    pkt[rtp_offset + 0] = 0x80;
    pkt[rtp_offset + 1] = 0x00;
    pkt[rtp_offset + 2] = static_cast<uint8_t>(seq >> 8);
    pkt[rtp_offset + 3] = static_cast<uint8_t>(seq & 0xFF);
    pkt[rtp_offset + 4] = static_cast<uint8_t>(ts >> 24);
    pkt[rtp_offset + 5] = static_cast<uint8_t>(ts >> 16);
    pkt[rtp_offset + 6] = static_cast<uint8_t>(ts >> 8);
    pkt[rtp_offset + 7] = static_cast<uint8_t>(ts & 0xFF);
    pkt[rtp_offset + 8] = static_cast<uint8_t>(ssrc >> 24);
    pkt[rtp_offset + 9] = static_cast<uint8_t>(ssrc >> 16);
    pkt[rtp_offset + 10] = static_cast<uint8_t>(ssrc >> 8);
    pkt[rtp_offset + 11] = static_cast<uint8_t>(ssrc & 0xFF);
}

enum class CrcProfile
{
    Rtp,
    Udp,
    Esp,
    Ip,
    RtpUdpLite,
    UdpLite
};

void refresh_ipv4_checksum(uint8_t* packet)
{
    packet[10] = 0x00;
    packet[11] = 0x00;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
}

void make_crc_profile_packet(CrcProfile profile, uint8_t* packet, uint16_t seq, uint32_t ts)
{
    std::memset(packet, 0, 64);

    switch(profile)
    {
    case CrcProfile::Rtp:
        make_valid_rtp(packet, seq, ts, 0xCAFEBABE);
        break;
    case CrcProfile::Udp:
        make_valid_rtp(packet, seq, ts, 0xCAFEBABE);
        packet[28] = 0x00;
        refresh_ipv4_checksum(packet);
        break;
    case CrcProfile::Esp:
        set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
        packet[8] = 64;
        packet[12] = 203;
        packet[13] = 0;
        packet[14] = 113;
        packet[15] = 1;
        packet[16] = 203;
        packet[17] = 0;
        packet[18] = 113;
        packet[19] = 2;
        packet[20] = 0xDE;
        packet[21] = 0xAD;
        packet[22] = 0xBE;
        packet[23] = 0xEF;
        packet[27] = static_cast<uint8_t>(seq & 0xFF);
        refresh_ipv4_checksum(packet);
        break;
    case CrcProfile::Ip:
        set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
        packet[8] = 64;
        packet[12] = 192;
        packet[13] = 0;
        packet[14] = 2;
        packet[15] = 1;
        packet[16] = 198;
        packet[17] = 51;
        packet[18] = 100;
        packet[19] = 2;
        packet[20] = static_cast<uint8_t>(seq & 0xFF);
        refresh_ipv4_checksum(packet);
        break;
    case CrcProfile::RtpUdpLite:
        make_valid_rtp(packet, seq, ts, 0xCAFEBABE);
        packet[9] = ROHC_IPPROTO_UDPLITE;
        packet[24] = 0x00;
        packet[25] = 0x20;
        packet[26] = 0x9A;
        packet[27] = 0xBC;
        refresh_ipv4_checksum(packet);
        break;
    case CrcProfile::UdpLite:
        set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
        packet[8] = 64;
        packet[20] = 0x12;
        packet[21] = 0x34;
        packet[22] = 0x56;
        packet[23] = 0x78;
        packet[24] = 0x00;
        packet[25] = 0x10;
        packet[26] = 0x9A;
        packet[27] = 0xBC;
        packet[28] = 0x44;
        packet[29] = static_cast<uint8_t>(seq & 0xFF);
        refresh_ipv4_checksum(packet);
        break;
    }
}

bool decode_crc_profile_ir(CrcProfile profile, const uint8_t* rohc, size_t rohc_len, rohccxx::Context& ctx)
{
    switch(profile)
    {
    case CrcProfile::Rtp:
        return rohccxx::decode_ir_rtp(rohc, rohc_len, ctx);
    case CrcProfile::Udp:
        return rohccxx::decode_ir_udp(rohc, rohc_len, ctx);
    case CrcProfile::Esp:
        return rohccxx::decode_ir_esp(rohc, rohc_len, ctx);
    case CrcProfile::Ip:
        return rohccxx::decode_ir_ip(rohc, rohc_len, ctx);
    case CrcProfile::RtpUdpLite:
        return rohccxx::decode_ir_rtp_udp_lite(rohc, rohc_len, ctx);
    case CrcProfile::UdpLite:
        return rohccxx::decode_ir_udp_lite(rohc, rohc_len, ctx);
    }

    return false;
}

bool decode_crc_profile_ir_dyn(CrcProfile profile, const uint8_t* rohc, size_t rohc_len, rohccxx::Context& ctx)
{
    switch(profile)
    {
    case CrcProfile::Rtp:
        return rohccxx::decode_ir_dyn_rtp(rohc, rohc_len, ctx);
    case CrcProfile::Udp:
        return rohccxx::decode_ir_dyn_udp(rohc, rohc_len, ctx);
    case CrcProfile::Esp:
        return rohccxx::decode_ir_dyn_esp(rohc, rohc_len, ctx);
    case CrcProfile::Ip:
        return rohccxx::decode_ir_dyn_ip(rohc, rohc_len, ctx);
    case CrcProfile::RtpUdpLite:
        return rohccxx::decode_ir_dyn_rtp_udp_lite(rohc, rohc_len, ctx);
    case CrcProfile::UdpLite:
        return rohccxx::decode_ir_dyn_udp_lite(rohc, rohc_len, ctx);
    }

    return false;
}

void require_ir_crc_rejection(CrcProfile profile)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t bad[128] = {};
    size_t rohc_len = sizeof(rohc);
    rohccxx::Context ctx{};

    make_crc_profile_packet(profile, packet, 1000, 1234);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(decode_crc_profile_ir(profile, rohc, rohc_len, ctx));

    std::memcpy(bad, rohc, rohc_len);
    bad[2] ^= 0xFF;
    REQUIRE_FALSE(decode_crc_profile_ir(profile, bad, rohc_len, ctx));

    rohc_comp_free(comp);
}

void require_ir_dyn_crc_rejection(CrcProfile profile)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t bad[128] = {};
    size_t rohc_len = sizeof(rohc);
    rohccxx::Context ctx{};

    make_crc_profile_packet(profile, packet, 1000, 1234);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(decode_crc_profile_ir(profile, rohc, rohc_len, ctx));

    make_crc_profile_packet(profile, packet, 1001, 1266);
    rohc_len = sizeof(rohc);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(decode_crc_profile_ir_dyn(profile, rohc, rohc_len, ctx));

    std::memcpy(bad, rohc, rohc_len);
    bad[2] ^= 0xFF;
    REQUIRE_FALSE(decode_crc_profile_ir_dyn(profile, bad, rohc_len, ctx));

    rohc_comp_free(comp);
}

void require_uncompressed_roundtrip(const uint8_t* packet, size_t packet_len)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, packet_len, rohc, &rohc_len) == 0);
    REQUIRE(rohc_len == packet_len + 1);
    REQUIRE(rohc[0] == 0x00);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == packet_len);
    REQUIRE(std::memcmp(out, packet, packet_len) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


void require_exact_roundtrip(const uint8_t* packet, size_t packet_len)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    for(int i = 0; i < 3; ++i)
    {
        uint8_t rohc[128] = {};
        uint8_t out[128] = {};
        size_t rohc_len = sizeof(rohc);
        size_t out_len = sizeof(out);

        REQUIRE(rohc_compress4(comp, packet, packet_len, rohc, &rohc_len) == 0);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == packet_len);
        REQUIRE(std::memcmp(out, packet, packet_len) == 0);
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

} // namespace

TEST_CASE("ROHCv2 RTP baseline is classified as RTP")
{
    uint8_t packet[64] = {};
    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
}


TEST_CASE("ROHCv2 RTP classifier handles extension and list grammar")
{
    SECTION("IPv4 options stay in the RTP profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        std::memmove(packet + 24, packet + 20, 40);
        packet[0] = 0x46;
        packet[2] = 0x00;
        packet[3] = 0x40;
        packet[20] = 0x01;
        packet[21] = 0x01;
        packet[22] = 0x01;
        packet[23] = 0x01;
        packet[28] = 0x00;
        packet[29] = 0x28;
        packet[10] = 0x00;
        packet[11] = 0x00;
        const uint16_t csum = ipv4_checksum(packet, 24);
        packet[10] = static_cast<uint8_t>(csum >> 8);
        packet[11] = static_cast<uint8_t>(csum & 0xFF);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("RTP CSRC lists stay in the RTP profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[28] = 0x81;
        packet[40] = 0x11;
        packet[41] = 0x22;
        packet[42] = 0x33;
        packet[43] = 0x44;
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("RTP extension headers stay in the RTP profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[28] = 0x90;
        packet[40] = 0xBE;
        packet[41] = 0xDE;
        packet[42] = 0x00;
        packet[43] = 0x01;
        packet[44] = 0xCA;
        packet[45] = 0xFE;
        packet[46] = 0xBA;
        packet[47] = 0xBE;
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("RTP padding stays in the RTP profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[28] = 0xA0;
        packet[60] = 0x00;
        packet[61] = 0x00;
        packet[62] = 0x00;
        packet[63] = 0x04;
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }


    SECTION("RTP over UDP-Lite keeps extension/list handling in the RTP UDP-Lite profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[9] = ROHC_IPPROTO_UDPLITE;
        packet[24] = 0x00;
        packet[25] = 0x20;
        packet[26] = 0x9A;
        packet[27] = 0xBC;
        packet[28] = 0x91;
        packet[40] = 0x11;
        packet[41] = 0x22;
        packet[42] = 0x33;
        packet[43] = 0x44;
        packet[44] = 0xBE;
        packet[45] = 0xDE;
        packet[46] = 0x00;
        packet[47] = 0x01;
        refresh_ipv4_checksum(packet);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP_UDP_Lite);
        require_exact_roundtrip(packet, sizeof(packet));
    }
}

TEST_CASE("ROHCv2 lower-layer protocols use compressed IP-only classification")
{
    SECTION("AH / IPsec outer headers enter IP-only compression")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_AH);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::IP);
    }

    SECTION("GRE and MINE enter IP-only compression")
    {
        uint8_t gre_packet[64] = {};
        uint8_t mine_packet[64] = {};
        set_ipv4_protocol(gre_packet, ROHC_IPPROTO_GRE);
        set_ipv4_protocol(mine_packet, ROHC_IPPROTO_MINE);
        REQUIRE(rohccxx::classify_packet(gre_packet, sizeof(gre_packet)) == rohccxx::Profile::IP);
        REQUIRE(rohccxx::classify_packet(mine_packet, sizeof(mine_packet)) == rohccxx::Profile::IP);
    }

    SECTION("IPv6 RTP stays in the RTP profile")
    {
        uint8_t packet[80] = {};
        make_valid_ipv6_rtp(packet, sizeof(packet), 1000, 1234, 0xCAFEBABE);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("IPv6 extension headers stay in the RTP profile")
    {
        uint8_t packet[88] = {};
        make_valid_ipv6_rtp(packet, sizeof(packet), 1000, 1234, 0xCAFEBABE, true);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP);
        require_exact_roundtrip(packet, sizeof(packet));
    }
}

TEST_CASE("ROHCv2 profile identifiers match RFC 5225 assignments")
{
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::Uncompressed) == 0x0000);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::RTP) == 0x0101);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::UDP) == 0x0102);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::ESP) == 0x0103);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::IP) == 0x0104);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::RTP_UDP_Lite) == 0x0107);
    REQUIRE(static_cast<uint16_t>(rohccxx::Profile::UDP_Lite) == 0x0108);
}

TEST_CASE("ROHCv2 C API exposes supported RFC 5225 profile capabilities")
{
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_UNCOMPRESSED) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_RTP) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_UDP) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_ESP) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_IP) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_RTP_UDP_LITE) == 1);
    REQUIRE(rohc_profile_is_supported(ROHCCXX_PROFILE_UDP_LITE) == 1);
    REQUIRE(rohc_profile_is_rohcv2(ROHCCXX_PROFILE_RTP) == 1);
    REQUIRE(rohc_profile_is_rohcv2(ROHCCXX_PROFILE_LLA_RTP) == 0);
    REQUIRE(rohc_profile_is_supported(0x0105) == 0);
}

TEST_CASE("ROHCv2 classifier recognizes supported profile families")
{
    SECTION("UDP without RTP maps to the UDP profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[28] = 0x00;
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::UDP);
    }

    SECTION("ESP maps to the ESP profile")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::ESP);
    }

    SECTION("non-special IPv4 protocols map to the IP-only profile")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::IP);
    }

    SECTION("UDP-Lite maps to the UDP-Lite profile")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::UDP_Lite);
    }

    SECTION("RTP over UDP-Lite maps to the RTP/UDP-Lite profile")
    {
        uint8_t packet[64] = {};
        make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
        packet[9] = ROHC_IPPROTO_UDPLITE;
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::RTP_UDP_Lite);
    }
}


TEST_CASE("ROHCv2 compressed profile IR CRC failures are rejected")
{
    SECTION("RTP/UDP/IP")
    {
        require_ir_crc_rejection(CrcProfile::Rtp);
    }

    SECTION("UDP/IP")
    {
        require_ir_crc_rejection(CrcProfile::Udp);
    }

    SECTION("ESP/IP")
    {
        require_ir_crc_rejection(CrcProfile::Esp);
    }

    SECTION("IP-only")
    {
        require_ir_crc_rejection(CrcProfile::Ip);
    }

    SECTION("RTP/UDP-Lite/IP")
    {
        require_ir_crc_rejection(CrcProfile::RtpUdpLite);
    }

    SECTION("UDP-Lite/IP")
    {
        require_ir_crc_rejection(CrcProfile::UdpLite);
    }
}

TEST_CASE("ROHCv2 compressed profile IR-DYN CRC failures are rejected")
{
    SECTION("RTP/UDP/IP")
    {
        require_ir_dyn_crc_rejection(CrcProfile::Rtp);
    }

    SECTION("UDP/IP")
    {
        require_ir_dyn_crc_rejection(CrcProfile::Udp);
    }

    SECTION("ESP/IP")
    {
        require_ir_dyn_crc_rejection(CrcProfile::Esp);
    }

    SECTION("IP-only")
    {
        require_ir_dyn_crc_rejection(CrcProfile::Ip);
    }

    SECTION("RTP/UDP-Lite/IP")
    {
        require_ir_dyn_crc_rejection(CrcProfile::RtpUdpLite);
    }

    SECTION("UDP-Lite/IP")
    {
        require_ir_dyn_crc_rejection(CrcProfile::UdpLite);
    }
}

TEST_CASE("Unsupported RFC 5225 profile families use uncompressed fallback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);

    rohc_comp_free(comp);
}


TEST_CASE("UDP/IP RFC 5225 profile emits compressed IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[28] = 0x00;

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x02);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("UDP/IP RFC 5225 profile emits IR-DYN after IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[28] = 0x00;
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x02);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[4] = 0x12;
    packet[5] = 0x34;
    packet[10] = 0x00;
    packet[11] = 0x00;
    packet[26] = 0x56;
    packet[27] = 0x78;
    packet[28] = 0x42;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x02);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("UDP/IP RFC 5225 profile emits FO after IR-DYN and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[28] = 0x00;
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[28] = 0x42;
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1002, 5680, 0xCAFEBABE);
    packet[4] = 0x56;
    packet[5] = 0x78;
    packet[10] = 0x00;
    packet[11] = 0x00;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[28] = 0x11;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0x7A);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("UDP/IP FO CRC failure triggers feedback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[28] = 0x00;
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[28] = 0x42;
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1002, 9012, 0xCAFEBABE);
    packet[28] = 0x11;
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0x7A);
    rohc[1] ^= 0x01;

    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}



TEST_CASE("ESP/IP RFC 5225 profile emits compressed IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
    packet[8] = 64;
    packet[12] = 203;
    packet[13] = 0;
    packet[14] = 113;
    packet[15] = 1;
    packet[16] = 203;
    packet[17] = 0;
    packet[18] = 113;
    packet[19] = 2;
    packet[20] = 0xDE;
    packet[21] = 0xAD;
    packet[22] = 0xBE;
    packet[23] = 0xEF;
    packet[24] = 0x00;
    packet[25] = 0x00;
    packet[26] = 0x00;
    packet[27] = 0x01;
    packet[10] = 0x00;
    packet[11] = 0x00;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x03);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ESP/IP RFC 5225 profile emits IR-DYN after IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
    packet[8] = 64;
    packet[20] = 0xDE;
    packet[21] = 0xAD;
    packet[22] = 0xBE;
    packet[23] = 0xEF;
    packet[24] = 0x00;
    packet[25] = 0x00;
    packet[26] = 0x00;
    packet[27] = 0x01;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x03);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[27] = 0x02;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x03);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("ESP/IP RFC 5225 profile emits FO after IR-DYN and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
    packet[8] = 64;
    packet[20] = 0xDE;
    packet[21] = 0xAD;
    packet[22] = 0xBE;
    packet[23] = 0xEF;
    packet[27] = 0x01;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[27] = 0x02;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x44;
    packet[5] = 0x55;
    packet[27] = 0x03;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0x78);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("ESP/IP FO CRC failure triggers feedback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_ESP);
    packet[8] = 64;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x44;
    packet[5] = 0x55;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0x78);
    rohc[1] ^= 0x01;

    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("IP-only RFC 5225 profile emits compressed IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
    packet[8] = 64;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    packet[20] = 0x45;
    packet[21] = 0x67;
    packet[10] = 0x00;
    packet[11] = 0x00;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x04);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("IP-only RFC 5225 profile emits IR-DYN after IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
    packet[8] = 64;
    packet[20] = 0x45;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x04);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[20] = 0x89;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x04);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("IP-only RFC 5225 profile emits FO after IR-DYN and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
    packet[8] = 64;
    packet[20] = 0x45;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[20] = 0x89;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x44;
    packet[5] = 0x55;
    packet[20] = 0xAB;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0x79);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("IP-only FO CRC failure triggers feedback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_TCP);
    packet[8] = 64;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x22;
    packet[5] = 0x33;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x44;
    packet[5] = 0x55;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0x79);
    rohc[1] ^= 0x01;

    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}



TEST_CASE("RTP/UDP-Lite/IP RFC 5225 profile emits compressed IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[24] = 0x00;
    packet[25] = 0x20;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[10] = 0x00;
    packet[11] = 0x00;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len <= sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x07);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("RTP/UDP-Lite/IP RFC 5225 profile emits IR-DYN after IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[24] = 0x00;
    packet[25] = 0x20;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x07);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[4] = 0x12;
    packet[5] = 0x34;
    packet[26] = 0x56;
    packet[27] = 0x78;
    packet[40] = 0x42;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x07);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("RTP/UDP-Lite/IP RFC 5225 profile emits FO after IR-DYN and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[24] = 0x00;
    packet[25] = 0x20;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[24] = 0x00;
    packet[25] = 0x24;
    packet[26] = 0x56;
    packet[27] = 0x78;
    packet[40] = 0x42;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1002, 5680, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[24] = 0x00;
    packet[25] = 0x24;
    packet[26] = 0x56;
    packet[27] = 0x78;
    packet[40] = 0x11;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE((rohc[0] & 0x80) == 0x00);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("RTP/UDP-Lite/IP FO CRC failure triggers feedback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    make_valid_rtp(packet, 1000, 1234, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1001, 5678, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    make_valid_rtp(packet, 1002, 9012, 0xCAFEBABE);
    packet[9] = ROHC_IPPROTO_UDPLITE;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE((rohc[0] & 0x80) == 0x00);
    rohc[1] ^= 0x01;

    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("UDP-Lite/IP RFC 5225 profile emits compressed IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
    packet[8] = 64;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x10;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[28] = 0x44;
    packet[10] = 0x00;
    packet[11] = 0x00;
    const uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x08);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("UDP-Lite/IP RFC 5225 profile emits IR-DYN after IR and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
    packet[8] = 64;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x10;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[28] = 0x44;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0xFD);
    REQUIRE(rohc[1] == 0x08);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x33;
    packet[5] = 0x44;
    packet[26] = 0x55;
    packet[27] = 0x66;
    packet[28] = 0x77;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0xF8);
    REQUIRE(rohc[1] == 0x08);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


TEST_CASE("UDP-Lite/IP RFC 5225 profile emits FO after IR-DYN and round-trips")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
    packet[8] = 64;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x2C;
    packet[26] = 0x9A;
    packet[27] = 0xBC;
    packet[28] = 0x44;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x33;
    packet[5] = 0x44;
    packet[26] = 0x55;
    packet[27] = 0x66;
    packet[28] = 0x77;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x55;
    packet[5] = 0x66;
    packet[26] = 0x77;
    packet[27] = 0x88;
    packet[28] = 0x11;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);

    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_len < sizeof(packet) + 1);
    REQUIRE(rohc[0] == 0x77);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(packet));
    REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("UDP-Lite/IP FO CRC failure triggers feedback")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    uint8_t packet[64] = {};
    uint8_t rohc[128] = {};
    uint8_t out[128] = {};
    size_t rohc_len = sizeof(rohc);
    size_t out_len = sizeof(out);

    set_ipv4_protocol(packet, ROHC_IPPROTO_UDPLITE);
    packet[8] = 64;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x2C;
    packet[10] = 0x00;
    packet[11] = 0x00;
    uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x33;
    packet[5] = 0x44;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);

    packet[4] = 0x55;
    packet[5] = 0x66;
    packet[10] = 0x00;
    packet[11] = 0x00;
    csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<uint8_t>(csum >> 8);
    packet[11] = static_cast<uint8_t>(csum & 0xFF);
    rohc_len = sizeof(rohc);
    out_len = sizeof(out);
    REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
    REQUIRE(rohc[0] == 0x77);
    rohc[1] ^= 0x01;

    REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("Lower-layer RFC 5225 profile families round-trip through IP-only compression")
{
    SECTION("AH is preserved by IP-only compression")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_AH);
        packet[8] = 64;
        packet[20] = 0x11;
        packet[21] = 0x22;
        packet[10] = 0x00;
        packet[11] = 0x00;
        const uint16_t csum = ipv4_checksum(packet, 20);
        packet[10] = static_cast<uint8_t>(csum >> 8);
        packet[11] = static_cast<uint8_t>(csum & 0xFF);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::IP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("GRE is preserved by IP-only compression")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_GRE);
        packet[8] = 64;
        packet[20] = 0x20;
        packet[21] = 0x00;
        packet[10] = 0x00;
        packet[11] = 0x00;
        const uint16_t csum = ipv4_checksum(packet, 20);
        packet[10] = static_cast<uint8_t>(csum >> 8);
        packet[11] = static_cast<uint8_t>(csum & 0xFF);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::IP);
        require_exact_roundtrip(packet, sizeof(packet));
    }

    SECTION("MINE is preserved by IP-only compression")
    {
        uint8_t packet[64] = {};
        set_ipv4_protocol(packet, ROHC_IPPROTO_MINE);
        packet[8] = 64;
        packet[20] = 0x30;
        packet[21] = 0x00;
        packet[10] = 0x00;
        packet[11] = 0x00;
        const uint16_t csum = ipv4_checksum(packet, 20);
        packet[10] = static_cast<uint8_t>(csum >> 8);
        packet[11] = static_cast<uint8_t>(csum & 0xFF);
        REQUIRE(rohccxx::classify_packet(packet, sizeof(packet)) == rohccxx::Profile::IP);
        require_exact_roundtrip(packet, sizeof(packet));
    }
}

TEST_CASE("ROHCoIPsec RFC 5856-5858 enablement supports NONE integrity")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    REQUIRE(rohc_comp_enable_rohcoipsec(nullptr) == -1);
    REQUIRE(rohc_decomp_enable_rohcoipsec(nullptr) == -1);
    REQUIRE(rohc_comp_enable_rohcoipsec(comp) == 0);
    REQUIRE(rohc_decomp_enable_rohcoipsec(decomp) == 0);
    REQUIRE(rohc_comp_rohcoipsec_next_header(comp) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_decomp_rohcoipsec_requires_decompression(decomp, ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

TEST_CASE("IPv6 ROHCv2 RTP paths compress and round-trip")
{
    uint8_t packet[80] = {};
    make_valid_ipv6_rtp(packet, sizeof(packet), 1000, 1234, 0xCAFEBABE);
    require_exact_roundtrip(packet, sizeof(packet));
}


namespace
{

enum class ParityProfile
{
    Rtp,
    Udp,
    Esp,
    Ip,
    RtpUdpLite,
    UdpLite
};

void make_profile_parity_packet(ParityProfile profile, std::uint8_t* packet, std::uint16_t seq, std::uint32_t ts)
{
    make_crc_profile_packet(static_cast<CrcProfile>(profile), packet, seq, ts);
}


void make_valid_ipv6_profile_packet(ParityProfile profile, uint8_t* packet, size_t packet_len)
{
    make_valid_ipv6_rtp(packet, packet_len, 1000, 1234, 0xCAFEBABE);
    const size_t udp_offset = 40;
    const size_t rtp_offset = 48;

    switch(profile)
    {
    case ParityProfile::Rtp:
        break;
    case ParityProfile::Udp:
        packet[rtp_offset] = 0x00;
        break;
    case ParityProfile::Esp:
        packet[6] = ROHC_IPPROTO_ESP;
        packet[40] = 0xDE;
        packet[41] = 0xAD;
        packet[42] = 0xBE;
        packet[43] = 0xEF;
        break;
    case ParityProfile::Ip:
        packet[6] = ROHC_IPPROTO_TCP;
        packet[40] = 0x45;
        packet[41] = 0x00;
        packet[42] = 0x00;
        packet[43] = 0x28;
        break;
    case ParityProfile::RtpUdpLite:
        packet[6] = ROHC_IPPROTO_UDPLITE;
        packet[udp_offset + 4] = 0x00;
        packet[udp_offset + 5] = 0x20;
        packet[udp_offset + 6] = 0x9A;
        packet[udp_offset + 7] = 0xBC;
        break;
    case ParityProfile::UdpLite:
        packet[6] = ROHC_IPPROTO_UDPLITE;
        packet[rtp_offset] = 0x00;
        packet[udp_offset + 4] = 0x00;
        packet[udp_offset + 5] = 0x20;
        packet[udp_offset + 6] = 0x9A;
        packet[udp_offset + 7] = 0xBC;
        break;
    }
}

TEST_CASE("IPv6 ROHCv2 supported profile families compress and round-trip")
{
    const ParityProfile profiles[] = {
        ParityProfile::Rtp,
        ParityProfile::Udp,
        ParityProfile::Esp,
        ParityProfile::Ip,
        ParityProfile::RtpUdpLite,
        ParityProfile::UdpLite,
    };

    for(ParityProfile profile : profiles)
    {
        uint8_t packet[80] = {};
        make_valid_ipv6_profile_packet(profile, packet, sizeof(packet));
        require_exact_roundtrip(packet, sizeof(packet));
    }
}


std::uint32_t fnv1a32(const std::uint8_t* data, size_t len)
{
    std::uint32_t hash = 2166136261U;
    for(size_t i = 0; i < len; ++i)
    {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

struct Ipv6TraceFixture
{
    ParityProfile profile;
    const char* name;
    size_t expected_len[3];
    std::uint32_t expected_hash[3];
};

static constexpr Ipv6TraceFixture ipv6_trace_fixtures[] = {
    {ParityProfile::Rtp, "IPv6 RTP/UDP/IP", {84, 41, 25}, {0x60B9A434U, 0x8763D373U, 0x2A4F555BU}},
    {ParityProfile::Udp, "IPv6 UDP/IP", {83, 44, 38}, {0x40661FBDU, 0x9EA29B8DU, 0xE796A23BU}},
    {ParityProfile::Esp, "IPv6 ESP/IP", {85, 50, 44}, {0xECE52491U, 0x55B2BD0CU, 0xE7AC098CU}},
    {ParityProfile::Ip, "IPv6 IP-only", {85, 50, 44}, {0xE4E4E154U, 0xA230CC88U, 0x8F543C06U}},
    {ParityProfile::RtpUdpLite, "IPv6 RTP/UDP-Lite/IP", {86, 43, 25}, {0xBC53256AU, 0x378AA1A6U, 0x2A4F555BU}},
    {ParityProfile::UdpLite, "IPv6 UDP-Lite/IP", {85, 46, 40}, {0x45CA8475U, 0xD5B9DECAU, 0x40B3AF3AU}},
};

TEST_CASE("IPv6 ROHCv2 supported profile families have deterministic trace fingerprints")
{
    for(const auto& fixture : ipv6_trace_fixtures)
    {
        CAPTURE(fixture.name);
        rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
        REQUIRE(comp != nullptr);
        REQUIRE(decomp != nullptr);

        for(int i = 0; i < 3; ++i)
        {
            std::uint8_t packet[80] = {};
            std::uint8_t rohc[160] = {};
            std::uint8_t out[160] = {};
            size_t rohc_len = sizeof(rohc);
            size_t out_len = sizeof(out);

            make_valid_ipv6_profile_packet(fixture.profile, packet, sizeof(packet));
            CAPTURE(i);
            REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
            REQUIRE(rohc_len == fixture.expected_len[i]);
            REQUIRE(fnv1a32(rohc, rohc_len) == fixture.expected_hash[i]);
            REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
            REQUIRE(out_len == sizeof(packet));
            REQUIRE(std::memcmp(out, packet, sizeof(packet)) == 0);
        }

        rohc_decomp_free(decomp);
        rohc_comp_free(comp);
    }
}


void require_profile_parity_output(ParityProfile profile,
                                   const std::uint8_t* expected,
                                   const std::uint8_t* actual,
                                   size_t len)
{
    REQUIRE(len == 64);
    REQUIRE(actual[0] == 0x45);
    REQUIRE(actual[2] == expected[2]);
    REQUIRE(actual[3] == expected[3]);
    REQUIRE(actual[4] == expected[4]);
    REQUIRE(actual[5] == expected[5]);
    REQUIRE(actual[8] == expected[8]);
    REQUIRE(actual[9] == expected[9]);
    REQUIRE(std::memcmp(actual + 12, expected + 12, 8) == 0);

    switch(profile)
    {
    case ParityProfile::Rtp:
    case ParityProfile::RtpUdpLite:
        REQUIRE(std::memcmp(actual + 20, expected + 20, 8) == 0);
        REQUIRE(std::memcmp(actual + 30, expected + 30, 10) == 0);
        REQUIRE(std::memcmp(actual + 40, expected + 40, 24) == 0);
        break;
    case ParityProfile::Udp:
    case ParityProfile::UdpLite:
        REQUIRE(std::memcmp(actual + 20, expected + 20, 8) == 0);
        REQUIRE(std::memcmp(actual + 28, expected + 28, 36) == 0);
        break;
    case ParityProfile::Esp:
    case ParityProfile::Ip:
        REQUIRE(std::memcmp(actual + 20, expected + 20, 44) == 0);
        break;
    }
}

void require_profile_parity_trace(ParityProfile profile)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    for(int i = 0; i < 3; ++i)
    {
        std::uint8_t packet[64] = {};
        std::uint8_t rohc[128] = {};
        std::uint8_t out[128] = {};
        size_t rohc_len = sizeof(rohc);
        size_t out_len = sizeof(out);

        make_profile_parity_packet(profile,
                                   packet,
                                   static_cast<std::uint16_t>(1000 + i),
                                   static_cast<std::uint32_t>(1234 + i));
        REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(packet));
        require_profile_parity_output(profile, packet, out, out_len);
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}


static constexpr std::uint8_t rtp_trace_0[] = {
    0xFD, 0x01, 0x9D, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x12, 0x34, 0x56, 0x78, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x04,
    0xD2, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};
static constexpr std::uint8_t rtp_trace_1[] = {
    0xF8, 0x01, 0x1F, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x03, 0xE9, 0x00, 0x00, 0x04, 0xD3, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t rtp_trace_2[] = {
    0x00, 0x6A, 0xB5, 0x00, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t udp_trace_0[] = {
    0xFD, 0x02, 0x51, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x04, 0xD2, 0xCA, 0xFE,
    0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};
static constexpr std::uint8_t udp_trace_1[] = {
    0xF8, 0x02, 0x76, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0xE9, 0x00, 0x00, 0x04, 0xD3, 0xCA, 0xFE, 0xBA, 0xBE, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t udp_trace_2[] = {
    0x7A, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xEA, 0x00, 0x00,
    0x04, 0xD4, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t esp_trace_0[] = {
    0xFD, 0x03, 0x1D, 0x40, 0x32, 0xCB, 0x00, 0x71, 0x01, 0xCB, 0x00, 0x71,
    0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t esp_trace_1[] = {
    0xF8, 0x03, 0x21, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE,
    0xEF, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t esp_trace_2[] = {
    0x78, 0x4E, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0xEA,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t ip_trace_0[] = {
    0xFD, 0x04, 0x87, 0x40, 0x06, 0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64,
    0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t ip_trace_1[] = {
    0xF8, 0x04, 0x91, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t ip_trace_2[] = {
    0x79, 0xC2, 0x00, 0x00, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t rtp_udp_lite_trace_0[] = {
    0xFD, 0x07, 0x8A, 0x40, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x12, 0x34, 0x56, 0x78, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x9A, 0xBC, 0x80, 0x00, 0x03, 0xE8, 0x00,
    0x00, 0x04, 0xD2, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t rtp_udp_lite_trace_1[] = {
    0xF8, 0x07, 0x23, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x9A,
    0xBC, 0x80, 0x00, 0x03, 0xE9, 0x00, 0x00, 0x04, 0xD3, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t rtp_udp_lite_trace_2[] = {
    0x00, 0x6A, 0xB5, 0x00, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t udp_lite_trace_0[] = {
    0xFD, 0x08, 0x08, 0x40, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x9A, 0xBC, 0x04, 0x44, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
static constexpr std::uint8_t udp_lite_trace_1[] = {
    0xF8, 0x08, 0x79, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x9A,
    0xBC, 0x44, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
};
static constexpr std::uint8_t udp_lite_trace_2[] = {
    0x77, 0xEE, 0x00, 0x00, 0x00, 0x10, 0x9A, 0xBC, 0x44, 0xEA, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct ProfileParityFixture
{
    ParityProfile profile;
    const char* name;
    const std::uint8_t* expected[3];
    size_t expected_len[3];
};

static constexpr ProfileParityFixture profile_parity_fixtures[] = {
    {
        ParityProfile::Rtp,
        "RTP/UDP/IP",
        {rtp_trace_0, rtp_trace_1, rtp_trace_2},
        {sizeof(rtp_trace_0), sizeof(rtp_trace_1), sizeof(rtp_trace_2)},
    },
    {
        ParityProfile::Udp,
        "UDP/IP",
        {udp_trace_0, udp_trace_1, udp_trace_2},
        {sizeof(udp_trace_0), sizeof(udp_trace_1), sizeof(udp_trace_2)},
    },
    {
        ParityProfile::Esp,
        "ESP/IP",
        {esp_trace_0, esp_trace_1, esp_trace_2},
        {sizeof(esp_trace_0), sizeof(esp_trace_1), sizeof(esp_trace_2)},
    },
    {
        ParityProfile::Ip,
        "IP-only",
        {ip_trace_0, ip_trace_1, ip_trace_2},
        {sizeof(ip_trace_0), sizeof(ip_trace_1), sizeof(ip_trace_2)},
    },
    {
        ParityProfile::RtpUdpLite,
        "RTP/UDP-Lite/IP",
        {rtp_udp_lite_trace_0, rtp_udp_lite_trace_1, rtp_udp_lite_trace_2},
        {sizeof(rtp_udp_lite_trace_0),
         sizeof(rtp_udp_lite_trace_1),
         sizeof(rtp_udp_lite_trace_2)},
    },
    {
        ParityProfile::UdpLite,
        "UDP-Lite/IP",
        {udp_lite_trace_0, udp_lite_trace_1, udp_lite_trace_2},
        {sizeof(udp_lite_trace_0), sizeof(udp_lite_trace_1), sizeof(udp_lite_trace_2)},
    },
};

void require_profile_parity_fixture(const ProfileParityFixture& fixture)
{
    CAPTURE(fixture.name);
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    for(int i = 0; i < 3; ++i)
    {
        std::uint8_t packet[64] = {};
        std::uint8_t rohc[128] = {};
        std::uint8_t out[128] = {};
        size_t rohc_len = sizeof(rohc);
        size_t out_len = sizeof(out);

        make_profile_parity_packet(fixture.profile,
                                   packet,
                                   static_cast<std::uint16_t>(1000 + i),
                                   static_cast<std::uint32_t>(1234 + i));
        CAPTURE(i);
        REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
        REQUIRE(rohc_len == fixture.expected_len[i]);
        REQUIRE(std::memcmp(rohc, fixture.expected[i], rohc_len) == 0);
        REQUIRE(rohc_decompress4(decomp, fixture.expected[i], fixture.expected_len[i], out, &out_len) == 0);
        REQUIRE(out_len == sizeof(packet));
        require_profile_parity_output(fixture.profile, packet, out, out_len);
    }

    std::uint8_t bad[128] = {};
    std::memcpy(bad, fixture.expected[2], fixture.expected_len[2]);
    bad[1] ^= 0x01;
    std::uint8_t out[128] = {};
    size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, bad, fixture.expected_len[2], out, &out_len) != 0);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}

} // namespace

TEST_CASE("RFC 5225 supported profiles have encoder decoder parity traces")
{
    for(const auto& fixture : profile_parity_fixtures)
    {
        require_profile_parity_trace(fixture.profile);
        require_profile_parity_fixture(fixture);
    }
}
