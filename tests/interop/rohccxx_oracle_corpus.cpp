// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <rohccxx.h>
#include "test_packet_helpers.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

enum class OracleProfile
{
    Rtp,
    Udp,
    Esp,
    Ip,
    RtpUdpLite,
    UdpLite,
};

const char* profile_name(OracleProfile profile)
{
    switch(profile)
    {
    case OracleProfile::Rtp: return "rtp_udp_ip";
    case OracleProfile::Udp: return "udp_ip";
    case OracleProfile::Esp: return "esp_ip";
    case OracleProfile::Ip: return "ip_only";
    case OracleProfile::RtpUdpLite: return "rtp_udplite_ip";
    case OracleProfile::UdpLite: return "udplite_ip";
    }
    return "unknown";
}

void finish_ipv4(std::uint8_t* packet)
{
    packet[10] = 0;
    packet[11] = 0;
    const std::uint16_t csum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<std::uint8_t>(csum >> 8);
    packet[11] = static_cast<std::uint8_t>(csum & 0xFFU);
}

void make_oracle_packet(OracleProfile profile, std::uint8_t* packet, std::uint16_t seq, std::uint32_t ts)
{
    make_valid_rtp(packet, seq, ts, 0xCAFEBABEU);
    switch(profile)
    {
    case OracleProfile::Rtp:
        break;
    case OracleProfile::Udp:
        packet[28] = 0x00;
        break;
    case OracleProfile::Esp:
        packet[9] = ROHCCXX_IPPROTO_ESP;
        packet[20] = 0xDE;
        packet[21] = 0xAD;
        packet[22] = 0xBE;
        packet[23] = 0xEF;
        break;
    case OracleProfile::Ip:
        packet[9] = 6;
        packet[20] = 0x45;
        packet[21] = 0x00;
        packet[22] = 0x00;
        packet[23] = 0x28;
        break;
    case OracleProfile::RtpUdpLite:
        packet[9] = 136;
        packet[24] = 0x00;
        packet[25] = 0x20;
        packet[26] = 0x9A;
        packet[27] = 0xBC;
        break;
    case OracleProfile::UdpLite:
        packet[9] = 136;
        packet[28] = 0x00;
        packet[24] = 0x00;
        packet[25] = 0x20;
        packet[26] = 0x9A;
        packet[27] = 0xBC;
        break;
    }
    finish_ipv4(packet);
}

void print_hex(const std::uint8_t* data, std::size_t len)
{
    static constexpr char digits[] = "0123456789abcdef";
    for(std::size_t i = 0; i < len; ++i)
    {
        std::putchar(digits[data[i] >> 4]);
        std::putchar(digits[data[i] & 0x0F]);
    }
}

bool emit_profile(OracleProfile profile)
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    if(!comp || !decomp)
        return false;

    bool ok = true;
    for(int step = 0; step < 3; ++step)
    {
        std::uint8_t ip[64] = {};
        std::uint8_t rohc[128] = {};
        std::uint8_t out[128] = {};
        std::size_t rohc_len = sizeof(rohc);
        std::size_t out_len = sizeof(out);
        make_oracle_packet(profile,
                           ip,
                           static_cast<std::uint16_t>(1000 + step),
                           static_cast<std::uint32_t>(1234 + step));
        if(rohc_compress4(comp, ip, sizeof(ip), rohc, &rohc_len) != 0 ||
           rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) != 0 ||
           out_len != sizeof(ip) || std::memcmp(out, ip, sizeof(ip)) != 0)
        {
            ok = false;
            break;
        }

        std::printf("case profile=%s step=%d ip_len=%zu rohc_len=%zu ip=", profile_name(profile), step, sizeof(ip), rohc_len);
        print_hex(ip, sizeof(ip));
        std::printf(" rohc=");
        print_hex(rohc, rohc_len);
        std::printf("\n");
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
    return ok;
}

} // namespace

int main()
{
    std::puts("rohccxx-oracle-corpus-v1 profiles=6 packets_per_profile=3 encoding=hex");
    const OracleProfile profiles[] = {
        OracleProfile::Rtp,
        OracleProfile::Udp,
        OracleProfile::Esp,
        OracleProfile::Ip,
        OracleProfile::RtpUdpLite,
        OracleProfile::UdpLite,
    };
    for(auto profile : profiles)
    {
        if(!emit_profile(profile))
            return 1;
    }
    return 0;
}
