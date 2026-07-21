// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <rohccxx.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

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

void make_rtp(std::uint8_t* packet, std::uint16_t seq, std::uint32_t ts, std::uint32_t ssrc)
{
    std::memset(packet, 0, 64);
    packet[0] = 0x45;
    packet[2] = 0x00;
    packet[3] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 192;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    const std::uint16_t ip_sum = checksum_ipv4_header(packet, 20);
    packet[10] = static_cast<std::uint8_t>(ip_sum >> 8);
    packet[11] = static_cast<std::uint8_t>(ip_sum & 0xFFU);
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[24] = 0x00;
    packet[25] = 0x2C;
    packet[26] = 0x00;
    packet[27] = 0x00;
    packet[28] = 0x80;
    packet[29] = 96;
    packet[30] = static_cast<std::uint8_t>(seq >> 8);
    packet[31] = static_cast<std::uint8_t>(seq & 0xFFU);
    packet[32] = static_cast<std::uint8_t>(ts >> 24);
    packet[33] = static_cast<std::uint8_t>(ts >> 16);
    packet[34] = static_cast<std::uint8_t>(ts >> 8);
    packet[35] = static_cast<std::uint8_t>(ts & 0xFFU);
    packet[36] = static_cast<std::uint8_t>(ssrc >> 24);
    packet[37] = static_cast<std::uint8_t>(ssrc >> 16);
    packet[38] = static_cast<std::uint8_t>(ssrc >> 8);
    packet[39] = static_cast<std::uint8_t>(ssrc & 0xFFU);
    for(std::size_t i = 40; i < 64; ++i)
        packet[i] = static_cast<std::uint8_t>(0xA0U + (i & 0x0FU));
}

void print_hex(const char* label, const std::uint8_t* data, std::size_t len)
{
    std::printf(" %s=", label);
    for(std::size_t i = 0; i < len; ++i)
        std::printf("%02x", data[i]);
}

rohccxx_lla_contract_t complete_contract()
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
    return contract;
}

rohccxx_lla_flow_t complete_flow()
{
    rohccxx_lla_flow_t flow{};
    flow.ipv4_udp_rtp = 1;
    flow.udp_checksum_disabled = 1;
    flow.rtp_sequence_increments_by_one = 1;
    flow.compressor_observed_in_order = 1;
    flow.synchronized_timing = 1;
    return flow;
}

} // namespace

int main()
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    if(!comp)
        return 1;
    auto contract = complete_contract();
    auto flow = complete_flow();
    if(rohc_comp_enable_rfc4362_lla(comp, &contract, &flow) != 0)
        return 1;

    std::uint8_t ip1[64] = {};
    std::uint8_t ip2[64] = {};
    std::uint8_t ip3[64] = {};
    make_rtp(ip1, 7000, 112000, 0xA1A2A3A4U);
    make_rtp(ip2, 7001, 112160, 0xA1A2A3A4U);
    make_rtp(ip3, 7002, 112320, 0xA1A2A3A4U);

    std::uint8_t rohc[160] = {};
    std::size_t rohc_len = sizeof(rohc);
    if(rohc_compress4(comp, ip1, sizeof(ip1), rohc, &rohc_len) != 0)
        return 1;
    std::printf("rohccxx-rfc4362-oracle-corpus-v1 cases=5 encoding=hex\n");
    std::printf("case kind=ir");
    print_hex("rohc", rohc, rohc_len);
    print_hex("ip", ip1, sizeof(ip1));
    std::printf("\n");

    rohc_len = sizeof(rohc);
    if(rohc_compress4(comp, ip2, sizeof(ip2), rohc, &rohc_len) != 0)
        return 1;
    std::printf("case kind=irdyn");
    print_hex("rohc", rohc, rohc_len);
    print_hex("ip", ip2, sizeof(ip2));
    std::printf("\n");

    std::uint8_t nhp[1] = {};
    std::size_t nhp_len = sizeof(nhp);
    if(rohc_comp_rfc4362_emit_nhp(comp, ip3, sizeof(ip3), nhp, &nhp_len) != 0)
        return 1;
    std::printf("case kind=nhp");
    print_hex("payload", ip3 + 40, sizeof(ip3) - 40);
    print_hex("expected_ip", ip3, sizeof(ip3));
    std::printf("\n");

    std::uint8_t csp[200] = {};
    std::size_t csp_len = sizeof(csp);
    if(rohc_comp_rfc4362_emit_csp(comp, ip3, sizeof(ip3), csp, &csp_len) != 0)
        return 1;
    std::printf("case kind=csp");
    print_hex("csp", csp, csp_len);
    print_hex("ip", ip3, sizeof(ip3));
    std::printf("\n");

    std::uint8_t ccp[8] = {};
    std::size_t ccp_len = sizeof(ccp);
    if(rohc_comp_rfc4362_emit_ccp(comp, ccp, &ccp_len) != 0)
        return 1;
    std::printf("case kind=ccp");
    print_hex("ccp", ccp, ccp_len);
    std::printf("\n");

    rohc_comp_free(comp);
    return 0;
}
