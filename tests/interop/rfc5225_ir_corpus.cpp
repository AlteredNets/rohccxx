// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "rohccxx/core/emit_ir_dyn.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/core/rfc5225_grammar.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace
{

struct ProfileSpec
{
    rohccxx::Profile profile;
    std::uint8_t protocol;
    std::uint8_t profile_id;
    const char* name;
    bool (*emit_ir)(std::uint8_t*, std::size_t*, const rohccxx::Context&);
    bool (*emit_ir_dyn)(std::uint8_t*, std::size_t*, const rohccxx::Context&);
};

struct CidSpec
{
    const char* name;
    std::uint32_t cid;
    bool large_cid;
};

rohccxx::Context make_context(rohccxx::Profile profile, std::uint8_t protocol)
{
    rohccxx::Context ctx{};
    ctx.cid = 0;
    ctx.profile = profile;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_tos = 0x22;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x1234;
    ctx.ipv4_flags = 0x02;
    ctx.ipv4_protocol = protocol;
    ctx.ipv4_saddr = 0xC0000201;
    ctx.ipv4_daddr = 0xC6336402;
    ctx.udp_sport = 0x1234;
    ctx.udp_dport = 0x5678;
    ctx.udp_length_or_coverage = 0x0020;
    ctx.udp_check = 0x9ABC;
    ctx.rtp.vpxcc = 0x80;
    ctx.rtp.mpt = 0xE0;
    ctx.rtp.last_seq = 0x2345;
    ctx.rtp.last_ts = 0x01020304;
    ctx.rtp.ssrc = 0x11223344;
    return ctx;
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

bool emit_case(const ProfileSpec& profile,
               const CidSpec& cid,
               const char* packet,
               bool (*emit)(std::uint8_t*, std::size_t*, const rohccxx::Context&))
{
    rohccxx::Context ctx = make_context(profile.profile, profile.protocol);
    ctx.cid = cid.cid;
    ctx.large_cid = cid.large_cid;

    std::uint8_t rohc[192] = {};
    std::size_t rohc_len = sizeof(rohc);
    if(!emit(rohc, &rohc_len, ctx))
        return false;

    rohccxx::ParsedRohcPacket parsed{};
    if(!rohccxx::parse_rohc_packet(rohc, rohc_len, parsed, cid.large_cid))
        return false;
    if(parsed.cid != cid.cid || parsed.profile_id != profile.profile_id)
        return false;
    if(packet[0] == 'i' && packet[1] == 'r' && packet[2] == '\0' && parsed.type != rohccxx::RohcPacketType::IR)
        return false;
    if(packet[0] == 'i' && packet[1] == 'r' && packet[2] == '_' && parsed.type != rohccxx::RohcPacketType::IR_DYN)
        return false;

    std::printf("case id=5225-%s-%s-current.cid-%s profile=%s packet=%s cid=%u cid_mode=%s rohc_len=%zu rohc=",
                profile.name,
                packet,
                cid.name,
                profile.name,
                packet,
                static_cast<unsigned>(cid.cid),
                cid.large_cid ? "large" : (cid.cid == 0 ? "small" : "add"),
                rohc_len);
    print_hex(rohc, rohc_len);
    std::putchar('\n');
    return true;
}

} // namespace

int main()
{
    const ProfileSpec profiles[] = {
        {rohccxx::Profile::RTP, 17, 0x01, "rtp_udp_ip", rohccxx::emit_ir_rtp, rohccxx::emit_ir_dyn_rtp},
        {rohccxx::Profile::UDP, 17, 0x02, "udp_ip", rohccxx::emit_ir_udp, rohccxx::emit_ir_dyn_udp},
        {rohccxx::Profile::ESP, 50, 0x03, "esp_ip", rohccxx::emit_ir_esp, rohccxx::emit_ir_dyn_esp},
        {rohccxx::Profile::IP, 6, 0x04, "ip_only", rohccxx::emit_ir_ip, rohccxx::emit_ir_dyn_ip},
        {rohccxx::Profile::RTP_UDP_Lite, 136, 0x07, "rtp_udplite_ip", rohccxx::emit_ir_rtp_udp_lite, rohccxx::emit_ir_dyn_rtp_udp_lite},
        {rohccxx::Profile::UDP_Lite, 136, 0x08, "udplite_ip", rohccxx::emit_ir_udp_lite, rohccxx::emit_ir_dyn_udp_lite},
    };
    const CidSpec cids[] = {
        {"small0", 0, false},
        {"add1", 1, false},
        {"add15", rohccxx::cid::small_cid_max, false},
        {"large0", 0, true},
        {"large127", 0x7F, true},
        {"large128", 0x80, true},
        {"large16383", rohccxx::cid::large_cid_max, true},
    };

    constexpr std::size_t case_count = 6U * 7U * 2U;
    std::printf("rohccxx-rfc5225-ir-corpus-v1 profiles=6 cid_cases=7 packets=2 cases=%zu encoding=hex\n",
                case_count);

    for(const auto& profile : profiles)
    {
        for(const auto& cid : cids)
        {
            if(!emit_case(profile, cid, "ir", profile.emit_ir))
                return 1;
            if(!emit_case(profile, cid, "ir_dyn", profile.emit_ir_dyn))
                return 1;
        }
    }

    return 0;
}
