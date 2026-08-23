// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/decode_esp_fo.hpp"
#include "rohccxx/core/decode_ip_fo.hpp"
#include "rohccxx/core/decode_udp_fo.hpp"
#include "rohccxx/core/decode_udplite_fo.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/feedback.hpp"
#include "rohccxx/core/formal_co.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/core/emit_ir_dyn.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/emit_udplite_fo.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/core/rfc5225_chains.hpp"
#include "rohccxx/core/rfc5225_grammar.hpp"
#include "rohccxx/utils/crc.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <algorithm>

namespace
{

rohccxx::Context grammar_context(rohccxx::Profile profile, std::uint8_t protocol)
{
    rohccxx::Context ctx{};
    ctx.cid = 0;
    ctx.profile = profile;
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.ipv4_tos = 0x22;
    ctx.ipv4_ttl = 63;
    ctx.ipv4_id = 0x1234;
    ctx.ipv4_flags = 0x02;
    ctx.ipv4_id_behavior = 0;
    ctx.ipv4_id_sequential = true;
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
    ctx.msn = ctx.rtp.last_seq;
    ctx.udp_checksum_used = true;
    ctx.esp_spi = 0xDEADBEEF;
    ctx.esp_sequence = 0x00002345;
    return ctx;
}

void configure_rtp_csrc_extension_padding(rohccxx::Context& ctx)
{
    ctx.rtp.vpxcc = 0xB2;
    ctx.rtp.csrc_list_len = 8;
    const std::uint8_t csrcs[] = {0xCA, 0xFE, 0x00, 0x01, 0xCA, 0xFE, 0x00, 0x02};
    std::memcpy(ctx.rtp.csrc_list.data(), csrcs, sizeof(csrcs));

    ctx.rtp.extension_len = 8;
    const std::uint8_t extension[] = {0xBE, 0xDE, 0x00, 0x01, 0xC0, 0xFF, 0xEE, 0x00};
    std::memcpy(ctx.rtp.extension_bytes.data(), extension, sizeof(extension));

    ctx.rtp.padding_len = 4;
    const std::uint8_t padding[] = {0x91, 0x92, 0x93, 0x04};
    std::memcpy(ctx.rtp.padding_bytes.data(), padding, sizeof(padding));
}

void require_rtp_extras_equal(const rohccxx::Context& lhs, const rohccxx::Context& rhs)
{
    REQUIRE(lhs.rtp.csrc_list_len == rhs.rtp.csrc_list_len);
    REQUIRE(std::memcmp(lhs.rtp.csrc_list.data(), rhs.rtp.csrc_list.data(), lhs.rtp.csrc_list_len) == 0);
    REQUIRE(lhs.rtp.extension_len == rhs.rtp.extension_len);
    REQUIRE(std::memcmp(lhs.rtp.extension_bytes.data(), rhs.rtp.extension_bytes.data(), lhs.rtp.extension_len) == 0);
    REQUIRE(lhs.rtp.padding_len == rhs.rtp.padding_len);
    REQUIRE(std::memcmp(lhs.rtp.padding_bytes.data(), rhs.rtp.padding_bytes.data(), lhs.rtp.padding_len) == 0);
}

std::uint16_t read_u16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t read_u32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

void require_crc8_at(std::uint8_t* packet, size_t len, size_t crc_index)
{
    const std::uint8_t received = packet[crc_index];
    packet[crc_index] = 0;
    REQUIRE(rohccxx::utils::crc8(packet, len) == received);
    packet[crc_index] = received;
}

void require_ipv4_static(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx, std::uint8_t protocol)
{
    REQUIRE(packet[pos] == rohccxx::rfc5225::ipv4_static_chain_terminal);
    REQUIRE(packet[pos + 1] == protocol);
    REQUIRE(read_u32(packet + pos + 2) == ctx.ipv4_saddr);
    REQUIRE(read_u32(packet + pos + 6) == ctx.ipv4_daddr);
}

void require_udp_static(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(read_u16(packet + pos) == ctx.udp_sport);
    REQUIRE(read_u16(packet + pos + 2) == ctx.udp_dport);
}

void require_ipv4_dynamic(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(packet[pos] == ctx.ipv4_tos);
    REQUIRE(packet[pos + 1] == ctx.ipv4_ttl);
    REQUIRE(read_u16(packet + pos + 2) == ctx.ipv4_id);
    REQUIRE(packet[pos + 4] == ctx.ipv4_flags);
    REQUIRE(packet[pos + 5] == rohccxx::rfc5225::generic_extension_list_empty);
}

void require_standard_ipv4_dynamic(const std::uint8_t* packet,
                                   size_t pos,
                                   const rohccxx::Context& ctx,
                                   bool endpoint)
{
    const std::uint8_t expected = static_cast<std::uint8_t>(
        (endpoint ? ((ctx.reorder_ratio & 0x03U) << 3U) : 0U) |
        (((ctx.ipv4_flags >> 1U) & 0x01U) << 2U) |
        (ctx.ipv4_id_behavior & 0x03U));
    REQUIRE(packet[pos] == expected);
    REQUIRE(packet[pos + 1] == ctx.ipv4_tos);
    REQUIRE(packet[pos + 2] == ctx.ipv4_ttl);
    REQUIRE(read_u16(packet + pos + 3) == ctx.ipv4_id);
    if(endpoint)
        REQUIRE(read_u16(packet + pos + 5) == ctx.msn);
}

void require_udp_dynamic(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(read_u16(packet + pos) == ctx.udp_check);
}

void require_udp_lite_dynamic(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(read_u16(packet + pos) == ctx.udp_length_or_coverage);
    REQUIRE(read_u16(packet + pos + 2) == ctx.udp_check);
}

void require_rtp_dynamic(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(packet[pos] == static_cast<std::uint8_t>((ctx.reorder_ratio & 0x03U) << 5U));
    REQUIRE(packet[pos + 1] == ctx.rtp.mpt);
    REQUIRE(read_u16(packet + pos + 2) == ctx.rtp.last_seq);
    REQUIRE(read_u32(packet + pos + 4) == ctx.rtp.last_ts);
}

void require_legacy_rtp_dynamic(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(packet[pos] == ctx.rtp.vpxcc);
    REQUIRE(packet[pos + 1] == ctx.rtp.mpt);
    REQUIRE(read_u16(packet + pos + 2) == ctx.rtp.last_seq);
    REQUIRE(read_u32(packet + pos + 4) == ctx.rtp.last_ts);
    REQUIRE(packet[pos + 8] == rohccxx::rfc5225::generic_extension_list_empty);
}

void require_mode_byte(const std::uint8_t* packet, size_t pos, const rohccxx::Context& ctx)
{
    REQUIRE(packet[pos] == static_cast<std::uint8_t>((static_cast<std::uint8_t>(ctx.mode) & 0x03U) << 2));
}


struct GrammarProfileCase
{
    rohccxx::Profile profile;
    std::uint8_t protocol;
    std::uint8_t profile_id;
    bool carries_udp_lite;
    bool (*emit_ir)(std::uint8_t*, size_t*, const rohccxx::Context&);
    bool (*emit_ir_dyn)(std::uint8_t*, size_t*, const rohccxx::Context&);
    bool (*decode_ir)(const std::uint8_t*, size_t, rohccxx::Context&, size_t*);
    bool (*decode_ir_dyn)(const std::uint8_t*, size_t, rohccxx::Context&, size_t*);
};

const GrammarProfileCase grammar_profile_cases[] = {
    {rohccxx::Profile::RTP, 17, 0x01, false, rohccxx::emit_ir_rtp, rohccxx::emit_ir_dyn_rtp, rohccxx::decode_ir_rtp, rohccxx::decode_ir_rtp},
    {rohccxx::Profile::UDP, 17, 0x02, false, rohccxx::emit_ir_udp, rohccxx::emit_ir_dyn_udp, rohccxx::decode_ir_udp, rohccxx::decode_ir_udp},
    {rohccxx::Profile::ESP, 50, 0x03, false, rohccxx::emit_ir_esp, rohccxx::emit_ir_dyn_esp, rohccxx::decode_ir_esp, rohccxx::decode_ir_esp},
    {rohccxx::Profile::IP, 6, 0x04, false, rohccxx::emit_ir_ip, rohccxx::emit_ir_dyn_ip, rohccxx::decode_ir_ip, rohccxx::decode_ir_ip},
    {rohccxx::Profile::RTP_UDP_Lite, 136, 0x07, true, rohccxx::emit_ir_rtp_udp_lite, rohccxx::emit_ir_dyn_rtp_udp_lite, rohccxx::decode_ir_rtp_udp_lite, rohccxx::decode_ir_dyn_rtp_udp_lite},
    {rohccxx::Profile::UDP_Lite, 136, 0x08, true, rohccxx::emit_ir_udp_lite, rohccxx::emit_ir_dyn_udp_lite, rohccxx::decode_ir_udp_lite, rohccxx::decode_ir_dyn_udp_lite},
};

size_t emit_legacy_ir_fixture(std::uint8_t* out,
                              size_t capacity,
                              const rohccxx::Context& ctx,
                              std::uint8_t profile_id)
{
    REQUIRE(capacity >= 256U);
    std::uint8_t* p = out;
    *p++ = 0xFD;
    *p++ = profile_id;
    std::uint8_t* crc = p++;
    rohccxx::rfc5225::write_ip_static_with_protocol(p, ctx, ctx.ipv4_protocol);
    if(ctx.profile == rohccxx::Profile::UDP || ctx.profile == rohccxx::Profile::UDP_Lite ||
       ctx.profile == rohccxx::Profile::RTP || ctx.profile == rohccxx::Profile::RTP_UDP_Lite)
        rohccxx::rfc5225::write_udp_static(p, ctx);
    if(ctx.profile == rohccxx::Profile::RTP || ctx.profile == rohccxx::Profile::RTP_UDP_Lite)
        rohccxx::rfc5225::write_rtp_static(p, ctx);
    rohccxx::rfc5225::write_ip_dynamic(p, ctx);
    if(ctx.profile == rohccxx::Profile::UDP || ctx.profile == rohccxx::Profile::RTP)
        rohccxx::rfc5225::write_udp_dynamic(p, ctx);
    else if(ctx.profile == rohccxx::Profile::UDP_Lite || ctx.profile == rohccxx::Profile::RTP_UDP_Lite)
        rohccxx::rfc5225::write_udp_lite_dynamic(p, ctx);
    if(ctx.profile == rohccxx::Profile::RTP || ctx.profile == rohccxx::Profile::RTP_UDP_Lite)
        REQUIRE(rohccxx::rfc5225::write_rtp_dynamic(p, out + capacity, ctx));
    *crc = rohccxx::utils::crc8(out, static_cast<size_t>(p - out));
    *p++ = static_cast<std::uint8_t>(static_cast<std::uint8_t>(ctx.mode) << 2U);
    return static_cast<size_t>(p - out);
}

bool decode_legacy_fixture(const GrammarProfileCase& item,
                           const std::uint8_t* packet,
                           size_t packet_len,
                           rohccxx::Context& ctx)
{
    switch(item.profile)
    {
    case rohccxx::Profile::RTP:
        return rohccxx::decode_ir_rtp_legacy(packet, packet_len, ctx, nullptr);
    case rohccxx::Profile::UDP:
        return rohccxx::decode_ir_udp_legacy(packet, packet_len, ctx, nullptr);
    case rohccxx::Profile::ESP:
        return rohccxx::decode_ir_esp_legacy(packet, packet_len, ctx, nullptr);
    case rohccxx::Profile::IP:
        return rohccxx::decode_ir_ip_legacy(packet, packet_len, ctx, nullptr);
    case rohccxx::Profile::RTP_UDP_Lite:
        return rohccxx::decode_ir_rtp_udp_lite_legacy(packet, packet_len, ctx, nullptr);
    case rohccxx::Profile::UDP_Lite:
        return rohccxx::decode_ir_udp_lite_legacy(packet, packet_len, ctx, nullptr);
    default:
        return false;
    }
}

enum class CoDecoderKind
{
    Rtp,
    Udp,
    Ip,
    Esp,
    UdpLite,
};

struct CoProfileCase
{
    rohccxx::Profile profile;
    std::uint8_t protocol;
    rohccxx::RohcPacketType packet_type;
    const char* current_variant_id;
    bool rtp_family;
    bool (*emit_co)(std::uint8_t*, size_t*, const rohccxx::Context&);
    CoDecoderKind decoder;
};

const CoProfileCase co_profile_cases[] = {
    {rohccxx::Profile::RTP, 17, rohccxx::RohcPacketType::FO_RTP, "5225-rtp-co-current-fo", true, rohccxx::emit_rtp_fo, CoDecoderKind::Rtp},
    {rohccxx::Profile::UDP, 17, rohccxx::RohcPacketType::FO_UDP, "5225-udp-co-current-fo", false, rohccxx::emit_udp_fo, CoDecoderKind::Udp},
    {rohccxx::Profile::ESP, 50, rohccxx::RohcPacketType::FO_ESP, "5225-esp-co-current-fo", false, rohccxx::emit_esp_fo, CoDecoderKind::Esp},
    {rohccxx::Profile::IP, 6, rohccxx::RohcPacketType::FO_IP, "5225-ip-co-current-fo", false, rohccxx::emit_ip_fo, CoDecoderKind::Ip},
    {rohccxx::Profile::RTP_UDP_Lite, 136, rohccxx::RohcPacketType::FO_RTP, "5225-rtp-udplite-co-current-fo", true, rohccxx::emit_rtp_fo, CoDecoderKind::Rtp},
    {rohccxx::Profile::UDP_Lite, 136, rohccxx::RohcPacketType::FO_UDP_Lite, "5225-udplite-co-current-fo", false, rohccxx::emit_udp_lite_fo, CoDecoderKind::UdpLite},
};

bool prepend_add_cid_for_co(std::uint8_t* packet, size_t& len, size_t capacity, std::uint32_t cid)
{
    if(cid == 0)
        return true;
    if(!packet || cid > rohccxx::cid::small_cid_max || len + 1U > capacity)
        return false;
    std::memmove(packet + 1, packet, len);
    packet[0] = static_cast<std::uint8_t>(0xE0U | (cid & 0x0FU));
    ++len;
    return true;
}

bool emit_co_wire_for_test(const CoProfileCase& profile,
                           const rohccxx::Context& ctx,
                           std::uint8_t* out,
                           size_t& len)
{
    const size_t capacity = len;
    if(!profile.emit_co(out, &len, ctx))
        return false;
    if(!profile.rtp_family && !ctx.large_cid && ctx.cid > 0)
        return prepend_add_cid_for_co(out, len, capacity, ctx.cid);
    return true;
}

bool decode_co_wire_for_test(const CoProfileCase& profile,
                             const std::uint8_t* packet,
                             size_t packet_len,
                             rohccxx::Context& ctx,
                             size_t& consumed)
{
    switch(profile.decoder)
    {
    case CoDecoderKind::Rtp:
    {
        std::uint16_t seq = 0;
        std::uint32_t ts = 0;
        return rohccxx::decode_fo_rtp(packet, packet_len, ctx, seq, ts, &consumed);
    }
    case CoDecoderKind::Udp:
        return rohccxx::decode_udp_fo(packet, packet_len, ctx, &consumed);
    case CoDecoderKind::Ip:
        return rohccxx::decode_ip_fo(packet, packet_len, ctx, &consumed);
    case CoDecoderKind::Esp:
        return rohccxx::decode_esp_fo(packet, packet_len, ctx, &consumed);
    case CoDecoderKind::UdpLite:
        return rohccxx::decode_udp_lite_fo(packet, packet_len, ctx, &consumed);
    }
    return false;
}

size_t co_crc_mutation_index(const CoProfileCase& profile,
                             const rohccxx::ParsedRohcPacket& parsed,
                             const std::uint8_t* wire,
                             size_t wire_len)
{
    if(profile.rtp_family)
        return wire_len - 1U;
    return static_cast<size_t>(parsed.packet - wire) + 1U + parsed.cid_len;
}

struct GeneratedCidCase
{
    std::uint32_t cid;
    bool large_cid;
    size_t expected_cid_len;
};

const GeneratedCidCase generated_cid_cases[] = {
    {0, false, 0},
    {1, false, 0},
    {rohccxx::cid::small_cid_max, false, 0},
    {0, true, 1},
    {0x7F, true, 1},
    {0x80, true, 2},
    {rohccxx::cid::large_cid_max, true, 2},
};

size_t ir_crc_index_for_parsed(const rohccxx::ParsedRohcPacket& parsed, const std::uint8_t* wire)
{
    return static_cast<size_t>(parsed.packet - wire) + 2U + parsed.cid_len;
}

bool decode_generated_ir_case(const GrammarProfileCase& profile,
                              bool dynamic_packet,
                              const std::uint8_t* wire,
                              size_t wire_len,
                              const GeneratedCidCase& cid_case)
{
    rohccxx::Context decoded = grammar_context(profile.profile, profile.protocol);
    decoded.cid = cid_case.cid;
    decoded.large_cid = cid_case.large_cid;
    size_t consumed = 0;
    const bool ok = dynamic_packet
        ? profile.decode_ir_dyn(wire, wire_len, decoded, &consumed)
        : profile.decode_ir(wire, wire_len, decoded, &consumed);
    return ok && consumed == wire_len && decoded.profile == profile.profile && decoded.cid == cid_case.cid;
}

bool decode_generated_co_case(const CoProfileCase& profile,
                              const std::uint8_t* wire,
                              size_t wire_len,
                              const GeneratedCidCase& cid_case)
{
    rohccxx::ParsedRohcPacket parsed{};
    if(!rohccxx::parse_rohc_packet(wire, wire_len, parsed, cid_case.large_cid))
        return false;
    if(parsed.type != profile.packet_type || parsed.cid != cid_case.cid)
        return false;

    rohccxx::Context decoded = grammar_context(profile.profile, profile.protocol);
    decoded.rohc_state = rohccxx::RohcState::DynamicEstablished;
    decoded.cid = cid_case.cid;
    decoded.large_cid = cid_case.large_cid;
    decoded.rtp.seq_window.init(decoded.rtp.last_seq);
    decoded.rtp.ts_window.init(decoded.rtp.last_ts);

    size_t consumed = 0;
    if(!decode_co_wire_for_test(profile, parsed.packet, parsed.packet_len, decoded, consumed))
        return false;
    return consumed == parsed.packet_len && decoded.profile == profile.profile && decoded.cid == cid_case.cid;
}

void require_ir_crc_mutation_rejected(const GrammarProfileCase& profile,
                                      bool dynamic_packet,
                                      const std::uint8_t* wire,
                                      size_t wire_len,
                                      const GeneratedCidCase& cid_case,
                                      size_t mutation_index)
{
    REQUIRE(mutation_index < wire_len);
    std::uint8_t mutated[256] = {};
    std::memcpy(mutated, wire, wire_len);
    mutated[mutation_index] ^= 0x01U;
    REQUIRE_FALSE(decode_generated_ir_case(profile, dynamic_packet, mutated, wire_len, cid_case));
}

void write_be16(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 8U);
    out[1] = static_cast<std::uint8_t>(value & 0xFFU);
}

void write_be32(std::uint8_t* out, std::uint32_t value)
{
    out[0] = static_cast<std::uint8_t>(value >> 24U);
    out[1] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[2] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[3] = static_cast<std::uint8_t>(value & 0xFFU);
}

std::uint16_t ipv4_header_checksum(const std::uint8_t* header)
{
    std::uint32_t sum = 0;
    for(size_t i = 0; i < 20U; i += 2U)
        sum += static_cast<std::uint16_t>((static_cast<std::uint16_t>(header[i]) << 8U) | header[i + 1U]);
    while((sum >> 16U) != 0)
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

size_t build_formal_crc_header_for_test(const GrammarProfileCase& profile,
                                        const rohccxx::Context& ctx,
                                        std::uint16_t msn,
                                        std::uint8_t* out)
{
    const bool rtp = profile.profile == rohccxx::Profile::RTP ||
                     profile.profile == rohccxx::Profile::RTP_UDP_Lite;
    const bool udp = profile.profile == rohccxx::Profile::UDP || rtp;
    const bool udplite = profile.profile == rohccxx::Profile::UDP_Lite ||
                         profile.profile == rohccxx::Profile::RTP_UDP_Lite;
    const bool esp = profile.profile == rohccxx::Profile::ESP;
    const std::uint16_t transport_len = static_cast<std::uint16_t>(
        rtp ? 20U : (udp || udplite || esp ? 8U : 0U));
    const std::uint16_t total_len = static_cast<std::uint16_t>(20U + transport_len);

    std::memset(out, 0, 96);
    out[0] = 0x45;
    out[1] = ctx.ipv4_tos;
    write_be16(out + 2, total_len);
    write_be16(out + 4, static_cast<std::uint16_t>(ctx.ipv4_id + (msn - ctx.rtp.last_seq)));
    out[6] = static_cast<std::uint8_t>((ctx.ipv4_flags & 0x07U) << 5U);
    out[8] = ctx.ipv4_ttl;
    out[9] = profile.protocol;
    write_be32(out + 12, ctx.ipv4_saddr);
    write_be32(out + 16, ctx.ipv4_daddr);
    const std::uint16_t ip_checksum = ipv4_header_checksum(out);
    write_be16(out + 10, ip_checksum);

    size_t pos = 20;
    if(udp || udplite || rtp)
    {
        write_be16(out + pos, ctx.udp_sport);
        write_be16(out + pos + 2U, ctx.udp_dport);
        write_be16(out + pos + 4U, udplite ? ctx.udp_length_or_coverage : transport_len);
        write_be16(out + pos + 6U, ctx.udp_check);
        pos += 8U;
    }
    if(rtp)
    {
        out[pos++] = ctx.rtp.vpxcc;
        out[pos++] = ctx.rtp.mpt;
        write_be16(out + pos, msn);
        pos += 2U;
        write_be32(out + pos, ctx.rtp.last_ts + static_cast<std::uint32_t>(msn - ctx.rtp.last_seq) * 160U);
        pos += 4U;
        write_be32(out + pos, ctx.rtp.ssrc);
        pos += 4U;
    }
    if(esp)
    {
        write_be32(out + pos, 0xA0B0C0D0U);
        write_be32(out + pos + 4U, static_cast<std::uint32_t>(msn));
        pos += 8U;
    }
    return pos;
}

std::uint16_t lsb_mask_for_bits(std::uint8_t bits)
{
    return bits >= 16U ? 0xFFFFU : static_cast<std::uint16_t>((1U << bits) - 1U);
}

size_t formal_base_wire_offset(size_t add_len, size_t cid_len, size_t base_index)
{
    return add_len + (base_index == 0 ? 0U : (1U + cid_len + base_index - 1U));
}

size_t formal_crc_base_index(rohccxx::Profile profile, rohccxx::rfc5225::FormalCoVariant variant)
{
    const bool rtp = rohccxx::rfc5225::is_rtp_formal_co_profile(profile);
    switch(variant)
    {
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc3:
        return 0U;
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc7:
    case rohccxx::rfc5225::FormalCoVariant::Pt1Rnd:
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqTs:
        return 1U;
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqId:
        return rtp ? 1U : 0U;
    case rohccxx::rfc5225::FormalCoVariant::Pt2Rnd:
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqBoth:
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqTs:
        return 2U;
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqId:
        return rtp ? 2U : 1U;
    case rohccxx::rfc5225::FormalCoVariant::CoCommon:
    case rohccxx::rfc5225::FormalCoVariant::CoRepair:
        return 1U;
    }
    return 0U;
}

std::uint8_t formal_crc_mutation_mask(rohccxx::Profile profile, rohccxx::rfc5225::FormalCoVariant variant)
{
    return (!rohccxx::rfc5225::is_rtp_formal_co_profile(profile) &&
            variant == rohccxx::rfc5225::FormalCoVariant::Pt1SeqId) ? 0x04U : 0x01U;
}

void require_formal_discriminator(rohccxx::Profile profile,
                                  rohccxx::rfc5225::FormalCoVariant variant,
                                  std::uint8_t first)
{
    const bool rtp = rohccxx::rfc5225::is_rtp_formal_co_profile(profile);
    switch(variant)
    {
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc3:
        REQUIRE((first & 0x80U) == 0);
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc7:
        if(rtp)
        {
            REQUIRE((first & 0xF0U) == 0x80U);
        }
        else
        {
            REQUIRE((first & 0xE0U) == 0x80U);
        }
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt1Rnd:
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqTs:
        REQUIRE((first & 0xE0U) == 0xA0U);
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqId:
        if(rtp)
        {
            REQUIRE((first & 0xF0U) == 0x90U);
        }
        else
        {
            REQUIRE((first & 0xE0U) == 0xA0U);
        }
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt2Rnd:
        REQUIRE((first & 0xE0U) == 0xC0U);
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqId:
        if(rtp)
        {
            REQUIRE((first & 0xF8U) == 0xC0U);
        }
        else
        {
            REQUIRE((first & 0xE0U) == 0xC0U);
        }
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqBoth:
        REQUIRE((first & 0xF8U) == 0xC8U);
        break;
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqTs:
        REQUIRE((first & 0xF0U) == 0xD0U);
        break;
    case rohccxx::rfc5225::FormalCoVariant::CoCommon:
        REQUIRE(first == 0xFAU);
        break;
    case rohccxx::rfc5225::FormalCoVariant::CoRepair:
        REQUIRE(first == 0xFBU);
        break;
    }
}

const rohccxx::rfc5225::FormalCoVariant formal_pt1_pt2_variants[] = {
    rohccxx::rfc5225::FormalCoVariant::Pt1Rnd,
    rohccxx::rfc5225::FormalCoVariant::Pt1SeqId,
    rohccxx::rfc5225::FormalCoVariant::Pt1SeqTs,
    rohccxx::rfc5225::FormalCoVariant::Pt2Rnd,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqId,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqBoth,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqTs,
};

const std::uint8_t rtp_common_variable[] = {
    0x81, 0x02, 0x80, 0x2A, 0x01, 0x02, 0x03, 0x04
};

const std::uint8_t udp_common_variable[] = {
    0x40, 0x11, 0x12, 0x34, 0x56, 0x78
};

const std::uint8_t esp_common_variable[] = {
    0x50, 0xA0, 0xB0, 0xC0, 0xD0, 0x00, 0x00, 0x23, 0x45
};

const std::uint8_t ip_common_variable[] = {
    0x60, 0x2F, 0x20, 0x01, 0x0D, 0xB8
};

const std::uint8_t rtp_udplite_common_variable[] = {
    0x83, 0x03, 0x88, 0x20, 0x00, 0x18, 0xAA, 0x55
};

const std::uint8_t udplite_common_variable[] = {
    0x48, 0x88, 0x20, 0x00, 0x18, 0x9A, 0xBC
};

const std::uint8_t rtp_repair_dynamic_chain[] = {
    0x22, 0x3F, 0x00, 0x10, 0x80, 0xE0, 0x23, 0x7C
};

const std::uint8_t udp_repair_dynamic_chain[] = {
    0x22, 0x3F, 0x12, 0x81, 0x9A, 0xBC
};

const std::uint8_t esp_repair_dynamic_chain[] = {
    0x22, 0x3F, 0xAA, 0xBB, 0xCC, 0xDD
};

const std::uint8_t ip_repair_dynamic_chain[] = {
    0x22, 0x3F, 0x40, 0x06, 0x12, 0x34
};

const std::uint8_t rtp_udplite_repair_dynamic_chain[] = {
    0x22, 0x3F, 0x88, 0x20, 0x80, 0xE0, 0x23, 0x7C
};

const std::uint8_t udplite_repair_dynamic_chain[] = {
    0x22, 0x3F, 0x88, 0x20, 0x00, 0x18
};

const rohccxx::rfc5225::FormalCoVariant formal_all_variants[] = {
    rohccxx::rfc5225::FormalCoVariant::CoCommon,
    rohccxx::rfc5225::FormalCoVariant::CoRepair,
    rohccxx::rfc5225::FormalCoVariant::Pt0Crc3,
    rohccxx::rfc5225::FormalCoVariant::Pt0Crc7,
    rohccxx::rfc5225::FormalCoVariant::Pt1Rnd,
    rohccxx::rfc5225::FormalCoVariant::Pt1SeqId,
    rohccxx::rfc5225::FormalCoVariant::Pt1SeqTs,
    rohccxx::rfc5225::FormalCoVariant::Pt2Rnd,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqId,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqBoth,
    rohccxx::rfc5225::FormalCoVariant::Pt2SeqTs,
};

rohccxx::rfc5225::FormalCoBytes formal_common_variable_for_profile(rohccxx::Profile profile)
{
    switch(profile)
    {
    case rohccxx::Profile::RTP:
        return {rtp_common_variable, sizeof(rtp_common_variable)};
    case rohccxx::Profile::UDP:
        return {udp_common_variable, sizeof(udp_common_variable)};
    case rohccxx::Profile::ESP:
        return {esp_common_variable, sizeof(esp_common_variable)};
    case rohccxx::Profile::IP:
        return {ip_common_variable, sizeof(ip_common_variable)};
    case rohccxx::Profile::RTP_UDP_Lite:
        return {rtp_udplite_common_variable, sizeof(rtp_udplite_common_variable)};
    case rohccxx::Profile::UDP_Lite:
        return {udplite_common_variable, sizeof(udplite_common_variable)};
    case rohccxx::Profile::Uncompressed:
    case rohccxx::Profile::LLA_RTP:
        return {};
    }
    return {};
}

rohccxx::rfc5225::FormalCoBytes formal_repair_dynamic_chain_for_profile(rohccxx::Profile profile)
{
    switch(profile)
    {
    case rohccxx::Profile::RTP:
        return {rtp_repair_dynamic_chain, sizeof(rtp_repair_dynamic_chain)};
    case rohccxx::Profile::UDP:
        return {udp_repair_dynamic_chain, sizeof(udp_repair_dynamic_chain)};
    case rohccxx::Profile::ESP:
        return {esp_repair_dynamic_chain, sizeof(esp_repair_dynamic_chain)};
    case rohccxx::Profile::IP:
        return {ip_repair_dynamic_chain, sizeof(ip_repair_dynamic_chain)};
    case rohccxx::Profile::RTP_UDP_Lite:
        return {rtp_udplite_repair_dynamic_chain, sizeof(rtp_udplite_repair_dynamic_chain)};
    case rohccxx::Profile::UDP_Lite:
        return {udplite_repair_dynamic_chain, sizeof(udplite_repair_dynamic_chain)};
    case rohccxx::Profile::Uncompressed:
    case rohccxx::Profile::LLA_RTP:
        return {};
    }
    return {};
}

rohccxx::rfc5225::FormalCoCommonFields make_formal_common_fields(rohccxx::Profile profile,
                                                                 const GeneratedCidCase& cid_case)
{
    rohccxx::rfc5225::FormalCoCommonFields fields{};
    fields.variable = formal_common_variable_for_profile(profile);
    fields.ip_id_indicator = true;
    if(rohccxx::rfc5225::is_rtp_formal_co_profile(profile))
    {
        fields.marker = (cid_case.cid & 0x01U) != 0;
        fields.flags1_indicator = true;
        fields.flags2_indicator = (cid_case.cid & 0x02U) != 0;
        fields.tsc_indicator = true;
        fields.tss_indicator = cid_case.large_cid;
    }
    else
    {
        fields.flags_indicator = true;
        fields.ttl_hopl_indicator = (cid_case.cid & 0x01U) != 0;
        fields.tos_tc_indicator = true;
        fields.reorder_ratio = static_cast<std::uint8_t>((cid_case.cid + (cid_case.large_cid ? 1U : 0U)) & 0x03U);
    }
    return fields;
}

rohccxx::rfc5225::FormalCoRepairFields make_formal_repair_fields(rohccxx::Profile profile)
{
    rohccxx::rfc5225::FormalCoRepairFields fields{};
    fields.dynamic_chain = formal_repair_dynamic_chain_for_profile(profile);
    return fields;
}

size_t build_formal_common_control_crc_for_test(rohccxx::Profile profile,
                                                const rohccxx::rfc5225::FormalCoCommonFields& fields,
                                                std::uint8_t* out)
{
    std::memset(out, 0, 32);
    size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(profile);
    if(rohccxx::rfc5225::is_rtp_formal_co_profile(profile))
    {
        out[pos++] = static_cast<std::uint8_t>(
            (fields.flags1_indicator ? 0x80U : 0U) |
            (fields.flags2_indicator ? 0x40U : 0U) |
            (fields.tsc_indicator ? 0x20U : 0U) |
            (fields.tss_indicator ? 0x10U : 0U) |
            (fields.ip_id_indicator ? 0x08U : 0U));
        write_be32(out + pos, 160U);
        pos += 4U;
        write_be32(out + pos, 1000U);
        pos += 4U;
    }
    else
    {
        out[pos++] = static_cast<std::uint8_t>(
            (fields.flags_indicator ? 0x80U : 0U) |
            (fields.ttl_hopl_indicator ? 0x40U : 0U) |
            (fields.tos_tc_indicator ? 0x20U : 0U) |
            ((fields.reorder_ratio & 0x03U) << 3U));
        write_be16(out + pos, 0x2345U);
        pos += 2U;
        if(profile == rohccxx::Profile::UDP_Lite)
            out[pos++] = 0x02U;
    }
    out[pos++] = fields.ip_id_indicator ? 0x01U : 0x00U;
    return pos;
}

size_t build_formal_repair_control_crc_for_test(rohccxx::Profile profile,
                                                const rohccxx::rfc5225::FormalCoRepairFields& fields,
                                                std::uint8_t* out)
{
    std::memset(out, 0, 32);
    size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(profile);
    out[pos++] = static_cast<std::uint8_t>(fields.dynamic_chain.len & 0xFFU);
    if(fields.dynamic_chain.len > 0)
    {
        const size_t copy_len = fields.dynamic_chain.len > 14U ? 14U : fields.dynamic_chain.len;
        std::memcpy(out + pos, fields.dynamic_chain.data, copy_len);
        pos += copy_len;
    }
    return pos;
}

void require_formal_common_fields_equal(const rohccxx::rfc5225::FormalCoCommonFields& expected,
                                        const rohccxx::rfc5225::FormalCoPacket& decoded,
                                        bool rtp_profile)
{
    if(rtp_profile)
    {
        REQUIRE(decoded.marker == expected.marker);
        REQUIRE(decoded.flags1_indicator == expected.flags1_indicator);
        REQUIRE(decoded.flags2_indicator == expected.flags2_indicator);
        REQUIRE(decoded.tsc_indicator == expected.tsc_indicator);
        REQUIRE(decoded.tss_indicator == expected.tss_indicator);
        REQUIRE(decoded.ip_id_indicator == expected.ip_id_indicator);
    }
    else
    {
        REQUIRE(decoded.ip_id_indicator == expected.ip_id_indicator);
        REQUIRE(decoded.flags_indicator == expected.flags_indicator);
        REQUIRE(decoded.ttl_hopl_indicator == expected.ttl_hopl_indicator);
        REQUIRE(decoded.tos_tc_indicator == expected.tos_tc_indicator);
        REQUIRE(decoded.reorder_ratio == expected.reorder_ratio);
    }
}

struct FeedbackStateCase
{
    rohccxx::RohcState state;
    std::uint8_t nack_count;
    bool static_acked;
    bool dynamic_acked;
    std::uint32_t tx_count;
};

const FeedbackStateCase feedback_state_cases[] = {
    {rohccxx::RohcState::NoContext, 0, false, false, 0},
    {rohccxx::RohcState::StaticEstablished, 0, false, false, 1},
    {rohccxx::RohcState::DynamicEstablished, 0, true, false, 2},
    {rohccxx::RohcState::DynamicEstablished, 1, true, true, 2},
};

void require_feedback_state_transition(const FeedbackStateCase& initial,
                                       const rohccxx::Feedback& feedback,
                                       rohccxx::Mode requested_mode)
{
    rohccxx::Context ctx{};
    ctx.mode = rohccxx::Mode::Optimistic;
    ctx.rohc_state = initial.state;
    ctx.nack_count = initial.nack_count;
    ctx.static_acked = initial.static_acked;
    ctx.dynamic_acked = initial.dynamic_acked;
    ctx.tx_count = initial.tx_count;

    rohccxx::apply_feedback_to_context(ctx, feedback);
    REQUIRE(ctx.mode == requested_mode);

    if(feedback.type == rohccxx::FeedbackType::ACK)
    {
        REQUIRE(ctx.rohc_state == initial.state);
        REQUIRE(ctx.tx_count == initial.tx_count);
        REQUIRE(ctx.nack_count == 0);
        REQUIRE(ctx.static_acked == (initial.static_acked ||
            initial.state == rohccxx::RohcState::StaticEstablished ||
            initial.state == rohccxx::RohcState::DynamicEstablished));
        REQUIRE(ctx.dynamic_acked == (initial.dynamic_acked ||
            initial.state == rohccxx::RohcState::DynamicEstablished));
        return;
    }

    if(feedback.type == rohccxx::FeedbackType::STATIC_NACK)
    {
        REQUIRE(ctx.rohc_state == rohccxx::RohcState::NoContext);
        REQUIRE(ctx.tx_count == 0);
        REQUIRE(ctx.nack_count == 0);
        REQUIRE_FALSE(ctx.static_acked);
        REQUIRE_FALSE(ctx.dynamic_acked);
        return;
    }

    REQUIRE(ctx.nack_count == static_cast<std::uint8_t>(initial.nack_count + 1U));
    REQUIRE_FALSE(ctx.dynamic_acked);
    if(initial.nack_count > 0)
    {
        REQUIRE(ctx.rohc_state == rohccxx::RohcState::NoContext);
        REQUIRE(ctx.tx_count == 0);
        REQUIRE_FALSE(ctx.static_acked);
    }
    else
    {
        REQUIRE(ctx.rohc_state == rohccxx::RohcState::StaticEstablished);
        REQUIRE(ctx.tx_count == 1);
        REQUIRE(ctx.static_acked == initial.static_acked);
    }
}

} // namespace

TEST_CASE("RFC 5225 shared chain helper emits canonical IPv4 and UDP chains")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::UDP, 17);
    std::uint8_t out[32] = {};
    std::uint8_t* p = out;

    rohccxx::rfc5225::write_ipv4_static(p, ctx);
    rohccxx::rfc5225::write_udp_static(p, ctx);
    rohccxx::rfc5225::write_ipv4_dynamic(p, ctx);
    rohccxx::rfc5225::write_udp_dynamic(p, ctx);

    REQUIRE(static_cast<size_t>(p - out) == 22);
    require_ipv4_static(out, 0, ctx, 17);
    require_udp_static(out, 10, ctx);
    require_ipv4_dynamic(out, 14, ctx);
    require_udp_dynamic(out, 20, ctx);
}

TEST_CASE("RFC 5225 RTP packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_rtp(out, &len, ctx));
    REQUIRE(len == 36);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x01);
    require_crc8_at(out, len, 2);
    require_ipv4_static(out, 3, ctx, 17);
    require_udp_static(out, 13, ctx);
    REQUIRE(read_u32(out + 17) == ctx.rtp.ssrc);
    require_standard_ipv4_dynamic(out, 21, ctx, false);
    require_udp_dynamic(out, 26, ctx);
    require_rtp_dynamic(out, 28, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_rtp(out, &len, ctx));
    REQUIRE(len == 36);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x01);
    require_crc8_at(out, len, 2);
    require_standard_ipv4_dynamic(out, 21, ctx, false);
    require_udp_dynamic(out, 26, ctx);
    require_rtp_dynamic(out, 28, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_rtp_fo(out, &len, ctx));
    REQUIRE(len == 5);
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.cid == 0);
    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    size_t consumed = 0;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    REQUIRE(rohccxx::decode_fo_rtp(out, len, ctx, seq, ts, &consumed));
    REQUIRE(consumed == len);
}


TEST_CASE("RFC 5225 RTP FO carries large CID with SDVL framing")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
    ctx.cid = 0x1234;
    ctx.large_cid = true;

    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_rtp_fo(out, &len, ctx));
    REQUIRE(len == 7);
    REQUIRE((out[0] & 0x80) == 0x00);
    REQUIRE(((out[0] >> 2) & 0x0F) == 0);
    REQUIRE(out[1] == 0x92);
    REQUIRE(out[2] == 0x34);

    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, true));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.has_large_cid);
    REQUIRE(parsed.cid == ctx.cid);
    REQUIRE(parsed.cid_len == 2);

    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    size_t consumed = 0;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    REQUIRE(rohccxx::decode_fo_rtp(out, len, ctx, seq, ts, &consumed));
    REQUIRE(consumed == len);
}

TEST_CASE("RFC 5225 dynamic decoders reject unsupported non-empty extension lists")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::UDP, 17);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_udp(out, &len, ctx));

    out[8] = 0x80;
    out[2] = 0x00;
    out[2] = rohccxx::utils::crc8(out, len);

    rohccxx::Context rx{};
    REQUIRE_FALSE(rohccxx::decode_ir_dyn_udp(out, len, rx));
}

TEST_CASE("RFC 5225 IPv4 option list compression covers generated mutations")
{
    struct OptionCase
    {
        const char* name;
        std::uint8_t bytes[16];
        std::uint8_t len;
    };

    const OptionCase cases[] = {
        {"insert", {0x01, 0x01, 0x00, 0x00}, 4},
        {"duplicate", {0x44, 0x04, 0xAA, 0xBB, 0x44, 0x04, 0xAA, 0xBB}, 8},
        {"reorder", {0x83, 0x03, 0x11, 0x01, 0x82, 0x04, 0x22, 0x33}, 8},
        {"maximum", {0x01, 0x01, 0x01, 0x01, 0x44, 0x04, 0x10, 0x11,
                     0x44, 0x04, 0x20, 0x21, 0x01, 0x01, 0x00, 0x00}, 16},
    };

    rohccxx::Context empty = grammar_context(rohccxx::Profile::IP, 6);
    std::uint8_t out[96] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::rfc5225::write_ipv4_options_list(p, out + sizeof(out), empty));
    REQUIRE(static_cast<size_t>(p - out) == 1);
    REQUIRE(out[0] == rohccxx::rfc5225::generic_extension_list_empty);
    rohccxx::Context decoded{};
    size_t pos = 0;
    REQUIRE(rohccxx::rfc5225::read_ipv4_options_list(out, static_cast<size_t>(p - out), pos, decoded));
    REQUIRE(decoded.ipv4_options_len == 0);

    for(const auto& item : cases)
    {
        CAPTURE(item.name);
        rohccxx::Context ctx = grammar_context(rohccxx::Profile::IP, 6);
        ctx.ipv4_options_len = item.len;
        std::memcpy(ctx.ipv4_options.data(), item.bytes, item.len);

        p = out;
        REQUIRE(rohccxx::rfc5225::write_ipv4_options_list(p, out + sizeof(out), ctx));
        REQUIRE(static_cast<size_t>(p - out) == 1U + item.len);
        REQUIRE((out[0] & 0xC0U) == rohccxx::rfc5225::ipv4_options_list_marker);
        REQUIRE((out[0] & 0x3FU) == item.len);

        decoded = {};
        pos = 0;
        REQUIRE(rohccxx::rfc5225::read_ipv4_options_list(out, static_cast<size_t>(p - out), pos, decoded));
        REQUIRE(pos == static_cast<size_t>(p - out));
        REQUIRE(decoded.ipv4_options_len == item.len);
        REQUIRE(std::memcmp(decoded.ipv4_options.data(), item.bytes, item.len) == 0);
    }

    const std::uint8_t malformed_marker[] = {0x80};
    pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_ipv4_options_list(malformed_marker, sizeof(malformed_marker), pos, decoded));
    const std::uint8_t zero_length_non_empty[] = {rohccxx::rfc5225::ipv4_options_list_marker};
    pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_ipv4_options_list(zero_length_non_empty, sizeof(zero_length_non_empty), pos, decoded));
    const std::uint8_t truncated[] = {static_cast<std::uint8_t>(rohccxx::rfc5225::ipv4_options_list_marker | 4U), 0x01, 0x02};
    pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_ipv4_options_list(truncated, sizeof(truncated), pos, decoded));
}

TEST_CASE("RFC 5225 IPv6 extension list compression covers ordered chains and malformed lengths")
{
    struct ExtensionCase
    {
        const char* name;
        std::uint8_t first_next_header;
        std::uint8_t terminal_next_header;
        std::uint8_t bytes[32];
        std::uint8_t len;
    };

    const ExtensionCase cases[] = {
        {"hop-dest-routing-ah", 0, 51,
         {60, 0, 0, 0, 0, 0, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0,
          51, 0, 0, 0, 0, 0, 0, 0}, 24},
        {"hop-gre-terminal", 0, 47,
         {47, 0, 0, 0, 0, 0, 0, 0}, 8},
        {"dest-mine-terminal", 60, 55,
         {55, 0, 0, 0, 0, 0, 0, 0}, 8},
    };

    for(const auto& item : cases)
    {
        CAPTURE(item.name);
        std::uint8_t terminal = 0;
        REQUIRE(rohccxx::encoding::validate_ipv6_extension_header_list(item.bytes,
                                                                       item.len,
                                                                       item.first_next_header,
                                                                       terminal));
        REQUIRE(terminal == item.terminal_next_header);

        rohccxx::Context ctx = grammar_context(rohccxx::Profile::IP, item.terminal_next_header);
        ctx.ip_version = 6;
        ctx.ipv6_next_header = item.first_next_header;
        ctx.ipv4_protocol = item.terminal_next_header;
        ctx.ipv6_extension_len = item.len;
        std::memcpy(ctx.ipv6_extensions.data(), item.bytes, item.len);

        std::uint8_t out[96] = {};
        std::uint8_t* p = out;
        REQUIRE(rohccxx::rfc5225::write_ipv6_extensions_list(p, out + sizeof(out), ctx));
        REQUIRE(static_cast<size_t>(p - out) == 1U + item.len);
        REQUIRE((out[0] & 0x80U) == rohccxx::rfc5225::ipv6_extensions_list_marker);
        REQUIRE((out[0] & 0x7FU) == item.len);

        rohccxx::Context decoded{};
        size_t pos = 0;
        REQUIRE(rohccxx::rfc5225::read_ipv6_extensions_list(out, static_cast<size_t>(p - out), pos, decoded));
        REQUIRE(pos == static_cast<size_t>(p - out));
        REQUIRE(decoded.ipv6_extension_len == item.len);
        REQUIRE(std::memcmp(decoded.ipv6_extensions.data(), item.bytes, item.len) == 0);
    }

    rohccxx::Context empty = grammar_context(rohccxx::Profile::IP, 6);
    empty.ip_version = 6;
    std::uint8_t out[160] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::rfc5225::write_ipv6_extensions_list(p, out + sizeof(out), empty));
    REQUIRE(static_cast<size_t>(p - out) == 1);
    REQUIRE(out[0] == rohccxx::rfc5225::generic_extension_list_empty);

    empty.ipv6_extension_len = 128;
    REQUIRE_FALSE(rohccxx::rfc5225::write_ipv6_extensions_list(p, out + sizeof(out), empty));

    rohccxx::Context decoded{};
    const std::uint8_t zero_length_non_empty[] = {rohccxx::rfc5225::ipv6_extensions_list_marker};
    size_t pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_ipv6_extensions_list(zero_length_non_empty, sizeof(zero_length_non_empty), pos, decoded));
    const std::uint8_t truncated[] = {static_cast<std::uint8_t>(rohccxx::rfc5225::ipv6_extensions_list_marker | 2U), 0x11};
    pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_ipv6_extensions_list(truncated, sizeof(truncated), pos, decoded));
}

TEST_CASE("RFC 5225 RTP extras list compression preserves CSRC extension and padding variants")
{
    auto roundtrip = [](const rohccxx::Context& ctx)
    {
        std::uint8_t out[640] = {};
        std::uint8_t* p = out;
        REQUIRE(rohccxx::rfc5225::write_rtp_extras_list(p, out + sizeof(out), ctx));

        rohccxx::Context decoded{};
        decoded.rtp.vpxcc = ctx.rtp.vpxcc;
        size_t pos = 0;
        REQUIRE(rohccxx::rfc5225::read_rtp_extras_list(out, static_cast<size_t>(p - out), pos, decoded));
        REQUIRE(pos == static_cast<size_t>(p - out));
        require_rtp_extras_equal(ctx, decoded);
    };

    rohccxx::Context empty = grammar_context(rohccxx::Profile::RTP, 17);
    roundtrip(empty);

    for(std::uint8_t count : {static_cast<std::uint8_t>(1), static_cast<std::uint8_t>(3), static_cast<std::uint8_t>(15)})
    {
        rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
        ctx.rtp.vpxcc = static_cast<std::uint8_t>(0x80U | count);
        ctx.rtp.csrc_list_len = static_cast<std::uint8_t>(count * 4U);
        for(std::uint8_t i = 0; i < ctx.rtp.csrc_list_len; ++i)
            ctx.rtp.csrc_list[i] = static_cast<std::uint8_t>(0x30U + ((i + count) & 0x0FU));
        if(count == 3)
            std::memcpy(ctx.rtp.csrc_list.data() + 8, ctx.rtp.csrc_list.data(), 4);
        roundtrip(ctx);
    }

    for(std::uint16_t extension_len : {static_cast<std::uint16_t>(4), static_cast<std::uint16_t>(8), static_cast<std::uint16_t>(256)})
    {
        rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
        ctx.rtp.vpxcc = 0x90;
        ctx.rtp.extension_len = extension_len;
        ctx.rtp.extension_bytes[0] = 0xBE;
        ctx.rtp.extension_bytes[1] = 0xDE;
        const std::uint16_t words = static_cast<std::uint16_t>((extension_len - 4U) / 4U);
        ctx.rtp.extension_bytes[2] = static_cast<std::uint8_t>(words >> 8);
        ctx.rtp.extension_bytes[3] = static_cast<std::uint8_t>(words & 0xFFU);
        for(std::uint16_t i = 4; i < extension_len; ++i)
            ctx.rtp.extension_bytes[i] = static_cast<std::uint8_t>(0xA0U + (i & 0x1FU));
        roundtrip(ctx);
    }

    for(std::uint16_t padding_len : {static_cast<std::uint16_t>(1), static_cast<std::uint16_t>(255)})
    {
        rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
        ctx.rtp.vpxcc = 0xA0;
        ctx.rtp.padding_len = static_cast<std::uint8_t>(padding_len);
        for(std::uint16_t i = 0; i < padding_len; ++i)
            ctx.rtp.padding_bytes[i] = static_cast<std::uint8_t>(0x40U + (i & 0x1FU));
        ctx.rtp.padding_bytes[padding_len - 1U] = static_cast<std::uint8_t>(padding_len);
        roundtrip(ctx);
    }

    rohccxx::Context combined = grammar_context(rohccxx::Profile::RTP, 17);
    configure_rtp_csrc_extension_padding(combined);
    roundtrip(combined);

    std::uint8_t out[128] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::rfc5225::write_rtp_extras_list(p, out + sizeof(out), combined));

    std::uint8_t malformed[128] = {};
    const size_t malformed_len = static_cast<size_t>(p - out);
    std::memcpy(malformed, out, malformed_len);
    malformed[3] = 3;
    rohccxx::Context decoded{};
    decoded.rtp.vpxcc = combined.rtp.vpxcc;
    size_t pos = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::read_rtp_extras_list(malformed, malformed_len, pos, decoded));

    const std::uint8_t empty_wire[] = {rohccxx::rfc5225::generic_extension_list_empty};
    decoded = {};
    decoded.rtp.vpxcc = 0xA0;
    pos = 0;
    REQUIRE(rohccxx::rfc5225::read_rtp_extras_list(empty_wire, sizeof(empty_wire), pos, decoded));
    REQUIRE(decoded.rtp.vpxcc == 0x80);

    rohccxx::Context bad_padding = grammar_context(rohccxx::Profile::RTP, 17);
    bad_padding.rtp.vpxcc = 0xA0;
    bad_padding.rtp.padding_len = 4;
    bad_padding.rtp.padding_bytes[0] = 0x01;
    bad_padding.rtp.padding_bytes[1] = 0x02;
    bad_padding.rtp.padding_bytes[2] = 0x03;
    bad_padding.rtp.padding_bytes[3] = 0x03;
    REQUIRE_FALSE(rohccxx::rfc5225::write_rtp_extras_list(p, out + sizeof(out), bad_padding));
}

TEST_CASE("RFC 5225 IR emitters reject unsupported RTP list features instead of emitting private chains")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP, 17);
    configure_rtp_csrc_extension_padding(ctx);

    std::uint8_t out[256] = {};
    size_t len = sizeof(out);
    REQUIRE_FALSE(rohccxx::emit_ir_rtp(out, &len, ctx));

    len = sizeof(out);
    REQUIRE_FALSE(rohccxx::emit_ir_dyn_rtp(out, &len, ctx));
}

TEST_CASE("RFC 5225 UDP packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::UDP, 17);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_udp(out, &len, ctx));
    REQUIRE(len == 27);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x02);
    require_crc8_at(out, len, 2);
    require_ipv4_static(out, 3, ctx, 17);
    require_udp_static(out, 13, ctx);
    require_standard_ipv4_dynamic(out, 17, ctx, false);
    require_udp_dynamic(out, 22, ctx);
    REQUIRE(read_u16(out + 24) == ctx.msn);
    REQUIRE(out[26] == ctx.reorder_ratio);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_udp(out, &len, ctx));
    REQUIRE(len == 27);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x02);
    require_crc8_at(out, len, 2);
    require_standard_ipv4_dynamic(out, 17, ctx, false);
    require_udp_dynamic(out, 22, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_udp_fo(out, &len, ctx));
    REQUIRE(len == 6);
    REQUIRE(out[0] == 0x7A);
    require_crc8_at(out, len, 1);
    REQUIRE(read_u16(out + 2) == ctx.ipv4_id);
    REQUIRE(read_u16(out + 4) == ctx.udp_check);
}

TEST_CASE("RFC 5225 IP-only packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::IP, 6);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_ip(out, &len, ctx));
    REQUIRE(len == 20);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x04);
    require_crc8_at(out, len, 2);
    require_ipv4_static(out, 3, ctx, 6);
    require_standard_ipv4_dynamic(out, 13, ctx, true);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_ip(out, &len, ctx));
    REQUIRE(len == 20);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x04);
    require_crc8_at(out, len, 2);
    require_standard_ipv4_dynamic(out, 13, ctx, true);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ip_fo(out, &len, ctx));
    REQUIRE(len == 4);
    REQUIRE(out[0] == 0x79);
    require_crc8_at(out, len, 1);
    REQUIRE(read_u16(out + 2) == ctx.ipv4_id);
}

TEST_CASE("RFC 5225 ESP packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::ESP, 50);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_esp(out, &len, ctx));
    REQUIRE(len == 27);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x03);
    require_crc8_at(out, len, 2);
    require_ipv4_static(out, 3, ctx, 50);
    REQUIRE(read_u32(out + 13) == ctx.esp_spi);
    require_standard_ipv4_dynamic(out, 17, ctx, false);
    REQUIRE(read_u32(out + 22) == ctx.esp_sequence);
    REQUIRE(out[26] == ctx.reorder_ratio);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_esp(out, &len, ctx));
    REQUIRE(len == 27);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x03);
    require_crc8_at(out, len, 2);
    REQUIRE(read_u32(out + 13) == ctx.esp_spi);
    require_standard_ipv4_dynamic(out, 17, ctx, false);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_esp_fo(out, &len, ctx));
    REQUIRE(len == 4);
    REQUIRE(out[0] == 0x78);
    require_crc8_at(out, len, 1);
    REQUIRE(read_u16(out + 2) == ctx.ipv4_id);
}


TEST_CASE("RFC 5225 RTP UDP-Lite packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::RTP_UDP_Lite, 136);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_rtp_udp_lite(out, &len, ctx));
    REQUIRE(len == 41);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x07);
    require_crc8_at(out, 40, 2);
    require_ipv4_static(out, 3, ctx, 136);
    require_udp_static(out, 13, ctx);
    REQUIRE(read_u32(out + 17) == ctx.rtp.ssrc);
    require_ipv4_dynamic(out, 21, ctx);
    require_udp_lite_dynamic(out, 27, ctx);
    require_legacy_rtp_dynamic(out, 31, ctx);
    require_mode_byte(out, 40, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_rtp_udp_lite(out, &len, ctx));
    REQUIRE(len == 22);
    REQUIRE(out[0] == 0xF8);
    REQUIRE(out[1] == 0x07);
    require_crc8_at(out, len, 2);
    require_ipv4_dynamic(out, 3, ctx);
    require_udp_lite_dynamic(out, 9, ctx);
    require_legacy_rtp_dynamic(out, 13, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_rtp_fo(out, &len, ctx));
    REQUIRE(len == 5);
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed));
    REQUIRE(parsed.type == rohccxx::RohcPacketType::FO_RTP);
    REQUIRE(parsed.cid == 0);
    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    size_t consumed = 0;
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    REQUIRE(rohccxx::decode_fo_rtp(out, len, ctx, seq, ts, &consumed));
    REQUIRE(consumed == len);
}

TEST_CASE("RFC 5225 UDP-Lite packet grammar is pinned for current IR IR-DYN and FO")
{
    rohccxx::Context ctx = grammar_context(rohccxx::Profile::UDP_Lite, 136);
    std::uint8_t out[128] = {};
    size_t len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_udp_lite(out, &len, ctx));
    REQUIRE(len == 28);
    REQUIRE(out[0] == 0xFD);
    REQUIRE(out[1] == 0x08);
    require_crc8_at(out, 27, 2);
    require_ipv4_static(out, 3, ctx, 136);
    require_udp_static(out, 13, ctx);
    require_ipv4_dynamic(out, 17, ctx);
    require_udp_lite_dynamic(out, 23, ctx);
    require_mode_byte(out, 27, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_ir_dyn_udp_lite(out, &len, ctx));
    REQUIRE(len == 13);
    REQUIRE(out[0] == 0xF8);
    REQUIRE(out[1] == 0x08);
    require_crc8_at(out, len, 2);
    require_ipv4_dynamic(out, 3, ctx);
    require_udp_lite_dynamic(out, 9, ctx);

    len = sizeof(out);
    REQUIRE(rohccxx::emit_udp_lite_fo(out, &len, ctx));
    REQUIRE(len == 8);
    REQUIRE(out[0] == 0x77);
    require_crc8_at(out, len, 1);
    REQUIRE(read_u16(out + 2) == ctx.ipv4_id);
    REQUIRE(read_u16(out + 4) == ctx.udp_length_or_coverage);
    REQUIRE(read_u16(out + 6) == ctx.udp_check);
}

TEST_CASE("RFC 5225 Add-CID grammar pins CRC coverage for current IR and IR-DYN packets")
{
    struct AddCidCase
    {
        rohccxx::Profile profile;
        std::uint8_t protocol;
        std::uint8_t profile_id;
        size_t ir_len;
        size_t ir_crc_len;
        size_t ir_dyn_len;
        bool (*emit_ir)(std::uint8_t*, size_t*, const rohccxx::Context&);
        bool (*emit_ir_dyn)(std::uint8_t*, size_t*, const rohccxx::Context&);
    };

    const AddCidCase cases[] = {
        {rohccxx::Profile::RTP, 17, 0x01, 37, 37, 37, rohccxx::emit_ir_rtp, rohccxx::emit_ir_dyn_rtp},
        {rohccxx::Profile::UDP, 17, 0x02, 28, 28, 28, rohccxx::emit_ir_udp, rohccxx::emit_ir_dyn_udp},
        {rohccxx::Profile::ESP, 50, 0x03, 28, 28, 28, rohccxx::emit_ir_esp, rohccxx::emit_ir_dyn_esp},
        {rohccxx::Profile::IP, 6, 0x04, 21, 21, 21, rohccxx::emit_ir_ip, rohccxx::emit_ir_dyn_ip},
        {rohccxx::Profile::RTP_UDP_Lite, 136, 0x07, 42, 41, 23, rohccxx::emit_ir_rtp_udp_lite, rohccxx::emit_ir_dyn_rtp_udp_lite},
        {rohccxx::Profile::UDP_Lite, 136, 0x08, 29, 28, 14, rohccxx::emit_ir_udp_lite, rohccxx::emit_ir_dyn_udp_lite},
    };

    for(const auto& item : cases)
    {
        rohccxx::Context ctx = grammar_context(item.profile, item.protocol);
        ctx.cid = 5;

        std::uint8_t out[128] = {};
        size_t len = sizeof(out);
        REQUIRE(item.emit_ir(out, &len, ctx));
        REQUIRE(len == item.ir_len);
        REQUIRE(out[0] == 0xE5);
        REQUIRE(out[1] == 0xFD);
        REQUIRE(out[2] == item.profile_id);
        require_crc8_at(out, item.ir_crc_len, 3);
        if(item.profile == rohccxx::Profile::RTP_UDP_Lite || item.profile == rohccxx::Profile::UDP_Lite)
            require_mode_byte(out, len - 1, ctx);

        rohccxx::ParsedRohcPacket parsed{};
        REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed));
        REQUIRE(parsed.has_add_cid);
        REQUIRE(parsed.cid == 5);
        REQUIRE(parsed.type == rohccxx::RohcPacketType::IR);
        REQUIRE(parsed.profile_id == item.profile_id);
        REQUIRE(parsed.packet == out + 1);
        REQUIRE(rohccxx::decoder_packet_start(parsed) == out);
        REQUIRE(rohccxx::decoder_packet_len(parsed) == len);

        len = sizeof(out);
        REQUIRE(item.emit_ir_dyn(out, &len, ctx));
        REQUIRE(len == item.ir_dyn_len);
        REQUIRE(out[0] == 0xE5);
        const bool standardized_refresh = item.profile == rohccxx::Profile::RTP ||
                                          item.profile == rohccxx::Profile::UDP ||
                                          item.profile == rohccxx::Profile::ESP ||
                                          item.profile == rohccxx::Profile::IP;
        REQUIRE(out[1] == (standardized_refresh ? 0xFD : 0xF8));
        REQUIRE(out[2] == item.profile_id);
        require_crc8_at(out, len, 3);

        REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed));
        REQUIRE(parsed.has_add_cid);
        REQUIRE(parsed.cid == 5);
        REQUIRE(parsed.type == (standardized_refresh ? rohccxx::RohcPacketType::IR
                                                    : rohccxx::RohcPacketType::IR_DYN));
        REQUIRE(parsed.profile_id == item.profile_id);
        REQUIRE(parsed.packet == out + 1);
        REQUIRE(rohccxx::decoder_packet_start(parsed) == out);
        REQUIRE(rohccxx::decoder_packet_len(parsed) == len);
    }
}


TEST_CASE("RFC 5225 exhaustive grammar manifest covers active profile families")
{
    namespace grammar = rohccxx::rfc5225::grammar;

    REQUIRE(grammar::profile_count() == 6);
    REQUIRE(grammar::case_count() == 36);

    for(const auto& profile : grammar::profile_manifest)
    {
        REQUIRE(profile.profile_id == static_cast<std::uint16_t>(profile.profile));
        REQUIRE(profile.profile_low_id == static_cast<std::uint8_t>(profile.profile_id & 0xFFU));
        REQUIRE(profile.name != nullptr);
        REQUIRE(profile.rfc_section != nullptr);
        REQUIRE(grammar::find_profile(profile.profile) == &profile);
        REQUIRE(grammar::has_case(profile.profile, grammar::PacketFamily::IR, grammar::CaseStatus::Implemented));
        REQUIRE(grammar::has_case(profile.profile, grammar::PacketFamily::IR_DYN, grammar::CaseStatus::Implemented));
        REQUIRE(grammar::has_case(profile.profile, grammar::PacketFamily::CO, grammar::CaseStatus::Implemented));
    }
}

TEST_CASE("RFC 5225 exhaustive grammar manifest tracks planned feature surface")
{
    namespace grammar = rohccxx::rfc5225::grammar;

    REQUIRE((grammar::manifest_cid_mode_mask() & grammar::CidAll) == grammar::CidAll);
    REQUIRE((grammar::manifest_encoding_mask() & grammar::all_required_encodings) == grammar::all_required_encodings);
    REQUIRE((grammar::manifest_chain_mask() & grammar::all_list_chains) == grammar::all_list_chains);
    REQUIRE(grammar::count_cases(grammar::CaseStatus::Implemented) == 35);
    REQUIRE(grammar::count_cases(grammar::CaseStatus::Planned) == 0);
    REQUIRE(grammar::count_cases(grammar::CaseStatus::OpenOracle) == 1);

    REQUIRE(grammar::find_case("5225-cid-large-sdvl-boundaries") != nullptr);
    REQUIRE(grammar::find_case("5225-ipv6-extension-list-compression") != nullptr);
    REQUIRE(grammar::find_case("5225-rtp-csrc-list-compression") != nullptr);
    REQUIRE(grammar::find_case("5225-wlsb-exhaustive") != nullptr);
    REQUIRE(grammar::find_case("5225-crc-mutation-cross-product") != nullptr);
    REQUIRE(grammar::find_case("5225-external-oracle-v2") != nullptr);
}

TEST_CASE("RFC 5225 exhaustive grammar manifest uses unique stable case ids")
{
    namespace grammar = rohccxx::rfc5225::grammar;

    for(std::size_t i = 0; i < grammar::case_manifest.size(); ++i)
    {
        const auto& lhs = grammar::case_manifest[i];
        REQUIRE(lhs.id != nullptr);
        REQUIRE(lhs.id[0] != '\0');
        REQUIRE(lhs.description != nullptr);
        REQUIRE(lhs.rfc_section != nullptr);

        for(std::size_t j = i + 1; j < grammar::case_manifest.size(); ++j)
        {
            const auto& rhs = grammar::case_manifest[j];
            REQUIRE(std::strcmp(lhs.id, rhs.id) != 0);
        }
    }
}


TEST_CASE("RFC 5225 generated CID cases cover IR and IR-DYN boundaries")
{
    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            ctx.cid = cid_case.cid;
            ctx.large_cid = cid_case.large_cid;

            std::uint8_t out[192] = {};
            size_t len = sizeof(out);
            REQUIRE(profile.emit_ir(out, &len, ctx));
            const std::uint8_t expected_ir_first = cid_case.large_cid ? 0xFD :
                (cid_case.cid == 0 ? 0xFD : static_cast<std::uint8_t>(0xE0U | cid_case.cid));
            REQUIRE(out[0] == expected_ir_first);

            rohccxx::ParsedRohcPacket parsed{};
            REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, cid_case.large_cid));
            REQUIRE(parsed.type == rohccxx::RohcPacketType::IR);
            REQUIRE(parsed.profile_id == profile.profile_id);
            REQUIRE(parsed.cid == cid_case.cid);
            REQUIRE(parsed.cid_len == cid_case.expected_cid_len);
            REQUIRE(parsed.has_large_cid == cid_case.large_cid);
            REQUIRE(parsed.has_add_cid == (!cid_case.large_cid && cid_case.cid > 0));

            rohccxx::Context decoded = grammar_context(profile.profile, profile.protocol);
            decoded.cid = cid_case.cid;
            decoded.large_cid = cid_case.large_cid;
            size_t consumed = 0;
            REQUIRE(profile.decode_ir(out, len, decoded, &consumed));
            REQUIRE(consumed == len);
            REQUIRE(decoded.profile == profile.profile);
            REQUIRE(decoded.cid == cid_case.cid);

            len = sizeof(out);
            REQUIRE(profile.emit_ir_dyn(out, &len, ctx));
            const bool standardized_refresh = !profile.carries_udp_lite;
            const std::uint8_t refresh_type = standardized_refresh ? 0xFDU : 0xF8U;
            const std::uint8_t expected_ir_dyn_first = cid_case.large_cid ? refresh_type :
                (cid_case.cid == 0 ? refresh_type : static_cast<std::uint8_t>(0xE0U | cid_case.cid));
            REQUIRE(out[0] == expected_ir_dyn_first);
            REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, cid_case.large_cid));
            REQUIRE(parsed.type == (standardized_refresh ? rohccxx::RohcPacketType::IR
                                                        : rohccxx::RohcPacketType::IR_DYN));
            REQUIRE(parsed.profile_id == profile.profile_id);
            REQUIRE(parsed.cid == cid_case.cid);
            REQUIRE(parsed.cid_len == cid_case.expected_cid_len);
            REQUIRE(parsed.has_large_cid == cid_case.large_cid);
            REQUIRE(parsed.has_add_cid == (!cid_case.large_cid && cid_case.cid > 0));

            decoded = grammar_context(profile.profile, profile.protocol);
            decoded.cid = cid_case.cid;
            decoded.large_cid = cid_case.large_cid;
            consumed = 0;
            REQUIRE(profile.decode_ir_dyn(out, len, decoded, &consumed));
            REQUIRE(consumed == len);
            REQUIRE(decoded.profile == profile.profile);
            REQUIRE(decoded.cid == cid_case.cid);
        }
    }
}

TEST_CASE("RFC 5225 parser rejects malformed packet starts and impossible CID forms")
{
    rohccxx::ParsedRohcPacket parsed{};
    REQUIRE_FALSE(rohccxx::parse_rohc_packet(nullptr, 0, parsed));

    size_t unknown_start_count = 0;
    for(std::uint16_t first = 0; first <= 0xFFU; ++first)
    {
        const auto start = static_cast<std::uint8_t>(first);
        if((start & 0xF0U) == 0xE0U)
            continue;
        if(rohccxx::detect_packet_type(start) != rohccxx::RohcPacketType::Unknown)
            continue;

        const std::uint8_t wire[] = {start, 0x01, 0x02, 0x03};
        CAPTURE(first);
        REQUIRE_FALSE(rohccxx::parse_rohc_packet(wire, sizeof(wire), parsed));
        REQUIRE_FALSE(rohccxx::parse_rohc_packet(wire, sizeof(wire), parsed, true));
        ++unknown_start_count;
    }
    REQUIRE(unknown_start_count > 0);

    struct MalformedStartCase
    {
        const char* name;
        std::uint8_t bytes[5];
        size_t len;
        bool large_cid_space;
    };

    const MalformedStartCase cases[] = {
        {"add-cid-only", {0xE5}, 1, false},
        {"add-cid-unknown-packet", {0xE5, 0x80}, 2, false},
        {"add-cid-in-large-cid-space", {0xE5, 0xF8, 0x01, 0x00}, 4, true},
        {"ir-missing-profile-id", {0xFD}, 1, false},
        {"ir-dyn-missing-profile-id", {0xF8}, 1, false},
        {"large-ir-missing-cid", {0xFD}, 1, true},
        {"large-ir-truncated-cid", {0xFD, 0x80}, 2, true},
        {"large-ir-missing-profile-after-cid", {0xFD, 0x7F}, 2, true},
        {"large-ir-non-minimal-cid", {0xFD, 0x80, 0x00, 0x01}, 4, true},
        {"large-ir-invalid-cid-prefix", {0xFD, 0xC0, 0x00, 0x01}, 4, true},
    };

    for(const auto& item : cases)
    {
        CAPTURE(item.name);
        REQUIRE_FALSE(rohccxx::parse_rohc_packet(item.bytes,
                                                 item.len,
                                                 parsed,
                                                 item.large_cid_space));
    }

    const std::uint8_t illegal_large_rtp_cid[] = {0x04, 0x01, 0x04, 0x00, 0x00};
    rohccxx::Context rtp = grammar_context(rohccxx::Profile::RTP, 17);
    rtp.large_cid = true;
    rtp.cid = 1;
    rtp.rtp.seq_window.init(rtp.rtp.last_seq);
    rtp.rtp.ts_window.init(rtp.rtp.last_ts);
    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    size_t consumed = 0;
    REQUIRE_FALSE(rohccxx::decode_fo_rtp(illegal_large_rtp_cid,
                                         sizeof(illegal_large_rtp_cid),
                                         rtp,
                                         seq,
                                         ts,
                                         &consumed));
}

TEST_CASE("RFC 5225 generated CRC mutations reject implemented packet families")
{
    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            ctx.cid = cid_case.cid;
            ctx.large_cid = cid_case.large_cid;

            for(bool dynamic_packet : {false, true})
            {
                std::uint8_t out[256] = {};
                size_t len = sizeof(out);
                const bool emitted = dynamic_packet
                    ? profile.emit_ir_dyn(out, &len, ctx)
                    : profile.emit_ir(out, &len, ctx);
                REQUIRE(emitted);
                REQUIRE(decode_generated_ir_case(profile, dynamic_packet, out, len, cid_case));

                rohccxx::ParsedRohcPacket parsed{};
                REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, cid_case.large_cid));
                const size_t crc_index = ir_crc_index_for_parsed(parsed, out);
                CAPTURE(profile.profile_id);
                CAPTURE(cid_case.cid);
                CAPTURE(cid_case.large_cid);
                CAPTURE(dynamic_packet);
                require_ir_crc_mutation_rejected(profile, dynamic_packet, out, len, cid_case, crc_index);
                require_ir_crc_mutation_rejected(profile, dynamic_packet, out, len, cid_case, crc_index + 1U);
            }
        }
    }

    for(const auto& profile : co_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            ctx.rohc_state = rohccxx::RohcState::DynamicEstablished;
            ctx.cid = cid_case.cid;
            ctx.large_cid = cid_case.large_cid;
            ctx.rtp.seq_window.init(ctx.rtp.last_seq);
            ctx.rtp.ts_window.init(ctx.rtp.last_ts);

            std::uint8_t out[192] = {};
            size_t len = sizeof(out);
            REQUIRE(emit_co_wire_for_test(profile, ctx, out, len));
            REQUIRE(decode_generated_co_case(profile, out, len, cid_case));

            rohccxx::ParsedRohcPacket parsed{};
            REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, cid_case.large_cid));
            const size_t crc_index = co_crc_mutation_index(profile, parsed, out, len);
            const size_t payload_index = profile.rtp_family ? (crc_index - 1U) : (crc_index + 1U);
            for(size_t mutation_index : {crc_index, payload_index})
            {
                CAPTURE(profile.current_variant_id);
                CAPTURE(cid_case.cid);
                CAPTURE(cid_case.large_cid);
                CAPTURE(mutation_index);
                REQUIRE(mutation_index < len);
                std::uint8_t mutated[192] = {};
                std::memcpy(mutated, out, len);
                mutated[mutation_index] ^= profile.rtp_family ? 0x02U : 0x01U;
                REQUIRE_FALSE(decode_generated_co_case(profile, mutated, len, cid_case));
            }
        }
    }
}

TEST_CASE("RFC 5225 formal CO inventory covers active profile packet families")
{
    namespace grammar = rohccxx::rfc5225::grammar;

    REQUIRE(grammar::co_variant_count() == 52);
    REQUIRE(grammar::count_co_variants(grammar::CaseStatus::Implemented) == 52);
    REQUIRE(grammar::count_co_variants(grammar::CaseStatus::Planned) == 0);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::RTP) == 12);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::RTP_UDP_Lite) == 12);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::UDP) == 7);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::ESP) == 7);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::IP) == 7);
    REQUIRE(grammar::count_co_variants(rohccxx::Profile::UDP_Lite) == 7);

    for(const auto& profile : co_profile_cases)
    {
        REQUIRE(grammar::has_co_variant(profile.profile,
                                        profile.current_variant_id,
                                        grammar::CaseStatus::Implemented));
    }

    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-co-common", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-co-repair", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP, "5225-udp-co-common", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::IP, "5225-ip-co-repair", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP_Lite, "5225-udplite-co-common", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP, "5225-udp-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP, "5225-udp-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::ESP, "5225-esp-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::ESP, "5225-esp-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::IP, "5225-ip-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::IP, "5225-ip-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP_Lite, "5225-udplite-pt-0-crc3", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP_Lite, "5225-udplite-pt-0-crc7", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-1-rnd", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-1-seq-ts", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-2-rnd", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-2-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-2-seq-both", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP, "5225-rtp-pt-2-seq-ts", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP, "5225-udp-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP, "5225-udp-pt-2-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::ESP, "5225-esp-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::ESP, "5225-esp-pt-2-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::IP, "5225-ip-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::IP, "5225-ip-pt-2-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-1-rnd", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-2-seq-both", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::RTP_UDP_Lite, "5225-rtp-udplite-pt-2-seq-ts", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP_Lite, "5225-udplite-pt-1-seq-id", grammar::CaseStatus::Implemented));
    REQUIRE(grammar::has_co_variant(rohccxx::Profile::UDP_Lite, "5225-udplite-pt-2-seq-id", grammar::CaseStatus::Implemented));
}

TEST_CASE("RFC 5225 formal pt-0 CO variants encode decode across profiles and CID modes")
{
    rohccxx::Context live{};
    live.rohc_state = rohccxx::RohcState::DynamicEstablished;
    live.profile = rohccxx::Profile::UDP;
    live.ip_version = 4;
    live.ipv4_id_behavior = 0;
    REQUIRE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    for(const auto profile : {rohccxx::Profile::UDP, rohccxx::Profile::ESP, rohccxx::Profile::IP})
    {
        live.profile = profile;
        REQUIRE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    }
    live.profile = rohccxx::Profile::UDP;
    live.ip_version = 6;
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    live.ip_version = 4;
    live.ipv4_id_behavior = 1;
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    live.ipv4_id_behavior = 2;
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    live.ipv4_id_behavior = 0;
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 1, true));
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, true, 0, false));
    live.large_cid = true;
    REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    live.large_cid = false;
    for(const auto profile : {rohccxx::Profile::RTP, rohccxx::Profile::RTP_UDP_Lite,
                              rohccxx::Profile::UDP_Lite, rohccxx::Profile::Uncompressed})
    {
        live.profile = profile;
        REQUIRE_FALSE(rohccxx::rfc5225::live_pt0_context_supported(live, false, 0, false));
    }

    REQUIRE(rohccxx::utils::crc3(nullptr, 0) == 7);
    const std::uint8_t zero[] = {0x00};
    REQUIRE(rohccxx::utils::crc3(zero, sizeof(zero)) == 5);
    const std::uint8_t sample[] = {0x12, 0x34};
    REQUIRE(rohccxx::utils::crc3(sample, sizeof(sample)) == 6);

    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            const std::uint16_t msn = static_cast<std::uint16_t>(
                rohccxx::rfc5225::is_rtp_formal_co_profile(profile.profile) ? ctx.rtp.last_seq : ctx.ipv4_id);
            std::uint8_t crc_header[96] = {};
            const size_t crc_header_len = build_formal_crc_header_for_test(profile, ctx, msn, crc_header);
            const rohccxx::rfc5225::FormalCoCrcInput crc_input{crc_header, crc_header_len};

            for(const auto variant : {rohccxx::rfc5225::FormalCoVariant::Pt0Crc3,
                                      rohccxx::rfc5225::FormalCoVariant::Pt0Crc7})
            {
                CAPTURE(profile.profile_id);
                CAPTURE(cid_case.cid);
                CAPTURE(cid_case.large_cid);
                CAPTURE(static_cast<int>(variant));

                std::uint8_t out[32] = {};
                size_t len = sizeof(out);
                REQUIRE(rohccxx::rfc5225::emit_formal_co_pt0(out,
                                                             &len,
                                                             profile.profile,
                                                             variant,
                                                             cid_case.cid,
                                                             cid_case.large_cid,
                                                             msn,
                                                             crc_input));
                const size_t add_len = (!cid_case.large_cid && cid_case.cid > 0) ? 1U : 0U;
                const size_t cid_len = cid_case.large_cid ? rohccxx::cid::encoded_len(cid_case.cid) : 0U;
                const size_t expected_len = add_len + rohccxx::rfc5225::formal_co_pt0_base_len(variant) + cid_len;
                REQUIRE(len == expected_len);
                if(add_len)
                    REQUIRE(out[0] == static_cast<std::uint8_t>(0xE0U | cid_case.cid));
                const size_t first = add_len;
                if(variant == rohccxx::rfc5225::FormalCoVariant::Pt0Crc3)
                {
                    REQUIRE((out[first] & 0x80U) == 0);
                    REQUIRE(((out[first] >> 3U) & 0x0FU) == (msn & 0x0FU));
                    REQUIRE((out[first] & 0x07U) == rohccxx::utils::crc3(crc_header, crc_header_len));
                }
                else
                {
                    if(rohccxx::rfc5225::is_rtp_formal_co_profile(profile.profile))
                    {
                        REQUIRE((out[first] & 0xF0U) == 0x80U);
                        REQUIRE(((out[first] & 0x0FU) << 1U) == ((msn & 0x1EU)));
                    }
                    else
                    {
                        REQUIRE((out[first] & 0xE0U) == 0x80U);
                        REQUIRE(((out[first] & 0x1FU) << 1U) == ((msn & 0x3EU)));
                    }
                    const size_t tail = first + 1U + cid_len;
                    REQUIRE(((out[tail] >> 7U) & 0x01U) == (msn & 0x01U));
                    REQUIRE((out[tail] & 0x7FU) == (rohccxx::utils::crc7(crc_header, crc_header_len) & 0x7FU));
                }

                rohccxx::rfc5225::FormalCoPacket decoded{};
                size_t consumed = 0;
                REQUIRE(rohccxx::rfc5225::decode_formal_co_pt0(out,
                                                               len,
                                                               profile.profile,
                                                               cid_case.large_cid,
                                                               crc_input,
                                                               decoded,
                                                               &consumed));
                REQUIRE(consumed == len);
                REQUIRE(decoded.profile == profile.profile);
                REQUIRE(decoded.variant == variant);
                REQUIRE(decoded.cid == cid_case.cid);
                REQUIRE(decoded.large_cid == cid_case.large_cid);
                REQUIRE(decoded.cid_len == cid_len);
                REQUIRE(decoded.msn == (msn & (variant == rohccxx::rfc5225::FormalCoVariant::Pt0Crc3 ? 0x0FU :
                    (rohccxx::rfc5225::is_rtp_formal_co_profile(profile.profile) ? 0x1FU : 0x3FU))));

                std::uint8_t short_out[32] = {};
                size_t short_len = expected_len - 1U;
                REQUIRE_FALSE(rohccxx::rfc5225::emit_formal_co_pt0(short_out,
                                                                   &short_len,
                                                                   profile.profile,
                                                                   variant,
                                                                   cid_case.cid,
                                                                   cid_case.large_cid,
                                                                   msn,
                                                                   crc_input));

                std::uint8_t mutated[32] = {};
                std::memcpy(mutated, out, len);
                const size_t crc_byte = variant == rohccxx::rfc5225::FormalCoVariant::Pt0Crc3
                    ? first
                    : first + 1U + cid_len;
                mutated[crc_byte] ^= 0x01U;
                REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_pt0(mutated,
                                                                     len,
                                                                     profile.profile,
                                                                     cid_case.large_cid,
                                                                     crc_input,
                                                                     decoded,
                                                                     &consumed));
            }
        }
    }
}

TEST_CASE("RFC 5225 formal pt-1 and pt-2 CO variants encode decode across profiles and CID modes")
{
    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            rohccxx::rfc5225::FormalCoFields fields{};
            fields.msn = static_cast<std::uint16_t>(ctx.rtp.last_seq + 0x37U);
            fields.ip_id = static_cast<std::uint16_t>(ctx.ipv4_id + 0x4DU);
            fields.ts_scaled = 0x55U;
            fields.marker = (cid_case.cid & 0x01U) != 0;
            std::uint8_t crc_header[96] = {};
            const size_t crc_header_len = build_formal_crc_header_for_test(profile, ctx, fields.msn, crc_header);
            const rohccxx::rfc5225::FormalCoCrcInput crc_input{crc_header, crc_header_len};

            for(const auto variant : formal_pt1_pt2_variants)
            {
                if(!rohccxx::rfc5225::formal_co_variant_valid_for_profile(profile.profile, variant))
                    continue;
                CAPTURE(profile.profile_id);
                CAPTURE(cid_case.cid);
                CAPTURE(cid_case.large_cid);
                CAPTURE(static_cast<int>(variant));

                std::uint8_t out[32] = {};
                size_t len = sizeof(out);
                REQUIRE(rohccxx::rfc5225::emit_formal_co(out,
                                                         &len,
                                                         profile.profile,
                                                         variant,
                                                         cid_case.cid,
                                                         cid_case.large_cid,
                                                         fields,
                                                         crc_input));
                const size_t add_len = (!cid_case.large_cid && cid_case.cid > 0) ? 1U : 0U;
                const size_t cid_len = cid_case.large_cid ? rohccxx::cid::encoded_len(cid_case.cid) : 0U;
                const size_t base_len = rohccxx::rfc5225::formal_co_base_len(profile.profile, variant);
                REQUIRE(base_len > 0);
                REQUIRE(len == add_len + base_len + cid_len);
                if(add_len)
                    REQUIRE(out[0] == static_cast<std::uint8_t>(0xE0U | cid_case.cid));
                require_formal_discriminator(profile.profile, variant, out[add_len]);

                rohccxx::rfc5225::FormalCoPacket decoded{};
                size_t consumed = 0;
                REQUIRE(rohccxx::rfc5225::decode_formal_co(out,
                                                           len,
                                                           profile.profile,
                                                           variant,
                                                           cid_case.large_cid,
                                                           crc_input,
                                                           decoded,
                                                           &consumed));
                REQUIRE(consumed == len);
                REQUIRE(decoded.profile == profile.profile);
                REQUIRE(decoded.variant == variant);
                REQUIRE(decoded.cid == cid_case.cid);
                REQUIRE(decoded.large_cid == cid_case.large_cid);
                REQUIRE(decoded.cid_len == cid_len);

                const std::uint8_t msn_bits = rohccxx::rfc5225::formal_co_msn_lsb_bits(profile.profile, variant);
                REQUIRE(decoded.msn == (fields.msn & lsb_mask_for_bits(msn_bits)));
                const std::uint8_t ip_bits = rohccxx::rfc5225::formal_co_ip_id_lsb_bits(profile.profile, variant);
                if(ip_bits != 0)
                    REQUIRE(decoded.ip_id == (fields.ip_id & lsb_mask_for_bits(ip_bits)));
                else
                    REQUIRE(decoded.ip_id == 0);
                const std::uint8_t ts_bits = rohccxx::rfc5225::formal_co_ts_scaled_lsb_bits(profile.profile, variant);
                if(ts_bits != 0)
                    REQUIRE(decoded.ts_scaled == (fields.ts_scaled & lsb_mask_for_bits(ts_bits)));
                else
                    REQUIRE(decoded.ts_scaled == 0);
                REQUIRE(decoded.marker == (rohccxx::rfc5225::formal_co_variant_has_marker(variant) && fields.marker));

                std::uint8_t short_out[32] = {};
                size_t short_len = len - 1U;
                REQUIRE_FALSE(rohccxx::rfc5225::emit_formal_co(short_out,
                                                               &short_len,
                                                               profile.profile,
                                                               variant,
                                                               cid_case.cid,
                                                               cid_case.large_cid,
                                                               fields,
                                                               crc_input));

                std::uint8_t mutated[32] = {};
                std::memcpy(mutated, out, len);
                const size_t crc_offset = formal_base_wire_offset(add_len,
                                                                  cid_len,
                                                                  formal_crc_base_index(profile.profile, variant));
                REQUIRE(crc_offset < len);
                mutated[crc_offset] ^= formal_crc_mutation_mask(profile.profile, variant);
                REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co(mutated,
                                                                 len,
                                                                 profile.profile,
                                                                 variant,
                                                                 cid_case.large_cid,
                                                                 crc_input,
                                                                 decoded,
                                                                 &consumed));
            }
        }
    }
}

TEST_CASE("RFC 5225 formal co_common and co_repair encode decode across profiles and CID modes")
{
    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            const std::uint16_t msn = static_cast<std::uint16_t>(ctx.rtp.last_seq + 0x37U);
            std::uint8_t crc_header[96] = {};
            const size_t crc_header_len = build_formal_crc_header_for_test(profile, ctx, msn, crc_header);
            const rohccxx::rfc5225::FormalCoCrcInput header_crc_input{crc_header, crc_header_len};
            const size_t add_len = (!cid_case.large_cid && cid_case.cid > 0) ? 1U : 0U;
            const size_t cid_len = cid_case.large_cid ? rohccxx::cid::encoded_len(cid_case.cid) : 0U;

            rohccxx::rfc5225::FormalCoCommonFields common_fields =
                make_formal_common_fields(profile.profile, cid_case);
            std::uint8_t common_control[32] = {};
            const size_t common_control_len =
                build_formal_common_control_crc_for_test(profile.profile, common_fields, common_control);
            const rohccxx::rfc5225::FormalCoCrcInput common_control_input{common_control, common_control_len};

            std::uint8_t out[96] = {};
            size_t len = sizeof(out);
            REQUIRE(rohccxx::rfc5225::emit_formal_co_common(out,
                                                            &len,
                                                            profile.profile,
                                                            cid_case.cid,
                                                            cid_case.large_cid,
                                                            common_fields,
                                                            header_crc_input,
                                                            common_control_input));
            REQUIRE(len == add_len + 1U + cid_len + 2U + common_fields.variable.len);
            if(add_len)
                REQUIRE(out[0] == static_cast<std::uint8_t>(0xE0U | cid_case.cid));
            const size_t first = add_len;
            REQUIRE(out[first] == 0xFAU);
            const size_t common_header_crc = first + 1U + cid_len;
            const size_t common_control_crc = common_header_crc + 1U;
            REQUIRE((out[common_header_crc] & 0x7FU) == (rohccxx::utils::crc7(crc_header, crc_header_len) & 0x7FU));
            REQUIRE((out[common_control_crc] & 0x07U) == rohccxx::utils::crc3(common_control, common_control_len));

            rohccxx::rfc5225::FormalCoPacket decoded{};
            size_t consumed = 0;
            REQUIRE(rohccxx::rfc5225::decode_formal_co_common(out,
                                                              len,
                                                              profile.profile,
                                                              cid_case.large_cid,
                                                              header_crc_input,
                                                              common_control_input,
                                                              decoded,
                                                              &consumed));
            REQUIRE(consumed == len);
            REQUIRE(decoded.profile == profile.profile);
            REQUIRE(decoded.variant == rohccxx::rfc5225::FormalCoVariant::CoCommon);
            REQUIRE(decoded.cid == cid_case.cid);
            REQUIRE(decoded.large_cid == cid_case.large_cid);
            REQUIRE(decoded.cid_len == cid_len);
            REQUIRE(decoded.header_crc == (rohccxx::utils::crc7(crc_header, crc_header_len) & 0x7FU));
            REQUIRE(decoded.control_crc3 == rohccxx::utils::crc3(common_control, common_control_len));
            require_formal_common_fields_equal(common_fields,
                                               decoded,
                                               rohccxx::rfc5225::is_rtp_formal_co_profile(profile.profile));
            REQUIRE(decoded.variable_offset == common_control_crc + 1U);
            REQUIRE(decoded.variable_len == common_fields.variable.len);
            REQUIRE(std::memcmp(out + decoded.variable_offset,
                                common_fields.variable.data,
                                common_fields.variable.len) == 0);

            std::uint8_t short_out[96] = {};
            size_t short_len = len - 1U;
            REQUIRE_FALSE(rohccxx::rfc5225::emit_formal_co_common(short_out,
                                                                  &short_len,
                                                                  profile.profile,
                                                                  cid_case.cid,
                                                                  cid_case.large_cid,
                                                                  common_fields,
                                                                  header_crc_input,
                                                                  common_control_input));

            std::uint8_t mutated[96] = {};
            std::memcpy(mutated, out, len);
            mutated[common_header_crc] ^= 0x01U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_common(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    common_control_input,
                                                                    decoded,
                                                                    &consumed));
            std::memcpy(mutated, out, len);
            mutated[common_control_crc] ^= 0x01U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_common(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    common_control_input,
                                                                    decoded,
                                                                    &consumed));

            rohccxx::rfc5225::FormalCoRepairFields repair_fields =
                make_formal_repair_fields(profile.profile);
            std::uint8_t repair_control[32] = {};
            const size_t repair_control_len =
                build_formal_repair_control_crc_for_test(profile.profile, repair_fields, repair_control);
            const rohccxx::rfc5225::FormalCoCrcInput repair_control_input{repair_control, repair_control_len};

            len = sizeof(out);
            REQUIRE(rohccxx::rfc5225::emit_formal_co_repair(out,
                                                            &len,
                                                            profile.profile,
                                                            cid_case.cid,
                                                            cid_case.large_cid,
                                                            repair_fields,
                                                            header_crc_input,
                                                            repair_control_input));
            REQUIRE(len == add_len + 1U + cid_len + 2U + repair_fields.dynamic_chain.len);
            if(add_len)
                REQUIRE(out[0] == static_cast<std::uint8_t>(0xE0U | cid_case.cid));
            REQUIRE(out[first] == 0xFBU);
            const size_t repair_header_crc = first + 1U + cid_len;
            const size_t repair_control_crc = repair_header_crc + 1U;
            REQUIRE((out[repair_header_crc] & 0x80U) == 0);
            REQUIRE((out[repair_header_crc] & 0x7FU) == (rohccxx::utils::crc7(crc_header, crc_header_len) & 0x7FU));
            REQUIRE((out[repair_control_crc] & 0xF8U) == 0);
            REQUIRE((out[repair_control_crc] & 0x07U) == rohccxx::utils::crc3(repair_control, repair_control_len));

            decoded = {};
            consumed = 0;
            REQUIRE(rohccxx::rfc5225::decode_formal_co_repair(out,
                                                              len,
                                                              profile.profile,
                                                              cid_case.large_cid,
                                                              header_crc_input,
                                                              repair_control_input,
                                                              decoded,
                                                              &consumed));
            REQUIRE(consumed == len);
            REQUIRE(decoded.profile == profile.profile);
            REQUIRE(decoded.variant == rohccxx::rfc5225::FormalCoVariant::CoRepair);
            REQUIRE(decoded.cid == cid_case.cid);
            REQUIRE(decoded.large_cid == cid_case.large_cid);
            REQUIRE(decoded.cid_len == cid_len);
            REQUIRE(decoded.variable_offset == repair_control_crc + 1U);
            REQUIRE(decoded.variable_len == repair_fields.dynamic_chain.len);
            REQUIRE(std::memcmp(out + decoded.variable_offset,
                                repair_fields.dynamic_chain.data,
                                repair_fields.dynamic_chain.len) == 0);

            short_len = len - 1U;
            REQUIRE_FALSE(rohccxx::rfc5225::emit_formal_co_repair(short_out,
                                                                  &short_len,
                                                                  profile.profile,
                                                                  cid_case.cid,
                                                                  cid_case.large_cid,
                                                                  repair_fields,
                                                                  header_crc_input,
                                                                  repair_control_input));

            std::memcpy(mutated, out, len);
            mutated[repair_header_crc] ^= 0x01U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_repair(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    repair_control_input,
                                                                    decoded,
                                                                    &consumed));
            std::memcpy(mutated, out, len);
            mutated[repair_control_crc] ^= 0x01U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_repair(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    repair_control_input,
                                                                    decoded,
                                                                    &consumed));
            std::memcpy(mutated, out, len);
            mutated[repair_header_crc] |= 0x80U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_repair(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    repair_control_input,
                                                                    decoded,
                                                                    &consumed));
            std::memcpy(mutated, out, len);
            mutated[repair_control_crc] |= 0x08U;
            REQUIRE_FALSE(rohccxx::rfc5225::decode_formal_co_repair(mutated,
                                                                    len,
                                                                    profile.profile,
                                                                    cid_case.large_cid,
                                                                    header_crc_input,
                                                                    repair_control_input,
                                                                    decoded,
                                                                    &consumed));
        }
    }
}

TEST_CASE("RFC 5225 mode and feedback cross-product covers formal CO families")
{
    const rohccxx::Mode modes[] = {
        rohccxx::Mode::Uncompressed,
        rohccxx::Mode::Optimistic,
        rohccxx::Mode::Reliable,
    };
    const rohccxx::FeedbackType feedback_types[] = {
        rohccxx::FeedbackType::NACK,
        rohccxx::FeedbackType::STATIC_NACK,
        rohccxx::FeedbackType::ACK,
    };

    for(const auto& profile : grammar_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            rohccxx::rfc5225::FormalCoFields fields{};
            fields.msn = static_cast<std::uint16_t>(ctx.rtp.last_seq + 0x37U);
            fields.ip_id = static_cast<std::uint16_t>(ctx.ipv4_id + 0x4DU);
            fields.ts_scaled = 0x55U;
            fields.marker = (cid_case.cid & 0x01U) != 0;

            std::uint8_t crc_header[96] = {};
            const size_t crc_header_len = build_formal_crc_header_for_test(profile, ctx, fields.msn, crc_header);
            const rohccxx::rfc5225::FormalCoCrcInput header_crc_input{crc_header, crc_header_len};
            rohccxx::rfc5225::FormalCoCommonFields common_fields =
                make_formal_common_fields(profile.profile, cid_case);
            std::uint8_t common_control[32] = {};
            const size_t common_control_len =
                build_formal_common_control_crc_for_test(profile.profile, common_fields, common_control);
            const rohccxx::rfc5225::FormalCoCrcInput common_control_input{common_control, common_control_len};
            rohccxx::rfc5225::FormalCoRepairFields repair_fields =
                make_formal_repair_fields(profile.profile);
            std::uint8_t repair_control[32] = {};
            const size_t repair_control_len =
                build_formal_repair_control_crc_for_test(profile.profile, repair_fields, repair_control);
            const rohccxx::rfc5225::FormalCoCrcInput repair_control_input{repair_control, repair_control_len};

            for(const auto variant : formal_all_variants)
            {
                if(!rohccxx::rfc5225::formal_co_variant_valid_for_profile(profile.profile, variant))
                    continue;

                std::uint8_t packet[96] = {};
                size_t packet_len = sizeof(packet);
                if(variant == rohccxx::rfc5225::FormalCoVariant::CoCommon)
                {
                    REQUIRE(rohccxx::rfc5225::emit_formal_co_common(packet,
                                                                    &packet_len,
                                                                    profile.profile,
                                                                    cid_case.cid,
                                                                    cid_case.large_cid,
                                                                    common_fields,
                                                                    header_crc_input,
                                                                    common_control_input));
                }
                else if(variant == rohccxx::rfc5225::FormalCoVariant::CoRepair)
                {
                    REQUIRE(rohccxx::rfc5225::emit_formal_co_repair(packet,
                                                                    &packet_len,
                                                                    profile.profile,
                                                                    cid_case.cid,
                                                                    cid_case.large_cid,
                                                                    repair_fields,
                                                                    header_crc_input,
                                                                    repair_control_input));
                }
                else
                {
                    REQUIRE(rohccxx::rfc5225::emit_formal_co(packet,
                                                             &packet_len,
                                                             profile.profile,
                                                             variant,
                                                             cid_case.cid,
                                                             cid_case.large_cid,
                                                             fields,
                                                             header_crc_input));
                }

                for(const auto mode : modes)
                {
                    for(const auto feedback_type : feedback_types)
                    {
                        rohccxx::Feedback feedback{};
                        feedback.cid = cid_case.large_cid ? 0U : cid_case.cid;
                        feedback.type = feedback_type;
                        feedback.has_mode = true;
                        feedback.mode = mode;
                        const std::uint8_t sn_option[] = {
                            static_cast<std::uint8_t>(fields.msn >> 8U),
                            static_cast<std::uint8_t>(fields.msn & 0xFFU),
                        };
                        const std::uint8_t crc_option[] = {static_cast<std::uint8_t>(packet[packet_len - 1U])};
                        REQUIRE(rohccxx::add_feedback_option(feedback,
                                                             rohccxx::FeedbackOptionType::SequenceNumber,
                                                             sn_option,
                                                             sizeof(sn_option)));
                        REQUIRE(rohccxx::add_feedback_option(feedback,
                                                             rohccxx::FeedbackOptionType::Crc,
                                                             crc_option,
                                                             sizeof(crc_option)));

                        std::uint8_t piggybacked[192] = {};
                        size_t piggybacked_len = sizeof(piggybacked);
                        REQUIRE(rohccxx::write_piggybacked_feedback(piggybacked,
                                                                    &piggybacked_len,
                                                                    feedback,
                                                                    packet,
                                                                    packet_len));

                        rohccxx::Feedback decoded_feedback{};
                        size_t feedback_len = 0;
                        REQUIRE(rohccxx::read_feedback_prefix(piggybacked,
                                                              piggybacked_len,
                                                              decoded_feedback,
                                                              feedback_len));
                        REQUIRE(decoded_feedback.cid == feedback.cid);
                        REQUIRE(decoded_feedback.type == feedback_type);
                        REQUIRE(decoded_feedback.has_mode);
                        REQUIRE(decoded_feedback.mode == mode);
                        REQUIRE(decoded_feedback.option_count == 2);
                        REQUIRE(decoded_feedback.options[0].type == rohccxx::FeedbackOptionType::SequenceNumber);
                        REQUIRE(decoded_feedback.options[0].len == sizeof(sn_option));
                        REQUIRE(std::memcmp(decoded_feedback.options[0].value, sn_option, sizeof(sn_option)) == 0);
                        REQUIRE(decoded_feedback.options[1].type == rohccxx::FeedbackOptionType::Crc);
                        REQUIRE(decoded_feedback.options[1].len == sizeof(crc_option));
                        REQUIRE(decoded_feedback.options[1].value[0] == crc_option[0]);

                        const std::uint8_t* payload = piggybacked + feedback_len;
                        const size_t payload_len = piggybacked_len - feedback_len;
                        REQUIRE(payload_len == packet_len);
                        rohccxx::rfc5225::FormalCoPacket decoded{};
                        size_t consumed = 0;
                        if(variant == rohccxx::rfc5225::FormalCoVariant::CoCommon)
                        {
                            REQUIRE(rohccxx::rfc5225::decode_formal_co_common(payload,
                                                                              payload_len,
                                                                              profile.profile,
                                                                              cid_case.large_cid,
                                                                              header_crc_input,
                                                                              common_control_input,
                                                                              decoded,
                                                                              &consumed));
                        }
                        else if(variant == rohccxx::rfc5225::FormalCoVariant::CoRepair)
                        {
                            REQUIRE(rohccxx::rfc5225::decode_formal_co_repair(payload,
                                                                              payload_len,
                                                                              profile.profile,
                                                                              cid_case.large_cid,
                                                                              header_crc_input,
                                                                              repair_control_input,
                                                                              decoded,
                                                                              &consumed));
                        }
                        else
                        {
                            REQUIRE(rohccxx::rfc5225::decode_formal_co(payload,
                                                                       payload_len,
                                                                       profile.profile,
                                                                       variant,
                                                                       cid_case.large_cid,
                                                                       header_crc_input,
                                                                       decoded,
                                                                       &consumed));
                        }
                        REQUIRE(consumed == payload_len);
                        REQUIRE(decoded.profile == profile.profile);
                        REQUIRE(decoded.variant == variant);
                        REQUIRE(decoded.cid == cid_case.cid);

                        for(const auto& state_case : feedback_state_cases)
                        {
                            require_feedback_state_transition(state_case,
                                                              decoded_feedback,
                                                              mode);
                        }
                    }
                }
            }
        }
    }
}

TEST_CASE("RFC 5225 generated CO cases cover current FO CID and CRC boundaries")
{
    for(const auto& profile : co_profile_cases)
    {
        for(const auto& cid_case : generated_cid_cases)
        {
            rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
            ctx.rohc_state = rohccxx::RohcState::DynamicEstablished;
            ctx.cid = cid_case.cid;
            ctx.large_cid = cid_case.large_cid;
            ctx.rtp.seq_window.init(ctx.rtp.last_seq);
            ctx.rtp.ts_window.init(ctx.rtp.last_ts);

            std::uint8_t out[192] = {};
            size_t len = sizeof(out);
            REQUIRE(emit_co_wire_for_test(profile, ctx, out, len));

            rohccxx::ParsedRohcPacket parsed{};
            REQUIRE(rohccxx::parse_rohc_packet(out, len, parsed, cid_case.large_cid));
            REQUIRE(parsed.type == profile.packet_type);
            REQUIRE(parsed.cid == cid_case.cid);
            REQUIRE(parsed.cid_len == cid_case.expected_cid_len);
            REQUIRE(parsed.has_large_cid == cid_case.large_cid);
            REQUIRE(parsed.has_add_cid == (!profile.rtp_family && !cid_case.large_cid && cid_case.cid > 0));

            rohccxx::Context decoded = grammar_context(profile.profile, profile.protocol);
            decoded.rohc_state = rohccxx::RohcState::DynamicEstablished;
            decoded.cid = cid_case.cid;
            decoded.large_cid = cid_case.large_cid;
            decoded.rtp.seq_window.init(decoded.rtp.last_seq);
            decoded.rtp.ts_window.init(decoded.rtp.last_ts);
            size_t consumed = 0;
            REQUIRE(decode_co_wire_for_test(profile, parsed.packet, parsed.packet_len, decoded, consumed));
            REQUIRE(consumed == parsed.packet_len);
            REQUIRE(decoded.profile == profile.profile);
            REQUIRE(decoded.cid == cid_case.cid);
            if(profile.decoder == CoDecoderKind::Rtp)
            {
                REQUIRE(decoded.rtp.last_seq == ctx.rtp.last_seq);
                REQUIRE(decoded.rtp.last_ts == ctx.rtp.last_ts);
            }
            else
            {
                REQUIRE(decoded.ipv4_id == ctx.ipv4_id);
            }
            if(profile.decoder == CoDecoderKind::Udp || profile.decoder == CoDecoderKind::UdpLite)
                REQUIRE(decoded.udp_check == ctx.udp_check);
            if(profile.decoder == CoDecoderKind::UdpLite)
                REQUIRE(decoded.udp_length_or_coverage == ctx.udp_length_or_coverage);

            std::uint8_t short_out[192] = {};
            size_t short_len = parsed.packet_len > 0 ? parsed.packet_len - 1U : 0U;
            REQUIRE_FALSE(profile.emit_co(short_out, &short_len, ctx));

            std::uint8_t mutated[192] = {};
            std::memcpy(mutated, out, len);
            const size_t crc_index = co_crc_mutation_index(profile, parsed, out, len);
            REQUIRE(crc_index < len);
            mutated[crc_index] ^= profile.rtp_family ? 0x02U : 0x01U;
            rohccxx::ParsedRohcPacket mutated_parsed{};
            REQUIRE(rohccxx::parse_rohc_packet(mutated, len, mutated_parsed, cid_case.large_cid));
            decoded = grammar_context(profile.profile, profile.protocol);
            decoded.rohc_state = rohccxx::RohcState::DynamicEstablished;
            decoded.cid = cid_case.cid;
            decoded.large_cid = cid_case.large_cid;
            decoded.rtp.seq_window.init(decoded.rtp.last_seq);
            decoded.rtp.ts_window.init(decoded.rtp.last_ts);
            consumed = 0;
            REQUIRE_FALSE(decode_co_wire_for_test(profile,
                                                  mutated_parsed.packet,
                                                  mutated_parsed.packet_len,
                                                  decoded,
                                                  consumed));
        }
    }
}

TEST_CASE("RFC 5225 CO emitters reject CID overflow in current FO paths")
{
    for(const auto& profile : co_profile_cases)
    {
        rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
        std::uint8_t out[192] = {};
        size_t len = sizeof(out);

        ctx.cid = rohccxx::cid::small_cid_max + 1U;
        ctx.large_cid = false;
        REQUIRE_FALSE(profile.emit_co(out, &len, ctx));

        ctx.cid = rohccxx::cid::large_cid_max + 1U;
        ctx.large_cid = true;
        len = sizeof(out);
        REQUIRE_FALSE(profile.emit_co(out, &len, ctx));
    }
}

TEST_CASE("RFC 5225 CID encoders reject out-of-range and malformed CID forms")
{
    for(const auto& profile : grammar_profile_cases)
    {
        rohccxx::Context ctx = grammar_context(profile.profile, profile.protocol);
        ctx.cid = rohccxx::cid::small_cid_max + 1U;
        ctx.large_cid = false;

        std::uint8_t out[192] = {};
        size_t len = sizeof(out);
        REQUIRE_FALSE(profile.emit_ir(out, &len, ctx));
        len = sizeof(out);
        REQUIRE_FALSE(profile.emit_ir_dyn(out, &len, ctx));

        ctx.cid = rohccxx::cid::large_cid_max + 1U;
        ctx.large_cid = true;
        len = sizeof(out);
        REQUIRE_FALSE(profile.emit_ir(out, &len, ctx));
        len = sizeof(out);
        REQUIRE_FALSE(profile.emit_ir_dyn(out, &len, ctx));
    }

    std::uint32_t value = 0;
    size_t consumed = 0;
    const std::uint8_t truncated_two_octet[] = {0x80};
    REQUIRE_FALSE(rohccxx::cid::read_large(truncated_two_octet, sizeof(truncated_two_octet), value, consumed));

    const std::uint8_t non_minimal_zero[] = {0x80, 0x00};
    REQUIRE_FALSE(rohccxx::cid::read_large(non_minimal_zero, sizeof(non_minimal_zero), value, consumed));

    const std::uint8_t non_minimal_127[] = {0x80, 0x7F};
    REQUIRE_FALSE(rohccxx::cid::read_large(non_minimal_127, sizeof(non_minimal_127), value, consumed));

    const std::uint8_t invalid_prefix[] = {0xC0, 0x00};
    REQUIRE_FALSE(rohccxx::cid::read_large(invalid_prefix, sizeof(invalid_prefix), value, consumed));

    const std::uint8_t minimal_127[] = {0x7F};
    REQUIRE(rohccxx::cid::read_large(minimal_127, sizeof(minimal_127), value, consumed));
    REQUIRE(value == 0x7F);
    REQUIRE(consumed == 1);

    const std::uint8_t minimal_128[] = {0x80, 0x80};
    REQUIRE(rohccxx::cid::read_large(minimal_128, sizeof(minimal_128), value, consumed));
    REQUIRE(value == 0x80);
    REQUIRE(consumed == 2);
}

TEST_CASE("RFC 5225 IR compatibility parser preserves exact legacy migration boundaries")
{
    const std::uint8_t legacy_rtp[] = {
        0xFD, 0x01, 0x9D, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x04,
        0xD2, 0x00, 0x04
    };

    rohccxx::Context decoded{};
    size_t consumed = 0;
    REQUIRE(rohccxx::decode_ir_rtp(legacy_rtp, sizeof(legacy_rtp), decoded, &consumed));
    REQUIRE(consumed == sizeof(legacy_rtp));
    REQUIRE(decoded.rtp.last_seq == 1000);
    REQUIRE(decoded.rtp.last_ts == 1234);
    REQUIRE(decoded.rtp.ssrc == 0xCAFEBABEU);

    for(size_t len = 0; len < sizeof(legacy_rtp); ++len)
    {
        rohccxx::Context unchanged{};
        unchanged.cid = 0;
        unchanged.ipv4_id = 0xBEEF;
        REQUIRE_FALSE(rohccxx::decode_ir_rtp(legacy_rtp, len, unchanged));
        REQUIRE(unchanged.ipv4_id == 0xBEEF);
        REQUIRE(unchanged.rohc_state == rohccxx::RohcState::NoContext);
    }

    std::uint8_t bad_crc[sizeof(legacy_rtp)] = {};
    std::memcpy(bad_crc, legacy_rtp, sizeof(bad_crc));
    bad_crc[2] ^= 0x01;
    rohccxx::Context unchanged{};
    unchanged.ipv4_id = 0xBEEF;
    REQUIRE_FALSE(rohccxx::decode_ir_rtp(bad_crc, sizeof(bad_crc), unchanged));
    REQUIRE(unchanged.ipv4_id == 0xBEEF);
    REQUIRE(unchanged.rohc_state == rohccxx::RohcState::NoContext);
}

TEST_CASE("RFC 5225 IR compatibility parser fails closed on dual-format ambiguity")
{
    rohccxx::Context source = grammar_context(rohccxx::Profile::UDP, 17);
    std::uint8_t packet[128] = {};
    size_t packet_len = sizeof(packet);
    REQUIRE(rohccxx::emit_ir_udp(packet, &packet_len, source));

    const auto conflicting_legacy = [](const std::uint8_t*, size_t len,
                                       rohccxx::Context& ctx, size_t* consumed) {
        ctx.profile = rohccxx::Profile::UDP;
        ctx.ipv4_id = 0xCAFE;
        if(consumed) *consumed = len;
        return true;
    };
    rohccxx::Context unchanged{};
    unchanged.ipv4_id = 0xBEEF;
    REQUIRE_FALSE(rohccxx::detail::decode_ir_compatible(
        packet, packet_len, unchanged, rohccxx::Profile::UDP, 0x02,
        conflicting_legacy, nullptr));
    REQUIRE(unchanged.ipv4_id == 0xBEEF);
    REQUIRE(unchanged.rohc_state == rohccxx::RohcState::NoContext);
}

TEST_CASE("RFC 5225 real standard and legacy parsers fail closed on semantic ambiguity")
{
    const auto& item = grammar_profile_cases[3];
    rohccxx::Context source = grammar_context(item.profile, item.protocol);
    source.msn = 0x4104; // legacy: one-byte options list containing 0x04
    std::array<std::uint8_t, 256> packet{};
    size_t packet_len = packet.size();
    REQUIRE(item.emit_ir(packet.data(), &packet_len, source));
    packet[packet_len++] = 0x04; // legacy O-mode; standard parser sees payload
    rohccxx::Context legacy{};
    size_t legacy_len = 0;
    REQUIRE(rohccxx::decode_ir_ip_legacy(packet.data(), packet_len, legacy, &legacy_len));
    rohccxx::Context standard{};
    size_t standard_len = 0;
    REQUIRE(rohccxx::detail::decode_ir_standard(packet.data(), packet_len, standard,
                                                item.profile, item.profile_id, &standard_len));
    REQUIRE((standard_len != legacy_len ||
             !rohccxx::detail::standard_context_equal(standard, legacy)));
    rohccxx::Context unchanged{};
    unchanged.ipv4_id = 0xBEEF;
    const rohccxx::Context before = unchanged;
    REQUIRE_FALSE(rohccxx::decode_ir_ip(packet.data(), packet_len, unchanged));
    REQUIRE(rohccxx::detail::standard_context_equal(unchanged, before));
}

TEST_CASE("RFC 5225 IR emitters preserve undersized destinations for every profile and CID mode")
{
    for(const auto& item : grammar_profile_cases)
    {
        for(const bool large_cid : {false, true})
        {
            rohccxx::Context ctx = grammar_context(item.profile, item.protocol);
            ctx.large_cid = large_cid;
            ctx.cid = large_cid ? 128U : 5U;
            for(const auto emitter : {item.emit_ir, item.emit_ir_dyn})
            {
                std::array<std::uint8_t, 512> complete{};
                size_t complete_len = complete.size();
                REQUIRE(emitter(complete.data(), &complete_len, ctx));
                for(size_t capacity = 0; capacity < complete_len; ++capacity)
                {
                    std::array<std::uint8_t, 512> guarded{};
                    guarded.fill(0xA5);
                    size_t attempted_len = capacity;
                    REQUIRE_FALSE(emitter(guarded.data(), &attempted_len, ctx));
                    REQUIRE(attempted_len == capacity);
                    REQUIRE(std::all_of(guarded.begin(), guarded.end(),
                                        [](std::uint8_t value) { return value == 0xA5; }));
                }
            }
        }
    }
}

TEST_CASE("RFC 5225 legacy UDP-Lite into emitters are directly capacity safe")
{
    using Emitter = bool (*)(std::uint8_t*, size_t*, const rohccxx::Context&);
    struct Case
    {
        rohccxx::Profile profile;
        std::uint8_t protocol;
        Emitter emitter;
    };
    const Case cases[] = {
        {rohccxx::Profile::UDP_Lite, 136, rohccxx::emit_ir_udp_lite_into},
        {rohccxx::Profile::RTP_UDP_Lite, 136, rohccxx::emit_ir_rtp_udp_lite_into},
        {rohccxx::Profile::UDP_Lite, 136, rohccxx::emit_ir_dyn_udp_lite_into},
        {rohccxx::Profile::RTP_UDP_Lite, 136, rohccxx::emit_ir_dyn_rtp_udp_lite_into},
    };

    for(const auto& item : cases)
    {
        rohccxx::Context ctx = grammar_context(item.profile, item.protocol);
        std::array<std::uint8_t, 512> complete{};
        size_t complete_len = complete.size();
        REQUIRE(item.emitter(complete.data(), &complete_len, ctx));
        for(size_t capacity = 0; capacity < complete_len; ++capacity)
        {
            std::array<std::uint8_t, 512> guarded{};
            guarded.fill(0xA5);
            size_t attempted_len = capacity;
            REQUIRE_FALSE(item.emitter(guarded.data(), &attempted_len, ctx));
            REQUIRE(attempted_len == capacity);
            REQUIRE(std::all_of(guarded.begin(), guarded.end(),
                                [](std::uint8_t value) { return value == 0xA5; }));
        }
    }
}

TEST_CASE("RFC 5225 payload boundary helper rejects invalid consumed lengths")
{
    const std::array<std::uint8_t, 4> packet = {1, 2, 3, 4};
    const std::uint8_t* payload = packet.data();
    size_t payload_len = 99;
    REQUIRE_FALSE(rohccxx::detail::payload_after_header(packet.data(), packet.size(),
                                                        packet.size() + 1U,
                                                        payload, payload_len));
    REQUIRE(payload == packet.data());
    REQUIRE(payload_len == 99);
    REQUIRE(rohccxx::detail::payload_after_header(packet.data(), packet.size(),
                                                  packet.size(), payload, payload_len));
    REQUIRE(payload == packet.data() + packet.size());
    REQUIRE(payload_len == 0);
}

TEST_CASE("RFC 5225 legacy profile parsers reject IPv4 and IPv6 truncation at every boundary")
{
    for(const auto& item : grammar_profile_cases)
    {
        for(const std::uint8_t ip_version : {std::uint8_t{4}, std::uint8_t{6}})
        {
            CAPTURE(item.profile, ip_version);
            rohccxx::Context source = grammar_context(item.profile, item.protocol);
            source.ip_version = ip_version;
            source.ipv6_next_header = item.protocol;
            source.ipv6_traffic_class = 0x2A;
            source.ipv6_flow_label = 0x12345;
            source.ipv6_hop_limit = 61;
            for(size_t i = 0; i < source.ipv6_saddr.size(); ++i)
            {
                source.ipv6_saddr[i] = static_cast<std::uint8_t>(i);
                source.ipv6_daddr[i] = static_cast<std::uint8_t>(0xF0U + i);
            }
            std::array<std::uint8_t, 256> packet{};
            const size_t packet_len = emit_legacy_ir_fixture(packet.data(), packet.size(), source, item.profile_id);
            rohccxx::Context decoded{};
            REQUIRE(decode_legacy_fixture(item, packet.data(), packet_len, decoded));
            for(size_t len = 0; len < packet_len; ++len)
            {
                rohccxx::Context unchanged{};
                unchanged.cid = 0xCAFE;
                unchanged.ipv4_id = 0xBEEF;
                const rohccxx::Context before = unchanged;
                REQUIRE_FALSE(item.decode_ir(packet.data(), len, unchanged, nullptr));
                REQUIRE(rohccxx::detail::standard_context_equal(unchanged, before));
            }
        }
    }
}

TEST_CASE("RFC 5225 legacy IR mode and terminal protocol validation is strict and context preserving")
{
    for(const auto& item : grammar_profile_cases)
    {
        CAPTURE(item.profile);
        rohccxx::Context source = grammar_context(item.profile, item.protocol);
        std::array<std::uint8_t, 256> packet{};
        const size_t packet_len = emit_legacy_ir_fixture(packet.data(), packet.size(), source, item.profile_id);
        for(const std::uint8_t invalid_mode : {std::uint8_t{0x00}, std::uint8_t{0x0C},
                                               std::uint8_t{0x05}, std::uint8_t{0xF4}})
        {
            packet[packet_len - 1U] = invalid_mode;
            rohccxx::Context unchanged{};
            unchanged.ipv4_id = 0xBEEF;
            const rohccxx::Context before = unchanged;
            REQUIRE_FALSE(item.decode_ir(packet.data(), packet_len, unchanged, nullptr));
            REQUIRE(rohccxx::detail::standard_context_equal(unchanged, before));
        }

        if(item.profile != rohccxx::Profile::IP)
        {
            packet = {};
            const size_t contradictory_len = emit_legacy_ir_fixture(packet.data(), packet.size(), source, item.profile_id);
            packet[4] = static_cast<std::uint8_t>(item.protocol ^ 0x01U);
            packet[2] = 0;
            packet[2] = rohccxx::utils::crc8(packet.data(), contradictory_len - 1U);
            rohccxx::Context unchanged{};
            unchanged.ipv4_id = 0xBEEF;
            const rohccxx::Context before = unchanged;
            REQUIRE_FALSE(item.decode_ir(packet.data(), contradictory_len, unchanged, nullptr));
            REQUIRE(rohccxx::detail::standard_context_equal(unchanged, before));
        }
    }
}
