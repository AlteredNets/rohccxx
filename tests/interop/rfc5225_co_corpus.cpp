// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/core/decode_esp_fo.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/decode_ip_fo.hpp"
#include "rohccxx/core/decode_udp_fo.hpp"
#include "rohccxx/core/decode_udplite_fo.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/formal_co.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/emit_udplite_fo.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/core/rfc5225_grammar.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

enum class DecoderKind
{
    Rtp,
    Udp,
    Ip,
    Esp,
    UdpLite,
};

struct ProfileSpec
{
    rohccxx::Profile profile;
    std::uint8_t protocol;
    rohccxx::RohcPacketType packet_type;
    const char* name;
    const char* variant_id;
    bool rtp_family;
    bool (*emit)(std::uint8_t*, std::size_t*, const rohccxx::Context&);
    DecoderKind decoder;
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
    ctx.rohc_state = rohccxx::RohcState::DynamicEstablished;
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
    ctx.rtp.seq_window.init(ctx.rtp.last_seq);
    ctx.rtp.ts_window.init(ctx.rtp.last_ts);
    return ctx;
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

size_t make_crc_header(const ProfileSpec& profile,
                       const rohccxx::Context& ctx,
                       std::uint16_t msn,
                       std::uint8_t* out)
{
    std::memset(out, 0, 64);
    out[0] = static_cast<std::uint8_t>(profile.profile);
    out[1] = profile.protocol;
    write_be16(out + 2, msn);
    write_be16(out + 4, ctx.ipv4_id);
    write_be32(out + 6, ctx.ipv4_saddr);
    write_be32(out + 10, ctx.ipv4_daddr);
    size_t pos = 14;
    switch(profile.profile)
    {
    case rohccxx::Profile::RTP:
    case rohccxx::Profile::RTP_UDP_Lite:
        write_be16(out + pos, ctx.udp_sport);
        write_be16(out + pos + 2U, ctx.udp_dport);
        write_be16(out + pos + 4U, msn);
        write_be32(out + pos + 6U, ctx.rtp.last_ts);
        write_be32(out + pos + 10U, ctx.rtp.ssrc);
        return pos + 14U;
    case rohccxx::Profile::UDP:
    case rohccxx::Profile::UDP_Lite:
        write_be16(out + pos, ctx.udp_sport);
        write_be16(out + pos + 2U, ctx.udp_dport);
        write_be16(out + pos + 4U, ctx.udp_length_or_coverage);
        write_be16(out + pos + 6U, ctx.udp_check);
        return pos + 8U;
    case rohccxx::Profile::ESP:
        write_be32(out + pos, 0xA0B0C0D0U);
        write_be32(out + pos + 4U, msn);
        return pos + 8U;
    default:
        return pos;
    }
}

bool prepend_add_cid(std::uint8_t* packet, std::size_t& len, std::size_t capacity, std::uint32_t cid)
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

bool emit_wire(const ProfileSpec& profile,
               const CidSpec& cid,
               std::uint8_t* rohc,
               std::size_t& rohc_len)
{
    rohccxx::Context ctx = make_context(profile.profile, profile.protocol);
    ctx.cid = cid.cid;
    ctx.large_cid = cid.large_cid;

    const std::size_t capacity = rohc_len;
    if(!profile.emit(rohc, &rohc_len, ctx))
        return false;
    if(!profile.rtp_family && !ctx.large_cid && ctx.cid > 0)
        return prepend_add_cid(rohc, rohc_len, capacity, ctx.cid);
    return true;
}

bool decode_wire(const ProfileSpec& profile,
                 const std::uint8_t* packet,
                 std::size_t packet_len,
                 rohccxx::Context& ctx,
                 std::size_t& consumed)
{
    switch(profile.decoder)
    {
    case DecoderKind::Rtp:
    {
        std::uint16_t seq = 0;
        std::uint32_t ts = 0;
        return rohccxx::decode_fo_rtp(packet, packet_len, ctx, seq, ts, &consumed);
    }
    case DecoderKind::Udp:
        return rohccxx::decode_udp_fo(packet, packet_len, ctx, &consumed);
    case DecoderKind::Ip:
        return rohccxx::decode_ip_fo(packet, packet_len, ctx, &consumed);
    case DecoderKind::Esp:
        return rohccxx::decode_esp_fo(packet, packet_len, ctx, &consumed);
    case DecoderKind::UdpLite:
        return rohccxx::decode_udp_lite_fo(packet, packet_len, ctx, &consumed);
    }
    return false;
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

const char* cid_mode(const CidSpec& cid, bool rtp_family)
{
    if(cid.large_cid)
        return "large";
    if(cid.cid == 0)
        return "small";
    return rtp_family ? "embedded" : "add";
}

bool emit_case(const ProfileSpec& profile, const CidSpec& cid)
{
    std::uint8_t rohc[192] = {};
    std::size_t rohc_len = sizeof(rohc);
    if(!emit_wire(profile, cid, rohc, rohc_len))
        return false;

    rohccxx::ParsedRohcPacket parsed{};
    if(!rohccxx::parse_rohc_packet(rohc, rohc_len, parsed, cid.large_cid))
        return false;
    if(parsed.type != profile.packet_type || parsed.cid != cid.cid)
        return false;
    if(parsed.has_large_cid != cid.large_cid)
        return false;
    if(parsed.has_add_cid != (!profile.rtp_family && !cid.large_cid && cid.cid > 0))
        return false;

    rohccxx::Context decoded = make_context(profile.profile, profile.protocol);
    decoded.cid = cid.cid;
    decoded.large_cid = cid.large_cid;
    std::size_t consumed = 0;
    if(!decode_wire(profile, parsed.packet, parsed.packet_len, decoded, consumed))
        return false;
    if(consumed != parsed.packet_len || decoded.cid != cid.cid)
        return false;

    std::printf("case id=5225-%s-co-current.cid-%s profile=%s variant=%s cid=%u cid_mode=%s rohc_len=%zu rohc=",
                profile.name,
                cid.name,
                profile.name,
                profile.variant_id,
                static_cast<unsigned>(cid.cid),
                cid_mode(cid, profile.rtp_family),
                rohc_len);
    print_hex(rohc, rohc_len);
    std::putchar('\n');
    return true;
}

std::uint16_t lsb_mask_for_bits(std::uint8_t bits)
{
    return bits >= 16U ? 0xFFFFU : static_cast<std::uint16_t>((1U << bits) - 1U);
}

const char* formal_profile_id_prefix(rohccxx::Profile profile)
{
    switch(profile)
    {
    case rohccxx::Profile::RTP: return "rtp";
    case rohccxx::Profile::UDP: return "udp";
    case rohccxx::Profile::ESP: return "esp";
    case rohccxx::Profile::IP: return "ip";
    case rohccxx::Profile::RTP_UDP_Lite: return "rtp-udplite";
    case rohccxx::Profile::UDP_Lite: return "udplite";
    case rohccxx::Profile::Uncompressed:
    case rohccxx::Profile::LLA_RTP:
        return nullptr;
    }
    return nullptr;
}

const char* formal_variant_suffix(rohccxx::rfc5225::FormalCoVariant variant)
{
    switch(variant)
    {
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc3: return "pt-0-crc3";
    case rohccxx::rfc5225::FormalCoVariant::Pt0Crc7: return "pt-0-crc7";
    case rohccxx::rfc5225::FormalCoVariant::Pt1Rnd: return "pt-1-rnd";
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqId: return "pt-1-seq-id";
    case rohccxx::rfc5225::FormalCoVariant::Pt1SeqTs: return "pt-1-seq-ts";
    case rohccxx::rfc5225::FormalCoVariant::Pt2Rnd: return "pt-2-rnd";
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqId: return "pt-2-seq-id";
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqBoth: return "pt-2-seq-both";
    case rohccxx::rfc5225::FormalCoVariant::Pt2SeqTs: return "pt-2-seq-ts";
    case rohccxx::rfc5225::FormalCoVariant::CoCommon: return "co-common";
    case rohccxx::rfc5225::FormalCoVariant::CoRepair: return "co-repair";
    }
    return nullptr;
}

rohccxx::rfc5225::FormalCoFields make_formal_fields(const rohccxx::Context& ctx, const CidSpec& cid)
{
    rohccxx::rfc5225::FormalCoFields fields{};
    fields.msn = static_cast<std::uint16_t>(ctx.rtp.last_seq + 0x37U);
    fields.ip_id = static_cast<std::uint16_t>(ctx.ipv4_id + 0x4DU);
    fields.ts_scaled = 0x55U;
    fields.marker = (cid.cid & 0x01U) != 0;
    return fields;
}

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
                                                                 const CidSpec& cid)
{
    rohccxx::rfc5225::FormalCoCommonFields fields{};
    fields.variable = formal_common_variable_for_profile(profile);
    fields.ip_id_indicator = true;
    if(rohccxx::rfc5225::is_rtp_formal_co_profile(profile))
    {
        fields.marker = (cid.cid & 0x01U) != 0;
        fields.flags1_indicator = true;
        fields.flags2_indicator = (cid.cid & 0x02U) != 0;
        fields.tsc_indicator = true;
        fields.tss_indicator = cid.large_cid;
    }
    else
    {
        fields.flags_indicator = true;
        fields.ttl_hopl_indicator = (cid.cid & 0x01U) != 0;
        fields.tos_tc_indicator = true;
        fields.reorder_ratio = static_cast<std::uint8_t>((cid.cid + (cid.large_cid ? 1U : 0U)) & 0x03U);
    }
    return fields;
}

rohccxx::rfc5225::FormalCoRepairFields make_formal_repair_fields(rohccxx::Profile profile)
{
    rohccxx::rfc5225::FormalCoRepairFields fields{};
    fields.dynamic_chain = formal_repair_dynamic_chain_for_profile(profile);
    return fields;
}

size_t build_formal_common_control_crc(const ProfileSpec& profile,
                                       const rohccxx::rfc5225::FormalCoCommonFields& fields,
                                       std::uint8_t* out)
{
    std::memset(out, 0, 32);
    size_t pos = 0;
    out[pos++] = profile.protocol;
    if(rohccxx::rfc5225::is_rtp_formal_co_profile(profile.profile))
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
        if(profile.profile == rohccxx::Profile::UDP_Lite)
            out[pos++] = 0x02U;
    }
    out[pos++] = fields.ip_id_indicator ? 0x01U : 0x00U;
    return pos;
}

size_t build_formal_repair_control_crc(const ProfileSpec& profile,
                                       const rohccxx::rfc5225::FormalCoRepairFields& fields,
                                       std::uint8_t* out)
{
    std::memset(out, 0, 32);
    size_t pos = 0;
    out[pos++] = profile.protocol;
    out[pos++] = static_cast<std::uint8_t>(fields.dynamic_chain.len & 0xFFU);
    if(fields.dynamic_chain.len > 0)
    {
        const size_t copy_len = fields.dynamic_chain.len > 14U ? 14U : fields.dynamic_chain.len;
        std::memcpy(out + pos, fields.dynamic_chain.data, copy_len);
        pos += copy_len;
    }
    return pos;
}

bool decoded_formal_fields_match(const ProfileSpec& profile,
                                 rohccxx::rfc5225::FormalCoVariant variant,
                                 const rohccxx::rfc5225::FormalCoFields& fields,
                                 const rohccxx::rfc5225::FormalCoPacket& decoded)
{
    const std::uint8_t msn_bits = rohccxx::rfc5225::formal_co_msn_lsb_bits(profile.profile, variant);
    if(decoded.msn != (fields.msn & lsb_mask_for_bits(msn_bits)))
        return false;

    const std::uint8_t ip_bits = rohccxx::rfc5225::formal_co_ip_id_lsb_bits(profile.profile, variant);
    if(ip_bits != 0 && decoded.ip_id != (fields.ip_id & lsb_mask_for_bits(ip_bits)))
        return false;
    if(ip_bits == 0 && decoded.ip_id != 0)
        return false;

    const std::uint8_t ts_bits = rohccxx::rfc5225::formal_co_ts_scaled_lsb_bits(profile.profile, variant);
    if(ts_bits != 0 && decoded.ts_scaled != (fields.ts_scaled & lsb_mask_for_bits(ts_bits)))
        return false;
    if(ts_bits == 0 && decoded.ts_scaled != 0)
        return false;

    const bool expected_marker = rohccxx::rfc5225::formal_co_variant_has_marker(variant) && fields.marker;
    return decoded.marker == expected_marker;
}

bool emit_formal_case(const ProfileSpec& profile,
                      const CidSpec& cid,
                      rohccxx::rfc5225::FormalCoVariant variant)
{
    rohccxx::Context ctx = make_context(profile.profile, profile.protocol);
    ctx.cid = cid.cid;
    ctx.large_cid = cid.large_cid;
    const rohccxx::rfc5225::FormalCoFields fields = make_formal_fields(ctx, cid);
    std::uint8_t crc_header[64] = {};
    const size_t crc_header_len = make_crc_header(profile, ctx, fields.msn, crc_header);
    const rohccxx::rfc5225::FormalCoCrcInput crc_input{crc_header, crc_header_len};
    std::uint8_t rohc[192] = {};
    size_t rohc_len = sizeof(rohc);
    std::uint8_t control_crc_data[32] = {};
    size_t control_crc_len = 0;
    if(variant == rohccxx::rfc5225::FormalCoVariant::CoCommon)
    {
        const auto common_fields = make_formal_common_fields(profile.profile, cid);
        control_crc_len = build_formal_common_control_crc(profile, common_fields, control_crc_data);
        const rohccxx::rfc5225::FormalCoCrcInput control_crc_input{control_crc_data, control_crc_len};
        if(!rohccxx::rfc5225::emit_formal_co_common(rohc,
                                                    &rohc_len,
                                                    profile.profile,
                                                    cid.cid,
                                                    cid.large_cid,
                                                    common_fields,
                                                    crc_input,
                                                    control_crc_input))
        {
            return false;
        }

        rohccxx::rfc5225::FormalCoPacket decoded{};
        size_t consumed = 0;
        if(!rohccxx::rfc5225::decode_formal_co_common(rohc,
                                                      rohc_len,
                                                      profile.profile,
                                                      cid.large_cid,
                                                      crc_input,
                                                      control_crc_input,
                                                      decoded,
                                                      &consumed))
        {
            return false;
        }
        if(consumed != rohc_len || decoded.cid != cid.cid ||
           decoded.variant != rohccxx::rfc5225::FormalCoVariant::CoCommon ||
           decoded.variable_len != common_fields.variable.len)
        {
            return false;
        }
        if(std::memcmp(rohc + decoded.variable_offset,
                       common_fields.variable.data,
                       common_fields.variable.len) != 0)
        {
            return false;
        }
    }
    else if(variant == rohccxx::rfc5225::FormalCoVariant::CoRepair)
    {
        const auto repair_fields = make_formal_repair_fields(profile.profile);
        control_crc_len = build_formal_repair_control_crc(profile, repair_fields, control_crc_data);
        const rohccxx::rfc5225::FormalCoCrcInput control_crc_input{control_crc_data, control_crc_len};
        if(!rohccxx::rfc5225::emit_formal_co_repair(rohc,
                                                    &rohc_len,
                                                    profile.profile,
                                                    cid.cid,
                                                    cid.large_cid,
                                                    repair_fields,
                                                    crc_input,
                                                    control_crc_input))
        {
            return false;
        }

        rohccxx::rfc5225::FormalCoPacket decoded{};
        size_t consumed = 0;
        if(!rohccxx::rfc5225::decode_formal_co_repair(rohc,
                                                      rohc_len,
                                                      profile.profile,
                                                      cid.large_cid,
                                                      crc_input,
                                                      control_crc_input,
                                                      decoded,
                                                      &consumed))
        {
            return false;
        }
        if(consumed != rohc_len || decoded.cid != cid.cid ||
           decoded.variant != rohccxx::rfc5225::FormalCoVariant::CoRepair ||
           decoded.variable_len != repair_fields.dynamic_chain.len)
        {
            return false;
        }
        if(std::memcmp(rohc + decoded.variable_offset,
                       repair_fields.dynamic_chain.data,
                       repair_fields.dynamic_chain.len) != 0)
        {
            return false;
        }
    }
    else if(!rohccxx::rfc5225::emit_formal_co(rohc,
                                              &rohc_len,
                                              profile.profile,
                                              variant,
                                              cid.cid,
                                              cid.large_cid,
                                              fields,
                                              crc_input))
    {
        return false;
    }
    else
    {
        rohccxx::rfc5225::FormalCoPacket decoded{};
        size_t consumed = 0;
        if(!rohccxx::rfc5225::decode_formal_co(rohc,
                                               rohc_len,
                                               profile.profile,
                                               variant,
                                               cid.large_cid,
                                               crc_input,
                                               decoded,
                                               &consumed))
        {
            return false;
        }
        if(consumed != rohc_len || decoded.cid != cid.cid || decoded.variant != variant)
            return false;
        if(!decoded_formal_fields_match(profile, variant, fields, decoded))
            return false;
    }

    const char* profile_prefix = formal_profile_id_prefix(profile.profile);
    const char* variant_suffix = formal_variant_suffix(variant);
    if(!profile_prefix || !variant_suffix)
        return false;

    std::printf("case id=5225-%s-%s.cid-%s profile=%s variant=5225-%s-%s cid=%u cid_mode=%s msn=0x%04x crc_data=",
                profile_prefix,
                variant_suffix,
                cid.name,
                profile.name,
                profile_prefix,
                variant_suffix,
                static_cast<unsigned>(cid.cid),
                cid_mode(cid, false),
                static_cast<unsigned>(fields.msn));
    print_hex(crc_header, crc_header_len);
    if(control_crc_len > 0)
    {
        std::printf(" control_crc_data=");
        print_hex(control_crc_data, control_crc_len);
    }
    std::printf(" rohc_len=%zu rohc=", rohc_len);
    print_hex(rohc, rohc_len);
    std::putchar('\n');
    return true;
}


} // namespace

int main()
{
    namespace grammar = rohccxx::rfc5225::grammar;
    if(grammar::co_variant_count() != 52 ||
       grammar::count_co_variants(grammar::CaseStatus::Implemented) != 52 ||
       grammar::count_co_variants(grammar::CaseStatus::Planned) != 0)
    {
        return 1;
    }

    const ProfileSpec profiles[] = {
        {rohccxx::Profile::RTP, 17, rohccxx::RohcPacketType::FO_RTP, "rtp_udp_ip", "5225-rtp-co-current-fo", true, rohccxx::emit_rtp_fo, DecoderKind::Rtp},
        {rohccxx::Profile::UDP, 17, rohccxx::RohcPacketType::FO_UDP, "udp_ip", "5225-udp-co-current-fo", false, rohccxx::emit_udp_fo, DecoderKind::Udp},
        {rohccxx::Profile::ESP, 50, rohccxx::RohcPacketType::FO_ESP, "esp_ip", "5225-esp-co-current-fo", false, rohccxx::emit_esp_fo, DecoderKind::Esp},
        {rohccxx::Profile::IP, 6, rohccxx::RohcPacketType::FO_IP, "ip_only", "5225-ip-co-current-fo", false, rohccxx::emit_ip_fo, DecoderKind::Ip},
        {rohccxx::Profile::RTP_UDP_Lite, 136, rohccxx::RohcPacketType::FO_RTP, "rtp_udplite_ip", "5225-rtp-udplite-co-current-fo", true, rohccxx::emit_rtp_fo, DecoderKind::Rtp},
        {rohccxx::Profile::UDP_Lite, 136, rohccxx::RohcPacketType::FO_UDP_Lite, "udplite_ip", "5225-udplite-co-current-fo", false, rohccxx::emit_udp_lite_fo, DecoderKind::UdpLite},
    };
    const CidSpec cids[] = {
        {"small0", 0, false},
        {"cid1", 1, false},
        {"cid15", rohccxx::cid::small_cid_max, false},
        {"large0", 0, true},
        {"large127", 0x7F, true},
        {"large128", 0x80, true},
        {"large16383", rohccxx::cid::large_cid_max, true},
    };
    const rohccxx::rfc5225::FormalCoVariant formal_variants[] = {
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

    constexpr std::size_t case_count = 364U;
    std::printf("rohccxx-rfc5225-co-corpus-v4 profiles=6 cid_cases=7 implemented_variants=52 cases=%zu encoding=hex\n",
                case_count);

    for(const auto& profile : profiles)
    {
        if(!grammar::find_co_variant(profile.variant_id))
            return 1;
        for(const auto& cid : cids)
        {
            if(!emit_case(profile, cid))
                return 1;
            for(const auto variant : formal_variants)
            {
                if(!rohccxx::rfc5225::formal_co_variant_valid_for_profile(profile.profile, variant))
                    continue;
                if(!emit_formal_case(profile, cid, variant))
                    return 1;
            }
        }
    }

    return 0;
}
