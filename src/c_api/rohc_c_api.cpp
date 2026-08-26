// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <rohccxx.h>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/context_crc.hpp"
#include "rohccxx/core/encoding_methods.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context_table.hpp"
#include "rohccxx/core/profile.hpp"
#include "rohccxx/core/classify.hpp"
#include "rohccxx/core/context_init.hpp"
#include "rohccxx/core/emit_uncompressed.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/emit_udp_fo.hpp"
#include "rohccxx/core/emit_ip_fo.hpp"
#include "rohccxx/core/emit_esp_fo.hpp"
#include "rohccxx/core/emit_udplite_fo.hpp"
#include "rohccxx/core/emit_ir.hpp"
#include "rohccxx/core/emit_ir_dyn.hpp"
#include "rohccxx/core/packet_type.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/core/decode_ir_dyn.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/decode_udp_fo.hpp"
#include "rohccxx/core/decode_ip_fo.hpp"
#include "rohccxx/core/decode_esp_fo.hpp"
#include "rohccxx/core/ppp.hpp"
#include "rohccxx/core/decode_udplite_fo.hpp"
#include "rohccxx/core/feedback.hpp"
#include "rohccxx/core/segment.hpp"
#include "rohccxx/core/rohcoipsec.hpp"
#include "rohccxx/core/lla.hpp"
#include "rohccxx/core/formal_co.hpp"

#include "rohccxx/protocols/ipv4.hpp"
#include "rohccxx/protocols/ipv6.hpp"
#include "rohccxx/protocols/udp.hpp"
#include "rohccxx/protocols/rtp.hpp"
#include "rohccxx/utils/bytes.hpp"
#include "rohccxx/utils/crc.hpp"

#include "rohccxx/wire/convert.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>

#ifndef ROHCCXX_DEBUG
//#define ROHCCXX_DEBUG 1
#endif

#if ROHCCXX_DEBUG
#define DBG(fmt, ...) \
    fprintf(stderr, "[rohccxx] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

static std::uint16_t ipv4_checksum(const std::uint8_t* hdr, int len)
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

static bool capture_ipv4_options(rohccxx::Context& ctx,
                                 const uint8_t* packet,
                                 size_t ip_hlen)
{
    constexpr size_t base_ipv4_len = 20;
    if(ip_hlen < base_ipv4_len)
        return false;

    const size_t options_len = ip_hlen - base_ipv4_len;
    if(options_len > ctx.ipv4_options.size() || (options_len % 4U) != 0U)
        return false;

    ctx.ipv4_options_len = static_cast<uint8_t>(options_len);
    ctx.ipv4_options.fill(0);
    if(options_len > 0)
        std::memcpy(ctx.ipv4_options.data(), packet + base_ipv4_len, options_len);
    return true;
}


struct ParsedIpView
{
    const rohccxx::ipv4::Header* ip4 = nullptr;
    const rohccxx::ipv6::Header* ip6 = nullptr;
    size_t header_len = 0;
    size_t extension_len = 0;
    uint8_t terminal_protocol = 0;
    bool is_ipv6 = false;
};

static bool parse_ip_view(const uint8_t* packet, size_t packet_len, ParsedIpView& view)
{
    size_t ip4_hlen = 0;
    if(rohccxx::ipv4::parse(packet, packet_len, view.ip4, ip4_hlen))
    {
        view.header_len = ip4_hlen;
        view.terminal_protocol = rohccxx::wire::to_host(view.ip4->protocol);
        view.is_ipv6 = false;
        return true;
    }

    if(rohccxx::ipv6::parse(packet,
                            packet_len,
                            view.ip6,
                            view.header_len,
                            view.terminal_protocol,
                            view.extension_len))
    {
        view.is_ipv6 = true;
        return true;
    }

    return false;
}

static bool capture_ip_context(rohccxx::Context& ctx,
                               const uint8_t* packet,
                               const ParsedIpView& view)
{
    ctx.ip_version = view.is_ipv6 ? 6 : 4;
    ctx.ipv4_protocol = view.terminal_protocol;
    ctx.ipv4_options_len = 0;
    ctx.ipv4_options.fill(0);
    ctx.ipv6_extension_len = 0;
    ctx.ipv6_extensions.fill(0);

    if(!view.is_ipv6)
    {
        ctx.ipv4_tos = rohccxx::wire::to_host(view.ip4->tos);
        ctx.ipv4_ttl = rohccxx::wire::to_host(view.ip4->ttl);
        ctx.ipv4_id = rohccxx::wire::to_host(view.ip4->identification);
        ctx.ipv4_flags = static_cast<std::uint8_t>(
            (rohccxx::wire::to_host(view.ip4->flags_fragment) >> 13U) & 0x07U);
        ctx.ipv4_saddr = rohccxx::wire::to_host(view.ip4->src);
        ctx.ipv4_daddr = rohccxx::wire::to_host(view.ip4->dst);
        ctx.ipv4_id_behavior = ctx.ipv4_id == 0 ? 3U : 2U;
        ctx.ipv4_id_sequential = false;
        return capture_ipv4_options(ctx, packet, view.header_len);
    }

    const uint32_t first_word = rohccxx::wire::to_host(view.ip6->version_tc_flow);
    ctx.ipv6_traffic_class = static_cast<uint8_t>((first_word >> 20) & 0xFFU);
    ctx.ipv6_flow_label = first_word & 0x000FFFFFU;
    ctx.ipv6_next_header = rohccxx::wire::to_host(view.ip6->next_header);
    ctx.ipv6_hop_limit = rohccxx::wire::to_host(view.ip6->hop_limit);
    std::memcpy(ctx.ipv6_saddr.data(), view.ip6->src, ctx.ipv6_saddr.size());
    std::memcpy(ctx.ipv6_daddr.data(), view.ip6->dst, ctx.ipv6_daddr.size());
    if(view.extension_len > ctx.ipv6_extensions.size())
        return false;
    ctx.ipv6_extension_len = static_cast<uint8_t>(view.extension_len);
    if(view.extension_len > 0)
        std::memcpy(ctx.ipv6_extensions.data(), packet + sizeof(rohccxx::ipv6::Header), view.extension_len);
    return true;
}

struct RtpPayloadView
{
    size_t payload_offset = sizeof(rohccxx::rtp::Header);
    size_t payload_len = 0;
};

static bool capture_rtp_context(rohccxx::Context& ctx,
                                const uint8_t* rtp_packet,
                                size_t rtp_packet_len,
                                RtpPayloadView& view)
{
    if(!rtp_packet || rtp_packet_len < sizeof(rohccxx::rtp::Header))
        return false;

    ctx.rtp.csrc_list_len = 0;
    ctx.rtp.csrc_list.fill(0);
    ctx.rtp.extension_len = 0;
    ctx.rtp.extension_bytes.fill(0);
    ctx.rtp.padding_len = 0;
    ctx.rtp.padding_bytes.fill(0);

    const uint8_t csrc_count = static_cast<uint8_t>(rtp_packet[0] & 0x0FU);
    const size_t csrc_len = static_cast<size_t>(csrc_count) * 4U;
    size_t pos = sizeof(rohccxx::rtp::Header);
    if(rtp_packet_len < pos + csrc_len || csrc_len > ctx.rtp.csrc_list.size())
        return false;
    ctx.rtp.csrc_list_len = static_cast<uint8_t>(csrc_len);
    if(csrc_len > 0)
        std::memcpy(ctx.rtp.csrc_list.data(), rtp_packet + pos, csrc_len);
    pos += csrc_len;

    if((rtp_packet[0] & 0x10U) != 0)
    {
        if(rtp_packet_len < pos + 4U)
            return false;
        const uint16_t extension_words = static_cast<uint16_t>((static_cast<uint16_t>(rtp_packet[pos + 2U]) << 8) |
                                                               static_cast<uint16_t>(rtp_packet[pos + 3U]));
        const size_t extension_len = 4U + static_cast<size_t>(extension_words) * 4U;
        if(extension_len > ctx.rtp.extension_bytes.size() || rtp_packet_len < pos + extension_len)
            return false;
        ctx.rtp.extension_len = static_cast<uint16_t>(extension_len);
        std::memcpy(ctx.rtp.extension_bytes.data(), rtp_packet + pos, extension_len);
        pos += extension_len;
    }

    size_t padding_len = 0;
    if((rtp_packet[0] & 0x20U) != 0)
    {
        padding_len = rtp_packet[rtp_packet_len - 1U];
        if(padding_len == 0 || padding_len > ctx.rtp.padding_bytes.size() || padding_len > rtp_packet_len - pos)
            return false;
        ctx.rtp.padding_len = static_cast<uint8_t>(padding_len);
        std::memcpy(ctx.rtp.padding_bytes.data(), rtp_packet + rtp_packet_len - padding_len, padding_len);
    }

    view.payload_offset = pos;
    view.payload_len = rtp_packet_len - pos - padding_len;
    uint32_t ignored_body_len = 0;
    return rohccxx::rfc5225::rtp_extras_body_len(ctx, ignored_body_len);
}

static bool rtp_context_payload_layout(const rohccxx::Context& ctx,
                                       size_t& csrc_len,
                                       size_t& extension_len,
                                       size_t& padding_len)
{
    uint32_t ignored_body_len = 0;
    if(!rohccxx::rfc5225::rtp_extras_body_len(ctx, ignored_body_len))
        return false;
    csrc_len = ctx.rtp.csrc_list_len;
    extension_len = ctx.rtp.extension_len;
    padding_len = ctx.rtp.padding_len;
    return true;
}

static bool prepend_small_cid(uint8_t* packet,
                              size_t* packet_len,
                              size_t capacity,
                              uint32_t cid)
{
    if(cid == 0)
        return true;
    if(!packet || !packet_len || cid > 0x0F || *packet_len + 1U > capacity)
        return false;

    std::memmove(packet + 1, packet, *packet_len);
    packet[0] = static_cast<uint8_t>(0xE0 | (cid & 0x0F));
    ++(*packet_len);
    return true;
}

static bool prepend_private_rtp_small_cid(uint8_t* packet,
                                          size_t* packet_len,
                                          size_t capacity,
                                          uint32_t cid)
{
    if(!packet || !packet_len || cid > 0x0FU || *packet_len + 1U > capacity)
        return false;
    std::memmove(packet + 1U, packet, *packet_len);
    packet[0] = static_cast<uint8_t>(0xE0U | cid);
    ++(*packet_len);
    return true;
}


static bool update_rtp_ipv4_id_behavior(rohccxx::Context& ctx,
                                        bool had_ipv4_rtp_context,
                                        std::uint16_t previous_ipv4_id,
                                        std::uint16_t previous_ipv4_flags,
                                        bool previous_ipv4_id_sequential,
                                        std::uint16_t previous_rtp_seq,
                                        std::uint16_t seq)
{
    if(ctx.ip_version != 4 || !had_ipv4_rtp_context)
    {
        ctx.ipv4_id_behavior = ctx.ipv4_id == 0 ? 3U : 2U;
        ctx.ipv4_id_sequential = false;
        return true;
    }

    const auto id_delta = static_cast<std::uint16_t>(ctx.ipv4_id - previous_ipv4_id);
    const auto seq_delta = static_cast<std::uint16_t>(seq - previous_rtp_seq);
    const auto swapped_id = static_cast<std::uint16_t>((ctx.ipv4_id >> 8U) | (ctx.ipv4_id << 8U));
    const auto swapped_previous = static_cast<std::uint16_t>((previous_ipv4_id >> 8U) |
                                                             (previous_ipv4_id << 8U));
    const auto swapped_delta = static_cast<std::uint16_t>(swapped_id - swapped_previous);
    if(id_delta == seq_delta)
        ctx.ipv4_id_behavior = 0U;
    else if(ctx.ipv4_id == 0)
        ctx.ipv4_id_behavior = 3U;
    else if(swapped_delta == seq_delta)
        ctx.ipv4_id_behavior = 1U;
    else
        ctx.ipv4_id_behavior = 2U;
    ctx.ipv4_id_sequential = ctx.ipv4_id_behavior <= 1U;

    const bool flags_unchanged = ctx.ipv4_flags == previous_ipv4_flags;
    // Compact RTP FO has no room to signal IPv4 ID/flag behavior changes.
    const bool behavior_unchanged = ctx.ipv4_id_sequential == previous_ipv4_id_sequential;
    const bool id_fo_safe = ctx.ipv4_id == previous_ipv4_id || ctx.ipv4_id_sequential;
    return flags_unchanged && behavior_unchanged && id_fo_safe;
}

static void update_ipv4_id_behavior(rohccxx::Context& ctx,
                                    bool had_ipv4_context,
                                    std::uint16_t previous_ipv4_id)
{
    if(ctx.ip_version != 4)
        return;
    if(ctx.ipv4_id == 0)
    {
        ctx.ipv4_id_behavior = 3U;
    }
    else if(had_ipv4_context)
    {
        const auto delta = static_cast<std::uint16_t>(ctx.ipv4_id - previous_ipv4_id);
        const auto swapped_id = static_cast<std::uint16_t>((ctx.ipv4_id >> 8U) | (ctx.ipv4_id << 8U));
        const auto swapped_previous = static_cast<std::uint16_t>((previous_ipv4_id >> 8U) |
                                                                 (previous_ipv4_id << 8U));
        const auto swapped_delta = static_cast<std::uint16_t>(swapped_id - swapped_previous);
        ctx.ipv4_id_behavior = delta == 1U ? 0U : (swapped_delta == 1U ? 1U : 2U);
    }
    else
    {
        ctx.ipv4_id_behavior = 2U;
    }
    ctx.ipv4_id_sequential = ctx.ipv4_id_behavior <= 1U;
}

static void update_rtp_timestamp_stride(rohccxx::Context& ctx,
                                        std::uint16_t seq,
                                        std::uint32_t ts)
{
    if(ctx.tx_count == 0)
    {
        ctx.rtp.ts_stride = 0;
        ctx.rtp.ts_residue = 0;
        return;
    }
    if(ctx.tx_count != 1)
        return;

    std::uint32_t stride = 0;
    std::uint32_t residue = 0;
    if(!rohccxx::encoding::infer_timestamp_stride(ctx.rtp.last_seq,
                                                   ctx.rtp.last_ts,
                                                   seq,
                                                   ts,
                                                   stride,
                                                   residue))
    {
        return;
    }

    ctx.rtp.ts_stride = stride;
    ctx.rtp.ts_residue = residue;
}

static bool rtp_pt0_reconstructable(const rohccxx::Context& previous,
                                    const rohccxx::Context& current)
{
    if(previous.profile != rohccxx::Profile::RTP ||
       previous.rohc_state != rohccxx::RohcState::DynamicEstablished ||
       previous.ip_version != 4 || current.ip_version != 4 ||
       previous.rtp.ts_stride == 0U)
        return false;
    const auto delta = static_cast<std::uint16_t>(current.rtp.last_seq - previous.rtp.last_seq);
    if(delta == 0U || delta > 15U ||
       current.rtp.last_ts != previous.rtp.last_ts + previous.rtp.ts_stride * delta ||
       current.rtp.vpxcc != previous.rtp.vpxcc || current.rtp.mpt != previous.rtp.mpt ||
       current.rtp.ssrc != previous.rtp.ssrc ||
       current.udp_sport != previous.udp_sport || current.udp_dport != previous.udp_dport ||
       current.udp_check != previous.udp_check ||
       current.ipv4_tos != previous.ipv4_tos || current.ipv4_ttl != previous.ipv4_ttl ||
       current.ipv4_flags != previous.ipv4_flags ||
       current.ipv4_protocol != previous.ipv4_protocol ||
       current.ipv4_saddr != previous.ipv4_saddr || current.ipv4_daddr != previous.ipv4_daddr ||
       current.ipv4_options_len != previous.ipv4_options_len ||
       current.ipv4_options != previous.ipv4_options ||
       current.ipv4_id_behavior != previous.ipv4_id_behavior)
        return false;
    if(current.ipv4_id_behavior == 0U)
        return current.ipv4_id == static_cast<std::uint16_t>(previous.ipv4_id + delta);
    return (current.ipv4_id_behavior == 2U || current.ipv4_id_behavior == 3U) &&
           current.ipv4_id == previous.ipv4_id;
}

static bool udp_pt0_reconstructable(const rohccxx::Context& previous,
                                    const rohccxx::Context& current)
{
    if(previous.profile != rohccxx::Profile::UDP ||
       previous.rohc_state != rohccxx::RohcState::DynamicEstablished ||
       previous.ip_version != 4 || current.ip_version != 4 ||
       current.msn != static_cast<std::uint16_t>(previous.msn + 1U) ||
       current.ipv4_id_behavior != 0U ||
       current.ipv4_id != static_cast<std::uint16_t>(previous.ipv4_id + 1U) ||
       current.udp_sport != previous.udp_sport || current.udp_dport != previous.udp_dport ||
       current.udp_check != 0U || previous.udp_check != 0U ||
       current.ipv4_tos != previous.ipv4_tos || current.ipv4_ttl != previous.ipv4_ttl ||
       current.ipv4_flags != previous.ipv4_flags ||
       current.ipv4_protocol != previous.ipv4_protocol ||
       current.ipv4_saddr != previous.ipv4_saddr || current.ipv4_daddr != previous.ipv4_daddr ||
       current.ipv4_options_len != previous.ipv4_options_len ||
       current.ipv4_options != previous.ipv4_options)
        return false;
    return true;
}

static bool esp_pt0_reconstructable(const rohccxx::Context& previous,
                                    const rohccxx::Context& current)
{
    if(previous.profile != rohccxx::Profile::ESP ||
       previous.rohc_state != rohccxx::RohcState::DynamicEstablished ||
       previous.ip_version != 4 || current.ip_version != 4 ||
       current.esp_spi != previous.esp_spi ||
       current.ipv4_id_behavior != 0U ||
       current.ipv4_tos != previous.ipv4_tos || current.ipv4_ttl != previous.ipv4_ttl ||
       current.ipv4_flags != previous.ipv4_flags ||
       current.ipv4_protocol != previous.ipv4_protocol ||
       current.ipv4_saddr != previous.ipv4_saddr || current.ipv4_daddr != previous.ipv4_daddr ||
       current.ipv4_options_len != previous.ipv4_options_len ||
       current.ipv4_options != previous.ipv4_options)
        return false;
    const std::uint32_t delta = current.esp_sequence - previous.esp_sequence;
    return delta > 0U && delta <= 15U &&
           current.msn == static_cast<std::uint16_t>(previous.msn + delta) &&
           current.ipv4_id == static_cast<std::uint16_t>(previous.ipv4_id + delta);
}

static bool ip_private_fo_reconstructable(const rohccxx::Context& previous,
                                          const rohccxx::Context& current)
{
    return previous.profile == rohccxx::Profile::IP &&
           previous.rohc_state == rohccxx::RohcState::DynamicEstablished &&
           previous.ip_version == 4 && current.ip_version == 4 &&
           current.ipv4_tos == previous.ipv4_tos &&
           current.ipv4_ttl == previous.ipv4_ttl &&
           current.ipv4_flags == previous.ipv4_flags &&
           current.ipv4_protocol == previous.ipv4_protocol &&
           current.ipv4_saddr == previous.ipv4_saddr &&
           current.ipv4_daddr == previous.ipv4_daddr &&
           current.ipv4_options_len == previous.ipv4_options_len &&
           current.ipv4_options == previous.ipv4_options;
}

static bool ip_pt0_reconstructable(const rohccxx::Context& previous,
                                   const rohccxx::Context& current)
{
    return ip_private_fo_reconstructable(previous, current) &&
           current.msn == static_cast<std::uint16_t>(previous.msn + 1U) &&
           current.ipv4_id_behavior == 0U &&
           current.ipv4_id == static_cast<std::uint16_t>(previous.ipv4_id + 1U);
}

static std::uint16_t byte_swap_u16(std::uint16_t value)
{
    return static_cast<std::uint16_t>((value >> 8U) | (value << 8U));
}

static bool ip_pt1_seq_id_reconstructable(const rohccxx::Context& previous,
                                          const rohccxx::Context& current,
                                          std::uint16_t& encoded_ip_id)
{
    encoded_ip_id = 0U;
    if(!ip_private_fo_reconstructable(previous, current) ||
       current.msn != static_cast<std::uint16_t>(previous.msn + 1U) ||
       previous.ipv4_id_behavior > 1U || current.ipv4_id == 0U)
        return false;

    const bool swapped = previous.ipv4_id_behavior == 1U;
    const std::uint16_t reference = swapped ? byte_swap_u16(previous.ipv4_id) : previous.ipv4_id;
    const std::uint16_t value = swapped ? byte_swap_u16(current.ipv4_id) : current.ipv4_id;
    std::uint32_t decoded = 0U;
    const std::uint16_t lsb = static_cast<std::uint16_t>(
        rohccxx::encoding::encode_field_lsb(rohccxx::encoding::EncodedField::IpId,
                                            value, 4U));
    if(!rohccxx::encoding::decode_field_lsb_with_p(
           rohccxx::encoding::EncodedField::IpId, lsb, reference, 4U, 0U, decoded) ||
       static_cast<std::uint16_t>(decoded) != value || value == reference)
        return false;
    encoded_ip_id = value;
    return true;
}

static bool pt0_private_fo_ambiguous(std::uint8_t pt0,
                                     const std::uint8_t* payload,
                                     size_t payload_len)
{
    const auto type = rohccxx::detect_packet_type(pt0);
    size_t private_header_len = 0U;
    if(type == rohccxx::RohcPacketType::FO_UDP)
        private_header_len = 6U;
    else if(type == rohccxx::RohcPacketType::FO_ESP ||
            type == rohccxx::RohcPacketType::FO_IP)
        private_header_len = 4U;
    else
        return false;
    if(!payload || payload_len < private_header_len - 1U)
        return false;
    std::array<std::uint8_t, 6> candidate{};
    candidate[0] = pt0;
    std::memcpy(candidate.data() + 1U, payload, private_header_len - 1U);
    rohccxx::Context tentative{};
    size_t consumed = 0U;
    if(type == rohccxx::RohcPacketType::FO_UDP)
        return rohccxx::decode_udp_fo(candidate.data(), private_header_len,
                                      tentative, &consumed);
    if(type == rohccxx::RohcPacketType::FO_ESP)
        return rohccxx::decode_esp_fo(candidate.data(), private_header_len,
                                      tentative, &consumed);
    return rohccxx::decode_ip_fo(candidate.data(), private_header_len,
                                 tentative, &consumed);
}

static bool emit_rtp_pt0_small_cid(std::uint8_t* out,
                                   size_t* out_len,
                                   std::uint32_t cid,
                                   std::uint16_t msn,
                                   const std::uint8_t* ipv4_udp_rtp_header)
{
    if(!out || !out_len || !ipv4_udp_rtp_header || cid > 0x0fU)
        return false;
    const size_t required = cid == 0U ? 1U : 2U;
    if(*out_len < required)
        return false;
    size_t pos = 0U;
    if(cid != 0U)
        out[pos++] = static_cast<std::uint8_t>(0xe0U | cid);
    out[pos++] = static_cast<std::uint8_t>(((msn & 0x0fU) << 3U) |
                                           rohccxx::utils::crc3(ipv4_udp_rtp_header, 40U));
    *out_len = pos;
    return true;
}

static bool checked_packet_size(size_t base, size_t payload, size_t& total)
{
    if(payload > std::numeric_limits<size_t>::max() - base)
        return false;
    total = base + payload;
    return true;
}

static bool build_ip_packet(uint8_t* out,
                            size_t* out_len,
                            const rohccxx::Context& ctx,
                            const uint8_t* payload,
                            size_t payload_len)
{
    const size_t ip_len = 20U + ctx.ipv4_options_len;
    size_t total = 0;
    if(!checked_packet_size(ip_len, payload_len, total) || total > 0xFFFFU)
        return false;

    if (*out_len < total)
        return false;

    std::memset(out, 0, total);

    out[0] = static_cast<std::uint8_t>(0x40U | (ip_len / 4U));
    out[1] = ctx.ipv4_tos;
    const std::uint16_t ip_total = static_cast<std::uint16_t>(total);
    out[2] = static_cast<std::uint8_t>(ip_total >> 8);
    out[3] = static_cast<std::uint8_t>(ip_total & 0xFF);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id & 0xFF);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5);
    out[7] = 0x00;
    out[8] = ctx.ipv4_ttl;
    out[9] = ctx.ipv4_protocol;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    if(ctx.ipv4_options_len > 0)
        std::memcpy(out + 20, ctx.ipv4_options.data(), ctx.ipv4_options_len);
    const std::uint16_t ip_csum = ipv4_checksum(out, static_cast<int>(ip_len));
    out[10] = static_cast<std::uint8_t>(ip_csum >> 8);
    out[11] = static_cast<std::uint8_t>(ip_csum & 0xFF);

    if(payload_len > 0)
        std::memcpy(out + ip_len, payload, payload_len);

    *out_len = total;
    return true;
}

static bool build_udp_packet(uint8_t* out,
                             size_t* out_len,
                             const rohccxx::Context& ctx,
                             const uint8_t* payload,
                             size_t payload_len)
{
    const size_t ip_len = 20U + ctx.ipv4_options_len;
    constexpr size_t udp_len = 8;
    size_t total = 0;
    if(!checked_packet_size(ip_len + udp_len, payload_len, total) || total > 0xFFFFU)
        return false;

    if (*out_len < total)
        return false;

    std::memset(out, 0, total);

    out[0] = static_cast<std::uint8_t>(0x40U | (ip_len / 4U));
    out[1] = ctx.ipv4_tos;
    const std::uint16_t ip_total = static_cast<std::uint16_t>(total);
    out[2] = static_cast<std::uint8_t>(ip_total >> 8);
    out[3] = static_cast<std::uint8_t>(ip_total & 0xFF);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id & 0xFF);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5);
    out[7] = 0x00;
    out[8] = ctx.ipv4_ttl;
    out[9] = ctx.profile == rohccxx::Profile::UDP_Lite ? 136 : 17;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    if(ctx.ipv4_options_len > 0)
        std::memcpy(out + 20, ctx.ipv4_options.data(), ctx.ipv4_options_len);
    const std::uint16_t ip_csum = ipv4_checksum(out, static_cast<int>(ip_len));
    out[10] = static_cast<std::uint8_t>(ip_csum >> 8);
    out[11] = static_cast<std::uint8_t>(ip_csum & 0xFF);

    uint8_t* udp_out = out + ip_len;
    udp_out[0] = static_cast<std::uint8_t>(ctx.udp_sport >> 8);
    udp_out[1] = static_cast<std::uint8_t>(ctx.udp_sport & 0xFF);
    udp_out[2] = static_cast<std::uint8_t>(ctx.udp_dport >> 8);
    udp_out[3] = static_cast<std::uint8_t>(ctx.udp_dport & 0xFF);
    const std::uint16_t udp_total = static_cast<std::uint16_t>(udp_len + payload_len);
    const std::uint16_t udp_length_or_coverage = ctx.profile == rohccxx::Profile::UDP_Lite
        ? ctx.udp_length_or_coverage
        : udp_total;
    udp_out[4] = static_cast<std::uint8_t>(udp_length_or_coverage >> 8);
    udp_out[5] = static_cast<std::uint8_t>(udp_length_or_coverage & 0xFF);
    udp_out[6] = static_cast<std::uint8_t>(ctx.udp_check >> 8);
    udp_out[7] = static_cast<std::uint8_t>(ctx.udp_check & 0xFF);

    if(payload_len > 0)
        std::memcpy(out + ip_len + udp_len, payload, payload_len);

    *out_len = total;
    return true;
}

static bool build_rtp_packet(uint8_t* out,
                             size_t* out_len,
                             const rohccxx::Context& ctx,
                             const uint8_t* payload,
                             size_t payload_len)
{
    size_t csrc_len = 0;
    size_t extension_len = 0;
    size_t padding_len = 0;
    if(!rtp_context_payload_layout(ctx, csrc_len, extension_len, padding_len))
        return false;

    const size_t ip_len = 20U + ctx.ipv4_options_len;
    constexpr size_t udp_len = 8;
    const size_t rtp_header_len = 12U + csrc_len + extension_len;
    if(payload_len > std::numeric_limits<size_t>::max() - rtp_header_len - padding_len)
        return false;
    const size_t rtp_wire_len = rtp_header_len + payload_len + padding_len;
    size_t total = 0;
    if(!checked_packet_size(ip_len + udp_len, rtp_wire_len, total) || total > 0xFFFFU)
        return false;

    if (*out_len < total)
        return false;

    std::memset(out, 0, total);

    out[0] = static_cast<std::uint8_t>(0x40U | (ip_len / 4U));
    out[1] = ctx.ipv4_tos;
    const std::uint16_t ip_total = static_cast<std::uint16_t>(total);
    out[2] = static_cast<std::uint8_t>(ip_total >> 8);
    out[3] = static_cast<std::uint8_t>(ip_total & 0xFF);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id & 0xFF);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5);
    out[7] = 0x00;
    out[8] = ctx.ipv4_ttl;
    out[9] = ctx.profile == rohccxx::Profile::RTP_UDP_Lite ? 136 : 17;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    if(ctx.ipv4_options_len > 0)
        std::memcpy(out + 20, ctx.ipv4_options.data(), ctx.ipv4_options_len);
    const std::uint16_t ip_csum = ipv4_checksum(out, static_cast<int>(ip_len));
    out[10] = static_cast<std::uint8_t>(ip_csum >> 8);
    out[11] = static_cast<std::uint8_t>(ip_csum & 0xFF);

    uint8_t* udp_out = out + ip_len;
    uint8_t* rtp_out = udp_out + udp_len;
    udp_out[0] = static_cast<std::uint8_t>(ctx.udp_sport >> 8);
    udp_out[1] = static_cast<std::uint8_t>(ctx.udp_sport & 0xFF);
    udp_out[2] = static_cast<std::uint8_t>(ctx.udp_dport >> 8);
    udp_out[3] = static_cast<std::uint8_t>(ctx.udp_dport & 0xFF);
    const std::uint16_t udp_total = static_cast<std::uint16_t>(udp_len + rtp_wire_len);
    const std::uint16_t udp_length_or_coverage = ctx.profile == rohccxx::Profile::RTP_UDP_Lite
        ? ctx.udp_length_or_coverage
        : udp_total;
    udp_out[4] = static_cast<std::uint8_t>(udp_length_or_coverage >> 8);
    udp_out[5] = static_cast<std::uint8_t>(udp_length_or_coverage & 0xFF);
    udp_out[6] = static_cast<std::uint8_t>(ctx.udp_check >> 8);
    udp_out[7] = static_cast<std::uint8_t>(ctx.udp_check & 0xFF);

    rtp_out[0] = ctx.rtp.vpxcc;
    rtp_out[1] = ctx.rtp.mpt;
    rtp_out[2] = static_cast<std::uint8_t>(ctx.rtp.last_seq >> 8);
    rtp_out[3] = static_cast<std::uint8_t>(ctx.rtp.last_seq & 0xFF);
    rtp_out[4] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 24);
    rtp_out[5] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 16);
    rtp_out[6] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 8);
    rtp_out[7] = static_cast<std::uint8_t>(ctx.rtp.last_ts & 0xFF);
    rtp_out[8] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 24);
    rtp_out[9] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 16);
    rtp_out[10] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 8);
    rtp_out[11] = static_cast<std::uint8_t>(ctx.rtp.ssrc & 0xFF);

    size_t rtp_pos = 12U;
    if(csrc_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.csrc_list.data(), csrc_len);
        rtp_pos += csrc_len;
    }
    if(extension_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.extension_bytes.data(), extension_len);
        rtp_pos += extension_len;
    }
    if(payload_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, payload, payload_len);
        rtp_pos += payload_len;
    }
    if(padding_len > 0)
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.padding_bytes.data(), padding_len);

    *out_len = total;
    return true;
}

static bool build_fixed_rtp_ipv4_header(std::array<std::uint8_t, 40>& out,
                                        const rohccxx::Context& ctx,
                                        size_t payload_len)
{
    if(ctx.ip_version != 4 || ctx.ipv4_options_len != 0U ||
       (ctx.rtp.vpxcc & 0x3fU) != 0U || ctx.rtp.csrc_list_len != 0U ||
       ctx.rtp.extension_len != 0U || ctx.rtp.padding_len != 0U ||
       payload_len > 0xffffU - out.size())
        return false;

    out.fill(0U);
    const auto total = static_cast<std::uint16_t>(out.size() + payload_len);
    const auto udp_total = static_cast<std::uint16_t>(20U + payload_len);
    out[0] = 0x45U;
    out[1] = ctx.ipv4_tos;
    out[2] = static_cast<std::uint8_t>(total >> 8U);
    out[3] = static_cast<std::uint8_t>(total);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8U);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5U);
    out[8] = ctx.ipv4_ttl;
    out[9] = 17U;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24U);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16U);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8U);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24U);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16U);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8U);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    out[20] = static_cast<std::uint8_t>(ctx.udp_sport >> 8U);
    out[21] = static_cast<std::uint8_t>(ctx.udp_sport);
    out[22] = static_cast<std::uint8_t>(ctx.udp_dport >> 8U);
    out[23] = static_cast<std::uint8_t>(ctx.udp_dport);
    out[24] = static_cast<std::uint8_t>(udp_total >> 8U);
    out[25] = static_cast<std::uint8_t>(udp_total);
    out[26] = static_cast<std::uint8_t>(ctx.udp_check >> 8U);
    out[27] = static_cast<std::uint8_t>(ctx.udp_check);
    out[28] = ctx.rtp.vpxcc;
    out[29] = ctx.rtp.mpt;
    out[30] = static_cast<std::uint8_t>(ctx.rtp.last_seq >> 8U);
    out[31] = static_cast<std::uint8_t>(ctx.rtp.last_seq);
    out[32] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 24U);
    out[33] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 16U);
    out[34] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 8U);
    out[35] = static_cast<std::uint8_t>(ctx.rtp.last_ts);
    out[36] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 24U);
    out[37] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 16U);
    out[38] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 8U);
    out[39] = static_cast<std::uint8_t>(ctx.rtp.ssrc);
    const auto checksum = ipv4_checksum(out.data(), 20);
    out[10] = static_cast<std::uint8_t>(checksum >> 8U);
    out[11] = static_cast<std::uint8_t>(checksum);
    return true;
}

static bool build_fixed_udp_ipv4_header(std::array<std::uint8_t, 28>& out,
                                        const rohccxx::Context& ctx,
                                        size_t payload_len)
{
    if(ctx.profile != rohccxx::Profile::UDP || ctx.ip_version != 4 ||
       ctx.ipv4_options_len != 0U || payload_len > 0xffffU - out.size())
        return false;
    out.fill(0U);
    const auto total = static_cast<std::uint16_t>(out.size() + payload_len);
    const auto udp_total = static_cast<std::uint16_t>(8U + payload_len);
    out[0] = 0x45U;
    out[1] = ctx.ipv4_tos;
    out[2] = static_cast<std::uint8_t>(total >> 8U);
    out[3] = static_cast<std::uint8_t>(total);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8U);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5U);
    out[8] = ctx.ipv4_ttl;
    out[9] = 17U;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24U);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16U);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8U);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24U);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16U);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8U);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    out[20] = static_cast<std::uint8_t>(ctx.udp_sport >> 8U);
    out[21] = static_cast<std::uint8_t>(ctx.udp_sport);
    out[22] = static_cast<std::uint8_t>(ctx.udp_dport >> 8U);
    out[23] = static_cast<std::uint8_t>(ctx.udp_dport);
    out[24] = static_cast<std::uint8_t>(udp_total >> 8U);
    out[25] = static_cast<std::uint8_t>(udp_total);
    out[26] = static_cast<std::uint8_t>(ctx.udp_check >> 8U);
    out[27] = static_cast<std::uint8_t>(ctx.udp_check);
    const auto checksum = ipv4_checksum(out.data(), 20);
    out[10] = static_cast<std::uint8_t>(checksum >> 8U);
    out[11] = static_cast<std::uint8_t>(checksum);
    return true;
}

static bool build_fixed_esp_ipv4_header(std::array<std::uint8_t, 28>& out,
                                        const rohccxx::Context& ctx,
                                        size_t payload_len)
{
    if(ctx.profile != rohccxx::Profile::ESP || ctx.ip_version != 4 ||
       ctx.ipv4_options_len != 0U || payload_len > 0xffffU - out.size())
        return false;
    out.fill(0U);
    const auto total = static_cast<std::uint16_t>(out.size() + payload_len);
    out[0] = 0x45U;
    out[1] = ctx.ipv4_tos;
    out[2] = static_cast<std::uint8_t>(total >> 8U);
    out[3] = static_cast<std::uint8_t>(total);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8U);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5U);
    out[8] = ctx.ipv4_ttl;
    out[9] = 50U;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24U);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16U);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8U);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24U);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16U);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8U);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    out[20] = static_cast<std::uint8_t>(ctx.esp_spi >> 24U);
    out[21] = static_cast<std::uint8_t>(ctx.esp_spi >> 16U);
    out[22] = static_cast<std::uint8_t>(ctx.esp_spi >> 8U);
    out[23] = static_cast<std::uint8_t>(ctx.esp_spi);
    out[24] = static_cast<std::uint8_t>(ctx.esp_sequence >> 24U);
    out[25] = static_cast<std::uint8_t>(ctx.esp_sequence >> 16U);
    out[26] = static_cast<std::uint8_t>(ctx.esp_sequence >> 8U);
    out[27] = static_cast<std::uint8_t>(ctx.esp_sequence);
    const auto checksum = ipv4_checksum(out.data(), 20U);
    out[10] = static_cast<std::uint8_t>(checksum >> 8U);
    out[11] = static_cast<std::uint8_t>(checksum);
    return true;
}

static bool build_fixed_ip_ipv4_header(std::array<std::uint8_t, 20>& out,
                                       const rohccxx::Context& ctx,
                                       size_t payload_len)
{
    if(ctx.profile != rohccxx::Profile::IP || ctx.ip_version != 4 ||
       ctx.ipv4_options_len != 0U || payload_len > 0xffffU - out.size())
        return false;
    out.fill(0U);
    const auto total = static_cast<std::uint16_t>(out.size() + payload_len);
    out[0] = 0x45U;
    out[1] = ctx.ipv4_tos;
    out[2] = static_cast<std::uint8_t>(total >> 8U);
    out[3] = static_cast<std::uint8_t>(total);
    out[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8U);
    out[5] = static_cast<std::uint8_t>(ctx.ipv4_id);
    out[6] = static_cast<std::uint8_t>(ctx.ipv4_flags << 5U);
    out[8] = ctx.ipv4_ttl;
    out[9] = ctx.ipv4_protocol;
    out[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24U);
    out[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16U);
    out[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8U);
    out[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr);
    out[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24U);
    out[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16U);
    out[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8U);
    out[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr);
    const auto checksum = ipv4_checksum(out.data(), out.size());
    out[10] = static_cast<std::uint8_t>(checksum >> 8U);
    out[11] = static_cast<std::uint8_t>(checksum);
    return true;
}

static bool build_ipv6_ip_packet(uint8_t* out,
                                 size_t* out_len,
                                 const rohccxx::Context& ctx,
                                 const uint8_t* payload,
                                 size_t payload_len);

static bool build_esp_packet(uint8_t* out,
                             size_t* out_len,
                             const rohccxx::Context& ctx,
                             const uint8_t* payload,
                             size_t payload_len)
{
    constexpr size_t esp_len = 8U;
    const size_t ip_len = ctx.ip_version == 6 ? 40U : 20U;
    if(payload_len > std::numeric_limits<size_t>::max() - esp_len ||
       esp_len + payload_len > std::numeric_limits<size_t>::max() - ip_len)
        return false;
    const size_t esp_payload_len = esp_len + payload_len;
    const size_t protocol_payload_limit = ctx.ip_version == 6
        ? 0xFFFFU - ctx.ipv6_extension_len
        : 0xFFFFU - ip_len;
    if(esp_payload_len > protocol_payload_limit)
        return false;
    if(*out_len < ip_len + esp_payload_len)
        return false;
    std::unique_ptr<uint8_t[]> esp_payload(new(std::nothrow) uint8_t[esp_payload_len]);
    if(!esp_payload)
        return false;
    esp_payload[0] = static_cast<uint8_t>(ctx.esp_spi >> 24);
    esp_payload[1] = static_cast<uint8_t>(ctx.esp_spi >> 16);
    esp_payload[2] = static_cast<uint8_t>(ctx.esp_spi >> 8);
    esp_payload[3] = static_cast<uint8_t>(ctx.esp_spi);
    esp_payload[4] = static_cast<uint8_t>(ctx.esp_sequence >> 24);
    esp_payload[5] = static_cast<uint8_t>(ctx.esp_sequence >> 16);
    esp_payload[6] = static_cast<uint8_t>(ctx.esp_sequence >> 8);
    esp_payload[7] = static_cast<uint8_t>(ctx.esp_sequence);
    if(payload_len > 0)
        std::memcpy(esp_payload.get() + esp_len, payload, payload_len);
    return ctx.ip_version == 6
        ? build_ipv6_ip_packet(out, out_len, ctx, esp_payload.get(), esp_payload_len)
        : build_ip_packet(out, out_len, ctx, esp_payload.get(), esp_payload_len);
}


static bool build_ipv6_header(uint8_t* out,
                              size_t total,
                              const rohccxx::Context& ctx,
                              size_t upper_len)
{
    if(total < 40U || upper_len > 0xFFFFU)
        return false;

    const uint32_t first_word = 0x60000000U |
        (static_cast<uint32_t>(ctx.ipv6_traffic_class) << 20) |
        (ctx.ipv6_flow_label & 0x000FFFFFU);
    out[0] = static_cast<uint8_t>(first_word >> 24);
    out[1] = static_cast<uint8_t>(first_word >> 16);
    out[2] = static_cast<uint8_t>(first_word >> 8);
    out[3] = static_cast<uint8_t>(first_word);
    out[4] = static_cast<uint8_t>(upper_len >> 8);
    out[5] = static_cast<uint8_t>(upper_len & 0xFF);
    out[6] = ctx.ipv6_next_header;
    out[7] = ctx.ipv6_hop_limit;
    std::memcpy(out + 8, ctx.ipv6_saddr.data(), ctx.ipv6_saddr.size());
    std::memcpy(out + 24, ctx.ipv6_daddr.data(), ctx.ipv6_daddr.size());
    if(ctx.ipv6_extension_len > 0)
        std::memcpy(out + 40, ctx.ipv6_extensions.data(), ctx.ipv6_extension_len);
    return true;
}

static bool build_ipv6_ip_packet(uint8_t* out,
                                 size_t* out_len,
                                 const rohccxx::Context& ctx,
                                 const uint8_t* payload,
                                 size_t payload_len)
{
    const size_t ip_len = 40U + ctx.ipv6_extension_len;
    size_t total = 0;
    size_t upper_len = 0;
    if(!checked_packet_size(ctx.ipv6_extension_len, payload_len, upper_len) ||
       upper_len > 0xFFFFU ||
       !checked_packet_size(ip_len, payload_len, total))
        return false;
    if(*out_len < total)
        return false;
    std::memset(out, 0, total);
    if(!build_ipv6_header(out, total, ctx, upper_len))
        return false;
    if(payload_len > 0)
        std::memcpy(out + ip_len, payload, payload_len);
    *out_len = total;
    return true;
}

static bool build_ipv6_udp_packet(uint8_t* out,
                                  size_t* out_len,
                                  const rohccxx::Context& ctx,
                                  const uint8_t* payload,
                                  size_t payload_len)
{
    constexpr size_t udp_len = 8;
    const size_t ip_len = 40U + ctx.ipv6_extension_len;
    size_t total = 0;
    size_t upper_len = 0;
    if(!checked_packet_size(ctx.ipv6_extension_len + udp_len, payload_len, upper_len) ||
       upper_len > 0xFFFFU ||
       !checked_packet_size(ip_len + udp_len, payload_len, total))
        return false;
    if(*out_len < total)
        return false;
    std::memset(out, 0, total);
    if(!build_ipv6_header(out, total, ctx, upper_len))
        return false;
    uint8_t* udp_out = out + ip_len;
    udp_out[0] = static_cast<uint8_t>(ctx.udp_sport >> 8);
    udp_out[1] = static_cast<uint8_t>(ctx.udp_sport & 0xFF);
    udp_out[2] = static_cast<uint8_t>(ctx.udp_dport >> 8);
    udp_out[3] = static_cast<uint8_t>(ctx.udp_dport & 0xFF);
    const uint16_t udp_total = static_cast<uint16_t>(udp_len + payload_len);
    const uint16_t length_or_coverage = ctx.profile == rohccxx::Profile::UDP_Lite ? ctx.udp_length_or_coverage : udp_total;
    udp_out[4] = static_cast<uint8_t>(length_or_coverage >> 8);
    udp_out[5] = static_cast<uint8_t>(length_or_coverage & 0xFF);
    udp_out[6] = static_cast<uint8_t>(ctx.udp_check >> 8);
    udp_out[7] = static_cast<uint8_t>(ctx.udp_check & 0xFF);
    if(payload_len > 0)
        std::memcpy(out + ip_len + udp_len, payload, payload_len);
    *out_len = total;
    return true;
}

static bool build_ipv6_rtp_packet(uint8_t* out,
                                  size_t* out_len,
                                  const rohccxx::Context& ctx,
                                  const uint8_t* payload,
                                  size_t payload_len)
{
    size_t csrc_len = 0;
    size_t extension_len = 0;
    size_t padding_len = 0;
    if(!rtp_context_payload_layout(ctx, csrc_len, extension_len, padding_len))
        return false;

    constexpr size_t udp_len = 8;
    const size_t rtp_header_len = 12U + csrc_len + extension_len;
    if(payload_len > std::numeric_limits<size_t>::max() - rtp_header_len - padding_len)
        return false;
    const size_t rtp_wire_len = rtp_header_len + payload_len + padding_len;
    const size_t ip_len = 40U + ctx.ipv6_extension_len;
    size_t total = 0;
    size_t upper_len = 0;
    if(!checked_packet_size(ctx.ipv6_extension_len + udp_len, rtp_wire_len, upper_len) ||
       upper_len > 0xFFFFU ||
       !checked_packet_size(ip_len + udp_len, rtp_wire_len, total))
        return false;
    if(*out_len < total)
        return false;
    std::memset(out, 0, total);
    if(!build_ipv6_header(out, total, ctx, upper_len))
        return false;
    uint8_t* udp_out = out + ip_len;
    uint8_t* rtp_out = udp_out + udp_len;
    udp_out[0] = static_cast<uint8_t>(ctx.udp_sport >> 8);
    udp_out[1] = static_cast<uint8_t>(ctx.udp_sport & 0xFF);
    udp_out[2] = static_cast<uint8_t>(ctx.udp_dport >> 8);
    udp_out[3] = static_cast<uint8_t>(ctx.udp_dport & 0xFF);
    const uint16_t udp_total = static_cast<uint16_t>(udp_len + rtp_wire_len);
    const uint16_t length_or_coverage = ctx.profile == rohccxx::Profile::RTP_UDP_Lite ? ctx.udp_length_or_coverage : udp_total;
    udp_out[4] = static_cast<uint8_t>(length_or_coverage >> 8);
    udp_out[5] = static_cast<uint8_t>(length_or_coverage & 0xFF);
    udp_out[6] = static_cast<uint8_t>(ctx.udp_check >> 8);
    udp_out[7] = static_cast<uint8_t>(ctx.udp_check & 0xFF);
    rtp_out[0] = ctx.rtp.vpxcc;
    rtp_out[1] = ctx.rtp.mpt;
    rtp_out[2] = static_cast<uint8_t>(ctx.rtp.last_seq >> 8);
    rtp_out[3] = static_cast<uint8_t>(ctx.rtp.last_seq & 0xFF);
    rtp_out[4] = static_cast<uint8_t>(ctx.rtp.last_ts >> 24);
    rtp_out[5] = static_cast<uint8_t>(ctx.rtp.last_ts >> 16);
    rtp_out[6] = static_cast<uint8_t>(ctx.rtp.last_ts >> 8);
    rtp_out[7] = static_cast<uint8_t>(ctx.rtp.last_ts & 0xFF);
    rtp_out[8] = static_cast<uint8_t>(ctx.rtp.ssrc >> 24);
    rtp_out[9] = static_cast<uint8_t>(ctx.rtp.ssrc >> 16);
    rtp_out[10] = static_cast<uint8_t>(ctx.rtp.ssrc >> 8);
    rtp_out[11] = static_cast<uint8_t>(ctx.rtp.ssrc & 0xFF);

    size_t rtp_pos = 12U;
    if(csrc_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.csrc_list.data(), csrc_len);
        rtp_pos += csrc_len;
    }
    if(extension_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.extension_bytes.data(), extension_len);
        rtp_pos += extension_len;
    }
    if(payload_len > 0)
    {
        std::memcpy(rtp_out + rtp_pos, payload, payload_len);
        rtp_pos += payload_len;
    }
    if(padding_len > 0)
        std::memcpy(rtp_out + rtp_pos, ctx.rtp.padding_bytes.data(), padding_len);

    *out_len = total;
    return true;
}

namespace rohccxx_internal
{
    constexpr size_t segment_buffer_max = 4096;
    constexpr size_t segment_header_len = 2;
    constexpr size_t rohcoipsec_key_max = 128;
    struct Compressor
    {
        mutable std::recursive_mutex mutex;
        rohccxx::Direction direction;
        rohccxx::Mode mode = rohccxx::Mode::Optimistic;
        rohccxx::ContextTable contexts;
        uint32_t current_cid = 0;
        bool large_cid_space = false;
        size_t mrru = 0;
        bool suppress_segmentation = false;
        uint8_t pending_segment[segment_buffer_max] = {};
        size_t pending_segment_len = 0;
        size_t pending_segment_pos = 0;
        uint16_t next_segment_sequence = 0;
        bool rohcoipsec_enabled = false;
        uint16_t rohcoipsec_algorithm = static_cast<uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None);
        uint8_t rohcoipsec_key[rohcoipsec_key_max] = {};
        size_t rohcoipsec_key_len = 0;
        size_t rohcoipsec_icv_len = 0;
        bool lla_enabled = false;
        rohccxx::lla::AssistingLayerContract lla_contract{};
        rohccxx::lla::ZeroByteFlow lla_flow{};
    };

    struct Decompressor
    {
        mutable std::recursive_mutex mutex;
        rohccxx::Direction direction;
        rohccxx::Mode mode = rohccxx::Mode::Optimistic;
        rohccxx::ContextTable contexts;
        bool large_cid_space = false;
        rohccxx::Feedback last_feedback;
        bool has_feedback = false;
        size_t mrru = 0;
        bool reassembly_active = false;
        uint8_t reassembly[segment_buffer_max] = {};
        size_t reassembly_len = 0;
        uint16_t expected_segment_sequence = 0;
        bool rohcoipsec_enabled = false;
        uint16_t rohcoipsec_algorithm = static_cast<uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None);
        uint8_t rohcoipsec_key[rohcoipsec_key_max] = {};
        size_t rohcoipsec_key_len = 0;
        size_t rohcoipsec_icv_len = 0;
        bool lla_enabled = false;
        rohccxx::lla::AssistingLayerContract lla_contract{};
        rohccxx::lla::ZeroByteFlow lla_flow{};
    };
}

/* ABI-safe opaque handles */
struct rohc_comp
{
    rohccxx_internal::Compressor impl;
};

struct rohc_decomp
{
    rohccxx_internal::Decompressor impl;
};


static rohccxx::lla::AssistingLayerContract c_lla_contract_to_core(const rohccxx_lla_contract_t& in)
{
    rohccxx::lla::AssistingLayerContract out{};
    out.identifies_packet_types = in.identifies_packet_types != 0;
    out.preserves_order = in.preserves_order != 0;
    out.reports_loss = in.reports_loss != 0;
    out.reports_residual_errors = in.reports_residual_errors != 0;
    out.delivers_feedback = in.delivers_feedback != 0;
    out.protects_context_packets = in.protects_context_packets != 0;
    out.supports_context_synchronization = in.supports_context_synchronization != 0;
    out.supports_context_check = in.supports_context_check != 0;
    out.supports_reliable_mode = in.supports_reliable_mode != 0;
    out.delivers_ack = in.delivers_ack != 0;
    out.delivers_static_nack = in.delivers_static_nack != 0;
    return out;
}

static rohccxx::lla::ZeroByteFlow c_lla_flow_to_core(const rohccxx_lla_flow_t& in)
{
    rohccxx::lla::ZeroByteFlow out{};
    out.ipv4_udp_rtp = in.ipv4_udp_rtp != 0;
    out.udp_checksum_disabled = in.udp_checksum_disabled != 0;
    out.rtp_sequence_increments_by_one = in.rtp_sequence_increments_by_one != 0;
    out.compressor_observed_in_order = in.compressor_observed_in_order != 0;
    out.synchronized_timing = in.synchronized_timing != 0;
    return out;
}


static bool c_ppp_option_to_core(const rohccxx_ppp_rohc_option_t& in,
                                 rohccxx::ppp::RohcOption& out)
{
    if(in.profile_count > rohccxx::ppp::max_profiles)
        return false;

    out = rohccxx::ppp::RohcOption{};
    out.max_cid = in.max_cid;
    out.mrru = in.mrru;
    out.max_header = in.max_header;
    for(size_t i = 0; i < in.profile_count; ++i)
    {
        if(!rohccxx::ppp::append_profile(out, in.profiles[i]))
            return false;
    }
    return true;
}

static bool core_ppp_option_to_c(const rohccxx::ppp::RohcOption& in,
                                 rohccxx_ppp_rohc_option_t& out)
{
    if(in.profile_count > ROHCCXX_PPP_MAX_PROFILES)
        return false;

    std::memset(&out, 0, sizeof(out));
    out.max_cid = in.max_cid;
    out.mrru = in.mrru;
    out.max_header = in.max_header;
    out.profile_count = in.profile_count;
    for(size_t i = 0; i < in.profile_count; ++i)
        out.profiles[i] = in.profiles[i];
    return true;
}

static int validation_to_c_result(rohccxx::lla::ContractValidation validation,
                                  uint32_t* missing)
{
    if(!missing)
        return -1;
    *missing = validation.missing;
    return validation.valid ? 1 : 0;
}
static bool lla_runtime_contract_valid(const rohccxx::lla::AssistingLayerContract& contract,
                                       const rohccxx::lla::ZeroByteFlow& flow)
{
    return rohccxx::lla::validate_rfc3409_lower_layer_guidelines(contract).valid &&
           rohccxx::lla::validate_rfc3243_zero_byte_flow(contract, flow).valid;
}

static bool lla_context_established(const rohccxx::Context& ctx)
{
    return (ctx.profile == rohccxx::Profile::RTP || ctx.profile == rohccxx::Profile::LLA_RTP) &&
           ctx.rohc_state != rohccxx::RohcState::NoContext;
}

static bool lla_context_ready(const rohccxx::Context& ctx)
{
    return lla_context_established(ctx) &&
           ctx.rohc_state == rohccxx::RohcState::DynamicEstablished;
}

static void set_feedback(rohccxx_internal::Decompressor& decomp,
                         uint32_t cid,
                         rohccxx::FeedbackType type)
{
    rohccxx::Feedback feedback{};
    feedback.cid = cid;
    feedback.type = type;
    decomp.last_feedback = feedback;
    decomp.has_feedback = true;
}

static bool c_mode_to_core(rohccxx_mode_t mode, rohccxx::Mode& core_mode)
{
    switch(mode)
    {
    case ROHCCXX_MODE_U:
        core_mode = rohccxx::Mode::Uncompressed;
        return true;
    case ROHCCXX_MODE_O:
        core_mode = rohccxx::Mode::Optimistic;
        return true;
    case ROHCCXX_MODE_R:
        core_mode = rohccxx::Mode::Reliable;
        return true;
    }
    return false;
}

static rohccxx_mode_t core_mode_to_c(rohccxx::Mode mode)
{
    switch(mode)
    {
    case rohccxx::Mode::Uncompressed:
        return ROHCCXX_MODE_U;
    case rohccxx::Mode::Reliable:
        return ROHCCXX_MODE_R;
    case rohccxx::Mode::Optimistic:
    default:
        return ROHCCXX_MODE_O;
    }
}

static bool should_emit_ir(const rohccxx::Context& ctx)
{
    return ctx.tx_count == 0 || ctx.rohc_state == rohccxx::RohcState::NoContext ||
           (ctx.mode == rohccxx::Mode::Reliable && !ctx.static_acked);
}

static bool should_emit_ir_dyn(const rohccxx::Context& ctx)
{
    // ROHCv2 has no IR-DYN format. Repeat the standards-compliant IR while
    // establishing the dynamic context before selecting a CO packet.
    if(ctx.tx_count == 1 || ctx.rohc_state == rohccxx::RohcState::StaticEstablished)
        return true;
    return ctx.mode == rohccxx::Mode::Reliable && ctx.static_acked && !ctx.dynamic_acked;
}

static bool write_next_segment(rohccxx_internal::Compressor& comp,
                               uint8_t* rohc_packet,
                               size_t* rohc_packet_len)
{
    if(!rohc_packet || !rohc_packet_len || *rohc_packet_len <= rohccxx_internal::segment_header_len ||
       comp.pending_segment_pos >= comp.pending_segment_len)
    {
        return false;
    }

    const size_t capacity = *rohc_packet_len;
    const size_t payload_capacity = capacity - rohccxx_internal::segment_header_len;
    const size_t remaining = comp.pending_segment_len - comp.pending_segment_pos;
    const size_t payload_len = remaining < payload_capacity ? remaining : payload_capacity;
    const bool final = payload_len == remaining;
    rohccxx::SegmentHeader segment{final, comp.next_segment_sequence++};
    if(!rohccxx::write_segment_packet(rohc_packet,
                                      rohc_packet_len,
                                      segment,
                                      comp.pending_segment + comp.pending_segment_pos,
                                      payload_len))
    {
        return false;
    }

    comp.pending_segment_pos += payload_len;
    if(final)
    {
        comp.pending_segment_len = 0;
        comp.pending_segment_pos = 0;
    }
    return true;
}



static bool configure_rohcoipsec(bool& enabled,
                                 uint16_t& algorithm,
                                 uint8_t* stored_key,
                                 size_t& stored_key_len,
                                 size_t& icv_len,
                                 uint16_t requested_algorithm,
                                 const uint8_t* key,
                                 size_t key_len,
                                 size_t requested_icv_len)
{
    if(!stored_key || key_len > rohccxx_internal::rohcoipsec_key_max || (!key && key_len > 0))
        return false;

    const size_t full_len = rohccxx::rohcoipsec::digest_len(requested_algorithm);
    const bool none = requested_algorithm == static_cast<uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None);
    if(!none && (full_len == 0 || requested_icv_len == 0 || requested_icv_len > full_len || key_len == 0))
        return false;

    algorithm = requested_algorithm;
    std::memset(stored_key, 0, rohccxx_internal::rohcoipsec_key_max);
    if(key_len > 0)
        std::memcpy(stored_key, key, key_len);
    stored_key_len = key_len;
    icv_len = none ? 0 : requested_icv_len;
    enabled = true;
    return true;
}

static bool c_rohcoipsec_to_core(const rohccxx_rohcoipsec_channel_t& in,
                                 rohccxx::rohcoipsec::ChannelParameters& out)
{
    if(in.profile_count > rohccxx::rohcoipsec::max_profiles ||
       in.integrity_algorithm_count > rohccxx::rohcoipsec::max_integrity_algorithms)
    {
        return false;
    }

    out = rohccxx::rohcoipsec::ChannelParameters{};
    out.max_cid = in.max_cid;
    for(size_t i = 0; i < in.profile_count; ++i)
    {
        if(!rohccxx::rohcoipsec::append_profile(out, in.profiles[i]))
            return false;
    }
    for(size_t i = 0; i < in.integrity_algorithm_count; ++i)
    {
        if(!rohccxx::rohcoipsec::append_integrity(out, in.integrity_algorithms[i]))
            return false;
    }
    out.icv_len = in.icv_len;
    out.has_icv_len = in.has_icv_len != 0;
    out.mrru = in.mrru;
    out.has_mrru = in.has_mrru != 0;
    return true;
}

static bool core_rohcoipsec_to_c(const rohccxx::rohcoipsec::ChannelParameters& in,
                                 rohccxx_rohcoipsec_channel_t& out)
{
    if(in.profile_count > ROHCCXX_ROHCOIPSEC_MAX_PROFILES ||
       in.integrity_algorithm_count > ROHCCXX_ROHCOIPSEC_MAX_INTEGRITY_ALGORITHMS)
    {
        return false;
    }

    std::memset(&out, 0, sizeof(out));
    out.max_cid = in.max_cid;
    out.profile_count = in.profile_count;
    for(size_t i = 0; i < in.profile_count; ++i)
        out.profiles[i] = in.profiles[i];
    out.integrity_algorithm_count = in.integrity_algorithm_count;
    for(size_t i = 0; i < in.integrity_algorithm_count; ++i)
        out.integrity_algorithms[i] = in.integrity_algorithms[i];
    out.icv_len = in.icv_len;
    out.has_icv_len = in.has_icv_len ? 1 : 0;
    out.mrru = in.mrru;
    out.has_mrru = in.has_mrru ? 1 : 0;
    return true;
}

extern "C"
{


ROHCCXX_API const char*
rohccxx_version_string(void)
{
    return ROHCCXX_VERSION_STRING;
}

ROHCCXX_API unsigned
rohccxx_version_major(void)
{
    return ROHCCXX_VERSION_MAJOR;
}

ROHCCXX_API unsigned
rohccxx_version_minor(void)
{
    return ROHCCXX_VERSION_MINOR;
}

ROHCCXX_API unsigned
rohccxx_version_patch(void)
{
    return ROHCCXX_VERSION_PATCH;
}


ROHCCXX_API int
rohc_profile_is_supported(uint16_t profile)
{
    switch(static_cast<rohccxx::Profile>(profile))
    {
    case rohccxx::Profile::Uncompressed:
    case rohccxx::Profile::LLA_RTP:
    case rohccxx::Profile::RTP:
    case rohccxx::Profile::UDP:
    case rohccxx::Profile::ESP:
    case rohccxx::Profile::IP:
    case rohccxx::Profile::RTP_UDP_Lite:
    case rohccxx::Profile::UDP_Lite:
        return 1;
    }
    return 0;
}

ROHCCXX_API int
rohc_profile_is_rohcv2(uint16_t profile)
{
    switch(static_cast<rohccxx::Profile>(profile))
    {
    case rohccxx::Profile::Uncompressed:
    case rohccxx::Profile::RTP:
    case rohccxx::Profile::UDP:
    case rohccxx::Profile::ESP:
    case rohccxx::Profile::IP:
    case rohccxx::Profile::RTP_UDP_Lite:
    case rohccxx::Profile::UDP_Lite:
        return 1;
    case rohccxx::Profile::LLA_RTP:
        return 0;
    }
    return 0;
}

ROHCCXX_API int
rohc_ppp_is_rohc_protocol(uint16_t protocol)
{
    return rohccxx::ppp::is_rohc_protocol_field(protocol) ? 1 : 0;
}

ROHCCXX_API int
rohc_ppp_uses_large_cid_protocol(uint16_t protocol)
{
    return rohccxx::ppp::uses_large_cid_protocol(protocol) ? 1 : 0;
}

ROHCCXX_API int
rohc_ppp_validate_rohc_option(const rohccxx_ppp_rohc_option_t* option)
{
    if(!option)
        return -1;
    rohccxx::ppp::RohcOption core{};
    if(!c_ppp_option_to_core(*option, core))
        return 0;
    return rohccxx::ppp::valid(core) ? 1 : 0;
}

ROHCCXX_API int
rohc_ppp_write_rohc_option(const rohccxx_ppp_rohc_option_t* option,
                           uint8_t* out,
                           size_t* out_len)
{
    if(!option || !out || !out_len)
        return -1;
    rohccxx::ppp::RohcOption core{};
    if(!c_ppp_option_to_core(*option, core))
        return -1;
    return rohccxx::ppp::write_rohc_option(core, out, out_len) ? 0 : -1;
}

ROHCCXX_API int
rohc_ppp_parse_rohc_option(const uint8_t* data,
                           size_t data_len,
                           rohccxx_ppp_rohc_option_t* option)
{
    if(!data || !option)
        return -1;
    rohccxx::ppp::RohcOption core{};
    if(!rohccxx::ppp::parse_rohc_option(data, data_len, core))
        return -1;
    return core_ppp_option_to_c(core, *option) ? 0 : -1;
}

ROHCCXX_API int
rohc_ppp_merge_rohc_options(const rohccxx_ppp_rohc_option_t* a,
                            const rohccxx_ppp_rohc_option_t* b,
                            rohccxx_ppp_rohc_option_t* merged)
{
    if(!a || !b || !merged)
        return -1;
    rohccxx::ppp::RohcOption core_a{};
    rohccxx::ppp::RohcOption core_b{};
    rohccxx::ppp::RohcOption core_merged{};
    if(!c_ppp_option_to_core(*a, core_a) || !c_ppp_option_to_core(*b, core_b) ||
       !rohccxx::ppp::merge_channel_options(core_a, core_b, core_merged))
    {
        return -1;
    }
    return core_ppp_option_to_c(core_merged, *merged) ? 0 : -1;
}

ROHCCXX_API int
rohc_lla_validate_rfc3243_zero_byte_assumptions(const rohccxx_lla_contract_t* contract,
                                                uint32_t* missing)
{
    if(!contract)
        return -1;
    return validation_to_c_result(
        rohccxx::lla::validate_rfc3243_zero_byte_assumptions(c_lla_contract_to_core(*contract)), missing);
}

ROHCCXX_API int
rohc_lla_validate_rfc3243_zero_byte_flow(const rohccxx_lla_contract_t* contract,
                                         const rohccxx_lla_flow_t* flow,
                                         uint32_t* missing)
{
    if(!contract || !flow)
        return -1;
    return validation_to_c_result(
        rohccxx::lla::validate_rfc3243_zero_byte_flow(c_lla_contract_to_core(*contract), c_lla_flow_to_core(*flow)),
        missing);
}

ROHCCXX_API int
rohc_lla_validate_rfc3408_r_mode_zero_byte_support(const rohccxx_lla_contract_t* contract,
                                                   uint32_t* missing)
{
    if(!contract)
        return -1;
    return validation_to_c_result(
        rohccxx::lla::validate_rfc3408_r_mode_zero_byte_support(c_lla_contract_to_core(*contract)), missing);
}

ROHCCXX_API int
rohc_lla_validate_rfc3409_lower_layer_guidelines(const rohccxx_lla_contract_t* contract,
                                                 uint32_t* missing)
{
    if(!contract)
        return -1;
    return validation_to_c_result(
        rohccxx::lla::validate_rfc3409_lower_layer_guidelines(c_lla_contract_to_core(*contract)), missing);
}

ROHCCXX_API int
rohc_lla_can_emit_no_header_packet(const rohccxx_lla_contract_t* contract)
{
    if(!contract)
        return -1;
    return rohccxx::lla::can_emit_no_header_packet(c_lla_contract_to_core(*contract)) ? 1 : 0;
}

ROHCCXX_API int
rohc_lla_can_emit_no_header_packet_for_flow(const rohccxx_lla_contract_t* contract,
                                            const rohccxx_lla_flow_t* flow)
{
    if(!contract || !flow)
        return -1;
    return rohccxx::lla::can_emit_no_header_packet_for_flow(c_lla_contract_to_core(*contract),
                                                            c_lla_flow_to_core(*flow)) ? 1 : 0;
}

ROHCCXX_API int
rohc_lla_can_emit_reliable_mode_no_header_packet(const rohccxx_lla_contract_t* contract)
{
    if(!contract)
        return -1;
    return rohccxx::lla::can_emit_reliable_mode_no_header_packet(c_lla_contract_to_core(*contract)) ? 1 : 0;
}

ROHCCXX_API int
rohc_lla_can_emit_context_synchronization_packet(const rohccxx_lla_contract_t* contract)
{
    if(!contract)
        return -1;
    return rohccxx::lla::can_emit_context_synchronization_packet(c_lla_contract_to_core(*contract)) ? 1 : 0;
}

ROHCCXX_API int
rohc_lla_can_emit_context_check_packet(const rohccxx_lla_contract_t* contract)
{
    if(!contract)
        return -1;
    return rohccxx::lla::can_emit_context_check_packet(c_lla_contract_to_core(*contract)) ? 1 : 0;
}

ROHCCXX_API int
rohc_rohcoipsec_append_icv(uint16_t algorithm,
                           const uint8_t* key,
                           size_t key_len,
                           const uint8_t* authenticated_packet,
                           size_t authenticated_packet_len,
                           const uint8_t* rohc_packet,
                           size_t rohc_packet_len,
                           uint8_t* out,
                           size_t* out_len,
                           size_t icv_len)
{
    return rohccxx::rohcoipsec::append_icv(algorithm,
                                           key,
                                           key_len,
                                           authenticated_packet,
                                           authenticated_packet_len,
                                           rohc_packet,
                                           rohc_packet_len,
                                           out,
                                           out_len,
                                           icv_len)
        ? 0
        : -1;
}

ROHCCXX_API int
rohc_rohcoipsec_strip_verify_icv(uint16_t algorithm,
                                 const uint8_t* key,
                                 size_t key_len,
                                 const uint8_t* authenticated_packet,
                                 size_t authenticated_packet_len,
                                 const uint8_t* rohcoipsec_packet,
                                 size_t rohcoipsec_packet_len,
                                 uint8_t* rohc_packet,
                                 size_t* rohc_packet_len,
                                 size_t icv_len)
{
    if(!rohc_packet || !rohc_packet_len)
        return -1;
    const uint8_t* stripped = nullptr;
    size_t stripped_len = 0;
    if(!rohccxx::rohcoipsec::strip_and_verify_icv(algorithm,
                                                  key,
                                                  key_len,
                                                  authenticated_packet,
                                                  authenticated_packet_len,
                                                  rohcoipsec_packet,
                                                  rohcoipsec_packet_len,
                                                  &stripped,
                                                  &stripped_len,
                                                  icv_len))
    {
        return -1;
    }
    if(*rohc_packet_len < stripped_len)
        return -1;
    std::memcpy(rohc_packet, stripped, stripped_len);
    *rohc_packet_len = stripped_len;
    return 0;
}


ROHCCXX_API int
rohc_rohcoipsec_derive_directional_keys(const uint8_t* keymat,
                                        size_t keymat_len,
                                        size_t key_len,
                                        uint8_t* outbound_key,
                                        size_t* outbound_key_len,
                                        uint8_t* inbound_key,
                                        size_t* inbound_key_len)
{
    if(!keymat || !outbound_key || !outbound_key_len || !inbound_key || !inbound_key_len ||
       key_len == 0 || key_len > ROHCCXX_ROHCOIPSEC_KEY_MAX || keymat_len < key_len * 2 ||
       *outbound_key_len < key_len || *inbound_key_len < key_len)
    {
        return -1;
    }

    std::memcpy(outbound_key, keymat, key_len);
    std::memcpy(inbound_key, keymat + key_len, key_len);
    *outbound_key_len = key_len;
    *inbound_key_len = key_len;
    return 0;
}

ROHCCXX_API int
rohc_rohcoipsec_build_sa(const rohccxx_rohcoipsec_channel_t* negotiated,
                         uint16_t integrity_algorithm,
                         const uint8_t* key,
                         size_t key_len,
                         uint32_t feedback_for,
                         int has_feedback_for,
                         rohccxx_rohcoipsec_sa_t* sa)
{
    if(!negotiated || !sa || key_len > ROHCCXX_ROHCOIPSEC_KEY_MAX || (!key && key_len > 0))
        return -1;

    rohccxx::rohcoipsec::ChannelParameters core{};
    if(!c_rohcoipsec_to_core(*negotiated, core) || !core.valid() ||
       !rohccxx::rohcoipsec::supports_integrity(core, integrity_algorithm))
    {
        return -1;
    }

    const bool none = integrity_algorithm == ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE;
    const size_t full_len = rohccxx::rohcoipsec::digest_len(integrity_algorithm);
    const size_t icv_len = none ? 0 : (core.has_icv_len ? core.icv_len : full_len);
    if(!none && (full_len == 0 || icv_len == 0 || icv_len > full_len || key_len == 0))
        return -1;

    std::memset(sa, 0, sizeof(*sa));
    sa->max_cid = core.max_cid;
    sa->large_cids = core.large_cids() ? 1 : 0;
    sa->integrity_algorithm = integrity_algorithm;
    sa->icv_len = static_cast<uint16_t>(icv_len);
    sa->mrru = core.has_mrru ? core.mrru : 0;
    sa->has_mrru = core.has_mrru ? 1 : 0;
    if(key_len > 0)
        std::memcpy(sa->key, key, key_len);
    sa->key_len = key_len;
    sa->feedback_for = feedback_for;
    sa->has_feedback_for = has_feedback_for ? 1 : 0;
    return 0;
}

ROHCCXX_API uint8_t
rohc_rohcoipsec_security_next_header(uint8_t original_next_header, int compressed)
{
    return compressed ? rohccxx::rohcoipsec::protocol_number : original_next_header;
}

ROHCCXX_API uint8_t
rohc_rohcoipsec_outbound_next_header(int compressed)
{
    return compressed ? rohccxx::rohcoipsec::protocol_number : 0;
}

ROHCCXX_API int
rohc_rohcoipsec_inbound_requires_decompression(uint8_t next_header)
{
    return rohccxx::rohcoipsec::is_rohc_next_header(next_header) ? 1 : 0;
}

ROHCCXX_API uint8_t
rohc_rohcoipsec_protocol_number(void)
{
    return rohccxx::rohcoipsec::protocol_number;
}

ROHCCXX_API int
rohc_rohcoipsec_write_supported(const rohccxx_rohcoipsec_channel_t* params,
                                uint8_t* out,
                                size_t* out_len)
{
    if(!params || !out || !out_len)
        return -1;
    rohccxx::rohcoipsec::ChannelParameters core{};
    if(!c_rohcoipsec_to_core(*params, core))
        return -1;
    return rohccxx::rohcoipsec::write_supported_notify_payload(core, out, out_len) ? 0 : -1;
}

ROHCCXX_API int
rohc_rohcoipsec_parse_supported(const uint8_t* data,
                                size_t data_len,
                                rohccxx_rohcoipsec_channel_t* params)
{
    if(!data || !params)
        return -1;
    rohccxx::rohcoipsec::ChannelParameters core{};
    if(!rohccxx::rohcoipsec::parse_supported_notify_payload(data, data_len, core))
        return -1;
    return core_rohcoipsec_to_c(core, *params) ? 0 : -1;
}

ROHCCXX_API int
rohc_rohcoipsec_negotiate(const rohccxx_rohcoipsec_channel_t* local,
                          const rohccxx_rohcoipsec_channel_t* peer,
                          rohccxx_rohcoipsec_channel_t* negotiated)
{
    if(!local || !peer || !negotiated)
        return -1;
    rohccxx::rohcoipsec::ChannelParameters core_local{};
    rohccxx::rohcoipsec::ChannelParameters core_peer{};
    rohccxx::rohcoipsec::ChannelParameters core_negotiated{};
    if(!c_rohcoipsec_to_core(*local, core_local) || !c_rohcoipsec_to_core(*peer, core_peer))
        return -1;
    if(!rohccxx::rohcoipsec::negotiate(core_local, core_peer, core_negotiated))
        return -1;
    return core_rohcoipsec_to_c(core_negotiated, *negotiated) ? 0 : -1;
}

void rohc_comp_handle_feedback(struct rohc_comp* comp,
                               uint32_t cid,
                               uint8_t feedback_type)
{
    using namespace rohccxx;

    if(!comp || !is_known_feedback_type(feedback_type))
        return;
    std::lock_guard<std::recursive_mutex> lock(comp->impl.mutex);

    Context* ctx = comp->impl.contexts.get(cid);
    if(!ctx)
        return;

    Feedback feedback{};
    feedback.cid = cid;
    feedback.type = static_cast<FeedbackType>(feedback_type & 0x03U);
    rohccxx::apply_feedback_to_context(*ctx, feedback);
}

ROHCCXX_API int
rohc_comp_deliver_feedback_packet(struct rohc_comp* comp,
                                  const uint8_t* packet,
                                  size_t packet_len)
{
    if(!comp || !packet || packet_len == 0)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(comp->impl.mutex);

    size_t pos = 0;
    bool delivered = false;
    while(pos < packet_len && rohccxx::is_feedback_packet_start(packet[pos]))
    {
        rohccxx::Feedback feedback{};
        size_t consumed = 0;
        if(!rohccxx::read_feedback_prefix(packet + pos, packet_len - pos, feedback, consumed))
            return -1;
        if(feedback.has_mode)
            comp->impl.mode = feedback.mode;
        rohccxx::Context* ctx = comp->impl.contexts.get(feedback.cid);
        if(ctx)
        {
            rohccxx::apply_feedback_to_context(*ctx, feedback);
            delivered = true;
        }
        else if(feedback.has_mode)
        {
            delivered = true;
        }
        pos += consumed;
    }

    return delivered ? 0 : -1;
}

ROHCCXX_API int
rohc_comp_set_mode(struct rohc_comp* comp, rohccxx_mode_t mode)
{
    if(!comp)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(comp->impl.mutex);
    rohccxx::Mode core_mode{};
    if(!c_mode_to_core(mode, core_mode))
        return -1;
    comp->impl.mode = core_mode;
    rohccxx::Context* ctx = comp->impl.contexts.get(comp->impl.current_cid);
    if(ctx)
        ctx->mode = core_mode;
    return 0;
}

ROHCCXX_API int
rohc_comp_get_mode(const struct rohc_comp* comp, rohccxx_mode_t* mode)
{
    if(!comp || !mode)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(comp->impl.mutex);
    *mode = core_mode_to_c(comp->impl.mode);
    return 0;
}

ROHCCXX_API struct rohc_comp*
rohc_comp_new2(uint32_t max_cid,
               rohccxx_direction_t d)
{
    auto* c = new rohc_comp{};
    c->impl.direction =
        d == ROHCCXX_DIRECTION_UPLINK
            ? rohccxx::Direction::Uplink
            : rohccxx::Direction::Downlink;

    c->impl.large_cid_space = max_cid > rohccxx::cid::small_cid_max;
    if(max_cid > rohccxx::cid::large_cid_max)
    {
        delete c;
        return nullptr;
    }

    if (!c->impl.contexts.init(max_cid))
    {
        delete c;
        return nullptr;
    }

    return c;
}

ROHCCXX_API int
rohc_comp_set_cid(struct rohc_comp* c,
                  uint32_t cid)
{
    if(!c)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    if(cid > c->impl.contexts.max_cid)
        return -1;
    if(!c->impl.large_cid_space && cid > rohccxx::cid::small_cid_max)
        return -1;
    if(c->impl.large_cid_space && cid > rohccxx::cid::large_cid_max)
        return -1;

    c->impl.current_cid = cid;
    return 0;
}

ROHCCXX_API int
rohc_comp_enable_rohcoipsec(struct rohc_comp* c)
{
    if(!c)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    return configure_rohcoipsec(c->impl.rohcoipsec_enabled,
                                c->impl.rohcoipsec_algorithm,
                                c->impl.rohcoipsec_key,
                                c->impl.rohcoipsec_key_len,
                                c->impl.rohcoipsec_icv_len,
                                static_cast<uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None),
                                nullptr,
                                0,
                                0)
        ? 0
        : -1;
}

ROHCCXX_API int
rohc_comp_set_rohcoipsec_integrity(struct rohc_comp* c,
                                   uint16_t algorithm,
                                   const uint8_t* key,
                                   size_t key_len,
                                   size_t icv_len)
{
    if(!c)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    return configure_rohcoipsec(c->impl.rohcoipsec_enabled,
                                c->impl.rohcoipsec_algorithm,
                                c->impl.rohcoipsec_key,
                                c->impl.rohcoipsec_key_len,
                                c->impl.rohcoipsec_icv_len,
                                algorithm,
                                key,
                                key_len,
                                icv_len)
        ? 0
        : -1;
}


ROHCCXX_API int
rohc_comp_apply_rohcoipsec_sa(struct rohc_comp* c, const rohccxx_rohcoipsec_sa_t* sa)
{
    if(!c || !sa)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    if(rohc_comp_set_rohcoipsec_integrity(c, sa->integrity_algorithm, sa->key, sa->key_len, sa->icv_len) != 0)
        return -1;
    if(sa->has_mrru && rohc_comp_set_mrru(c, sa->mrru) != 0)
        return -1;
    return 0;
}

ROHCCXX_API uint8_t
rohc_comp_rohcoipsec_next_header(const struct rohc_comp* c)
{
    if(!c)
        return 0;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    return c->impl.rohcoipsec_enabled ? rohccxx::rohcoipsec::protocol_number : 0;
}


ROHCCXX_API int
rohc_comp_enable_rfc4362_lla(struct rohc_comp* c,
                             const rohccxx_lla_contract_t* contract,
                             const rohccxx_lla_flow_t* flow)
{
    if(!c || !contract || !flow)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    const auto core_contract = c_lla_contract_to_core(*contract);
    const auto core_flow = c_lla_flow_to_core(*flow);
    if(!lla_runtime_contract_valid(core_contract, core_flow))
        return -1;
    c->impl.lla_contract = core_contract;
    c->impl.lla_flow = core_flow;
    c->impl.lla_enabled = true;
    return 0;
}

ROHCCXX_API int
rohc_comp_rfc4362_emit_nhp(struct rohc_comp* c,
                           const uint8_t* ip_packet,
                           size_t ip_packet_len,
                           uint8_t* rohc_packet,
                           size_t* rohc_packet_len)
{
    if(!c || !ip_packet || !rohc_packet || !rohc_packet_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    if(!c->impl.lla_enabled || !rohccxx::lla::can_emit_no_header_packet_for_flow(c->impl.lla_contract, c->impl.lla_flow))
        return -1;
    rohccxx::Context* ctx = c->impl.contexts.get(c->impl.current_cid);
    if(!ctx || !lla_context_ready(*ctx))
        return -1;
    if(ctx->mode == rohccxx::Mode::Reliable && !ctx->dynamic_acked)
        return -1;
    uint8_t scratch[rohccxx_internal::segment_buffer_max] = {};
    size_t scratch_len = sizeof(scratch);
    c->impl.suppress_segmentation = true;
    const int rc = rohc_compress4(c, ip_packet, ip_packet_len, scratch, &scratch_len);
    c->impl.suppress_segmentation = false;
    if(rc != 0)
        return -1;
    *rohc_packet_len = 0;
    (void)rohc_packet;
    return 0;
}

ROHCCXX_API int
rohc_comp_rfc4362_emit_csp(struct rohc_comp* c,
                           const uint8_t* ip_packet,
                           size_t ip_packet_len,
                           uint8_t* csp_packet,
                           size_t* csp_packet_len)
{
    if(!c || !ip_packet || !csp_packet || !csp_packet_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    if(!c->impl.lla_enabled || !rohccxx::lla::can_emit_context_synchronization_packet(c->impl.lla_contract))
        return -1;
    uint8_t rohc_header[rohccxx_internal::segment_buffer_max] = {};
    size_t rohc_header_len = sizeof(rohc_header);
    c->impl.suppress_segmentation = true;
    const int rc = rohc_compress4(c, ip_packet, ip_packet_len, rohc_header, &rohc_header_len);
    c->impl.suppress_segmentation = false;
    if(rc != 0)
        return -1;
    size_t rtp_payload_len = 0;
    ParsedIpView ip_view{};
    const rohccxx::udp::Header* udp = nullptr;
    const rohccxx::rtp::Header* rtp = nullptr;
    if(parse_ip_view(ip_packet, ip_packet_len, ip_view) &&
       rohccxx::udp::parse(ip_packet, ip_packet_len, ip_packet + ip_view.header_len, udp) &&
       rohccxx::rtp::parse(ip_packet, ip_packet_len, ip_packet + ip_view.header_len + sizeof(*udp), rtp))
    {
        const size_t payload_offset = ip_view.header_len + sizeof(*udp) + sizeof(*rtp);
        rtp_payload_len = ip_packet_len > payload_offset ? ip_packet_len - payload_offset : 0;
    }
    if(rtp_payload_len > 0xFFFFU)
        return -1;
    return rohccxx::lla::write_context_synchronization_packet(csp_packet,
                                                              csp_packet_len,
                                                              static_cast<uint16_t>(rtp_payload_len),
                                                              rohc_header,
                                                              rohc_header_len) ? 0 : -1;
}

ROHCCXX_API int
rohc_comp_rfc4362_emit_ccp(struct rohc_comp* c,
                           uint8_t* ccp_packet,
                           size_t* ccp_packet_len)
{
    if(!c || !ccp_packet || !ccp_packet_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    if(!c->impl.lla_enabled || !rohccxx::lla::can_emit_context_check_packet(c->impl.lla_contract))
        return -1;
    rohccxx::Context* ctx = c->impl.contexts.get(c->impl.current_cid);
    if(!ctx || !lla_context_established(*ctx))
        return -1;
    rohccxx::lla::ContextCheckPacket ccp{};
    ccp.has_crc = true;
    ccp.crc7 = rohccxx::detail::context_crc7(*ctx);
    return rohccxx::lla::write_context_check_packet(ccp_packet, ccp_packet_len, ccp) ? 0 : -1;
}

ROHCCXX_API int
rohc_comp_set_mrru(struct rohc_comp* c, size_t mrru)
{
    if(!c || mrru > rohccxx_internal::segment_buffer_max)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    c->impl.mrru = mrru;
    return 0;
}

ROHCCXX_API int
rohc_comp_has_segment(const struct rohc_comp* c)
{
    if(!c)
        return 0;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    return c->impl.pending_segment_pos < c->impl.pending_segment_len ? 1 : 0;
}

ROHCCXX_API int
rohc_comp_get_segment(struct rohc_comp* c, uint8_t* rohc_packet, size_t* rohc_packet_len)
{
    if(!c)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(c->impl.mutex);
    return write_next_segment(c->impl, rohc_packet, rohc_packet_len) ? 0 : -1;
}

ROHCCXX_API void
rohc_comp_free(struct rohc_comp* c)
{
    if (!c)
        return;

    std::unique_lock<std::recursive_mutex> lock(c->impl.mutex);
    c->impl.contexts.destroy();
    lock.unlock();
    delete c;
}

ROHCCXX_API int
rohc_compress4(struct rohc_comp* comp,
               const uint8_t* ip_packet,
               size_t ip_packet_len,
               uint8_t* rohc_packet,
               size_t* rohc_packet_len)
{
    using namespace rohccxx;

    DBG("compress4: ip_len=%zu", ip_packet_len);

    if (!comp || !ip_packet || !rohc_packet || !rohc_packet_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(comp->impl.mutex);

    if(!comp->impl.suppress_segmentation)
    {
        const size_t requested_capacity = *rohc_packet_len;
        if(requested_capacity <= rohccxx_internal::segment_header_len)
            return -1;

        uint8_t full_packet[rohccxx_internal::segment_buffer_max] = {};
        size_t full_packet_len = sizeof(full_packet);
        comp->impl.suppress_segmentation = true;
        const int rc = rohc_compress4(comp, ip_packet, ip_packet_len, full_packet, &full_packet_len);
        comp->impl.suppress_segmentation = false;
        if(rc != 0)
            return rc;
        if(comp->impl.rohcoipsec_enabled)
        {
            uint8_t with_icv[rohccxx_internal::segment_buffer_max] = {};
            size_t with_icv_len = sizeof(with_icv);
            if(!rohccxx::rohcoipsec::append_icv(comp->impl.rohcoipsec_algorithm,
                                                comp->impl.rohcoipsec_key,
                                                comp->impl.rohcoipsec_key_len,
                                                ip_packet,
                                                ip_packet_len,
                                                full_packet,
                                                full_packet_len,
                                                with_icv,
                                                &with_icv_len,
                                                comp->impl.rohcoipsec_icv_len))
            {
                return -1;
            }
            std::memcpy(full_packet, with_icv, with_icv_len);
            full_packet_len = with_icv_len;
        }
        if(full_packet_len <= requested_capacity)
        {
            std::memcpy(rohc_packet, full_packet, full_packet_len);
            *rohc_packet_len = full_packet_len;
            return 0;
        }
        if(comp->impl.mrru == 0 || full_packet_len > comp->impl.mrru || full_packet_len > sizeof(comp->impl.pending_segment))
            return -1;
        std::memcpy(comp->impl.pending_segment, full_packet, full_packet_len);
        comp->impl.pending_segment_len = full_packet_len;
        comp->impl.pending_segment_pos = 0;
        comp->impl.next_segment_sequence = 0;
        return write_next_segment(comp->impl, rohc_packet, rohc_packet_len) ? 0 : -1;
    }

    ParsedIpView ip_view{};
    if(!parse_ip_view(ip_packet, ip_packet_len, ip_view))
        return -1;
    const bool ipv4_fragmented = ip_view.ip4 && ipv4::is_fragmented(*ip_view.ip4);

    const udp::Header* udp = nullptr;
    if(!ipv4_fragmented && (ip_view.terminal_protocol == 17 || ip_view.terminal_protocol == 136))
    {
        // Malformed/truncated UDP-family transports remain valid IP packets and
        // should be carried by the RFC 5795 uncompressed profile fallback.
        udp::parse(ip_packet, ip_packet_len, ip_packet + ip_view.header_len, udp);
    }

    const rtp::Header* rtp = nullptr;
    if(udp)
    {
        const bool ok = rtp::parse(ip_packet,
                                   ip_packet_len,
                                   ip_packet + ip_view.header_len + sizeof(*udp),
                                   rtp);
        DBG("rtp::parse() -> %s, rtp=%p", ok ? "true" : "false", (void*)rtp);
    }
    else
    {
        DBG("no UDP, skipping RTP parse");
    }

    Profile profile = ipv4_fragmented ? Profile::Uncompressed : classify_packet(ip_packet, ip_packet_len);
    const bool unsupported_standard_chain =
        (!ip_view.is_ipv6 && ip_view.header_len != sizeof(ipv4::Header)) ||
        (ip_view.is_ipv6 && (ip_view.extension_len != 0 ||
         (wire::to_host(ip_view.ip6->version_tc_flow) & 0x000FFFFFU) != 0)) ||
        (rtp && (wire::to_host(rtp->vpxcc) & 0x3FU) != 0);
    if(unsupported_standard_chain &&
       (profile == Profile::RTP || profile == Profile::UDP ||
        profile == Profile::ESP || profile == Profile::IP))
    {
        profile = Profile::Uncompressed;
    }
    DBG("profile=%u", static_cast<unsigned>(profile));

    uint32_t cid = comp->impl.current_cid;
    Context* ctx = comp->impl.contexts.get(cid);
    if(!ctx)
        return -1;
    const Context context_before_compress = *ctx;
    ctx->cid = cid;
    ctx->large_cid = comp->impl.large_cid_space;

    auto append_payload_range = [&](size_t header_len,
                                    size_t payload_offset,
                                    size_t payload_len,
                                    size_t out_capacity) -> bool
    {
        if(payload_offset > ip_packet_len || payload_len > ip_packet_len - payload_offset)
            return false;
        if(header_len + payload_len > out_capacity)
            return false;
        if(payload_len > 0)
            std::memcpy(rohc_packet + header_len, ip_packet + payload_offset, payload_len);
        *rohc_packet_len = header_len + payload_len;
        ++ctx->tx_count;
        if(ctx->mode != Mode::Reliable)
        {
            if(ctx->tx_count > 0)
                ctx->static_acked = true;
            if(ctx->tx_count > 1)
                ctx->dynamic_acked = true;
        }
        ctx->nack_count = 0;
        return true;
    };

    auto append_payload = [&](size_t header_len,
                              size_t payload_offset,
                              size_t out_capacity) -> bool
    {
        const size_t payload_len = (ip_packet_len > payload_offset)
            ? (ip_packet_len - payload_offset)
            : 0;
        return append_payload_range(header_len, payload_offset, payload_len, out_capacity);
    };

    auto capture_common = [&]() -> bool
    {
        return capture_ip_context(*ctx, ip_packet, ip_view);
    };

    if(profile == Profile::RTP_UDP_Lite && udp && rtp)
    {
        ctx->profile = Profile::RTP_UDP_Lite;
        ctx->mode = comp->impl.mode;
        const bool had_ipv4_rtp_context = ctx->ip_version == 4 && ctx->tx_count > 0;
        const std::uint16_t previous_ipv4_id = ctx->ipv4_id;
        const std::uint16_t previous_ipv4_flags = ctx->ipv4_flags;
        const bool previous_ipv4_id_sequential = ctx->ipv4_id_sequential;
        const std::uint16_t previous_rtp_seq = ctx->rtp.last_seq;
        if(!capture_common())
            return -1;
        ctx->udp_sport = wire::to_host(udp->src_port);
        ctx->udp_dport = wire::to_host(udp->dst_port);
        ctx->udp_length_or_coverage = wire::to_host(udp->length);
        ctx->udp_check = wire::to_host(udp->checksum);
        const uint16_t seq = wire::to_host(rtp->sequence);
        const uint32_t ts = wire::to_host(rtp->timestamp);
        const bool rtp_fo_ipv4_safe = update_rtp_ipv4_id_behavior(*ctx,
                                                                  had_ipv4_rtp_context,
                                                                  previous_ipv4_id,
                                                                  previous_ipv4_flags,
                                                                  previous_ipv4_id_sequential,
                                                                  previous_rtp_seq,
                                                                  seq);
        update_rtp_timestamp_stride(*ctx, seq, ts);
        ctx->rtp.vpxcc = wire::to_host(rtp->vpxcc);
        ctx->rtp.mpt = wire::to_host(rtp->mpt);
        ctx->rtp.last_seq = seq;
        ctx->rtp.last_ts = ts;
        ctx->msn = seq;
        ctx->udp_checksum_used = ctx->udp_check != 0;
        ctx->rtp.ssrc = wire::to_host(rtp->ssrc);
        const size_t rtp_offset = ip_view.header_len + sizeof(*udp);
        RtpPayloadView rtp_payload{};
        if(ip_packet_len < rtp_offset ||
           !capture_rtp_context(*ctx, ip_packet + rtp_offset, ip_packet_len - rtp_offset, rtp_payload))
        {
            return -1;
        }

        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!emit_ir_rtp_udp_lite(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx) || !rtp_fo_ipv4_safe)
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_rtp_udp_lite(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(ctx->large_cid)
            {
                if(!emit_ir_rtp_udp_lite(rohc_packet, rohc_packet_len, *ctx))
                    return -1;
            }
            else if(!emit_rtp_fo(rohc_packet, rohc_packet_len, *ctx) ||
                    !prepend_private_rtp_small_cid(rohc_packet, rohc_packet_len,
                                                   out_capacity, cid))
                return -1;
        }
        return append_payload_range(*rohc_packet_len,
                                    rtp_offset + rtp_payload.payload_offset,
                                    rtp_payload.payload_len,
                                    out_capacity) ? 0 : -1;
    }

    if(profile == Profile::RTP && udp && rtp)
    {
        ctx->profile = Profile::RTP;
        ctx->mode = comp->impl.mode;
        const bool had_ipv4_rtp_context = ctx->ip_version == 4 && ctx->tx_count > 0;
        const std::uint16_t previous_ipv4_id = ctx->ipv4_id;
        const std::uint16_t previous_ipv4_flags = ctx->ipv4_flags;
        const bool previous_ipv4_id_sequential = ctx->ipv4_id_sequential;
        const std::uint16_t previous_rtp_seq = ctx->rtp.last_seq;
        if(!capture_common())
            return -1;
        ctx->udp_sport = wire::to_host(udp->src_port);
        ctx->udp_dport = wire::to_host(udp->dst_port);
        ctx->udp_length_or_coverage = wire::to_host(udp->length);
        ctx->udp_check = wire::to_host(udp->checksum);
        const uint16_t seq = wire::to_host(rtp->sequence);
        const uint32_t ts = wire::to_host(rtp->timestamp);
        const bool rtp_fo_ipv4_safe = update_rtp_ipv4_id_behavior(*ctx,
                                                                  had_ipv4_rtp_context,
                                                                  previous_ipv4_id,
                                                                  previous_ipv4_flags,
                                                                  previous_ipv4_id_sequential,
                                                                  previous_rtp_seq,
                                                                  seq);
        update_rtp_timestamp_stride(*ctx, seq, ts);
        ctx->rtp.vpxcc = wire::to_host(rtp->vpxcc);
        ctx->rtp.mpt = wire::to_host(rtp->mpt);
        ctx->rtp.last_seq = seq;
        ctx->rtp.last_ts = ts;
        ctx->msn = seq;
        ctx->udp_checksum_used = ctx->udp_check != 0;
        ctx->rtp.ssrc = wire::to_host(rtp->ssrc);
        const size_t rtp_offset = ip_view.header_len + sizeof(*udp);
        RtpPayloadView rtp_payload{};
        if(ip_packet_len < rtp_offset ||
           !capture_rtp_context(*ctx, ip_packet + rtp_offset, ip_packet_len - rtp_offset, rtp_payload))
        {
            return -1;
        }

        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            init_rtp_context(comp->impl.contexts, cid, rtp);
            ctx->profile = Profile::RTP;
            ctx->mode = comp->impl.mode;
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!capture_common())
                return -1;
            ctx->udp_sport = wire::to_host(udp->src_port);
            ctx->udp_dport = wire::to_host(udp->dst_port);
            ctx->udp_length_or_coverage = wire::to_host(udp->length);
            ctx->udp_check = wire::to_host(udp->checksum);
            ctx->rtp.vpxcc = wire::to_host(rtp->vpxcc);
            ctx->rtp.mpt = wire::to_host(rtp->mpt);
            if(!emit_ir_rtp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx) || !rtp_fo_ipv4_safe)
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_rtp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(ctx->large_cid)
            {
                if(!emit_ir_rtp(rohc_packet, rohc_packet_len, *ctx))
                    return -1;
            }
            else if(rtp_pt0_reconstructable(context_before_compress, *ctx))
            {
                if(!emit_rtp_pt0_small_cid(rohc_packet, rohc_packet_len, cid,
                                           ctx->msn, ip_packet))
                    return -1;
                const std::size_t base_offset = cid == 0U ? 0U : 1U;
                bool ambiguous_private_rtp = false;
                if(cid != 0U)
                {
                    std::array<std::uint8_t, 32> candidate{};
                    candidate[0] = rohc_packet[base_offset];
                    const std::size_t copied_payload = std::min<std::size_t>(
                        candidate.size() - 1U, rtp_payload.payload_len);
                    std::memcpy(candidate.data() + 1U,
                                ip_packet + rtp_offset + rtp_payload.payload_offset,
                                copied_payload);
                    Context private_context = context_before_compress;
                    private_context.cid = cid;
                    private_context.large_cid = false;
                    std::uint16_t private_sequence = 0;
                    std::uint32_t private_timestamp = 0;
                    std::size_t private_header_len = 0;
                    ambiguous_private_rtp = decode_fo_rtp(
                        candidate.data(), copied_payload + 1U, private_context,
                        private_sequence, private_timestamp, &private_header_len);
                }
                if(ambiguous_private_rtp ||
                   (rohc_packet[base_offset] >= 0x77U && rohc_packet[base_offset] <= 0x7aU))
                {
                    *rohc_packet_len = out_capacity;
                    if(!emit_ir_dyn_rtp(rohc_packet, rohc_packet_len, *ctx))
                        return -1;
                }
            }
            else if(!emit_rtp_fo(rohc_packet, rohc_packet_len, *ctx) ||
                    !prepend_private_rtp_small_cid(rohc_packet, rohc_packet_len,
                                                   out_capacity, cid))
                return -1;
        }
        return append_payload_range(*rohc_packet_len,
                                    rtp_offset + rtp_payload.payload_offset,
                                    rtp_payload.payload_len,
                                    out_capacity) ? 0 : -1;
    }

    if(profile == Profile::UDP && udp)
    {
        const Context previous = *ctx;
        ctx->profile = Profile::UDP;
        ctx->mode = comp->impl.mode;
        const bool had_ipv4_context = ctx->ip_version == 4 && ctx->tx_count > 0;
        const std::uint16_t previous_ipv4_id = ctx->ipv4_id;
        if(!capture_common())
            return -1;
        update_ipv4_id_behavior(*ctx, had_ipv4_context, previous_ipv4_id);
        ctx->udp_sport = wire::to_host(udp->src_port);
        ctx->udp_dport = wire::to_host(udp->dst_port);
        ctx->udp_length_or_coverage = wire::to_host(udp->length);
        ctx->udp_check = wire::to_host(udp->checksum);
        ctx->udp_checksum_used = ctx->udp_check != 0;
        ctx->msn = static_cast<std::uint16_t>(ctx->tx_count + 1U);
        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!emit_ir_udp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx))
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_udp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!ctx->large_cid && cid <= 0x0fU &&
               udp_pt0_reconstructable(previous, *ctx))
            {
                const rfc5225::FormalCoFields fields{ctx->msn, 0, 0, false};
                const rfc5225::FormalCoCrcInput crc_input{ip_packet, ip_view.header_len + sizeof(*udp)};
                std::array<std::uint8_t, 2> formal{};
                size_t formal_len = formal.size();
                const bool emitted = rfc5225::emit_formal_co(
                    formal.data(), &formal_len, ctx->profile,
                    rfc5225::FormalCoVariant::Pt0Crc3, cid, false, fields, crc_input);
                const size_t payload_offset = ip_view.header_len + sizeof(*udp);
                const std::uint8_t pt0 = formal[cid == 0U ? 0U : 1U];
                if(!emitted || pt0_private_fo_ambiguous(
                       pt0, ip_packet + payload_offset, ip_packet_len - payload_offset))
                {
                    if(!emit_udp_fo(rohc_packet, rohc_packet_len, *ctx) ||
                       (!ctx->large_cid && !prepend_small_cid(
                           rohc_packet, rohc_packet_len, out_capacity, cid)))
                        return -1;
                }
                else
                {
                    if(*rohc_packet_len < formal_len)
                        return -1;
                    std::memset(rohc_packet, 0, *rohc_packet_len);
                    std::memcpy(rohc_packet, formal.data(), formal_len);
                    *rohc_packet_len = formal_len;
                }
            }
            else
            {
                if(!emit_udp_fo(rohc_packet, rohc_packet_len, *ctx) ||
                   (!ctx->large_cid && !prepend_small_cid(rohc_packet, rohc_packet_len, out_capacity, cid)))
                    return -1;
            }
        }
        return append_payload(*rohc_packet_len, ip_view.header_len + sizeof(*udp), out_capacity) ? 0 : -1;
    }

    if(profile == Profile::IP)
    {
        const Context previous = *ctx;
        ctx->profile = Profile::IP;
        ctx->mode = comp->impl.mode;
        const bool had_ipv4_context = ctx->ip_version == 4 && ctx->tx_count > 0;
        const std::uint16_t previous_ipv4_id = ctx->ipv4_id;
        if(!capture_common())
            return -1;
        update_ipv4_id_behavior(*ctx, had_ipv4_context, previous_ipv4_id);
        ctx->msn = static_cast<std::uint16_t>(ctx->tx_count + 1U);
        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!emit_ir_ip(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx))
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_ip(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!ctx->large_cid && cid <= 0x0fU &&
               ip_pt0_reconstructable(previous, *ctx))
            {
                const rfc5225::FormalCoFields fields{ctx->msn, 0, 0, false};
                const rfc5225::FormalCoCrcInput crc_input{ip_packet, ip_view.header_len};
                std::array<std::uint8_t, 2> formal{};
                size_t formal_len = formal.size();
                const bool emitted = rfc5225::emit_formal_co(
                    formal.data(), &formal_len, ctx->profile,
                    rfc5225::FormalCoVariant::Pt0Crc3, cid, false, fields, crc_input);
                const size_t payload_offset = ip_view.header_len;
                const std::uint8_t pt0 = formal[cid == 0U ? 0U : 1U];
                if(!emitted || pt0_private_fo_ambiguous(
                       pt0, ip_packet + payload_offset, ip_packet_len - payload_offset))
                {
                    if(!emit_ip_fo(rohc_packet, rohc_packet_len, *ctx) ||
                       !prepend_small_cid(rohc_packet, rohc_packet_len, out_capacity, cid))
                        return -1;
                }
                else
                {
                    if(*rohc_packet_len < formal_len)
                        return -1;
                    std::memcpy(rohc_packet, formal.data(), formal_len);
                    *rohc_packet_len = formal_len;
                }
            }
            else if(!ctx->large_cid && cid <= 0x0fU && ctx->ip_version == 4U)
            {
                std::uint16_t encoded_ip_id = 0U;
                if(ip_pt1_seq_id_reconstructable(previous, *ctx, encoded_ip_id))
                {
                    ctx->ipv4_id_behavior = previous.ipv4_id_behavior;
                    ctx->ipv4_id_sequential = true;
                    const rfc5225::FormalCoFields fields{ctx->msn, encoded_ip_id, 0, false};
                    const rfc5225::FormalCoCrcInput crc_input{ip_packet, ip_view.header_len};
                    std::array<std::uint8_t, 3> formal{};
                    size_t formal_len = formal.size();
                    if(!rfc5225::emit_formal_co(
                           formal.data(), &formal_len, ctx->profile,
                           rfc5225::FormalCoVariant::Pt1SeqId, cid, false, fields, crc_input) ||
                       *rohc_packet_len < formal_len)
                        return -1;
                    std::memcpy(rohc_packet, formal.data(), formal_len);
                    *rohc_packet_len = formal_len;
                }
                else if(ip_private_fo_reconstructable(previous, *ctx))
                {
                    if(!emit_ip_fo(rohc_packet, rohc_packet_len, *ctx) ||
                       !prepend_small_cid(rohc_packet, rohc_packet_len, out_capacity, cid))
                        return -1;
                }
                else if(!emit_ir_ip(rohc_packet, rohc_packet_len, *ctx))
                {
                    return -1;
                }
            }
            else
            {
                if(ctx->ip_version != 4 || ip_private_fo_reconstructable(previous, *ctx))
                {
                    if(!emit_ip_fo(rohc_packet, rohc_packet_len, *ctx) ||
                       (!ctx->large_cid && !prepend_small_cid(
                           rohc_packet, rohc_packet_len, out_capacity, cid)))
                        return -1;
                }
                else if(!emit_ir_ip(rohc_packet, rohc_packet_len, *ctx))
                {
                    return -1;
                }
            }
        }
        return append_payload(*rohc_packet_len, ip_view.header_len, out_capacity) ? 0 : -1;
    }

    if(profile == Profile::ESP)
    {
        const Context previous = *ctx;
        ctx->profile = Profile::ESP;
        ctx->mode = comp->impl.mode;
        const bool had_ipv4_context = ctx->ip_version == 4 && ctx->tx_count > 0;
        const std::uint16_t previous_ipv4_id = ctx->ipv4_id;
        if(!capture_common())
            return -1;
        update_ipv4_id_behavior(*ctx, had_ipv4_context, previous_ipv4_id);
        if(ip_packet_len < ip_view.header_len + 8U)
            return -1;
        const uint8_t* esp = ip_packet + ip_view.header_len;
        ctx->esp_spi = (static_cast<uint32_t>(esp[0]) << 24U) |
                       (static_cast<uint32_t>(esp[1]) << 16U) |
                       (static_cast<uint32_t>(esp[2]) << 8U) |
                       static_cast<uint32_t>(esp[3]);
        ctx->esp_sequence = (static_cast<uint32_t>(esp[4]) << 24U) |
                            (static_cast<uint32_t>(esp[5]) << 16U) |
                            (static_cast<uint32_t>(esp[6]) << 8U) |
                            static_cast<uint32_t>(esp[7]);
        ctx->msn = static_cast<std::uint16_t>(ctx->esp_sequence);
        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!emit_ir_esp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx))
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_esp(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!ctx->large_cid && cid <= 0x0fU &&
               esp_pt0_reconstructable(previous, *ctx))
            {
                const rfc5225::FormalCoFields fields{ctx->msn, 0, 0, false};
                const rfc5225::FormalCoCrcInput crc_input{ip_packet, ip_view.header_len + 8U};
                std::array<std::uint8_t, 2> formal{};
                size_t formal_len = formal.size();
                const bool emitted = rfc5225::emit_formal_co(
                    formal.data(), &formal_len, ctx->profile,
                    rfc5225::FormalCoVariant::Pt0Crc3, cid, false, fields, crc_input);
                const size_t payload_offset = ip_view.header_len + 8U;
                const std::uint8_t pt0 = formal[cid == 0U ? 0U : 1U];
                if(!emitted || pt0_private_fo_ambiguous(
                       pt0, ip_packet + payload_offset, ip_packet_len - payload_offset))
                {
                    if(!emit_ir_esp(rohc_packet, rohc_packet_len, *ctx))
                        return -1;
                }
                else
                {
                    if(*rohc_packet_len < formal_len)
                        return -1;
                    std::memcpy(rohc_packet, formal.data(), formal_len);
                    *rohc_packet_len = formal_len;
                }
            }
            else if(!emit_ir_esp(rohc_packet, rohc_packet_len, *ctx))
            {
                return -1;
            }
        }
        return append_payload(*rohc_packet_len, ip_view.header_len + 8U, out_capacity) ? 0 : -1;
    }

    if(profile == Profile::UDP_Lite && udp)
    {
        ctx->profile = Profile::UDP_Lite;
        ctx->mode = comp->impl.mode;
        if(!capture_common())
            return -1;
        ctx->udp_sport = wire::to_host(udp->src_port);
        ctx->udp_dport = wire::to_host(udp->dst_port);
        ctx->udp_length_or_coverage = wire::to_host(udp->length);
        ctx->udp_check = wire::to_host(udp->checksum);
        const size_t out_capacity = *rohc_packet_len;
        if(should_emit_ir(*ctx))
        {
            ctx->rohc_state = RohcState::StaticEstablished;
            if(!emit_ir_udp_lite(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else if(should_emit_ir_dyn(*ctx))
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_ir_dyn_udp_lite(rohc_packet, rohc_packet_len, *ctx))
                return -1;
        }
        else
        {
            ctx->rohc_state = RohcState::DynamicEstablished;
            if(!emit_udp_lite_fo(rohc_packet, rohc_packet_len, *ctx))
                return -1;
            if(!ctx->large_cid && !prepend_small_cid(rohc_packet, rohc_packet_len, out_capacity, cid))
                return -1;
        }
        return append_payload(*rohc_packet_len, ip_view.header_len + sizeof(*udp), out_capacity) ? 0 : -1;
    }

    if(!is_uncompressed_ip_payload(ip_packet, ip_packet_len))
        return -1;

    ctx->profile = Profile::Uncompressed;
    ctx->mode = Mode::Uncompressed;
    ctx->rohc_state = RohcState::DynamicEstablished;
    ctx->tx_count++;
    ctx->nack_count = 0;
    ctx->static_acked = true;
    ctx->dynamic_acked = true;

    DBG("FALLBACK: emitting uncompressed 2");
    return emit_uncompressed(rohc_packet,
                             rohc_packet_len,
                             ip_packet,
                             ip_packet_len) ? 0 : -1;
}

ROHCCXX_API int
rohc_decomp_has_feedback(const struct rohc_decomp* decomp)
{
    if (!decomp)
        return 0;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);

    return decomp->impl.has_feedback ? 1 : 0;
}

ROHCCXX_API int
rohc_decomp_get_feedback(const struct rohc_decomp* decomp,
                          uint32_t* cid,
                          uint8_t* feedback_type)
{
    if (!decomp)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);
    if(!decomp->impl.has_feedback)
        return -1;

    if (cid)
        *cid = decomp->impl.last_feedback.cid;

    if (feedback_type)
        *feedback_type =
            static_cast<uint8_t>(decomp->impl.last_feedback.type);

    return 0;
}

ROHCCXX_API struct rohc_decomp*
rohc_decomp_new2(uint32_t max_cid,
                 rohccxx_direction_t d)
{
    auto* dcp = new rohc_decomp{};
    dcp->impl.direction =
        d == ROHCCXX_DIRECTION_UPLINK
            ? rohccxx::Direction::Uplink
            : rohccxx::Direction::Downlink;

    dcp->impl.large_cid_space = max_cid > rohccxx::cid::small_cid_max;
    if(max_cid > rohccxx::cid::large_cid_max)
    {
        delete dcp;
        return nullptr;
    }

    if (!dcp->impl.contexts.init(max_cid))
    {
        delete dcp;
        return nullptr;
    }

    return dcp;
}

ROHCCXX_API int
rohc_decomp_enable_rohcoipsec(struct rohc_decomp* d)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    return configure_rohcoipsec(d->impl.rohcoipsec_enabled,
                                d->impl.rohcoipsec_algorithm,
                                d->impl.rohcoipsec_key,
                                d->impl.rohcoipsec_key_len,
                                d->impl.rohcoipsec_icv_len,
                                static_cast<uint16_t>(rohccxx::rohcoipsec::IntegrityAlgorithm::None),
                                nullptr,
                                0,
                                0)
        ? 0
        : -1;
}

ROHCCXX_API int
rohc_decomp_set_rohcoipsec_integrity(struct rohc_decomp* d,
                                     uint16_t algorithm,
                                     const uint8_t* key,
                                     size_t key_len,
                                     size_t icv_len)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    return configure_rohcoipsec(d->impl.rohcoipsec_enabled,
                                d->impl.rohcoipsec_algorithm,
                                d->impl.rohcoipsec_key,
                                d->impl.rohcoipsec_key_len,
                                d->impl.rohcoipsec_icv_len,
                                algorithm,
                                key,
                                key_len,
                                icv_len)
        ? 0
        : -1;
}


ROHCCXX_API int
rohc_decomp_apply_rohcoipsec_sa(struct rohc_decomp* d, const rohccxx_rohcoipsec_sa_t* sa)
{
    if(!d || !sa)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    if(rohc_decomp_set_rohcoipsec_integrity(d, sa->integrity_algorithm, sa->key, sa->key_len, sa->icv_len) != 0)
        return -1;
    if(sa->has_mrru && rohc_decomp_set_mrru(d, sa->mrru) != 0)
        return -1;
    return 0;
}

ROHCCXX_API int
rohc_decomp_rohcoipsec_requires_decompression(const struct rohc_decomp* d, uint8_t next_header)
{
    if(!d)
        return 0;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    return d->impl.rohcoipsec_enabled && rohccxx::rohcoipsec::is_rohc_next_header(next_header) ? 1 : 0;
}


ROHCCXX_API int
rohc_decomp_enable_rfc4362_lla(struct rohc_decomp* d,
                               const rohccxx_lla_contract_t* contract,
                               const rohccxx_lla_flow_t* flow)
{
    if(!d || !contract || !flow)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    const auto core_contract = c_lla_contract_to_core(*contract);
    const auto core_flow = c_lla_flow_to_core(*flow);
    if(!lla_runtime_contract_valid(core_contract, core_flow))
        return -1;
    d->impl.lla_contract = core_contract;
    d->impl.lla_flow = core_flow;
    d->impl.lla_enabled = true;
    return 0;
}

static int receive_nhp_for_cid_locked(rohccxx_internal::Decompressor& decomp,
                                     uint32_t cid,
                                     const uint8_t* payload,
                                     size_t payload_len,
                                     uint8_t* ip_packet,
                                     size_t* ip_packet_len)
{
    if((!payload && payload_len > 0) || !ip_packet || !ip_packet_len)
        return -1;
    if(!decomp.lla_enabled || !rohccxx::lla::can_emit_no_header_packet_for_flow(decomp.lla_contract, decomp.lla_flow))
        return -1;
    rohccxx::Context* ctx = decomp.contexts.get(cid);
    if(!ctx || !lla_context_ready(*ctx))
        return -1;
    ++ctx->rtp.last_seq;
    if(ctx->ip_version == 4 && ctx->ipv4_id_sequential)
        ++ctx->ipv4_id;
    ctx->rtp.last_ts += ctx->rtp.ts_stride != 0 ? ctx->rtp.ts_stride : 160U;
    const bool built = ctx->ip_version == 6
        ? build_ipv6_rtp_packet(ip_packet, ip_packet_len, *ctx, payload, payload_len)
        : build_rtp_packet(ip_packet, ip_packet_len, *ctx, payload, payload_len);
    if(!built)
    {
        set_feedback(decomp, ctx->cid, rohccxx::FeedbackType::NACK);
        return -1;
    }
    decomp.has_feedback = false;
    return 0;
}

ROHCCXX_API int
rohc_decomp_rfc4362_receive_nhp(struct rohc_decomp* d,
                                const uint8_t* payload,
                                size_t payload_len,
                                uint8_t* ip_packet,
                                size_t* ip_packet_len)
{
    return rohc_decomp_rfc4362_receive_nhp_for_cid(d, 0, payload, payload_len, ip_packet, ip_packet_len);
}

ROHCCXX_API int
rohc_decomp_rfc4362_receive_nhp_for_cid(struct rohc_decomp* d,
                                        uint32_t cid,
                                        const uint8_t* payload,
                                        size_t payload_len,
                                        uint8_t* ip_packet,
                                        size_t* ip_packet_len)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    return receive_nhp_for_cid_locked(d->impl, cid, payload, payload_len, ip_packet, ip_packet_len);
}

ROHCCXX_API int
rohc_decomp_rfc4362_receive_csp(struct rohc_decomp* d,
                                const uint8_t* csp_packet,
                                size_t csp_packet_len,
                                uint8_t* ip_packet,
                                size_t* ip_packet_len)
{
    if(!d || !csp_packet || !ip_packet || !ip_packet_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    if(!d->impl.lla_enabled || !rohccxx::lla::can_emit_context_synchronization_packet(d->impl.lla_contract))
        return -1;
    rohccxx::lla::ContextSynchronizationPacket csp{};
    if(!rohccxx::lla::read_context_synchronization_packet(csp_packet, csp_packet_len, csp) ||
       csp.rohc_header_len == 0)
    {
        set_feedback(d->impl, 0, rohccxx::FeedbackType::NACK);
        return -1;
    }
    return rohc_decompress4(d, csp.rohc_header, csp.rohc_header_len, ip_packet, ip_packet_len);
}

static int receive_ccp_for_cid_locked(rohccxx_internal::Decompressor& decomp,
                                     uint32_t cid,
                                     const uint8_t* ccp_packet,
                                     size_t ccp_packet_len)
{
    if(!ccp_packet)
        return -1;
    if(!decomp.lla_enabled || !rohccxx::lla::can_emit_context_check_packet(decomp.lla_contract))
        return -1;
    rohccxx::lla::ContextCheckPacket ccp{};
    if(!rohccxx::lla::read_context_check_packet(ccp_packet, ccp_packet_len, ccp) || !ccp.has_crc)
    {
        set_feedback(decomp, cid, rohccxx::FeedbackType::NACK);
        return -1;
    }
    rohccxx::Context* ctx = decomp.contexts.get(cid);
    if(!ctx || !lla_context_established(*ctx))
    {
        set_feedback(decomp, cid, rohccxx::FeedbackType::STATIC_NACK);
        return -1;
    }
    if(ccp.crc7 != rohccxx::detail::context_crc7(*ctx))
    {
        set_feedback(decomp, ctx->cid, rohccxx::FeedbackType::STATIC_NACK);
        return -1;
    }
    decomp.has_feedback = false;
    return 0;
}

ROHCCXX_API int
rohc_decomp_rfc4362_receive_ccp(struct rohc_decomp* d,
                                const uint8_t* ccp_packet,
                                size_t ccp_packet_len)
{
    return rohc_decomp_rfc4362_receive_ccp_for_cid(d, 0, ccp_packet, ccp_packet_len);
}

ROHCCXX_API int
rohc_decomp_rfc4362_receive_ccp_for_cid(struct rohc_decomp* d,
                                        uint32_t cid,
                                        const uint8_t* ccp_packet,
                                        size_t ccp_packet_len)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    return receive_ccp_for_cid_locked(d->impl, cid, ccp_packet, ccp_packet_len);
}

ROHCCXX_API int
rohc_decomp_rfc4362_report_loss(struct rohc_decomp* d, uint32_t cid)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    if(!d->impl.lla_enabled || !d->impl.lla_contract.reports_loss)
        return -1;
    set_feedback(d->impl, cid, rohccxx::FeedbackType::NACK);
    return 0;
}

ROHCCXX_API int
rohc_decomp_rfc4362_report_residual_error(struct rohc_decomp* d, uint32_t cid)
{
    if(!d)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(d->impl.mutex);
    if(!d->impl.lla_enabled || !d->impl.lla_contract.reports_residual_errors)
        return -1;
    set_feedback(d->impl, cid, rohccxx::FeedbackType::STATIC_NACK);
    return 0;
}

ROHCCXX_API int
rohc_decomp_set_mode(struct rohc_decomp* decomp, rohccxx_mode_t mode)
{
    if(!decomp)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);
    rohccxx::Mode core_mode{};
    if(!c_mode_to_core(mode, core_mode))
        return -1;
    decomp->impl.mode = core_mode;
    return 0;
}

ROHCCXX_API int
rohc_decomp_get_mode(const struct rohc_decomp* decomp, rohccxx_mode_t* mode)
{
    if(!decomp || !mode)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);
    *mode = core_mode_to_c(decomp->impl.mode);
    return 0;
}

ROHCCXX_API int
rohc_decomp_set_mrru(struct rohc_decomp* decomp, size_t mrru)
{
    if(!decomp || mrru > rohccxx_internal::segment_buffer_max)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);
    decomp->impl.mrru = mrru;
    return 0;
}

ROHCCXX_API void
rohc_decomp_free(struct rohc_decomp* d)
{
    if (!d)
        return;

    std::unique_lock<std::recursive_mutex> lock(d->impl.mutex);
    d->impl.contexts.destroy();
    lock.unlock();
    delete d;
}


ROHCCXX_API int
rohc_decompress4(struct rohc_decomp* decomp,
                 const uint8_t* rohc_packet,
                 size_t rohc_packet_len,
                 uint8_t* ip_packet,
                 size_t* ip_packet_len)
{
    using namespace rohccxx;

    if(!ip_packet_len)
        return -1;
    struct OutputLengthGuard
    {
        size_t* length;
        bool complete = false;
        ~OutputLengthGuard() { if(!complete) *length = 0; }
        int finish(int rc) { complete = rc == 0; return rc; }
    } output_length_guard{ip_packet_len};
    if (!decomp || !rohc_packet || !ip_packet)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(decomp->impl.mutex);

    if (rohc_packet_len == 0)
        return -1;

    decomp->impl.has_feedback = false;

    auto fail_with_feedback = [&](uint32_t feedback_cid) -> int
    {
        Feedback feedback{};
        feedback.cid = feedback_cid;
        feedback.type = FeedbackType::NACK;
        decomp->impl.last_feedback = feedback;
        decomp->impl.has_feedback = true;
        return -1;
    };

    size_t feedback_prefix_len = 0;
    while(feedback_prefix_len < rohc_packet_len && is_feedback_packet_start(rohc_packet[feedback_prefix_len]))
    {
        Feedback incoming{};
        size_t consumed = 0;
        if(!read_feedback_prefix(rohc_packet + feedback_prefix_len,
                                 rohc_packet_len - feedback_prefix_len,
                                 incoming,
                                 consumed))
        {
            return fail_with_feedback(0);
        }
        feedback_prefix_len += consumed;
    }
    if(feedback_prefix_len == rohc_packet_len)
        return -1;
    rohc_packet += feedback_prefix_len;
    rohc_packet_len -= feedback_prefix_len;

    auto parse_live_packet = [&](const uint8_t* wire, size_t wire_len,
                                 ParsedRohcPacket& result) -> bool
    {
        if(parse_rohc_packet(wire, wire_len, result, decomp->impl.large_cid_space))
            return true;
        if(decomp->impl.large_cid_space || !wire || wire_len == 0U)
            return false;
        size_t base = 0U;
        std::uint32_t candidate_cid = 0U;
        bool has_add_cid = false;
        if((wire[0] & 0xf0U) == 0xe0U)
        {
            if(wire_len < 2U)
                return false;
            has_add_cid = true;
            candidate_cid = wire[0] & 0x0fU;
            base = 1U;
        }
        if((wire[base] & 0xe0U) != 0xa0U)
            return false;
        result = {};
        result.wire = wire;
        result.wire_len = wire_len;
        result.packet = wire + base;
        result.packet_len = wire_len - base;
        result.has_add_cid = has_add_cid;
        result.cid = candidate_cid;
        result.type = RohcPacketType::Unknown;
        return true;
    };

    ParsedRohcPacket parsed{};
    if(!parse_live_packet(rohc_packet, rohc_packet_len, parsed))
        return fail_with_feedback(0);

    uint8_t received_icv[rohccxx::rohcoipsec::sha256_digest_len] = {};
    size_t received_icv_len = 0;
    if(decomp->impl.rohcoipsec_enabled && parsed.type != RohcPacketType::Segment && decomp->impl.rohcoipsec_icv_len > 0)
    {
        received_icv_len = decomp->impl.rohcoipsec_icv_len;
        if(received_icv_len > sizeof(received_icv) || rohc_packet_len < received_icv_len)
            return fail_with_feedback(parsed.cid);
        std::memcpy(received_icv, rohc_packet + rohc_packet_len - received_icv_len, received_icv_len);
        rohc_packet_len -= received_icv_len;
        parsed = ParsedRohcPacket{};
        if(!parse_live_packet(rohc_packet, rohc_packet_len, parsed))
            return fail_with_feedback(0);
    }

    constexpr size_t max_reconstructed_ip_packet = 40U + 0xFFFFU;
    const bool stage_authenticated_output =
        decomp->impl.rohcoipsec_enabled && received_icv_len > 0;
    std::unique_ptr<uint8_t[]> authenticated_output;
    std::unique_ptr<uint8_t[]> formal_co_output;
    bool stage_formal_co_output = false;
    if(stage_authenticated_output)
    {
        authenticated_output.reset(new(std::nothrow) uint8_t[max_reconstructed_ip_packet]);
        if(!authenticated_output)
            return fail_with_feedback(parsed.cid);
    }
    uint8_t* reconstruction_packet = stage_authenticated_output
        ? authenticated_output.get() : ip_packet;
    size_t reconstruction_len = stage_authenticated_output
        ? std::min(*ip_packet_len, max_reconstructed_ip_packet) : *ip_packet_len;

    auto verify_rohcoipsec_icv = [&](int rc) -> int
    {
        if(rc != 0 || !decomp->impl.rohcoipsec_enabled || received_icv_len == 0)
            return rc;
        uint8_t computed[rohccxx::rohcoipsec::sha256_digest_len] = {};
        size_t computed_len = received_icv_len;
        if(!rohccxx::rohcoipsec::compute_icv(decomp->impl.rohcoipsec_algorithm,
                                             decomp->impl.rohcoipsec_key,
                                             decomp->impl.rohcoipsec_key_len,
                                             reconstruction_packet,
                                             reconstruction_len,
                                             computed,
                                             &computed_len) ||
           !rohccxx::rohcoipsec::detail::constant_time_equal(computed, received_icv, received_icv_len))
        {
            return fail_with_feedback(parsed.cid);
        }
        return 0;
    };

    // A small-CID-0 formal PT-0 byte carries MSN bits where the legacy RTP FO
    // parser expects an embedded CID. Resolve that ambiguity from the CID-0
    // context before looking up any CID inferred from those bits.
    if(!decomp->impl.large_cid_space && !parsed.has_add_cid &&
       parsed.packet_len > 0 &&
       (parsed.packet[0] & 0x80U) == 0)
    {
        Context* const cid_zero = decomp->impl.contexts.get(0);
        if(cid_zero && rfc5225::live_pt0_context_supported(*cid_zero, false, 0, false))
        {
            parsed.cid = 0;
        }
    }
    uint32_t cid = parsed.cid;
    Context* ctx = decomp->impl.contexts.get(cid);
    if(parsed.type == RohcPacketType::FO_RTP && !parsed.has_add_cid &&
       (!ctx || ctx->rohc_state == RohcState::NoContext))
    {
        Context* const cid_zero = decomp->impl.contexts.get(0);
        if(cid_zero && cid_zero->rohc_state == RohcState::DynamicEstablished)
        {
            cid = 0;
            ctx = cid_zero;
        }
    }
    if (!ctx)
        return fail_with_feedback(cid);
    const Context context_before_decode = *ctx;
    const Mode decompressor_mode_before = decomp->impl.mode;
    ctx->cid = cid;
    ctx->large_cid = decomp->impl.large_cid_space;
    if(ctx->tx_count == 0 && ctx->rohc_state == RohcState::NoContext)
        ctx->mode = decomp->impl.mode;
    auto finish_decoding = [&](int rc) -> int
    {
        if(rc != 0)
        {
            *ctx = context_before_decode;
            decomp->impl.mode = decompressor_mode_before;
        }
        else
        {
            if(stage_authenticated_output || stage_formal_co_output)
                std::memcpy(ip_packet, reconstruction_packet, reconstruction_len);
            *ip_packet_len = reconstruction_len;
        }
        return output_length_guard.finish(rc);
    };

    // In the small-CID space, CID 0 FO-RTP and the uncompressed profile both
    // start with 0x00.  Payload bytes in a valid FO-RTP packet may therefore
    // accidentally satisfy the uncompressed IPv4/IPv6 length heuristic.  An
    // established RTP context resolves that ambiguity; the FO decoder below
    // still validates the packet structure and fails closed if it is invalid.
    const bool established_rtp_context =
        ctx->rohc_state == RohcState::DynamicEstablished &&
        (ctx->profile == Profile::RTP || ctx->profile == Profile::RTP_UDP_Lite);
    if(!decomp->impl.large_cid_space && parsed.cid == 0 &&
       parsed.type == RohcPacketType::Uncompressed &&
       parsed.packet_len > 0 && parsed.packet[0] == 0x00 &&
       established_rtp_context)
    {
        parsed.type = RohcPacketType::FO_RTP;
    }

    bool ok = false;
    size_t header_len = 0;
    bool verify_formal_co_crc = false;
    std::uint8_t formal_co_crc = 0;
    size_t formal_co_uncompressed_header_len = 0;
    const uint8_t* packet = parsed.packet;
    size_t packet_len = parsed.packet_len;
    const uint8_t* decode_packet = decoder_packet_start(parsed);
    size_t decode_packet_len = decoder_packet_len(parsed);
    bool prefer_private_rtp_fo = false;

    // The unauthenticated fixed-header UDP PT-0 path authenticates a temporary
    // context and a 28-byte reconstruction before touching live state or caller
    // output. Authenticated packets retain the full-packet staging path below.
    const bool fixed_udp_pt0_candidate =
        !stage_authenticated_output && packet_len > 0U &&
        (packet[0] & 0x80U) == 0U &&
        context_before_decode.profile == Profile::UDP &&
        context_before_decode.ipv4_options_len == 0U &&
        rfc5225::live_pt0_context_supported(context_before_decode,
                                            decomp->impl.large_cid_space,
                                            cid, parsed.has_add_cid);
    if(fixed_udp_pt0_candidate)
    {
        Context formal_context = context_before_decode;
        rfc5225::FormalCoPacket formal{};
        bool formal_valid = rfc5225::read_formal_co_base(
            packet, 1U, Profile::UDP, rfc5225::FormalCoVariant::Pt0Crc3, formal);
        std::array<std::uint8_t, 28> formal_header{};
        const std::uint8_t* formal_payload = nullptr;
        size_t formal_payload_len = 0U;
        if(formal_valid)
        {
            std::uint16_t next_msn = formal_context.msn;
            for(std::uint16_t delta = 1U; delta <= 15U; ++delta)
            {
                const auto candidate = static_cast<std::uint16_t>(formal_context.msn + delta);
                if((candidate & 0x0fU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            formal_valid = next_msn != formal_context.msn;
            if(formal_valid)
            {
                const auto delta = static_cast<std::uint16_t>(next_msn - formal_context.msn);
                formal_context.msn = next_msn;
                formal_context.ipv4_id =
                    static_cast<std::uint16_t>(formal_context.ipv4_id + delta);
                formal_valid = detail::payload_after_header(packet, packet_len, 1U,
                                                             formal_payload,
                                                             formal_payload_len) &&
                    build_fixed_udp_ipv4_header(formal_header, formal_context,
                                                formal_payload_len) &&
                    utils::crc3(formal_header.data(), formal_header.size()) ==
                        formal.header_crc;
            }
        }

        bool private_valid = false;
        Context private_context = context_before_decode;
        size_t private_header_len = 0U;
        switch(parsed.type)
        {
        case RohcPacketType::FO_UDP:
            private_valid = decode_udp_fo(packet, packet_len, private_context,
                                          &private_header_len);
            break;
        case RohcPacketType::FO_ESP:
            private_valid = decode_esp_fo(packet, packet_len, private_context,
                                          &private_header_len);
            break;
        case RohcPacketType::FO_IP:
            private_valid = decode_ip_fo(packet, packet_len, private_context,
                                         &private_header_len);
            break;
        default:
            break;
        }

        if(formal_valid && private_valid)
            return finish_decoding(fail_with_feedback(cid));
        if(formal_valid)
        {
            if(formal_payload_len > std::numeric_limits<size_t>::max() - formal_header.size() ||
               *ip_packet_len < formal_header.size() + formal_payload_len)
                return finish_decoding(fail_with_feedback(cid));
            const size_t final_len = formal_header.size() + formal_payload_len;
            *ctx = formal_context;
            decomp->impl.mode = formal_context.mode;
            std::memcpy(ip_packet, formal_header.data(), formal_header.size());
            if(formal_payload_len > 0U)
                std::memcpy(ip_packet + formal_header.size(), formal_payload,
                            formal_payload_len);
            reconstruction_len = final_len;
            return finish_decoding(0);
        }
        if(!private_valid)
            return finish_decoding(fail_with_feedback(cid));
        // A valid private packet continues through the unchanged decoder below.
    }

    // IP-only pt_1_seq_id carries a six-bit MSN and a four-bit sequential
    // IPv4-ID. Decode both through the shared W-LSB implementation and
    // authenticate a fixed-header reconstruction before committing any state.
    const bool fixed_ip_pt1_candidate =
        packet_len >= 2U && (packet[0] & 0xe0U) == 0xa0U &&
        context_before_decode.profile == Profile::IP &&
        context_before_decode.rohc_state == RohcState::DynamicEstablished &&
        context_before_decode.ip_version == 4U &&
        context_before_decode.ipv4_options_len == 0U &&
        context_before_decode.ipv4_id_behavior <= 1U &&
        !decomp->impl.large_cid_space && !context_before_decode.large_cid &&
        cid <= 0x0fU && parsed.has_add_cid == (cid != 0U);
    if(fixed_ip_pt1_candidate)
    {
        Context formal_context = context_before_decode;
        rfc5225::FormalCoPacket formal{};
        bool formal_valid = rfc5225::read_formal_co_base(
            packet, 2U, Profile::IP, rfc5225::FormalCoVariant::Pt1SeqId, formal);
        std::array<std::uint8_t, 20> formal_header{};
        const uint8_t* formal_payload = nullptr;
        size_t formal_payload_len = 0U;
        if(formal_valid)
        {
            std::uint32_t decoded_msn = 0U;
            std::uint32_t decoded_id = 0U;
            const bool swapped = formal_context.ipv4_id_behavior == 1U;
            const std::uint16_t reference_id = swapped
                ? byte_swap_u16(formal_context.ipv4_id) : formal_context.ipv4_id;
            formal_valid = encoding::decode_field_lsb_with_p(
                    encoding::EncodedField::RtpSequence, formal.msn,
                    formal_context.msn, 6U, 0U, decoded_msn) &&
                static_cast<std::uint16_t>(decoded_msn) ==
                    static_cast<std::uint16_t>(formal_context.msn + 1U) &&
                encoding::decode_field_lsb_with_p(
                    encoding::EncodedField::IpId, formal.ip_id,
                    reference_id, 4U, 0U, decoded_id) &&
                static_cast<std::uint16_t>(decoded_id) != reference_id;
            if(formal_valid)
            {
                formal_context.msn = static_cast<std::uint16_t>(decoded_msn);
                const auto decoded_id16 = static_cast<std::uint16_t>(decoded_id);
                formal_context.ipv4_id = swapped ? byte_swap_u16(decoded_id16) : decoded_id16;
                formal_context.ipv4_id_sequential = true;
                formal_valid = formal_context.ipv4_id != 0U &&
                    detail::payload_after_header(packet, packet_len, 2U,
                                                 formal_payload, formal_payload_len) &&
                    build_fixed_ip_ipv4_header(formal_header, formal_context,
                                               formal_payload_len) &&
                    utils::crc3(formal_header.data(), formal_header.size()) ==
                        formal.header_crc;
            }
        }
        if(!formal_valid ||
           formal_payload_len > std::numeric_limits<size_t>::max() - formal_header.size() ||
           reconstruction_len < formal_header.size() + formal_payload_len)
        {
            return finish_decoding(fail_with_feedback(cid));
        }

        const size_t final_len = formal_header.size() + formal_payload_len;
        *ctx = formal_context;
        decomp->impl.mode = formal_context.mode;
        std::memcpy(reconstruction_packet, formal_header.data(), formal_header.size());
        if(formal_payload_len > 0U)
            std::memcpy(reconstruction_packet + formal_header.size(), formal_payload,
                        formal_payload_len);
        reconstruction_len = final_len;
        return finish_decoding(verify_rohcoipsec_icv(0));
    }

    // The unauthenticated fixed-header ESP PT-0 path authenticates a temporary
    // context and a 28-byte reconstruction before touching live state or caller
    // output. ROHCoIPsec retains its existing full-packet authenticated staging.
    const bool fixed_esp_pt0_candidate =
        !stage_authenticated_output && packet_len > 0U &&
        (packet[0] & 0x80U) == 0U &&
        context_before_decode.profile == Profile::ESP &&
        context_before_decode.ipv4_options_len == 0U &&
        rfc5225::live_pt0_context_supported(context_before_decode,
                                            decomp->impl.large_cid_space,
                                            cid, parsed.has_add_cid);
    if(fixed_esp_pt0_candidate)
    {
        Context formal_context = context_before_decode;
        rfc5225::FormalCoPacket formal{};
        bool formal_valid = rfc5225::read_formal_co_base(
            packet, 1U, Profile::ESP, rfc5225::FormalCoVariant::Pt0Crc3, formal);
        std::array<std::uint8_t, 28> formal_header{};
        const uint8_t* formal_payload = nullptr;
        size_t formal_payload_len = 0U;
        if(formal_valid)
        {
            std::uint16_t next_msn = formal_context.msn;
            for(std::uint16_t delta = 1U; delta <= 15U; ++delta)
            {
                const auto candidate = static_cast<std::uint16_t>(formal_context.msn + delta);
                if((candidate & 0x0fU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            formal_valid = next_msn != formal_context.msn;
            if(formal_valid)
            {
                const auto delta = static_cast<std::uint16_t>(next_msn - formal_context.msn);
                formal_context.msn = next_msn;
                formal_context.ipv4_id =
                    static_cast<std::uint16_t>(formal_context.ipv4_id + delta);
                formal_context.esp_sequence += delta;
                formal_valid = detail::payload_after_header(packet, packet_len, 1U,
                                                             formal_payload,
                                                             formal_payload_len) &&
                    build_fixed_esp_ipv4_header(formal_header, formal_context,
                                                formal_payload_len) &&
                    utils::crc3(formal_header.data(), formal_header.size()) ==
                        formal.header_crc;
            }
        }

        Context private_context = context_before_decode;
        size_t private_header_len = 0U;
        const bool private_valid =
            decode_esp_fo(packet, packet_len, private_context, &private_header_len) &&
            private_context.profile == Profile::ESP;

        if(formal_valid && private_valid)
            return finish_decoding(fail_with_feedback(cid));
        if(formal_valid)
        {
            if(formal_payload_len > std::numeric_limits<size_t>::max() - formal_header.size() ||
               *ip_packet_len < formal_header.size() + formal_payload_len)
                return finish_decoding(fail_with_feedback(cid));
            const size_t final_len = formal_header.size() + formal_payload_len;
            *ctx = formal_context;
            decomp->impl.mode = formal_context.mode;
            std::memcpy(ip_packet, formal_header.data(), formal_header.size());
            if(formal_payload_len > 0U)
                std::memcpy(ip_packet + formal_header.size(), formal_payload,
                            formal_payload_len);
            reconstruction_len = final_len;
            return finish_decoding(0);
        }
        if(!private_valid)
            return finish_decoding(fail_with_feedback(cid));
        // A valid private packet continues through the unchanged decoder below.
    }

    // The unauthenticated fixed-header IP-only PT-0 path authenticates a
    // temporary context and a 20-byte reconstruction before touching live
    // state or caller output. Authenticated packets retain staged reconstruction.
    const bool fixed_ip_pt0_candidate =
        !stage_authenticated_output && packet_len > 0U &&
        (packet[0] & 0x80U) == 0U &&
        context_before_decode.profile == Profile::IP &&
        context_before_decode.ipv4_options_len == 0U &&
        rfc5225::live_pt0_context_supported(context_before_decode,
                                            decomp->impl.large_cid_space,
                                            cid, parsed.has_add_cid);
    if(fixed_ip_pt0_candidate)
    {
        Context formal_context = context_before_decode;
        rfc5225::FormalCoPacket formal{};
        bool formal_valid = rfc5225::read_formal_co_base(
            packet, 1U, Profile::IP, rfc5225::FormalCoVariant::Pt0Crc3, formal);
        std::array<std::uint8_t, 20> formal_header{};
        const uint8_t* formal_payload = nullptr;
        size_t formal_payload_len = 0U;
        if(formal_valid)
        {
            std::uint16_t next_msn = formal_context.msn;
            for(std::uint16_t delta = 1U; delta <= 15U; ++delta)
            {
                const auto candidate = static_cast<std::uint16_t>(formal_context.msn + delta);
                if((candidate & 0x0fU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            formal_valid = next_msn != formal_context.msn;
            if(formal_valid)
            {
                const auto delta = static_cast<std::uint16_t>(next_msn - formal_context.msn);
                formal_context.msn = next_msn;
                formal_context.ipv4_id =
                    static_cast<std::uint16_t>(formal_context.ipv4_id + delta);
                formal_valid = detail::payload_after_header(packet, packet_len, 1U,
                                                             formal_payload,
                                                             formal_payload_len) &&
                    build_fixed_ip_ipv4_header(formal_header, formal_context,
                                               formal_payload_len) &&
                    utils::crc3(formal_header.data(), formal_header.size()) ==
                        formal.header_crc;
            }
        }

        Context private_context = context_before_decode;
        size_t private_header_len = 0U;
        const bool private_valid =
            decode_ip_fo(packet, packet_len, private_context, &private_header_len) &&
            private_context.profile == Profile::IP;

        if(formal_valid && private_valid)
            return finish_decoding(fail_with_feedback(cid));
        if(formal_valid)
        {
            if(formal_payload_len > std::numeric_limits<size_t>::max() - formal_header.size() ||
               *ip_packet_len < formal_header.size() + formal_payload_len)
                return finish_decoding(fail_with_feedback(cid));
            const size_t final_len = formal_header.size() + formal_payload_len;
            *ctx = formal_context;
            decomp->impl.mode = formal_context.mode;
            std::memcpy(ip_packet, formal_header.data(), formal_header.size());
            if(formal_payload_len > 0U)
                std::memcpy(ip_packet + formal_header.size(), formal_payload,
                            formal_payload_len);
            reconstruction_len = final_len;
            return finish_decoding(0);
        }
        if(!private_valid)
            return finish_decoding(fail_with_feedback(cid));
        // A valid private packet continues through the unchanged decoder below.
    }

    // The unauthenticated fixed-header RTP PT-0 path authenticates a temporary
    // context and a 40-byte reconstruction before touching live state or caller
    // output. ROHCoIPsec retains its existing full-packet authenticated staging.
    const bool fixed_rtp_pt0_candidate =
        !stage_authenticated_output && parsed.type == RohcPacketType::FO_RTP &&
        packet_len > 0U && (packet[0] & 0x80U) == 0U &&
        context_before_decode.profile == Profile::RTP &&
        context_before_decode.ipv4_options_len == 0U &&
        (context_before_decode.rtp.vpxcc & 0x3fU) == 0U &&
        context_before_decode.rtp.csrc_list_len == 0U &&
        context_before_decode.rtp.extension_len == 0U &&
        context_before_decode.rtp.padding_len == 0U &&
        rfc5225::live_pt0_context_supported(context_before_decode,
                                            decomp->impl.large_cid_space,
                                            cid,
                                            parsed.has_add_cid);
    if(fixed_rtp_pt0_candidate)
    {
        Context formal_context = *ctx;
        rfc5225::FormalCoPacket formal{};
        bool formal_valid = rfc5225::read_formal_co_base(
            packet, 1U, Profile::RTP, rfc5225::FormalCoVariant::Pt0Crc3, formal);
        std::array<std::uint8_t, 40> formal_header{};
        const uint8_t* formal_payload = nullptr;
        size_t formal_payload_len = 0U;
        if(formal_valid)
        {
            std::uint16_t next_msn = formal_context.msn;
            for(std::uint16_t delta = 1U; delta <= 15U; ++delta)
            {
                const auto candidate = static_cast<std::uint16_t>(formal_context.msn + delta);
                if((candidate & 0x0fU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            formal_valid = next_msn != formal_context.msn;
            if(formal_valid)
            {
                const auto delta = static_cast<std::uint16_t>(next_msn - formal_context.msn);
                formal_context.msn = next_msn;
                if(formal_context.ipv4_id_behavior == 0U)
                    formal_context.ipv4_id =
                        static_cast<std::uint16_t>(formal_context.ipv4_id + delta);
                formal_context.rtp.last_seq = next_msn;
                formal_context.rtp.last_ts += formal_context.rtp.ts_stride * delta;
                formal_valid = detail::payload_after_header(packet, packet_len, 1U,
                                                             formal_payload,
                                                             formal_payload_len) &&
                    build_fixed_rtp_ipv4_header(formal_header, formal_context,
                                                formal_payload_len) &&
                    utils::crc3(formal_header.data(), formal_header.size()) ==
                        formal.header_crc;
            }
        }

        bool private_valid = false;
        if(parsed.has_add_cid)
        {
            Context private_context = *ctx;
            std::uint16_t private_sequence = 0U;
            std::uint32_t private_timestamp = 0U;
            size_t private_header_len = 0U;
            if(decode_fo_rtp(packet, packet_len, private_context,
                             private_sequence, private_timestamp,
                             &private_header_len))
            {
                const uint8_t* private_payload = nullptr;
                size_t private_payload_len = 0U;
                std::array<std::uint8_t, 40> private_header{};
                private_valid = detail::payload_after_header(
                                    packet, packet_len, private_header_len,
                                    private_payload, private_payload_len) &&
                    build_fixed_rtp_ipv4_header(private_header, private_context,
                                                private_payload_len);
            }
        }

        if(formal_valid && private_valid)
            return finish_decoding(fail_with_feedback(cid));
        if(formal_valid)
        {
            if(formal_payload_len > std::numeric_limits<size_t>::max() - formal_header.size() ||
               *ip_packet_len < formal_header.size() + formal_payload_len)
                return finish_decoding(fail_with_feedback(cid));
            const size_t final_len = formal_header.size() + formal_payload_len;
            *ctx = formal_context;
            decomp->impl.mode = formal_context.mode;
            std::memcpy(ip_packet, formal_header.data(), formal_header.size());
            if(formal_payload_len > 0U)
                std::memcpy(ip_packet + formal_header.size(), formal_payload,
                            formal_payload_len);
            reconstruction_len = final_len;
            return finish_decoding(0);
        }
        if(private_valid)
            prefer_private_rtp_fo = true;
        else
            return finish_decoding(fail_with_feedback(cid));
    }

    // RFC 5225 PT-0 uses the entire zero-MSB octet space.  The legacy/private
    // FO markers 0x77..0x7a therefore overlap valid CID-0 PT-0 values.  Resolve
    // only that overlap, only for an established small-CID-0 formal context,
    // and authenticate both possible meanings without touching live state or
    // caller output.  A genuinely ambiguous packet is rejected rather than
    // choosing a format by parser precedence.
    const bool private_fo_overlap =
        parsed.type == RohcPacketType::FO_UDP_Lite ||
        parsed.type == RohcPacketType::FO_ESP ||
        parsed.type == RohcPacketType::FO_IP ||
        parsed.type == RohcPacketType::FO_UDP;
    if(private_fo_overlap && packet_len > 0 && (packet[0] & 0x80U) == 0 &&
       rfc5225::live_pt0_context_supported(context_before_decode,
                                           decomp->impl.large_cid_space,
                                           cid,
                                           parsed.has_add_cid))
    {
        struct TentativeMeaning
        {
            enum class Interpretation
            {
                FormalPt0,
                PrivateFo,
            } interpretation = Interpretation::FormalPt0;
            bool valid = false;
            Context context{};
            std::unique_ptr<std::uint8_t[]> output;
            size_t output_len = 0;
            size_t consumed_len = 0;
            Profile profile = Profile::Uncompressed;
            std::uint32_t cid = 0;
        };

        auto reconstruct_tentative = [&](TentativeMeaning& meaning,
                                         size_t candidate_header_len) -> bool
        {
            const uint8_t* candidate_payload = nullptr;
            size_t candidate_payload_len = 0;
            if(!detail::payload_after_header(packet, packet_len, candidate_header_len,
                                             candidate_payload, candidate_payload_len))
                return false;

            meaning.output.reset(new(std::nothrow) uint8_t[max_reconstructed_ip_packet]);
            if(!meaning.output)
                return false;
            meaning.output_len = max_reconstructed_ip_packet;
            switch(meaning.context.profile)
            {
            case Profile::RTP:
                return build_rtp_packet(meaning.output.get(), &meaning.output_len,
                                        meaning.context, candidate_payload,
                                        candidate_payload_len);
            case Profile::UDP:
                return build_udp_packet(meaning.output.get(), &meaning.output_len,
                                        meaning.context, candidate_payload,
                                        candidate_payload_len);
            case Profile::ESP:
                return meaning.context.legacy_esp_payload_includes_header
                    ? build_ip_packet(meaning.output.get(), &meaning.output_len,
                                      meaning.context, candidate_payload,
                                      candidate_payload_len)
                    : build_esp_packet(meaning.output.get(), &meaning.output_len,
                                       meaning.context, candidate_payload,
                                       candidate_payload_len);
            case Profile::IP:
                return build_ip_packet(meaning.output.get(), &meaning.output_len,
                                       meaning.context, candidate_payload,
                                       candidate_payload_len);
            default:
                return false;
            }
        };

        auto try_formal_pt0 = [&]() -> TentativeMeaning
        {
            TentativeMeaning meaning{};
            meaning.interpretation = TentativeMeaning::Interpretation::FormalPt0;
            meaning.context = context_before_decode;
            meaning.profile = context_before_decode.profile;
            meaning.cid = cid;
            rfc5225::FormalCoPacket formal{};
            if(!rfc5225::read_formal_co_base(packet, 1U, meaning.context.profile,
                                             rfc5225::FormalCoVariant::Pt0Crc3,
                                             formal))
                return meaning;

            std::uint16_t next_msn = meaning.context.msn;
            for(std::uint16_t delta = 1; delta <= 15U; ++delta)
            {
                const std::uint16_t candidate =
                    static_cast<std::uint16_t>(meaning.context.msn + delta);
                if((candidate & 0x0FU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            if(next_msn == meaning.context.msn)
                return meaning;

            const std::uint16_t msn_delta =
                static_cast<std::uint16_t>(next_msn - meaning.context.msn);
            meaning.context.msn = next_msn;
            if(meaning.context.ipv4_id_behavior == 0U)
                meaning.context.ipv4_id =
                    static_cast<std::uint16_t>(meaning.context.ipv4_id + msn_delta);
            if(meaning.context.profile == Profile::ESP)
                meaning.context.esp_sequence += msn_delta;
            if(meaning.context.profile == Profile::RTP)
            {
                meaning.context.rtp.last_seq = next_msn;
                meaning.context.rtp.last_ts += meaning.context.rtp.ts_stride * msn_delta;
            }

            size_t candidate_header_len = 1U;
            if(meaning.context.profile == Profile::UDP &&
               meaning.context.udp_checksum_used)
            {
                if(packet_len < candidate_header_len + 2U)
                    return meaning;
                meaning.context.udp_check = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(packet[candidate_header_len]) << 8U) |
                    packet[candidate_header_len + 1U]);
                candidate_header_len += 2U;
            }
            if(!reconstruct_tentative(meaning, candidate_header_len))
                return meaning;
            meaning.consumed_len = candidate_header_len;
            const size_t crc_header_len = meaning.context.profile == Profile::RTP ? 40U :
                (meaning.context.profile == Profile::IP ? 20U : 28U);
            meaning.valid = meaning.output_len >= crc_header_len &&
                utils::crc3(meaning.output.get(), crc_header_len) == formal.header_crc;
            return meaning;
        };

        auto try_private_fo = [&]() -> TentativeMeaning
        {
            TentativeMeaning meaning{};
            meaning.interpretation = TentativeMeaning::Interpretation::PrivateFo;
            meaning.context = context_before_decode;
            meaning.profile = context_before_decode.profile;
            meaning.cid = cid;
            size_t candidate_header_len = 0;
            bool decoded = false;
            switch(parsed.type)
            {
            case RohcPacketType::FO_RTP:
            {
                std::uint16_t sequence = 0;
                std::uint32_t timestamp = 0;
                decoded = parsed.has_add_cid &&
                          decode_fo_rtp(packet, packet_len, meaning.context,
                                        sequence, timestamp, &candidate_header_len) &&
                          meaning.context.profile == Profile::RTP;
                break;
            }
            case RohcPacketType::FO_UDP:
                decoded = decode_udp_fo(packet, packet_len, meaning.context,
                                        &candidate_header_len) &&
                          meaning.context.profile == Profile::UDP;
                break;
            case RohcPacketType::FO_ESP:
                decoded = decode_esp_fo(packet, packet_len, meaning.context,
                                        &candidate_header_len) &&
                          meaning.context.profile == Profile::ESP;
                break;
            case RohcPacketType::FO_IP:
                decoded = decode_ip_fo(packet, packet_len, meaning.context,
                                       &candidate_header_len) &&
                          meaning.context.profile == Profile::IP;
                break;
            case RohcPacketType::FO_UDP_Lite:
            default:
                // live_pt0_context_supported excludes UDP-Lite, so a 0x77
                // collision can only be private if the established profile
                // also changes; reject that downgrade here.
                decoded = false;
                break;
            }
            if(decoded)
            {
                meaning.profile = meaning.context.profile;
                meaning.cid = meaning.context.cid;
                meaning.consumed_len = candidate_header_len;
                meaning.valid = reconstruct_tentative(meaning, candidate_header_len);
            }
            return meaning;
        };

        TentativeMeaning formal = try_formal_pt0();
        TentativeMeaning private_fo = try_private_fo();
        if(formal.valid)
        {
            if(private_fo.valid)
            {
                const bool same_interpretation =
                    formal.interpretation == private_fo.interpretation;
                const bool same_consumed_len =
                    formal.consumed_len == private_fo.consumed_len;
                const bool same_profile = formal.profile == private_fo.profile;
                const bool same_cid = formal.cid == private_fo.cid;
                const bool same_output_len = formal.output_len == private_fo.output_len;
                const bool same_output = same_output_len &&
                    std::memcmp(formal.output.get(), private_fo.output.get(),
                                formal.output_len) == 0;
                const bool same_context =
                    detail::standard_context_equal(formal.context, private_fo.context);
                if(!(same_interpretation && same_consumed_len && same_profile &&
                     same_cid && same_output && same_context))
                {
                    *ctx = context_before_decode;
                    decomp->impl.mode = decompressor_mode_before;
                    return fail_with_feedback(cid);
                }
            }
            parsed.type = RohcPacketType::FO_RTP;
        }
        else if(parsed.type == RohcPacketType::FO_RTP && private_fo.valid)
        {
            prefer_private_rtp_fo = true;
        }
        // If formal authentication fails but the complete private packet,
        // including its CRC-8, succeeds below, preserve legacy compatibility.
        // An identical wire image carries no provenance that could distinguish
        // a genuine private packet from a corrupted formal packet.
    }

    if(parsed.type == RohcPacketType::Feedback)
    {
        Feedback incoming{};
        size_t consumed = 0;
        return read_feedback_packet(packet, packet_len, incoming, &consumed) ? -1 : fail_with_feedback(cid);
    }

    if(parsed.type == RohcPacketType::Segment)
    {
        SegmentHeader segment{};
        if(decomp->impl.mrru == 0 ||
           !read_segment_header(packet, packet_len, segment) ||
           packet_len <= rohccxx_internal::segment_header_len)
        {
            decomp->impl.reassembly_active = false;
            decomp->impl.reassembly_len = 0;
            return fail_with_feedback(cid);
        }

        const size_t payload_len = packet_len - rohccxx_internal::segment_header_len;
        const uint8_t* payload = packet + rohccxx_internal::segment_header_len;
        if(!decomp->impl.reassembly_active)
        {
            if(segment.sequence != 0)
                return fail_with_feedback(cid);
            decomp->impl.reassembly_active = true;
            decomp->impl.reassembly_len = 0;
            decomp->impl.expected_segment_sequence = 0;
        }

        const size_t next_len = decomp->impl.reassembly_len + payload_len;
        if(segment.sequence != (decomp->impl.expected_segment_sequence & 0xFFU) ||
           next_len > decomp->impl.mrru ||
           next_len > sizeof(decomp->impl.reassembly))
        {
            decomp->impl.reassembly_active = false;
            decomp->impl.reassembly_len = 0;
            return fail_with_feedback(cid);
        }

        std::memcpy(decomp->impl.reassembly + decomp->impl.reassembly_len, payload, payload_len);
        decomp->impl.reassembly_len = next_len;
        ++decomp->impl.expected_segment_sequence;
        if(!segment.final)
            return 1;

        uint8_t reassembled[rohccxx_internal::segment_buffer_max] = {};
        const size_t reassembled_len = decomp->impl.reassembly_len;
        std::memcpy(reassembled, decomp->impl.reassembly, reassembled_len);
        decomp->impl.reassembly_active = false;
        decomp->impl.reassembly_len = 0;
        decomp->impl.expected_segment_sequence = 0;
        return output_length_guard.finish(
            rohc_decompress4(decomp, reassembled, reassembled_len, ip_packet, ip_packet_len));
    }

    if(parsed.type == RohcPacketType::Uncompressed && packet_len > 1 &&
       is_uncompressed_ip_payload(packet + 1, packet_len - 1))
    {
        const size_t original_len = packet_len - 1;
        if(reconstruction_len < original_len)
            return fail_with_feedback(cid);

        std::memcpy(reconstruction_packet, packet + 1, original_len);
        reconstruction_len = original_len;
        ctx->profile = Profile::Uncompressed;
        ctx->mode = Mode::Uncompressed;
        ctx->rohc_state = RohcState::DynamicEstablished;
        ctx->tx_count++;
        ctx->nack_count = 0;
        decomp->impl.mode = ctx->mode;
        return finish_decoding(verify_rohcoipsec_icv(0));
    }

    if(parsed.type == RohcPacketType::IR)
    {
        switch(parsed.profile_id)
        {
        case 0x02:
            ok = decode_ir_udp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x08:
            ok = decode_ir_udp_lite(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x03:
            ok = decode_ir_esp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x04:
            ok = decode_ir_ip(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x07:
            ok = decode_ir_rtp_udp_lite(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x01:
            ok = decode_ir_rtp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        default:
            ok = false;
            break;
        }
    }
    else if(parsed.type == RohcPacketType::IR_DYN)
    {
        switch(parsed.profile_id)
        {
        case 0x02:
            ok = decode_ir_dyn_udp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x07:
            ok = decode_ir_dyn_rtp_udp_lite(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x08:
            ok = decode_ir_dyn_udp_lite(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x03:
            ok = decode_ir_dyn_esp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x04:
            ok = decode_ir_dyn_ip(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        case 0x01:
            ok = decode_ir_dyn_rtp(decode_packet, decode_packet_len, *ctx, &header_len);
            break;
        default:
            ok = false;
            break;
        }
    }
    else if(parsed.type == RohcPacketType::FO_RTP &&
            !prefer_private_rtp_fo &&
            ctx->profile != Profile::RTP_UDP_Lite &&
            ctx->profile != Profile::Uncompressed && packet_len > 0 &&
            (packet[0] & 0x80U) == 0 &&
            rfc5225::live_pt0_context_supported(*ctx, decomp->impl.large_cid_space,
                                                cid, parsed.has_add_cid))
    {
        const bool supported_context = rfc5225::live_pt0_context_supported(
            *ctx, decomp->impl.large_cid_space, cid, parsed.has_add_cid);
        rfc5225::FormalCoPacket formal{};
        if(supported_context &&
           rfc5225::read_formal_co_base(packet, 1U, ctx->profile,
                                        rfc5225::FormalCoVariant::Pt0Crc3, formal))
        {
            if(!stage_authenticated_output)
            {
                reconstruction_len = std::min(reconstruction_len, max_reconstructed_ip_packet);
                formal_co_output.reset(new(std::nothrow) uint8_t[reconstruction_len]);
                if(!formal_co_output)
                    return fail_with_feedback(cid);
                reconstruction_packet = formal_co_output.get();
                stage_formal_co_output = true;
            }
            std::uint16_t next_msn = ctx->msn;
            for(std::uint16_t delta = 1; delta <= 15U; ++delta)
            {
                const std::uint16_t candidate = static_cast<std::uint16_t>(ctx->msn + delta);
                if((candidate & 0x0FU) == formal.msn)
                {
                    next_msn = candidate;
                    break;
                }
            }
            ok = next_msn != ctx->msn;
            DBG("formal PT0 profile=%u cid=%u ref_msn=%u decoded_msn=%u lsb=%u crc=%u",
                static_cast<unsigned>(ctx->profile), static_cast<unsigned>(cid),
                static_cast<unsigned>(ctx->msn), static_cast<unsigned>(next_msn),
                static_cast<unsigned>(formal.msn), static_cast<unsigned>(formal.header_crc));
            if(ok)
            {
                const std::uint16_t msn_delta = static_cast<std::uint16_t>(next_msn - ctx->msn);
                ctx->msn = next_msn;
                if(ctx->ip_version == 4 && ctx->ipv4_id_behavior == 0U)
                    ctx->ipv4_id = static_cast<std::uint16_t>(ctx->ipv4_id + msn_delta);
                if(ctx->profile == Profile::ESP)
                    ctx->esp_sequence += msn_delta;
                if(ctx->profile == Profile::RTP)
                {
                    ctx->rtp.last_seq = next_msn;
                    ctx->rtp.last_ts += ctx->rtp.ts_stride * msn_delta;
                }
                header_len = 1U;
                if(ctx->profile == Profile::UDP && ctx->udp_checksum_used)
                {
                    if(packet_len < header_len + 2U)
                    {
                        ok = false;
                    }
                    else
                    {
                        ctx->udp_check = static_cast<std::uint16_t>(
                            (static_cast<std::uint16_t>(packet[header_len]) << 8U) |
                            packet[header_len + 1U]);
                        header_len += 2U;
                    }
                }
                formal_co_crc = formal.header_crc;
                verify_formal_co_crc = true;
                formal_co_uncompressed_header_len = ctx->profile == Profile::RTP ? 40U :
                    (ctx->profile == Profile::UDP || ctx->profile == Profile::ESP ? 28U : 20U);
            }
        }
    }
    else if(parsed.type == RohcPacketType::FO_UDP)
    {
        const std::uint16_t previous_msn = ctx->msn;
        ok = decode_udp_fo(packet, packet_len, *ctx, &header_len);
        if(ok)
            ctx->msn = static_cast<std::uint16_t>(previous_msn + 1U);
        if (ok && ctx->profile != Profile::UDP)
            ok = false;
    }
    else if(parsed.type == RohcPacketType::FO_IP)
    {
        ok = decode_ip_fo(packet, packet_len, *ctx, &header_len);
        if (ok && ctx->profile != Profile::IP)
            ok = false;
    }
    else if(parsed.type == RohcPacketType::FO_ESP)
    {
        ok = decode_esp_fo(packet, packet_len, *ctx, &header_len);
        if (ok && ctx->profile != Profile::ESP)
            ok = false;
    }
    else if(parsed.type == RohcPacketType::FO_UDP_Lite)
    {
        ok = decode_udp_lite_fo(packet, packet_len, *ctx, &header_len);
        if (ok && ctx->profile != Profile::UDP_Lite)
            ok = false;
    }
    else if(parsed.type == RohcPacketType::FO_RTP)
    {
        uint16_t seq;
        uint32_t ts;

        // Private/current RTP FO remains explicitly framed with Add-CID in the
        // small-CID space; formal PT-0 was handled above.
        const bool private_rtp_framing = !decomp->impl.large_cid_space && parsed.has_add_cid;
        ok = private_rtp_framing && decode_fo_rtp(packet, packet_len, *ctx, seq, ts, &header_len);
        if(ok)
            ctx->msn = seq;
        if (ok && ctx->rohc_state != RohcState::DynamicEstablished)
            ok = false;
    }

    // ? Unified failure path (Sprint 7 semantics)
    if (!ok)
    {
        *ctx = context_before_decode;
        return fail_with_feedback(cid);
    }
    const uint8_t* payload_base = (decode_packet == parsed.wire) ? decode_packet : packet;
    const size_t payload_base_len = (decode_packet == parsed.wire) ? decode_packet_len : packet_len;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if(!detail::payload_after_header(payload_base, payload_base_len, header_len,
                                     payload, payload_len))
    {
        *ctx = context_before_decode;
        return fail_with_feedback(cid);
    }
    auto finish_built_packet = [&](bool built) -> int
    {
        if(verify_formal_co_crc && built && reconstruction_len >= formal_co_uncompressed_header_len)
            DBG("formal PT0 reconstructed crc=%u received=%u header_len=%zu output_len=%zu",
                static_cast<unsigned>(utils::crc3(reconstruction_packet, formal_co_uncompressed_header_len)),
                static_cast<unsigned>(formal_co_crc), formal_co_uncompressed_header_len, reconstruction_len);
        if(!built || (verify_formal_co_crc &&
           (reconstruction_len < formal_co_uncompressed_header_len ||
            utils::crc3(reconstruction_packet, formal_co_uncompressed_header_len) != formal_co_crc)))
        {
            *ctx = context_before_decode;
            return fail_with_feedback(cid);
        }
        decomp->impl.mode = ctx->mode;
        return finish_decoding(verify_rohcoipsec_icv(0));
    };
    if(ctx->profile == Profile::UDP || ctx->profile == Profile::UDP_Lite)
    {
        const bool built = ctx->ip_version == 6
            ? build_ipv6_udp_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len)
            : build_udp_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len);
        return finish_built_packet(built);
    }

    if(ctx->profile == Profile::ESP)
    {
        const bool built = ctx->legacy_esp_payload_includes_header
            ? (ctx->ip_version == 6
                ? build_ipv6_ip_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len)
                : build_ip_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len))
            : build_esp_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len);
        return finish_built_packet(built);
    }

    if(ctx->profile == Profile::IP)
    {
        const bool built = ctx->ip_version == 6
            ? build_ipv6_ip_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len)
            : build_ip_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len);
        return finish_built_packet(built);
    }

    const bool built = ctx->ip_version == 6
        ? build_ipv6_rtp_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len)
        : build_rtp_packet(reconstruction_packet, &reconstruction_len, *ctx, payload, payload_len);
    return finish_built_packet(built);
}



} // extern "C"
