// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "decompressor.h"

#include <rohccxx/core/context.hpp>
#include <rohccxx/core/context_table.hpp>
#include <rohccxx/core/decode_ir.hpp>
#include <rohccxx/core/decode_ir_dyn.hpp>
#include <rohccxx/core/lla.hpp>
#include <rohccxx/utils/crc.hpp>

#include <cstring>
#include <mutex>

namespace rohccxx {


namespace
{

std::uint16_t ipv4_checksum(const std::uint8_t* hdr, int len)
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

bool lla_runtime_contract_valid(const lla::AssistingLayerContract& contract,
                                const lla::ZeroByteFlow& flow)
{
    return lla::validate_rfc3409_lower_layer_guidelines(contract).valid &&
           lla::validate_rfc3243_zero_byte_flow(contract, flow).valid;
}

bool lla_context_established(const Context& ctx)
{
    return (ctx.profile == Profile::RTP || ctx.profile == Profile::LLA_RTP) &&
           ctx.rohc_state != RohcState::NoContext;
}

bool lla_context_ready(const Context& ctx)
{
    return lla_context_established(ctx) && ctx.rohc_state == RohcState::DynamicEstablished;
}

void write_context_u16(uint8_t* data, size_t& pos, uint16_t value)
{
    data[pos++] = static_cast<uint8_t>(value >> 8);
    data[pos++] = static_cast<uint8_t>(value & 0xFFU);
}

void write_context_u32(uint8_t* data, size_t& pos, uint32_t value)
{
    data[pos++] = static_cast<uint8_t>(value >> 24);
    data[pos++] = static_cast<uint8_t>(value >> 16);
    data[pos++] = static_cast<uint8_t>(value >> 8);
    data[pos++] = static_cast<uint8_t>(value & 0xFFU);
}

uint8_t context_crc7(const Context& ctx)
{
    uint8_t data[64] = {};
    size_t pos = 0;
    write_context_u16(data, pos, static_cast<uint16_t>(ctx.profile));
    write_context_u32(data, pos, ctx.cid);
    data[pos++] = static_cast<uint8_t>(ctx.ip_version);
    data[pos++] = ctx.ipv4_tos;
    data[pos++] = ctx.ipv4_ttl;
    write_context_u16(data, pos, ctx.ipv4_id);
    write_context_u32(data, pos, ctx.ipv4_saddr);
    write_context_u32(data, pos, ctx.ipv4_daddr);
    write_context_u16(data, pos, ctx.udp_sport);
    write_context_u16(data, pos, ctx.udp_dport);
    write_context_u16(data, pos, ctx.udp_check);
    data[pos++] = ctx.rtp.vpxcc;
    data[pos++] = ctx.rtp.mpt;
    write_context_u16(data, pos, ctx.rtp.last_seq);
    write_context_u32(data, pos, ctx.rtp.last_ts);
    write_context_u32(data, pos, ctx.rtp.ssrc);
    write_context_u32(data, pos, ctx.rtp.ts_stride);
    return static_cast<uint8_t>(utils::crc7(data, pos) & 0x7FU);
}

bool build_rtp_packet_from_context(std::uint8_t* ip_packet,
                                   std::size_t* ip_len,
                                   const Context& ctx,
                                   const std::uint8_t* payload,
                                   std::size_t payload_len)
{
    const std::size_t total = 40U + payload_len;
    if(!ip_packet || !ip_len || *ip_len < total || (!payload && payload_len > 0))
        return false;
    std::memset(ip_packet, 0, total);
    ip_packet[0] = 0x45;
    ip_packet[1] = ctx.ipv4_tos;
    ip_packet[2] = static_cast<std::uint8_t>(total >> 8);
    ip_packet[3] = static_cast<std::uint8_t>(total & 0xFFU);
    ip_packet[4] = static_cast<std::uint8_t>(ctx.ipv4_id >> 8);
    ip_packet[5] = static_cast<std::uint8_t>(ctx.ipv4_id & 0xFFU);
    ip_packet[6] = static_cast<std::uint8_t>((ctx.ipv4_flags & 0x07U) << 5U);
    ip_packet[8] = ctx.ipv4_ttl;
    ip_packet[9] = 17;
    ip_packet[12] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 24);
    ip_packet[13] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 16);
    ip_packet[14] = static_cast<std::uint8_t>(ctx.ipv4_saddr >> 8);
    ip_packet[15] = static_cast<std::uint8_t>(ctx.ipv4_saddr & 0xFFU);
    ip_packet[16] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 24);
    ip_packet[17] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 16);
    ip_packet[18] = static_cast<std::uint8_t>(ctx.ipv4_daddr >> 8);
    ip_packet[19] = static_cast<std::uint8_t>(ctx.ipv4_daddr & 0xFFU);
    const std::uint16_t csum = ipv4_checksum(ip_packet, 20);
    ip_packet[10] = static_cast<std::uint8_t>(csum >> 8);
    ip_packet[11] = static_cast<std::uint8_t>(csum & 0xFFU);

    ip_packet[20] = static_cast<std::uint8_t>(ctx.udp_sport >> 8);
    ip_packet[21] = static_cast<std::uint8_t>(ctx.udp_sport & 0xFFU);
    ip_packet[22] = static_cast<std::uint8_t>(ctx.udp_dport >> 8);
    ip_packet[23] = static_cast<std::uint8_t>(ctx.udp_dport & 0xFFU);
    const std::uint16_t udp_len = static_cast<std::uint16_t>(20U + payload_len);
    ip_packet[24] = static_cast<std::uint8_t>(udp_len >> 8);
    ip_packet[25] = static_cast<std::uint8_t>(udp_len & 0xFFU);
    ip_packet[26] = static_cast<std::uint8_t>(ctx.udp_check >> 8);
    ip_packet[27] = static_cast<std::uint8_t>(ctx.udp_check & 0xFFU);

    ip_packet[28] = ctx.rtp.vpxcc;
    ip_packet[29] = ctx.rtp.mpt;
    ip_packet[30] = static_cast<std::uint8_t>(ctx.rtp.last_seq >> 8);
    ip_packet[31] = static_cast<std::uint8_t>(ctx.rtp.last_seq & 0xFFU);
    ip_packet[32] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 24);
    ip_packet[33] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 16);
    ip_packet[34] = static_cast<std::uint8_t>(ctx.rtp.last_ts >> 8);
    ip_packet[35] = static_cast<std::uint8_t>(ctx.rtp.last_ts & 0xFFU);
    ip_packet[36] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 24);
    ip_packet[37] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 16);
    ip_packet[38] = static_cast<std::uint8_t>(ctx.rtp.ssrc >> 8);
    ip_packet[39] = static_cast<std::uint8_t>(ctx.rtp.ssrc & 0xFFU);
    if(payload_len > 0)
        std::memcpy(ip_packet + 40, payload, payload_len);
    *ip_len = total;
    return true;
}

} // namespace

Decompressor::Decompressor(uint32_t cid, uint32_t max_cid)
    : cid_(cid)
{
    if(max_cid == 0)
        max_cid = cid;

    context_table_.init(max_cid);
}

Decompressor::~Decompressor()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    context_table_.destroy();
}

int Decompressor::decompress(const uint8_t* rohc_packet,
                             size_t rohc_len,
                             uint8_t* ip_packet,
                             size_t* ip_len)
{
    if(!rohc_packet || !ip_packet || !ip_len || rohc_len == 0)
        return -1;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Context* ctx = context_table_.get(cid_);
    if(!ctx)
        return -1;

    ctx->profile = Profile::RTP;
    ctx->mode = Mode::Optimistic;

    bool ok = false;
    switch(ctx->rohc_state)
    {
        case RohcState::NoContext:
            ok = decode_ir_rtp(rohc_packet, rohc_len, *ctx);
            break;

        case RohcState::StaticEstablished:
        case RohcState::DynamicEstablished:
            ok = decode_ir_dyn_rtp(rohc_packet, rohc_len, *ctx);
            break;
    }

    if(!ok)
        return -1;

    uint8_t* p = ip_packet;
    std::memset(p, 0, 20);
    p[0] = 0x45;
    p[1] = ctx->ipv4_tos;
    p[8] = ctx->ipv4_ttl;
    p[9] = 17;
    p[12] = static_cast<uint8_t>(ctx->ipv4_saddr >> 24);
    p[13] = static_cast<uint8_t>(ctx->ipv4_saddr >> 16);
    p[14] = static_cast<uint8_t>(ctx->ipv4_saddr >> 8);
    p[15] = static_cast<uint8_t>(ctx->ipv4_saddr & 0xFF);
    p[16] = static_cast<uint8_t>(ctx->ipv4_daddr >> 24);
    p[17] = static_cast<uint8_t>(ctx->ipv4_daddr >> 16);
    p[18] = static_cast<uint8_t>(ctx->ipv4_daddr >> 8);
    p[19] = static_cast<uint8_t>(ctx->ipv4_daddr & 0xFF);

    p += 20;
    std::memset(p, 0, 8);
    p[0] = static_cast<uint8_t>(ctx->udp_sport >> 8);
    p[1] = static_cast<uint8_t>(ctx->udp_sport & 0xFF);
    p[2] = static_cast<uint8_t>(ctx->udp_dport >> 8);
    p[3] = static_cast<uint8_t>(ctx->udp_dport & 0xFF);
    p[6] = static_cast<uint8_t>(ctx->udp_check >> 8);
    p[7] = static_cast<uint8_t>(ctx->udp_check & 0xFF);

    p += 8;
    p[0] = ctx->rtp.vpxcc;
    p[1] = ctx->rtp.mpt;
    p[2] = static_cast<uint8_t>(ctx->rtp.last_seq >> 8);
    p[3] = static_cast<uint8_t>(ctx->rtp.last_seq & 0xFF);
    p[4] = static_cast<uint8_t>(ctx->rtp.last_ts >> 24);
    p[5] = static_cast<uint8_t>(ctx->rtp.last_ts >> 16);
    p[6] = static_cast<uint8_t>(ctx->rtp.last_ts >> 8);
    p[7] = static_cast<uint8_t>(ctx->rtp.last_ts & 0xFF);
    p[8] = static_cast<uint8_t>(ctx->rtp.ssrc >> 24);
    p[9] = static_cast<uint8_t>(ctx->rtp.ssrc >> 16);
    p[10] = static_cast<uint8_t>(ctx->rtp.ssrc >> 8);
    p[11] = static_cast<uint8_t>(ctx->rtp.ssrc & 0xFF);

    *ip_len = 40;
    return 0;
}


bool Decompressor::enable_rfc4362_lla(const lla::AssistingLayerContract& contract,
                                      const lla::ZeroByteFlow& flow)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_runtime_contract_valid(contract, flow))
        return false;
    lla_contract_ = contract;
    lla_flow_ = flow;
    lla_enabled_ = true;
    return true;
}

int Decompressor::rfc4362_receive_nhp(const uint8_t* payload,
                                      size_t payload_len,
                                      uint8_t* ip_packet,
                                      size_t* ip_len)
{
    if((!payload && payload_len > 0) || !ip_packet || !ip_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_no_header_packet_for_flow(lla_contract_, lla_flow_))
        return -1;
    Context* ctx = context_table_.get(cid_);
    if(!ctx || !lla_context_ready(*ctx))
        return -1;
    ++ctx->rtp.last_seq;
    if(ctx->ip_version == 4 && ctx->ipv4_id_sequential)
        ++ctx->ipv4_id;
    if(ctx->rtp.ts_stride > 0)
        ctx->rtp.last_ts += ctx->rtp.ts_stride;
    return build_rtp_packet_from_context(ip_packet, ip_len, *ctx, payload, payload_len) ? 0 : -1;
}

int Decompressor::rfc4362_receive_csp(const uint8_t* csp_packet,
                                      size_t csp_len,
                                      uint8_t* ip_packet,
                                      size_t* ip_len)
{
    if(!csp_packet || !ip_packet || !ip_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_context_synchronization_packet(lla_contract_))
        return -1;
    lla::ContextSynchronizationPacket csp{};
    if(!lla::read_context_synchronization_packet(csp_packet, csp_len, csp))
        return -1;
    return decompress(csp.rohc_header, csp.rohc_header_len, ip_packet, ip_len);
}

int Decompressor::rfc4362_receive_ccp(const uint8_t* ccp_packet,
                                      size_t ccp_len)
{
    if(!ccp_packet)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_context_check_packet(lla_contract_))
        return -1;
    lla::ContextCheckPacket ccp{};
    if(!lla::read_context_check_packet(ccp_packet, ccp_len, ccp) || !ccp.has_crc)
        return -1;
    Context* ctx = context_table_.get(cid_);
    if(!ctx || !lla_context_established(*ctx))
        return -1;
    return ccp.crc7 == context_crc7(*ctx) ? 0 : -1;
}

} // namespace rohccxx
