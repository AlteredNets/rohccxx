// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "compressor.h"

#include <rohccxx/core/context.hpp>
#include <rohccxx/core/context_crc.hpp>
#include <rohccxx/core/context_init.hpp>
#include <rohccxx/core/context_table.hpp>
#include <rohccxx/core/emit_ir.hpp>
#include <rohccxx/core/emit_ir_dyn.hpp>
#include <rohccxx/core/encoding_methods.hpp>
#include <rohccxx/core/packet_type.hpp>
#include <rohccxx/core/lla.hpp>
#include <rohccxx/protocols/ipv4.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace rohccxx {
namespace {

inline uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
}

inline uint32_t read_u32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}


inline bool lla_runtime_contract_valid(const lla::AssistingLayerContract& contract,
                                       const lla::ZeroByteFlow& flow)
{
    return lla::validate_rfc3409_lower_layer_guidelines(contract).valid &&
           lla::validate_rfc3243_zero_byte_flow(contract, flow).valid;
}

inline bool lla_context_established(const Context& ctx)
{
    return (ctx.profile == Profile::RTP || ctx.profile == Profile::LLA_RTP) &&
           ctx.rohc_state != RohcState::NoContext;
}

inline bool lla_context_ready(const Context& ctx)
{
    return lla_context_established(ctx) && ctx.rohc_state == RohcState::DynamicEstablished;
}

inline bool capture_rtp_packet(Context& ctx,
                              const uint8_t* ip_packet,
                              size_t ip_len)
{
    if(ip_len < 40)
        return false;
    if(ipv4::is_fragmented(read_u16(ip_packet + 6)))
        return false;

    const bool had_ipv4_rtp_context = ctx.rtp.initialized != 0;
    const std::uint16_t previous_ipv4_id = ctx.ipv4_id;
    const std::uint16_t previous_rtp_seq = ctx.rtp.last_seq;

    ctx.ipv4_tos = ip_packet[1];
    ctx.ipv4_ttl = ip_packet[8];
    ctx.ipv4_id = read_u16(ip_packet + 4);
    ctx.ipv4_flags = static_cast<std::uint8_t>((read_u16(ip_packet + 6) >> 13U) & 0x07U);
    ctx.ipv4_saddr = read_u32(ip_packet + 12);
    ctx.ipv4_daddr = read_u32(ip_packet + 16);
    ctx.udp_sport = read_u16(ip_packet + 20);
    ctx.udp_dport = read_u16(ip_packet + 22);
    ctx.udp_check = read_u16(ip_packet + 26);

    const uint8_t* rtp = ip_packet + 28;
    const uint16_t seq = read_u16(rtp + 2);
    const uint32_t ts = read_u32(rtp + 4);
    if(ctx.rtp.initialized && ctx.rtp.ts_stride == 0)
    {
        uint32_t stride = 0;
        uint32_t residue = 0;
        if(encoding::infer_timestamp_stride(ctx.rtp.last_seq, ctx.rtp.last_ts, seq, ts, stride, residue))
        {
            ctx.rtp.ts_stride = stride;
            ctx.rtp.ts_residue = residue;
        }
    }

    if(had_ipv4_rtp_context)
    {
        const auto id_delta = static_cast<std::uint16_t>(ctx.ipv4_id - previous_ipv4_id);
        const auto seq_delta = static_cast<std::uint16_t>(seq - previous_rtp_seq);
        ctx.ipv4_id_sequential = id_delta != 0U && id_delta == seq_delta;
    }
    else
    {
        ctx.ipv4_id_sequential = false;
    }

    ctx.rtp.vpxcc = rtp[0];
    ctx.rtp.mpt = rtp[1];
    ctx.rtp.last_seq = seq;
    ctx.rtp.last_ts = ts;
    ctx.rtp.ssrc = read_u32(rtp + 8);

    if(!ctx.rtp.initialized)
    {
        ctx.rtp.seq_window.init(ctx.rtp.last_seq);
        ctx.rtp.ts_window.init(ctx.rtp.last_ts);
        ctx.rtp.initialized = 1;
    }

    return true;
}

} // namespace

Compressor::Compressor(uint32_t cid, uint32_t max_cid)
    : cid_(cid),
      packet_count_(0)
{
    if(max_cid == 0)
        max_cid = cid;

    context_table_.init(max_cid);
    init_rtp_context(context_table_, cid_, nullptr);
}

Compressor::~Compressor()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    context_table_.destroy();
}

int Compressor::compress(const uint8_t* ip_packet,
                         size_t ip_len,
                         uint8_t* rohc_packet,
                         size_t* rohc_len)
{
    if(!rohc_packet || !rohc_len || *rohc_len == 0)
        return -1;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Context* ctx = context_table_.get(cid_);
    if(!ctx)
        return -1;

    ctx->profile = Profile::RTP;
    ctx->mode = Mode::Optimistic;

    if(!capture_rtp_packet(*ctx, ip_packet, ip_len))
        return -1;

    bool ok = false;
    switch(ctx->rohc_state)
    {
        case RohcState::NoContext:
            ok = emit_ir_rtp(rohc_packet, rohc_len, *ctx);
            if(ok)
                ctx->rohc_state = RohcState::StaticEstablished;
            break;

        case RohcState::StaticEstablished:
        case RohcState::DynamicEstablished:
            ok = emit_ir_dyn_rtp(rohc_packet, rohc_len, *ctx);
            if(ok)
                ctx->rohc_state = RohcState::DynamicEstablished;
            break;
    }

    if(!ok)
        return -1;

    ++packet_count_;
    return 0;
}


bool Compressor::enable_rfc4362_lla(const lla::AssistingLayerContract& contract,
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

int Compressor::rfc4362_emit_nhp(const uint8_t* ip_packet,
                                 size_t ip_len,
                                 uint8_t* rohc_packet,
                                 size_t* rohc_len)
{
    if(!ip_packet || !rohc_packet || !rohc_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_no_header_packet_for_flow(lla_contract_, lla_flow_))
        return -1;
    Context* ctx = context_table_.get(cid_);
    if(!ctx || !lla_context_ready(*ctx))
        return -1;
    uint8_t scratch[512] = {};
    size_t scratch_len = sizeof(scratch);
    if(compress(ip_packet, ip_len, scratch, &scratch_len) != 0)
        return -1;
    *rohc_len = 0;
    return 0;
}

int Compressor::rfc4362_emit_csp(const uint8_t* ip_packet,
                                 size_t ip_len,
                                 uint8_t* csp_packet,
                                 size_t* csp_len)
{
    if(!ip_packet || !csp_packet || !csp_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_context_synchronization_packet(lla_contract_))
        return -1;
    uint8_t rohc_header[512] = {};
    size_t rohc_header_len = sizeof(rohc_header);
    if(compress(ip_packet, ip_len, rohc_header, &rohc_header_len) != 0)
        return -1;
    const size_t rtp_payload_len = ip_len > 40U ? ip_len - 40U : 0U;
    if(rtp_payload_len > 0xFFFFU)
        return -1;
    return lla::write_context_synchronization_packet(csp_packet,
                                                     csp_len,
                                                     static_cast<uint16_t>(rtp_payload_len),
                                                     rohc_header,
                                                     rohc_header_len) ? 0 : -1;
}

int Compressor::rfc4362_emit_ccp(uint8_t* ccp_packet,
                                 size_t* ccp_len)
{
    if(!ccp_packet || !ccp_len)
        return -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if(!lla_enabled_ || !lla::can_emit_context_check_packet(lla_contract_))
        return -1;
    Context* ctx = context_table_.get(cid_);
    if(!ctx || !lla_context_established(*ctx))
        return -1;
    lla::ContextCheckPacket ccp{};
    ccp.has_crc = true;
    ccp.crc7 = detail::context_crc7(*ctx);
    return lla::write_context_check_packet(ccp_packet, ccp_len, ccp) ? 0 : -1;
}

} // namespace rohccxx
