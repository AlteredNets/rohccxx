// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.


#pragma once

#include "rohccxx/core/context_table.hpp"
#include "rohccxx/protocols/rtp.hpp"

namespace rohccxx
{

inline Context* init_rtp_context(ContextTable& tbl,
                                 uint32_t cid,
                                 const rtp::Header* rtp)
{
    auto* ctx = tbl.get(cid);
    if (!ctx)
        return nullptr;

    ctx->cid        = cid;
    ctx->profile    = Profile::RTP;
    ctx->mode       = Mode::Optimistic;
    ctx->tx_count   = 0;
    ctx->nack_count = 0;

    if(rtp != nullptr)
    {
        ctx->rtp.ssrc     = wire::to_host(rtp->ssrc);
        ctx->rtp.last_seq = wire::to_host(rtp->sequence);
        ctx->rtp.last_ts  = wire::to_host(rtp->timestamp);
        ctx->rtp.seq_window.init(ctx->rtp.last_seq);
        ctx->rtp.ts_window.init(ctx->rtp.last_ts);
        ctx->rtp.initialized = 1;
    }

    return ctx;
}

} // namespace rohccxx
