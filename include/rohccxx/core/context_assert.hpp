// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cassert>
#include "rohccxx/core/context.hpp"
#include "rohccxx/utils/endian.hpp"

namespace rohccxx
{

/*
 * Assert RTP context semantic invariants.
 * These checks validate that wire-order data
 * has not leaked into host-order state.
 */
inline void assert_rtp_context_host_endian(const Context& ctx)
{
#ifndef NDEBUG
    // initialized == 0 means context unused → nothing to check
    if (!ctx.rtp.initialized)
        return;

    /*
     * Heuristic sanity checks:
     * - RTP sequence numbers are rarely > 0xF000 initially
     * - Timestamp deltas grow gradually
     * - SSRC is non-zero but not byte-swapped garbage
     */

    assert(ctx.rtp.last_seq < 0xF000);
    assert(ctx.rtp.last_ts  < 0xFFFFFF00u);
    assert(ctx.rtp.ssrc     != 0x00000000u);
#endif
}

} // namespace rohccxx
