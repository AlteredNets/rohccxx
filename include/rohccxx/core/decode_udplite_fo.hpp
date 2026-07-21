// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/decode_ir.hpp"
#include "rohccxx/utils/crc.hpp"

namespace rohccxx
{

inline bool decode_udp_lite_fo(const uint8_t* in,
                                   size_t len,
                                   Context& ctx,
                                   size_t* consumed = nullptr)
{
    const size_t cid_len = ctx.large_cid ? cid::encoded_len(ctx.cid) : 0U;
    const size_t header_len = 8U + cid_len;
    if(!in || len < header_len)
        return false;

    size_t pos = 0;
    if(in[pos++] != 0x77)
        return false;

    if(!detail::read_large_cid_if_present(in, len, pos, ctx))
        return false;

    uint8_t crc_buf[16];
    if(header_len > sizeof(crc_buf))
        return false;
    std::memcpy(crc_buf, in, header_len);
    const uint8_t received_crc = crc_buf[pos];
    crc_buf[pos++] = 0x00;
    if(utils::crc8(crc_buf, header_len) != received_crc)
        return false;

    ctx.ipv4_id = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_length_or_coverage = detail::read_u16(in + pos);
    pos += 2;
    ctx.udp_check = detail::read_u16(in + pos);
    pos += 2;
    ctx.profile = Profile::UDP_Lite;
    ctx.rohc_state = RohcState::DynamicEstablished;

    if(consumed)
        *consumed = header_len;

    return true;
}

} // namespace rohccxx
