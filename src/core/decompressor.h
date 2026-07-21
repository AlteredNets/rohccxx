// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// src/core/decompressor.h
#pragma once

#include <rohccxx/core/context_table.hpp>
#include <rohccxx/core/lla.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace rohccxx {

class Decompressor
{
public:
    explicit Decompressor(uint32_t cid, uint32_t max_cid = 0);
    ~Decompressor();

    Decompressor(const Decompressor&) = delete;
    Decompressor& operator=(const Decompressor&) = delete;

    // Decompress one ROHC packet into one IP packet
    int decompress(const uint8_t* rohc_packet,
                   size_t rohc_len,
                   uint8_t* ip_packet,
                   size_t* ip_len);

    bool enable_rfc4362_lla(const lla::AssistingLayerContract& contract,
                            const lla::ZeroByteFlow& flow);

    int rfc4362_receive_nhp(const uint8_t* payload,
                            size_t payload_len,
                            uint8_t* ip_packet,
                            size_t* ip_len);

    int rfc4362_receive_csp(const uint8_t* csp_packet,
                            size_t csp_len,
                            uint8_t* ip_packet,
                            size_t* ip_len);

    int rfc4362_receive_ccp(const uint8_t* ccp_packet,
                            size_t ccp_len);

private:
    mutable std::recursive_mutex mutex_;
    uint32_t                     cid_;
    ContextTable                 context_table_;
    lla::AssistingLayerContract  lla_contract_{};
    lla::ZeroByteFlow            lla_flow_{};
    bool                         lla_enabled_ = false;
};

} // namespace rohccxx
