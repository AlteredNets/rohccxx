// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/lsb_window.hpp"

#include <array>
#include <cstdint>

namespace rohccxx
{

enum class Profile : uint16_t
{
    Uncompressed = 0x0000,
    LLA_RTP      = 0x0005,
    RTP          = 0x0101,
    UDP          = 0x0102,
    ESP          = 0x0103,
    IP           = 0x0104,
    RTP_UDP_Lite = 0x0107,
    UDP_Lite     = 0x0108
};

enum class Direction : uint8_t
{
    Uplink,
    Downlink
};

enum class Mode : uint8_t
{
    Uncompressed,
    Optimistic,
    Reliable
};

enum class RohcState : uint8_t
{
    NoContext,
    StaticEstablished,
    DynamicEstablished
};

struct alignas(64) RtpContext
{
    uint32_t ssrc;
    uint16_t last_seq;
    uint32_t last_ts;
    uint8_t  vpxcc;
    uint8_t  mpt;
    uint8_t  initialized;
    uint32_t ts_stride = 0;
    uint32_t ts_residue = 0;
    uint32_t timer_elapsed_ticks = 0;
    bool timer_based_ts = false;
    uint8_t  csrc_list_len = 0;
    std::array<uint8_t, 60> csrc_list{};
    uint16_t extension_len = 0;
    std::array<uint8_t, 256> extension_bytes{};
    uint8_t  padding_len = 0;
    std::array<uint8_t, 255> padding_bytes{};

    LsbWindow<uint16_t, 8> seq_window;
    LsbWindow<uint32_t, 8> ts_window;
};

struct Context
{
    Profile   profile;
    Mode      mode;
    RohcState rohc_state;
    uint32_t  cid;
    bool      large_cid = false;
    uint32_t  tx_count = 0;
    uint8_t   nack_count = 0;
    bool      static_acked = false;
    bool      dynamic_acked = false;
    uint16_t  msn = 0;
    uint8_t   reorder_ratio = 0;

    uint8_t   ip_version = 4;
    uint8_t   ipv4_tos = 0;
    uint8_t   ipv4_ttl = 0;
    uint16_t  ipv4_id = 0;
    uint8_t   ipv4_flags = 0;
    bool      ipv4_id_sequential = false;
    uint8_t   ipv4_id_behavior = 0;
    uint8_t   ipv4_protocol = 0;
    uint32_t  ipv4_saddr = 0;
    uint32_t  ipv4_daddr = 0;
    uint8_t   ipv4_options_len = 0;
    std::array<uint8_t, 40> ipv4_options{};
    uint8_t   ipv6_traffic_class = 0;
    uint32_t  ipv6_flow_label = 0;
    uint8_t   ipv6_next_header = 0;
    uint8_t   ipv6_hop_limit = 0;
    uint8_t   ipv6_extension_len = 0;
    std::array<uint8_t, 16> ipv6_saddr{};
    std::array<uint8_t, 16> ipv6_daddr{};
    std::array<uint8_t, 128> ipv6_extensions{};
    uint16_t  udp_sport = 0;
    uint16_t  udp_dport = 0;
    uint16_t  udp_length_or_coverage = 0;
    uint16_t  udp_check = 0;
    bool      udp_checksum_used = false;
    uint32_t  esp_spi = 0;
    uint32_t  esp_sequence = 0;
    bool      legacy_esp_payload_includes_header = false;

    RtpContext rtp;
};

} // namespace rohccxx
