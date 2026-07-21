// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/packet_type.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace rohccxx::rfc5225::grammar
{

enum class PacketFamily : std::uint8_t
{
    IR,
    IR_DYN,
    CO,
    Feedback,
    CID,
    Chain,
    Encoding,
    Negative,
    Oracle,
    Traceability,
};

enum class CaseKind : std::uint8_t
{
    Positive,
    Negative,
    Requirement,
    Oracle,
};

enum class CaseStatus : std::uint8_t
{
    Implemented,
    Planned,
    OpenOracle,
};

enum CidModeMask : std::uint32_t
{
    CidNone = 0U,
    CidSmall = 1U << 0U,
    CidAdd = 1U << 1U,
    CidLarge = 1U << 2U,
    CidAll = CidSmall | CidAdd | CidLarge,
};

enum ChainMask : std::uint32_t
{
    ChainNone = 0U,
    ChainIPv4Static = 1U << 0U,
    ChainIPv4Dynamic = 1U << 1U,
    ChainIPv4Options = 1U << 2U,
    ChainIPv6Static = 1U << 3U,
    ChainIPv6Dynamic = 1U << 4U,
    ChainIPv6Extensions = 1U << 5U,
    ChainUDPStatic = 1U << 6U,
    ChainUDPDynamic = 1U << 7U,
    ChainUDPLiteDynamic = 1U << 8U,
    ChainRTPStatic = 1U << 9U,
    ChainRTPDynamic = 1U << 10U,
    ChainRTPCsrcList = 1U << 11U,
    ChainRTPExtension = 1U << 12U,
    ChainRTPPadding = 1U << 13U,
    ChainESPFields = 1U << 14U,
};

enum EncodingMask : std::uint32_t
{
    EncodingNone = 0U,
    EncodingCRC3 = 1U << 0U,
    EncodingCRC7 = 1U << 1U,
    EncodingCRC8 = 1U << 2U,
    EncodingWLSB = 1U << 3U,
    EncodingScaledTimestamp = 1U << 4U,
    EncodingTimerTimestamp = 1U << 5U,
    EncodingOffsetIpId = 1U << 6U,
    EncodingSDVL = 1U << 7U,
    EncodingListCompression = 1U << 8U,
};

struct ProfileRow
{
    Profile profile;
    std::uint16_t profile_id;
    std::uint8_t profile_low_id;
    const char* name;
    const char* rfc_section;
    bool carries_rtp;
    bool carries_udp;
    bool carries_udp_lite;
    bool carries_esp;
};

struct CaseRow
{
    const char* id;
    Profile profile;
    PacketFamily family;
    CaseKind kind;
    CaseStatus status;
    RohcPacketType packet_type;
    const char* description;
    std::uint32_t cid_modes;
    std::uint32_t chains;
    std::uint32_t encodings;
    const char* rfc_section;
};

struct CoVariantRow
{
    const char* id;
    Profile profile;
    CaseStatus status;
    RohcPacketType packet_type;
    const char* discriminator;
    const char* description;
    std::uint32_t cid_modes;
    std::uint32_t chains;
    std::uint32_t encodings;
    const char* rfc_section;
};

inline constexpr std::array<ProfileRow, 6> profile_manifest{{
    {Profile::RTP, 0x0101, 0x01, "rtp_udp_ip", "RFC5225-6.5", true, true, false, false},
    {Profile::UDP, 0x0102, 0x02, "udp_ip", "RFC5225-6.6", false, true, false, false},
    {Profile::ESP, 0x0103, 0x03, "esp_ip", "RFC5225-6.7", false, false, false, true},
    {Profile::IP, 0x0104, 0x04, "ip_only", "RFC5225-6.8", false, false, false, false},
    {Profile::RTP_UDP_Lite, 0x0107, 0x07, "rtp_udplite_ip", "RFC5225-6.9", true, false, true, false},
    {Profile::UDP_Lite, 0x0108, 0x08, "udplite_ip", "RFC5225-6.9", false, false, true, false},
}};

inline constexpr std::uint32_t ipv4_base_chains = ChainIPv4Static | ChainIPv4Dynamic;
inline constexpr std::uint32_t ipv6_base_chains = ChainIPv6Static | ChainIPv6Dynamic;
inline constexpr std::uint32_t udp_chains = ChainUDPStatic | ChainUDPDynamic;
inline constexpr std::uint32_t udplite_chains = ChainUDPStatic | ChainUDPLiteDynamic;
inline constexpr std::uint32_t rtp_chains = ChainRTPStatic | ChainRTPDynamic;
inline constexpr std::uint32_t all_ip_chains = ipv4_base_chains | ipv6_base_chains;
inline constexpr std::uint32_t all_list_chains = ChainIPv4Options | ChainIPv6Extensions |
                                                     ChainRTPCsrcList | ChainRTPExtension |
                                                     ChainRTPPadding;
inline constexpr std::uint32_t all_required_encodings = EncodingCRC3 | EncodingCRC7 |
                                                         EncodingCRC8 | EncodingWLSB |
                                                         EncodingScaledTimestamp |
                                                         EncodingTimerTimestamp |
                                                         EncodingOffsetIpId |
                                                         EncodingSDVL |
                                                         EncodingListCompression;

inline constexpr std::uint32_t rtp_co_chains = ChainIPv4Dynamic | ChainUDPDynamic | ChainRTPDynamic;
inline constexpr std::uint32_t rtp_udplite_co_chains = ChainIPv4Dynamic | ChainUDPLiteDynamic | ChainRTPDynamic;
inline constexpr std::uint32_t udp_co_chains = ChainIPv4Dynamic | ChainUDPDynamic;
inline constexpr std::uint32_t udplite_co_chains = ChainIPv4Dynamic | ChainUDPLiteDynamic;
inline constexpr std::uint32_t ip_co_chains = ChainIPv4Dynamic;
inline constexpr std::uint32_t esp_co_chains = ChainIPv4Dynamic | ChainESPFields;
inline constexpr std::uint32_t rtp_co_encodings = EncodingCRC3 | EncodingCRC7 | EncodingWLSB |
                                                   EncodingScaledTimestamp | EncodingTimerTimestamp |
                                                   EncodingOffsetIpId | EncodingSDVL | EncodingListCompression;
inline constexpr std::uint32_t non_rtp_co_encodings = EncodingCRC3 | EncodingCRC7 | EncodingWLSB |
                                                       EncodingOffsetIpId | EncodingSDVL | EncodingListCompression;

inline constexpr std::array<CoVariantRow, 52> co_variant_manifest{{
    {"5225-rtp-co-current-fo", Profile::RTP, CaseStatus::Implemented, RohcPacketType::FO_RTP, "current-fo", "Current implemented RTP FO packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp | EncodingTimerTimestamp, "RFC5225-6.5"},
    {"5225-rtp-co-common", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal RTP co_common packet", CidAll, rtp_co_chains, rtp_co_encodings, "RFC5225-6.5"},
    {"5225-rtp-co-repair", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal RTP co_repair packet", CidAll, rtp_co_chains, rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-rtp-pt-0-crc3", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal RTP pt_0_crc3 packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB, "RFC5225-6.5"},
    {"5225-rtp-pt-0-crc7", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "1000", "Formal RTP pt_0_crc7 packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB, "RFC5225-6.5"},
    {"5225-rtp-pt-1-rnd", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal RTP pt_1_rnd packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.5"},
    {"5225-rtp-pt-1-seq-id", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "1001", "Formal RTP pt_1_seq_id packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.5"},
    {"5225-rtp-pt-1-seq-ts", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal RTP pt_1_seq_ts packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.5"},
    {"5225-rtp-pt-2-rnd", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal RTP pt_2_rnd packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.5"},
    {"5225-rtp-pt-2-seq-id", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "11000", "Formal RTP pt_2_seq_id packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.5"},
    {"5225-rtp-pt-2-seq-both", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "11001", "Formal RTP pt_2_seq_both packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp | EncodingOffsetIpId, "RFC5225-6.5"},
    {"5225-rtp-pt-2-seq-ts", Profile::RTP, CaseStatus::Implemented, RohcPacketType::Unknown, "1101", "Formal RTP pt_2_seq_ts packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.5"},

    {"5225-udp-co-current-fo", Profile::UDP, CaseStatus::Implemented, RohcPacketType::FO_UDP, "0x7a", "Current implemented UDP/IP FO packet", CidAll, udp_co_chains, EncodingCRC8 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.6"},
    {"5225-udp-co-common", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal UDP/IP co_common packet", CidAll, udp_co_chains, non_rtp_co_encodings, "RFC5225-6.6"},
    {"5225-udp-co-repair", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal UDP/IP co_repair packet", CidAll, udp_co_chains, non_rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-udp-pt-0-crc3", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal UDP/IP pt_0_crc3 packet", CidAll, udp_co_chains, EncodingCRC3 | EncodingWLSB, "RFC5225-6.6"},
    {"5225-udp-pt-0-crc7", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "100", "Formal UDP/IP pt_0_crc7 packet", CidAll, udp_co_chains, EncodingCRC7 | EncodingWLSB, "RFC5225-6.6"},
    {"5225-udp-pt-1-seq-id", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal UDP/IP pt_1_seq_id packet", CidAll, udp_co_chains, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.6"},
    {"5225-udp-pt-2-seq-id", Profile::UDP, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal UDP/IP pt_2_seq_id packet", CidAll, udp_co_chains, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.6"},

    {"5225-esp-co-current-fo", Profile::ESP, CaseStatus::Implemented, RohcPacketType::FO_ESP, "0x78", "Current implemented ESP/IP FO packet", CidAll, esp_co_chains, EncodingCRC8 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.7"},
    {"5225-esp-co-common", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal ESP/IP co_common packet", CidAll, esp_co_chains, non_rtp_co_encodings, "RFC5225-6.7"},
    {"5225-esp-co-repair", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal ESP/IP co_repair packet", CidAll, esp_co_chains, non_rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-esp-pt-0-crc3", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal ESP/IP pt_0_crc3 packet", CidAll, esp_co_chains, EncodingCRC3 | EncodingWLSB, "RFC5225-6.7"},
    {"5225-esp-pt-0-crc7", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "100", "Formal ESP/IP pt_0_crc7 packet", CidAll, esp_co_chains, EncodingCRC7 | EncodingWLSB, "RFC5225-6.7"},
    {"5225-esp-pt-1-seq-id", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal ESP/IP pt_1_seq_id packet", CidAll, esp_co_chains, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.7"},
    {"5225-esp-pt-2-seq-id", Profile::ESP, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal ESP/IP pt_2_seq_id packet", CidAll, esp_co_chains, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.7"},

    {"5225-ip-co-current-fo", Profile::IP, CaseStatus::Implemented, RohcPacketType::FO_IP, "0x79", "Current implemented IP-only FO packet", CidAll, ip_co_chains, EncodingCRC8 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.8"},
    {"5225-ip-co-common", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal IP-only co_common packet", CidAll, ip_co_chains, non_rtp_co_encodings, "RFC5225-6.8"},
    {"5225-ip-co-repair", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal IP-only co_repair packet", CidAll, ip_co_chains, non_rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-ip-pt-0-crc3", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal IP-only pt_0_crc3 packet", CidAll, ip_co_chains, EncodingCRC3 | EncodingWLSB, "RFC5225-6.8"},
    {"5225-ip-pt-0-crc7", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "100", "Formal IP-only pt_0_crc7 packet", CidAll, ip_co_chains, EncodingCRC7 | EncodingWLSB, "RFC5225-6.8"},
    {"5225-ip-pt-1-seq-id", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal IP-only pt_1_seq_id packet", CidAll, ip_co_chains, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.8"},
    {"5225-ip-pt-2-seq-id", Profile::IP, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal IP-only pt_2_seq_id packet", CidAll, ip_co_chains, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.8"},

    {"5225-rtp-udplite-co-current-fo", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::FO_RTP, "current-fo", "Current implemented RTP/UDP-Lite FO packet", CidAll, ChainUDPLiteDynamic | ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp | EncodingTimerTimestamp, "RFC5225-6.9"},
    {"5225-rtp-udplite-co-common", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal RTP/UDP-Lite co_common packet", CidAll, rtp_udplite_co_chains, rtp_co_encodings, "RFC5225-6.9"},
    {"5225-rtp-udplite-co-repair", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal RTP/UDP-Lite co_repair packet", CidAll, rtp_udplite_co_chains, rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-rtp-udplite-pt-0-crc3", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal RTP/UDP-Lite pt_0_crc3 packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-0-crc7", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "1000", "Formal RTP/UDP-Lite pt_0_crc7 packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-1-rnd", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal RTP/UDP-Lite pt_1_rnd packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-1-seq-id", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "1001", "Formal RTP/UDP-Lite pt_1_seq_id packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-1-seq-ts", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal RTP/UDP-Lite pt_1_seq_ts packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-2-rnd", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal RTP/UDP-Lite pt_2_rnd packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-2-seq-id", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11000", "Formal RTP/UDP-Lite pt_2_seq_id packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-2-seq-both", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11001", "Formal RTP/UDP-Lite pt_2_seq_both packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp | EncodingOffsetIpId, "RFC5225-6.9"},
    {"5225-rtp-udplite-pt-2-seq-ts", Profile::RTP_UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "1101", "Formal RTP/UDP-Lite pt_2_seq_ts packet", CidAll, ChainRTPDynamic, EncodingCRC7 | EncodingWLSB | EncodingScaledTimestamp, "RFC5225-6.9"},

    {"5225-udplite-co-current-fo", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::FO_UDP_Lite, "0x77", "Current implemented UDP-Lite/IP FO packet", CidAll, udplite_co_chains, EncodingCRC8 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},
    {"5225-udplite-co-common", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11111010", "Formal UDP-Lite/IP co_common packet", CidAll, udplite_co_chains, non_rtp_co_encodings, "RFC5225-6.9"},
    {"5225-udplite-co-repair", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "11111011", "Formal UDP-Lite/IP co_repair packet", CidAll, udplite_co_chains, non_rtp_co_encodings, "RFC5225-6.8.2.2"},
    {"5225-udplite-pt-0-crc3", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "0", "Formal UDP-Lite/IP pt_0_crc3 packet", CidAll, udplite_co_chains, EncodingCRC3 | EncodingWLSB, "RFC5225-6.9"},
    {"5225-udplite-pt-0-crc7", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "100", "Formal UDP-Lite/IP pt_0_crc7 packet", CidAll, udplite_co_chains, EncodingCRC7 | EncodingWLSB, "RFC5225-6.9"},
    {"5225-udplite-pt-1-seq-id", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "101", "Formal UDP-Lite/IP pt_1_seq_id packet", CidAll, udplite_co_chains, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},
    {"5225-udplite-pt-2-seq-id", Profile::UDP_Lite, CaseStatus::Implemented, RohcPacketType::Unknown, "110", "Formal UDP-Lite/IP pt_2_seq_id packet", CidAll, udplite_co_chains, EncodingCRC7 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},
}};

inline constexpr std::array<CaseRow, 36> case_manifest{{
    {"5225-rtp-ir-current", Profile::RTP, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "RTP IR static and dynamic chains", CidAll, ipv4_base_chains | udp_chains | rtp_chains, EncodingCRC8 | EncodingListCompression, "RFC5225-6.5"},
    {"5225-rtp-irdyn-current", Profile::RTP, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "RTP IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic | ChainUDPDynamic | ChainRTPDynamic, EncodingCRC8 | EncodingListCompression, "RFC5225-6.5"},
    {"5225-rtp-co-current", Profile::RTP, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_RTP, "Current RTP compressed/FO packet", CidAll, ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp | EncodingTimerTimestamp, "RFC5225-6.5"},

    {"5225-udp-ir-current", Profile::UDP, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "UDP IR static and dynamic chains", CidAll, ipv4_base_chains | udp_chains, EncodingCRC8 | EncodingListCompression, "RFC5225-6.6"},
    {"5225-udp-irdyn-current", Profile::UDP, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "UDP IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic | ChainUDPDynamic, EncodingCRC8 | EncodingListCompression, "RFC5225-6.6"},
    {"5225-udp-co-current", Profile::UDP, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_UDP, "Current UDP compressed/FO packet", CidAll, ChainIPv4Dynamic | ChainUDPDynamic, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.6"},

    {"5225-esp-ir-current", Profile::ESP, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "ESP/IP IR static and dynamic chains", CidAll, ipv4_base_chains | ChainESPFields, EncodingCRC8 | EncodingListCompression, "RFC5225-6.7"},
    {"5225-esp-irdyn-current", Profile::ESP, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "ESP/IP IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic | ChainESPFields, EncodingCRC8 | EncodingListCompression, "RFC5225-6.7"},
    {"5225-esp-co-current", Profile::ESP, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_ESP, "Current ESP/IP compressed/FO packet", CidAll, ChainIPv4Dynamic | ChainESPFields, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.7"},

    {"5225-ip-ir-current", Profile::IP, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "IP-only IR static and dynamic chains", CidAll, ipv4_base_chains, EncodingCRC8 | EncodingListCompression, "RFC5225-6.8"},
    {"5225-ip-irdyn-current", Profile::IP, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "IP-only IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic, EncodingCRC8 | EncodingListCompression, "RFC5225-6.8"},
    {"5225-ip-co-current", Profile::IP, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_IP, "Current IP-only compressed/FO packet", CidAll, ChainIPv4Dynamic, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.8"},

    {"5225-rtp-udplite-ir-current", Profile::RTP_UDP_Lite, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "RTP/UDP-Lite IR static and dynamic chains", CidAll, ipv4_base_chains | udplite_chains | rtp_chains, EncodingCRC8 | EncodingListCompression, "RFC5225-6.9"},
    {"5225-rtp-udplite-irdyn-current", Profile::RTP_UDP_Lite, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "RTP/UDP-Lite IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic | ChainUDPLiteDynamic | ChainRTPDynamic, EncodingCRC8 | EncodingListCompression, "RFC5225-6.9"},
    {"5225-rtp-udplite-co-current", Profile::RTP_UDP_Lite, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_RTP, "Current RTP/UDP-Lite compressed/FO packet", CidAll, ChainUDPLiteDynamic | ChainRTPDynamic, EncodingCRC3 | EncodingWLSB | EncodingScaledTimestamp | EncodingTimerTimestamp, "RFC5225-6.9"},

    {"5225-udplite-ir-current", Profile::UDP_Lite, PacketFamily::IR, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR, "UDP-Lite IR static and dynamic chains", CidAll, ipv4_base_chains | udplite_chains, EncodingCRC8 | EncodingListCompression, "RFC5225-6.9"},
    {"5225-udplite-irdyn-current", Profile::UDP_Lite, PacketFamily::IR_DYN, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::IR_DYN, "UDP-Lite IR-DYN dynamic chain", CidAll, ChainIPv4Dynamic | ChainUDPLiteDynamic, EncodingCRC8 | EncodingListCompression, "RFC5225-6.9"},
    {"5225-udplite-co-current", Profile::UDP_Lite, PacketFamily::CO, CaseKind::Positive, CaseStatus::Implemented, RohcPacketType::FO_UDP_Lite, "Current UDP-Lite compressed/FO packet", CidAll, ChainIPv4Dynamic | ChainUDPLiteDynamic, EncodingCRC3 | EncodingWLSB | EncodingOffsetIpId, "RFC5225-6.9"},

    {"5225-cid-small-boundaries", Profile::Uncompressed, PacketFamily::CID, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust CID 0 and maximum small-CID boundaries", CidSmall, ChainNone, EncodingNone, "RFC5225-5.1"},
    {"5225-cid-add-boundaries", Profile::Uncompressed, PacketFamily::CID, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust Add-CID prefixes and malformed Add-CID starts", CidAdd, ChainNone, EncodingNone, "RFC5225-5.1"},
    {"5225-cid-large-sdvl-boundaries", Profile::Uncompressed, PacketFamily::CID, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust large-CID SDVL boundaries, truncation, and non-minimal encodings", CidLarge, ChainNone, EncodingSDVL, "RFC5225-5.1"},
    {"5225-ipv4-options-list-compression", Profile::IP, PacketFamily::Chain, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate IPv4 option list insert/remove/reorder cases", CidAll, ChainIPv4Options, EncodingListCompression, "RFC5225-6.8"},
    {"5225-ipv6-extension-list-compression", Profile::IP, PacketFamily::Chain, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate IPv6 extension list insert/remove/reorder cases", CidAll, ChainIPv6Static | ChainIPv6Dynamic | ChainIPv6Extensions, EncodingListCompression, "RFC5225-6.8"},
    {"5225-rtp-csrc-list-compression", Profile::RTP, PacketFamily::Chain, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate RTP CSRC list update cases", CidAll, ChainRTPCsrcList, EncodingListCompression, "RFC5225-6.5"},
    {"5225-rtp-extension-header", Profile::RTP, PacketFamily::Chain, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate RTP extension header preservation and malformed-length cases", CidAll, ChainRTPExtension, EncodingListCompression, "RFC5225-6.5"},
    {"5225-rtp-padding", Profile::RTP, PacketFamily::Chain, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate RTP padding present/absent and malformed padding cases", CidAll, ChainRTPPadding, EncodingNone, "RFC5225-6.5"},
    {"5225-wlsb-exhaustive", Profile::Uncompressed, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust W-LSB p-values, intervals, wraparound, loss, and reordering", CidAll, ChainNone, EncodingWLSB, "RFC5225-4"},
    {"5225-scaled-timestamp-exhaustive", Profile::RTP, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust scaled RTP timestamp stride and residue behavior", CidAll, ChainRTPDynamic, EncodingScaledTimestamp, "RFC5225-6.5"},
    {"5225-timer-timestamp-exhaustive", Profile::RTP, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust timer-based RTP timestamp reconstruction", CidAll, ChainRTPDynamic, EncodingTimerTimestamp, "RFC5225-6.5"},
    {"5225-ipid-exhaustive", Profile::IP, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust sequential, swapped, random, zero, offset, and wraparound IP-ID behavior", CidAll, all_ip_chains, EncodingOffsetIpId | EncodingWLSB, "RFC5225-6.8"},
    {"5225-sdvl-field-exhaustive", Profile::Uncompressed, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust SDVL users beyond CID where packet grammar requires them", CidAll, ChainNone, EncodingSDVL, "RFC5225-4"},
    {"5225-generic-list-compression-exhaustive", Profile::Uncompressed, PacketFamily::Encoding, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Unknown, "Exhaust empty/static/dynamic generic list compression state", CidAll, all_list_chains, EncodingListCompression, "RFC5225-4"},
    {"5225-malformed-packet-starts", Profile::Uncompressed, PacketFamily::Negative, CaseKind::Negative, CaseStatus::Implemented, RohcPacketType::Unknown, "Generate reserved, unknown, truncated, and impossible packet-start cases for implemented packet families", CidAll, ChainNone, all_required_encodings, "RFC5225-5"},
    {"5225-crc-mutation-cross-product", Profile::Uncompressed, PacketFamily::Negative, CaseKind::Negative, CaseStatus::Implemented, RohcPacketType::Unknown, "Mutate CRC bytes and protected payload bytes for every implemented generated packet case", CidAll, ChainNone, EncodingCRC3 | EncodingCRC7 | EncodingCRC8, "RFC5225-5"},
    {"5225-mode-feedback-cross-product", Profile::Uncompressed, PacketFamily::Feedback, CaseKind::Requirement, CaseStatus::Implemented, RohcPacketType::Feedback, "Generate U/O/R mode and feedback state transitions across packet families", CidAll, ChainNone, EncodingNone, "RFC5225-5"},
    {"5225-external-oracle-v2", Profile::Uncompressed, PacketFamily::Oracle, CaseKind::Oracle, CaseStatus::OpenOracle, RohcPacketType::Unknown, "Attach independent oracle corpus v2 for every generated grammar case", CidAll, ChainNone, all_required_encodings, "RFC5225-appendix"},
}};

inline constexpr std::size_t profile_count()
{
    return profile_manifest.size();
}

inline constexpr std::size_t case_count()
{
    return case_manifest.size();
}

inline constexpr std::size_t co_variant_count()
{
    return co_variant_manifest.size();
}

inline std::size_t count_co_variants(CaseStatus status)
{
    std::size_t count = 0;
    for(const auto& row : co_variant_manifest)
    {
        if(row.status == status)
            ++count;
    }
    return count;
}

inline std::size_t count_co_variants(Profile profile)
{
    std::size_t count = 0;
    for(const auto& row : co_variant_manifest)
    {
        if(row.profile == profile)
            ++count;
    }
    return count;
}

inline const CoVariantRow* find_co_variant(const char* id)
{
    if(!id)
        return nullptr;
    for(const auto& row : co_variant_manifest)
    {
        if(std::strcmp(row.id, id) == 0)
            return &row;
    }
    return nullptr;
}

inline bool has_co_variant(Profile profile, const char* id, CaseStatus status)
{
    const auto* row = find_co_variant(id);
    return row && row->profile == profile && row->status == status;
}

inline const char* to_string(PacketFamily family)
{
    switch(family)
    {
    case PacketFamily::IR: return "ir";
    case PacketFamily::IR_DYN: return "ir_dyn";
    case PacketFamily::CO: return "co";
    case PacketFamily::Feedback: return "feedback";
    case PacketFamily::CID: return "cid";
    case PacketFamily::Chain: return "chain";
    case PacketFamily::Encoding: return "encoding";
    case PacketFamily::Negative: return "negative";
    case PacketFamily::Oracle: return "oracle";
    case PacketFamily::Traceability: return "traceability";
    }
    return "unknown";
}

inline const char* to_string(CaseKind kind)
{
    switch(kind)
    {
    case CaseKind::Positive: return "positive";
    case CaseKind::Negative: return "negative";
    case CaseKind::Requirement: return "requirement";
    case CaseKind::Oracle: return "oracle";
    }
    return "unknown";
}

inline const char* to_string(CaseStatus status)
{
    switch(status)
    {
    case CaseStatus::Implemented: return "implemented";
    case CaseStatus::Planned: return "planned";
    case CaseStatus::OpenOracle: return "open_oracle";
    }
    return "unknown";
}

inline const ProfileRow* find_profile(Profile profile)
{
    for(const auto& row : profile_manifest)
    {
        if(row.profile == profile)
            return &row;
    }
    return nullptr;
}

inline const CaseRow* find_case(const char* id)
{
    if(!id)
        return nullptr;
    for(const auto& row : case_manifest)
    {
        if(std::strcmp(row.id, id) == 0)
            return &row;
    }
    return nullptr;
}

inline bool has_case(Profile profile, PacketFamily family, CaseStatus status)
{
    for(const auto& row : case_manifest)
    {
        if(row.profile == profile && row.family == family && row.status == status)
            return true;
    }
    return false;
}

inline std::uint32_t manifest_encoding_mask()
{
    std::uint32_t mask = EncodingNone;
    for(const auto& row : case_manifest)
        mask |= row.encodings;
    return mask;
}

inline std::uint32_t manifest_chain_mask()
{
    std::uint32_t mask = ChainNone;
    for(const auto& row : case_manifest)
        mask |= row.chains;
    return mask;
}

inline std::uint32_t manifest_cid_mode_mask()
{
    std::uint32_t mask = CidNone;
    for(const auto& row : case_manifest)
        mask |= row.cid_modes;
    return mask;
}

inline std::size_t count_cases(CaseStatus status)
{
    std::size_t count = 0;
    for(const auto& row : case_manifest)
    {
        if(row.status == status)
            ++count;
    }
    return count;
}

} // namespace rohccxx::rfc5225::grammar
