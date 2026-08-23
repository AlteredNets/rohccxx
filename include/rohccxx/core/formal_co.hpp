// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "rohccxx/core/bit_reader.hpp"
#include "rohccxx/core/bit_writer.hpp"
#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/context.hpp"
#include "rohccxx/utils/crc.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace rohccxx::rfc5225
{

enum class FormalCoVariant : std::uint8_t
{
    Pt0Crc3,
    Pt0Crc7,
    Pt1Rnd,
    Pt1SeqId,
    Pt1SeqTs,
    Pt2Rnd,
    Pt2SeqId,
    Pt2SeqBoth,
    Pt2SeqTs,
    CoCommon,
    CoRepair,
};

struct FormalCoCrcInput
{
    const std::uint8_t* data = nullptr;
    size_t len = 0;
};

struct FormalCoBytes
{
    const std::uint8_t* data = nullptr;
    size_t len = 0;
};

struct FormalCoFields
{
    std::uint16_t msn = 0;
    std::uint16_t ip_id = 0;
    std::uint16_t ts_scaled = 0;
    bool marker = false;
};

struct FormalCoCommonFields
{
    bool marker = false;
    bool flags1_indicator = false;
    bool flags2_indicator = false;
    bool tsc_indicator = false;
    bool tss_indicator = false;
    bool ip_id_indicator = false;
    bool flags_indicator = false;
    bool ttl_hopl_indicator = false;
    bool tos_tc_indicator = false;
    std::uint8_t reorder_ratio = 0;
    FormalCoBytes variable{};
};

struct FormalCoRepairFields
{
    FormalCoBytes dynamic_chain{};
};

struct FormalCoPacket
{
    Profile profile = Profile::Uncompressed;
    FormalCoVariant variant = FormalCoVariant::Pt0Crc3;
    std::uint32_t cid = 0;
    bool large_cid = false;
    size_t cid_len = 0;
    std::uint16_t msn = 0;
    std::uint16_t ip_id = 0;
    std::uint16_t ts_scaled = 0;
    bool marker = false;
    std::uint8_t header_crc = 0;
    std::uint8_t control_crc3 = 0;
    bool flags1_indicator = false;
    bool flags2_indicator = false;
    bool tsc_indicator = false;
    bool tss_indicator = false;
    bool ip_id_indicator = false;
    bool flags_indicator = false;
    bool ttl_hopl_indicator = false;
    bool tos_tc_indicator = false;
    std::uint8_t reorder_ratio = 0;
    size_t variable_offset = 0;
    size_t variable_len = 0;
};

inline bool is_rtp_formal_co_profile(Profile profile)
{
    return profile == Profile::RTP || profile == Profile::RTP_UDP_Lite;
}

inline bool is_supported_formal_co_profile(Profile profile)
{
    switch(profile)
    {
    case Profile::RTP:
    case Profile::UDP:
    case Profile::ESP:
    case Profile::IP:
    case Profile::RTP_UDP_Lite:
    case Profile::UDP_Lite:
        return true;
    case Profile::Uncompressed:
    case Profile::LLA_RTP:
        return false;
    }
    return false;
}

inline bool live_pt0_context_supported(const Context& ctx,
                                       bool large_cid_space,
                                       std::uint32_t cid_value,
                                       bool has_add_cid)
{
    return ctx.rohc_state == RohcState::DynamicEstablished &&
           ctx.ip_version == 4 && ctx.ipv4_id_behavior == 0U &&
           !large_cid_space && !ctx.large_cid && cid_value == 0U && !has_add_cid &&
           (ctx.profile == Profile::UDP || ctx.profile == Profile::ESP ||
            ctx.profile == Profile::IP);
}

inline bool formal_co_variant_valid_for_profile(Profile profile, FormalCoVariant variant)
{
    if(!is_supported_formal_co_profile(profile))
        return false;
    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1SeqId:
    case FormalCoVariant::Pt2SeqId:
        return true;
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqBoth:
    case FormalCoVariant::Pt2SeqTs:
        return is_rtp_formal_co_profile(profile);
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return true;
    }
    return false;
}

inline bool formal_co_variant_uses_crc3(FormalCoVariant variant)
{
    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqId:
    case FormalCoVariant::Pt1SeqTs:
        return true;
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqId:
    case FormalCoVariant::Pt2SeqBoth:
    case FormalCoVariant::Pt2SeqTs:
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return false;
    }
    return false;
}

inline std::uint8_t formal_co_msn_lsb_bits(Profile profile, FormalCoVariant variant)
{
    if(!formal_co_variant_valid_for_profile(profile, variant))
        return 0;
    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
        return 4;
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1SeqId:
        return is_rtp_formal_co_profile(profile) ? 5 : 6;
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqBoth:
    case FormalCoVariant::Pt2SeqTs:
        return 7;
    case FormalCoVariant::Pt2SeqId:
        return is_rtp_formal_co_profile(profile) ? 7 : 8;
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return 0;
    }
    return 0;
}

inline std::uint8_t formal_co_ip_id_lsb_bits(Profile profile, FormalCoVariant variant)
{
    if(!formal_co_variant_valid_for_profile(profile, variant))
        return 0;
    switch(variant)
    {
    case FormalCoVariant::Pt1SeqId:
        return 4;
    case FormalCoVariant::Pt2SeqId:
        return is_rtp_formal_co_profile(profile) ? 5 : 6;
    case FormalCoVariant::Pt2SeqBoth:
        return 5;
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqTs:
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return 0;
    }
    return 0;
}

inline std::uint8_t formal_co_ts_scaled_lsb_bits(Profile profile, FormalCoVariant variant)
{
    if(!formal_co_variant_valid_for_profile(profile, variant))
        return 0;
    switch(variant)
    {
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
    case FormalCoVariant::Pt2SeqTs:
        return 5;
    case FormalCoVariant::Pt2Rnd:
        return 6;
    case FormalCoVariant::Pt2SeqBoth:
        return 7;
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1SeqId:
    case FormalCoVariant::Pt2SeqId:
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return 0;
    }
    return 0;
}

inline bool formal_co_variant_has_marker(FormalCoVariant variant)
{
    switch(variant)
    {
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqBoth:
    case FormalCoVariant::Pt2SeqTs:
        return true;
    case FormalCoVariant::Pt0Crc3:
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1SeqId:
    case FormalCoVariant::Pt2SeqId:
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return false;
    }
    return false;
}

inline size_t formal_co_base_len(Profile profile, FormalCoVariant variant)
{
    if(!formal_co_variant_valid_for_profile(profile, variant))
        return 0;
    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
        return 1U;
    case FormalCoVariant::Pt0Crc7:
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqId:
    case FormalCoVariant::Pt1SeqTs:
        return 2U;
    case FormalCoVariant::Pt2Rnd:
    case FormalCoVariant::Pt2SeqId:
    case FormalCoVariant::Pt2SeqTs:
        return 3U;
    case FormalCoVariant::Pt2SeqBoth:
        return 4U;
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return 0U;
    }
    return 0;
}

inline size_t formal_co_pt0_base_len(FormalCoVariant variant)
{
    return variant == FormalCoVariant::Pt0Crc3 ? 1U : 2U;
}

inline bool formal_co_crc_input_valid(FormalCoCrcInput crc_input)
{
    return crc_input.len == 0 || crc_input.data != nullptr;
}

inline bool formal_co_bytes_valid(FormalCoBytes bytes)
{
    return bytes.len == 0 || bytes.data != nullptr;
}

inline std::uint8_t formal_co_header_crc(FormalCoVariant variant, FormalCoCrcInput crc_input)
{
    return formal_co_variant_uses_crc3(variant)
        ? utils::crc3(crc_input.data, crc_input.len)
        : static_cast<std::uint8_t>(utils::crc7(crc_input.data, crc_input.len) & 0x7FU);
}

inline std::uint8_t formal_co_control_crc(FormalCoCrcInput control_crc_input)
{
    return static_cast<std::uint8_t>(utils::crc3(control_crc_input.data, control_crc_input.len) & 0x07U);
}

inline bool write_formal_co_base(std::uint8_t* base,
                                 size_t base_len,
                                 Profile profile,
                                 FormalCoVariant variant,
                                 FormalCoFields fields,
                                 std::uint8_t crc)
{
    if(!base || base_len == 0 || base_len > 4U ||
       !formal_co_variant_valid_for_profile(profile, variant))
    {
        return false;
    }

    std::memset(base, 0, base_len);
    BitWriter writer(base);
    const bool rtp = is_rtp_formal_co_profile(profile);

    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
        writer.write_bits(0, 1);
        writer.write_bits(fields.msn & 0x0FU, 4);
        writer.write_bits(crc & 0x07U, 3);
        break;
    case FormalCoVariant::Pt0Crc7:
        if(rtp)
        {
            writer.write_bits(0x08U, 4);
            writer.write_bits(fields.msn & 0x1FU, 5);
        }
        else
        {
            writer.write_bits(0x04U, 3);
            writer.write_bits(fields.msn & 0x3FU, 6);
        }
        writer.write_bits(crc & 0x7FU, 7);
        break;
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
        if(!rtp)
            return false;
        writer.write_bits(0x05U, 3);
        writer.write_bits(fields.marker ? 1U : 0U, 1);
        writer.write_bits(fields.msn & 0x0FU, 4);
        writer.write_bits(fields.ts_scaled & 0x1FU, 5);
        writer.write_bits(crc & 0x07U, 3);
        break;
    case FormalCoVariant::Pt1SeqId:
        if(rtp)
        {
            writer.write_bits(0x09U, 4);
            writer.write_bits(fields.ip_id & 0x0FU, 4);
            writer.write_bits(fields.msn & 0x1FU, 5);
            writer.write_bits(crc & 0x07U, 3);
        }
        else
        {
            writer.write_bits(0x05U, 3);
            writer.write_bits(crc & 0x07U, 3);
            writer.write_bits(fields.msn & 0x3FU, 6);
            writer.write_bits(fields.ip_id & 0x0FU, 4);
        }
        break;
    case FormalCoVariant::Pt2Rnd:
        if(!rtp)
            return false;
        writer.write_bits(0x06U, 3);
        writer.write_bits(fields.msn & 0x7FU, 7);
        writer.write_bits(fields.ts_scaled & 0x3FU, 6);
        writer.write_bits(fields.marker ? 1U : 0U, 1);
        writer.write_bits(crc & 0x7FU, 7);
        break;
    case FormalCoVariant::Pt2SeqId:
        if(rtp)
        {
            writer.write_bits(0x18U, 5);
            writer.write_bits(fields.msn & 0x7FU, 7);
            writer.write_bits(fields.ip_id & 0x1FU, 5);
            writer.write_bits(crc & 0x7FU, 7);
        }
        else
        {
            writer.write_bits(0x06U, 3);
            writer.write_bits(fields.ip_id & 0x3FU, 6);
            writer.write_bits(crc & 0x7FU, 7);
            writer.write_bits(fields.msn & 0xFFU, 8);
        }
        break;
    case FormalCoVariant::Pt2SeqBoth:
        if(!rtp)
            return false;
        writer.write_bits(0x19U, 5);
        writer.write_bits(fields.msn & 0x7FU, 7);
        writer.write_bits(fields.ip_id & 0x1FU, 5);
        writer.write_bits(crc & 0x7FU, 7);
        writer.write_bits(fields.ts_scaled & 0x7FU, 7);
        writer.write_bits(fields.marker ? 1U : 0U, 1);
        break;
    case FormalCoVariant::Pt2SeqTs:
        if(!rtp)
            return false;
        writer.write_bits(0x0DU, 4);
        writer.write_bits(fields.msn & 0x7FU, 7);
        writer.write_bits(fields.ts_scaled & 0x1FU, 5);
        writer.write_bits(fields.marker ? 1U : 0U, 1);
        writer.write_bits(crc & 0x7FU, 7);
        break;
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return false;
    }
    return writer.bytes_written() == base_len;
}

inline bool read_formal_co_base(const std::uint8_t* base,
                                size_t base_len,
                                Profile profile,
                                FormalCoVariant variant,
                                FormalCoPacket& packet)
{
    if(!base || base_len == 0 || !formal_co_variant_valid_for_profile(profile, variant))
        return false;

    BitReader reader(base);
    const bool rtp = is_rtp_formal_co_profile(profile);
    packet.variant = variant;
    packet.msn = 0;
    packet.ip_id = 0;
    packet.ts_scaled = 0;
    packet.marker = false;

    switch(variant)
    {
    case FormalCoVariant::Pt0Crc3:
        if(reader.read_bits(1) != 0)
            return false;
        packet.msn = static_cast<std::uint16_t>(reader.read_bits(4));
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(3));
        break;
    case FormalCoVariant::Pt0Crc7:
        if(rtp)
        {
            if(reader.read_bits(4) != 0x08U)
                return false;
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(5));
        }
        else
        {
            if(reader.read_bits(3) != 0x04U)
                return false;
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(6));
        }
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
        break;
    case FormalCoVariant::Pt1Rnd:
    case FormalCoVariant::Pt1SeqTs:
        if(!rtp || reader.read_bits(3) != 0x05U)
            return false;
        packet.marker = reader.read_bits(1) != 0;
        packet.msn = static_cast<std::uint16_t>(reader.read_bits(4));
        packet.ts_scaled = static_cast<std::uint16_t>(reader.read_bits(5));
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(3));
        break;
    case FormalCoVariant::Pt1SeqId:
        if(rtp)
        {
            if(reader.read_bits(4) != 0x09U)
                return false;
            packet.ip_id = static_cast<std::uint16_t>(reader.read_bits(4));
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(5));
            packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(3));
        }
        else
        {
            if(reader.read_bits(3) != 0x05U)
                return false;
            packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(3));
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(6));
            packet.ip_id = static_cast<std::uint16_t>(reader.read_bits(4));
        }
        break;
    case FormalCoVariant::Pt2Rnd:
        if(!rtp || reader.read_bits(3) != 0x06U)
            return false;
        packet.msn = static_cast<std::uint16_t>(reader.read_bits(7));
        packet.ts_scaled = static_cast<std::uint16_t>(reader.read_bits(6));
        packet.marker = reader.read_bits(1) != 0;
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
        break;
    case FormalCoVariant::Pt2SeqId:
        if(rtp)
        {
            if(reader.read_bits(5) != 0x18U)
                return false;
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(7));
            packet.ip_id = static_cast<std::uint16_t>(reader.read_bits(5));
            packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
        }
        else
        {
            if(reader.read_bits(3) != 0x06U)
                return false;
            packet.ip_id = static_cast<std::uint16_t>(reader.read_bits(6));
            packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
            packet.msn = static_cast<std::uint16_t>(reader.read_bits(8));
        }
        break;
    case FormalCoVariant::Pt2SeqBoth:
        if(!rtp || reader.read_bits(5) != 0x19U)
            return false;
        packet.msn = static_cast<std::uint16_t>(reader.read_bits(7));
        packet.ip_id = static_cast<std::uint16_t>(reader.read_bits(5));
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
        packet.ts_scaled = static_cast<std::uint16_t>(reader.read_bits(7));
        packet.marker = reader.read_bits(1) != 0;
        break;
    case FormalCoVariant::Pt2SeqTs:
        if(!rtp || reader.read_bits(4) != 0x0DU)
            return false;
        packet.msn = static_cast<std::uint16_t>(reader.read_bits(7));
        packet.ts_scaled = static_cast<std::uint16_t>(reader.read_bits(5));
        packet.marker = reader.read_bits(1) != 0;
        packet.header_crc = static_cast<std::uint8_t>(reader.read_bits(7));
        break;
    case FormalCoVariant::CoCommon:
    case FormalCoVariant::CoRepair:
        return false;
    }
    return ((reader.bitpos + 7U) >> 3U) == base_len;
}

inline bool emit_formal_co(std::uint8_t* out,
                           size_t* out_len,
                           Profile profile,
                           FormalCoVariant variant,
                           std::uint32_t cid_value,
                           bool large_cid_space,
                           FormalCoFields fields,
                           FormalCoCrcInput crc_input)
{
    if(!out || !out_len || !formal_co_variant_valid_for_profile(profile, variant) ||
       !cid::is_valid_for_space(cid_value, large_cid_space) ||
       !formal_co_crc_input_valid(crc_input))
    {
        return false;
    }

    const size_t base_len = formal_co_base_len(profile, variant);
    if(base_len == 0 || base_len > 4U)
        return false;
    std::uint8_t base[4] = {};
    const std::uint8_t crc = formal_co_header_crc(variant, crc_input);
    if(!write_formal_co_base(base, base_len, profile, variant, fields, crc))
        return false;

    const bool add_cid = !large_cid_space && cid_value > 0;
    const size_t cid_len = large_cid_space ? cid::encoded_len(cid_value) : 0U;
    const size_t required_len = (add_cid ? 1U : 0U) + 1U + cid_len + (base_len - 1U);
    const size_t capacity = *out_len;
    if(capacity < required_len)
        return false;

    std::memset(out, 0, capacity);
    size_t pos = 0;
    if(add_cid)
        out[pos++] = static_cast<std::uint8_t>(0xE0U | (cid_value & 0x0FU));

    out[pos++] = base[0];
    if(large_cid_space)
    {
        std::uint8_t* cid_pos = out + pos;
        if(!cid::write_large(cid_pos, out + capacity, cid_value))
            return false;
        pos = static_cast<size_t>(cid_pos - out);
    }

    if(base_len > 1U)
    {
        std::memcpy(out + pos, base + 1U, base_len - 1U);
        pos += base_len - 1U;
    }

    *out_len = pos;
    return true;
}

inline bool decode_formal_co(const std::uint8_t* in,
                             size_t len,
                             Profile profile,
                             FormalCoVariant variant,
                             bool large_cid_space,
                             FormalCoCrcInput crc_input,
                             FormalCoPacket& packet,
                             size_t* consumed = nullptr)
{
    packet = {};
    if(!in || len == 0 || !formal_co_variant_valid_for_profile(profile, variant) ||
       !formal_co_crc_input_valid(crc_input))
    {
        return false;
    }

    const size_t base_len = formal_co_base_len(profile, variant);
    if(base_len == 0 || base_len > 4U)
        return false;

    size_t pos = 0;
    std::uint32_t decoded_cid = 0;
    if(!large_cid_space && (in[0] & 0xF0U) == 0xE0U)
    {
        decoded_cid = static_cast<std::uint32_t>(in[0] & 0x0FU);
        if(decoded_cid == 0 || len < 2U)
            return false;
        ++pos;
    }

    if(pos >= len)
        return false;
    std::uint8_t base[4] = {};
    base[0] = in[pos++];

    size_t decoded_cid_len = 0;
    if(large_cid_space)
    {
        if(!cid::read_large(in + pos, len - pos, decoded_cid, decoded_cid_len))
            return false;
        pos += decoded_cid_len;
    }

    if(len - pos < base_len - 1U)
        return false;
    if(base_len > 1U)
    {
        std::memcpy(base + 1U, in + pos, base_len - 1U);
        pos += base_len - 1U;
    }

    packet.profile = profile;
    packet.cid = decoded_cid;
    packet.large_cid = large_cid_space;
    packet.cid_len = decoded_cid_len;
    if(!read_formal_co_base(base, base_len, profile, variant, packet))
        return false;
    if(packet.header_crc != formal_co_header_crc(packet.variant, crc_input))
        return false;
    if(consumed)
        *consumed = pos;
    return consumed || pos == len;
}

inline bool emit_formal_co_common(std::uint8_t* out,
                                  size_t* out_len,
                                  Profile profile,
                                  std::uint32_t cid_value,
                                  bool large_cid_space,
                                  FormalCoCommonFields fields,
                                  FormalCoCrcInput header_crc_input,
                                  FormalCoCrcInput control_crc_input)
{
    if(!out || !out_len || !formal_co_variant_valid_for_profile(profile, FormalCoVariant::CoCommon) ||
       !cid::is_valid_for_space(cid_value, large_cid_space) ||
       !formal_co_crc_input_valid(header_crc_input) ||
       !formal_co_crc_input_valid(control_crc_input) ||
       !formal_co_bytes_valid(fields.variable) ||
       fields.reorder_ratio > 3U)
    {
        return false;
    }

    const bool add_cid = !large_cid_space && cid_value > 0;
    const size_t cid_len = large_cid_space ? cid::encoded_len(cid_value) : 0U;
    const size_t required_len = (add_cid ? 1U : 0U) + 1U + cid_len + 2U + fields.variable.len;
    const size_t capacity = *out_len;
    if(capacity < required_len)
        return false;

    std::memset(out, 0, capacity);
    size_t pos = 0;
    if(add_cid)
        out[pos++] = static_cast<std::uint8_t>(0xE0U | (cid_value & 0x0FU));

    out[pos++] = 0xFAU;
    if(large_cid_space)
    {
        std::uint8_t* cid_pos = out + pos;
        if(!cid::write_large(cid_pos, out + capacity, cid_value))
            return false;
        pos = static_cast<size_t>(cid_pos - out);
    }

    const std::uint8_t header_crc = formal_co_header_crc(FormalCoVariant::CoCommon, header_crc_input);
    const std::uint8_t control_crc = formal_co_control_crc(control_crc_input);
    if(is_rtp_formal_co_profile(profile))
    {
        out[pos++] = static_cast<std::uint8_t>((fields.marker ? 0x80U : 0U) | (header_crc & 0x7FU));
        out[pos++] = static_cast<std::uint8_t>(
            (fields.flags1_indicator ? 0x80U : 0U) |
            (fields.flags2_indicator ? 0x40U : 0U) |
            (fields.tsc_indicator ? 0x20U : 0U) |
            (fields.tss_indicator ? 0x10U : 0U) |
            (fields.ip_id_indicator ? 0x08U : 0U) |
            (control_crc & 0x07U));
    }
    else
    {
        out[pos++] = static_cast<std::uint8_t>((fields.ip_id_indicator ? 0x80U : 0U) | (header_crc & 0x7FU));
        out[pos++] = static_cast<std::uint8_t>(
            (fields.flags_indicator ? 0x80U : 0U) |
            (fields.ttl_hopl_indicator ? 0x40U : 0U) |
            (fields.tos_tc_indicator ? 0x20U : 0U) |
            ((fields.reorder_ratio & 0x03U) << 3U) |
            (control_crc & 0x07U));
    }

    if(fields.variable.len > 0)
    {
        std::memcpy(out + pos, fields.variable.data, fields.variable.len);
        pos += fields.variable.len;
    }

    *out_len = pos;
    return true;
}

inline bool decode_formal_co_common(const std::uint8_t* in,
                                    size_t len,
                                    Profile profile,
                                    bool large_cid_space,
                                    FormalCoCrcInput header_crc_input,
                                    FormalCoCrcInput control_crc_input,
                                    FormalCoPacket& packet,
                                    size_t* consumed = nullptr)
{
    packet = {};
    if(!in || len == 0 || !formal_co_variant_valid_for_profile(profile, FormalCoVariant::CoCommon) ||
       !formal_co_crc_input_valid(header_crc_input) ||
       !formal_co_crc_input_valid(control_crc_input))
    {
        return false;
    }

    size_t pos = 0;
    std::uint32_t decoded_cid = 0;
    if(!large_cid_space && (in[0] & 0xF0U) == 0xE0U)
    {
        decoded_cid = static_cast<std::uint32_t>(in[0] & 0x0FU);
        if(decoded_cid == 0 || len < 2U)
            return false;
        ++pos;
    }

    if(pos >= len || in[pos++] != 0xFAU)
        return false;

    size_t decoded_cid_len = 0;
    if(large_cid_space)
    {
        if(!cid::read_large(in + pos, len - pos, decoded_cid, decoded_cid_len))
            return false;
        pos += decoded_cid_len;
    }

    if(len - pos < 2U)
        return false;
    const std::uint8_t crc_octet = in[pos++];
    const std::uint8_t control_octet = in[pos++];

    packet.profile = profile;
    packet.variant = FormalCoVariant::CoCommon;
    packet.cid = decoded_cid;
    packet.large_cid = large_cid_space;
    packet.cid_len = decoded_cid_len;
    packet.header_crc = static_cast<std::uint8_t>(crc_octet & 0x7FU);
    packet.control_crc3 = static_cast<std::uint8_t>(control_octet & 0x07U);

    if(is_rtp_formal_co_profile(profile))
    {
        packet.marker = (crc_octet & 0x80U) != 0;
        packet.flags1_indicator = (control_octet & 0x80U) != 0;
        packet.flags2_indicator = (control_octet & 0x40U) != 0;
        packet.tsc_indicator = (control_octet & 0x20U) != 0;
        packet.tss_indicator = (control_octet & 0x10U) != 0;
        packet.ip_id_indicator = (control_octet & 0x08U) != 0;
    }
    else
    {
        packet.ip_id_indicator = (crc_octet & 0x80U) != 0;
        packet.flags_indicator = (control_octet & 0x80U) != 0;
        packet.ttl_hopl_indicator = (control_octet & 0x40U) != 0;
        packet.tos_tc_indicator = (control_octet & 0x20U) != 0;
        packet.reorder_ratio = static_cast<std::uint8_t>((control_octet >> 3U) & 0x03U);
    }

    if(packet.header_crc != formal_co_header_crc(FormalCoVariant::CoCommon, header_crc_input))
        return false;
    if(packet.control_crc3 != formal_co_control_crc(control_crc_input))
        return false;

    packet.variable_offset = pos;
    packet.variable_len = len - pos;
    if(consumed)
        *consumed = len;
    return true;
}

inline bool emit_formal_co_repair(std::uint8_t* out,
                                  size_t* out_len,
                                  Profile profile,
                                  std::uint32_t cid_value,
                                  bool large_cid_space,
                                  FormalCoRepairFields fields,
                                  FormalCoCrcInput header_crc_input,
                                  FormalCoCrcInput control_crc_input)
{
    if(!out || !out_len || !formal_co_variant_valid_for_profile(profile, FormalCoVariant::CoRepair) ||
       !cid::is_valid_for_space(cid_value, large_cid_space) ||
       !formal_co_crc_input_valid(header_crc_input) ||
       !formal_co_crc_input_valid(control_crc_input) ||
       !formal_co_bytes_valid(fields.dynamic_chain))
    {
        return false;
    }

    const bool add_cid = !large_cid_space && cid_value > 0;
    const size_t cid_len = large_cid_space ? cid::encoded_len(cid_value) : 0U;
    const size_t required_len = (add_cid ? 1U : 0U) + 1U + cid_len + 2U + fields.dynamic_chain.len;
    const size_t capacity = *out_len;
    if(capacity < required_len)
        return false;

    std::memset(out, 0, capacity);
    size_t pos = 0;
    if(add_cid)
        out[pos++] = static_cast<std::uint8_t>(0xE0U | (cid_value & 0x0FU));

    out[pos++] = 0xFBU;
    if(large_cid_space)
    {
        std::uint8_t* cid_pos = out + pos;
        if(!cid::write_large(cid_pos, out + capacity, cid_value))
            return false;
        pos = static_cast<size_t>(cid_pos - out);
    }

    out[pos++] = formal_co_header_crc(FormalCoVariant::CoRepair, header_crc_input);
    out[pos++] = formal_co_control_crc(control_crc_input);
    if(fields.dynamic_chain.len > 0)
    {
        std::memcpy(out + pos, fields.dynamic_chain.data, fields.dynamic_chain.len);
        pos += fields.dynamic_chain.len;
    }

    *out_len = pos;
    return true;
}

inline bool decode_formal_co_repair(const std::uint8_t* in,
                                    size_t len,
                                    Profile profile,
                                    bool large_cid_space,
                                    FormalCoCrcInput header_crc_input,
                                    FormalCoCrcInput control_crc_input,
                                    FormalCoPacket& packet,
                                    size_t* consumed = nullptr)
{
    packet = {};
    if(!in || len == 0 || !formal_co_variant_valid_for_profile(profile, FormalCoVariant::CoRepair) ||
       !formal_co_crc_input_valid(header_crc_input) ||
       !formal_co_crc_input_valid(control_crc_input))
    {
        return false;
    }

    size_t pos = 0;
    std::uint32_t decoded_cid = 0;
    if(!large_cid_space && (in[0] & 0xF0U) == 0xE0U)
    {
        decoded_cid = static_cast<std::uint32_t>(in[0] & 0x0FU);
        if(decoded_cid == 0 || len < 2U)
            return false;
        ++pos;
    }

    if(pos >= len || in[pos++] != 0xFBU)
        return false;

    size_t decoded_cid_len = 0;
    if(large_cid_space)
    {
        if(!cid::read_large(in + pos, len - pos, decoded_cid, decoded_cid_len))
            return false;
        pos += decoded_cid_len;
    }

    if(len - pos < 2U)
        return false;
    const std::uint8_t crc_octet = in[pos++];
    const std::uint8_t control_octet = in[pos++];
    if((crc_octet & 0x80U) != 0 || (control_octet & 0xF8U) != 0)
        return false;

    packet.profile = profile;
    packet.variant = FormalCoVariant::CoRepair;
    packet.cid = decoded_cid;
    packet.large_cid = large_cid_space;
    packet.cid_len = decoded_cid_len;
    packet.header_crc = static_cast<std::uint8_t>(crc_octet & 0x7FU);
    packet.control_crc3 = static_cast<std::uint8_t>(control_octet & 0x07U);
    if(packet.header_crc != formal_co_header_crc(FormalCoVariant::CoRepair, header_crc_input))
        return false;
    if(packet.control_crc3 != formal_co_control_crc(control_crc_input))
        return false;

    packet.variable_offset = pos;
    packet.variable_len = len - pos;
    if(consumed)
        *consumed = len;
    return true;
}

inline bool emit_formal_co_pt0(std::uint8_t* out,
                               size_t* out_len,
                               Profile profile,
                               FormalCoVariant variant,
                               std::uint32_t cid_value,
                               bool large_cid_space,
                               std::uint16_t msn,
                               FormalCoCrcInput crc_input)
{
    if(!out || !out_len || !is_supported_formal_co_profile(profile) ||
       !cid::is_valid_for_space(cid_value, large_cid_space) ||
       !formal_co_crc_input_valid(crc_input))
    {
        return false;
    }

    const bool add_cid = !large_cid_space && cid_value > 0;
    const size_t cid_len = large_cid_space ? cid::encoded_len(cid_value) : 0U;
    const size_t required_len = (add_cid ? 1U : 0U) + 1U + cid_len + (formal_co_pt0_base_len(variant) - 1U);
    if(*out_len < required_len)
        return false;

    std::memset(out, 0, *out_len);
    size_t pos = 0;
    if(add_cid)
        out[pos++] = static_cast<std::uint8_t>(0xE0U | (cid_value & 0x0FU));

    const size_t first_octet_pos = pos++;
    const std::uint8_t crc = formal_co_header_crc(variant, crc_input);

    if(variant == FormalCoVariant::Pt0Crc3)
    {
        out[first_octet_pos] = static_cast<std::uint8_t>(((msn & 0x0FU) << 3U) | (crc & 0x07U));
    }
    else if(is_rtp_formal_co_profile(profile))
    {
        const std::uint8_t msn_lsb = static_cast<std::uint8_t>(msn & 0x1FU);
        out[first_octet_pos] = static_cast<std::uint8_t>(0x80U | ((msn_lsb >> 1U) & 0x0FU));
        if(large_cid_space)
        {
            std::uint8_t* cid_pos = out + pos;
            if(!cid::write_large(cid_pos, out + *out_len, cid_value))
                return false;
            pos = static_cast<size_t>(cid_pos - out);
        }
        out[pos++] = static_cast<std::uint8_t>(((msn_lsb & 0x01U) << 7U) | (crc & 0x7FU));
        *out_len = pos;
        return true;
    }
    else
    {
        const std::uint8_t msn_lsb = static_cast<std::uint8_t>(msn & 0x3FU);
        out[first_octet_pos] = static_cast<std::uint8_t>(0x80U | ((msn_lsb >> 1U) & 0x1FU));
        if(large_cid_space)
        {
            std::uint8_t* cid_pos = out + pos;
            if(!cid::write_large(cid_pos, out + *out_len, cid_value))
                return false;
            pos = static_cast<size_t>(cid_pos - out);
        }
        out[pos++] = static_cast<std::uint8_t>(((msn_lsb & 0x01U) << 7U) | (crc & 0x7FU));
        *out_len = pos;
        return true;
    }

    if(large_cid_space)
    {
        std::uint8_t* cid_pos = out + pos;
        if(!cid::write_large(cid_pos, out + *out_len, cid_value))
            return false;
        pos = static_cast<size_t>(cid_pos - out);
    }

    *out_len = pos;
    return true;
}

inline bool decode_formal_co_pt0(const std::uint8_t* in,
                                 size_t len,
                                 Profile profile,
                                 bool large_cid_space,
                                 FormalCoCrcInput crc_input,
                                 FormalCoPacket& packet,
                                 size_t* consumed = nullptr)
{
    packet = {};
    if(!in || len == 0 || !is_supported_formal_co_profile(profile) || !formal_co_crc_input_valid(crc_input))
        return false;

    size_t pos = 0;
    bool has_add_cid = false;
    std::uint32_t decoded_cid = 0;
    if(!large_cid_space && (in[0] & 0xF0U) == 0xE0U)
    {
        has_add_cid = true;
        decoded_cid = static_cast<std::uint32_t>(in[0] & 0x0FU);
        if(len < 2)
            return false;
        ++pos;
    }

    const std::uint8_t first = in[pos++];
    size_t decoded_cid_len = 0;
    if(large_cid_space)
    {
        if(!cid::read_large(in + pos, len - pos, decoded_cid, decoded_cid_len))
            return false;
        pos += decoded_cid_len;
    }

    packet.profile = profile;
    packet.cid = decoded_cid;
    packet.large_cid = large_cid_space;
    packet.cid_len = decoded_cid_len;

    if((first & 0x80U) == 0)
    {
        packet.variant = FormalCoVariant::Pt0Crc3;
        packet.msn = static_cast<std::uint16_t>((first >> 3U) & 0x0FU);
        packet.header_crc = static_cast<std::uint8_t>(first & 0x07U);
        if(packet.header_crc != formal_co_header_crc(packet.variant, crc_input))
            return false;
        if(consumed)
            *consumed = pos;
        return consumed || pos == len;
    }

    packet.variant = FormalCoVariant::Pt0Crc7;
    if(pos >= len)
        return false;
    const std::uint8_t tail = in[pos++];
    if(is_rtp_formal_co_profile(profile))
    {
        if((first & 0xF0U) != 0x80U)
            return false;
        packet.msn = static_cast<std::uint16_t>(((first & 0x0FU) << 1U) | ((tail >> 7U) & 0x01U));
    }
    else
    {
        if((first & 0xE0U) != 0x80U)
            return false;
        packet.msn = static_cast<std::uint16_t>(((first & 0x1FU) << 1U) | ((tail >> 7U) & 0x01U));
    }
    packet.header_crc = static_cast<std::uint8_t>(tail & 0x7FU);
    if(packet.header_crc != formal_co_header_crc(packet.variant, crc_input))
        return false;
    if(has_add_cid && packet.cid == 0)
        return false;
    if(consumed)
        *consumed = pos;
    return consumed || pos == len;
}

} // namespace rohccxx::rfc5225
