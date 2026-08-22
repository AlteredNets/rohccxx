// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>

#include "rohccxx/core/cid.hpp"
#include "rohccxx/core/lsb_window.hpp"

namespace rohccxx::encoding
{

enum class ExtensionListKind : std::uint8_t
{
    Empty,
    NonEmpty
};

struct TimerScaledTimestamp
{
    bool valid = false;
    std::uint32_t timestamp = 0;
};

struct ExtensionListItem
{
    std::uint8_t type = 0;
    std::uint8_t value = 0;
};

struct Ipv6ExtensionHeaderItem
{
    std::uint8_t type = 0;
    std::uint8_t next_header = 0;
    std::uint8_t offset = 0;
    std::uint8_t length = 0;
};


enum class EncodedField : std::uint8_t
{
    RtpSequence,
    RtpTimestamp,
    IpId,
    IpIdOffset,
    UdpChecksum,
    UdpLiteCoverage
};

enum class ProfileList : std::uint8_t
{
    Generic,
    Ipv4Options,
    Ipv6ExtensionHeaders,
    RtpCsrc,
    RtpExtensionHeaders
};

inline std::uint8_t natural_field_width(EncodedField field)
{
    switch(field)
    {
    case EncodedField::RtpTimestamp:
        return 32;
    case EncodedField::RtpSequence:
    case EncodedField::IpId:
    case EncodedField::IpIdOffset:
    case EncodedField::UdpChecksum:
    case EncodedField::UdpLiteCoverage:
        return 16;
    }
    return 16;
}

inline std::uint8_t default_lsb_width(EncodedField field)
{
    switch(field)
    {
    case EncodedField::RtpSequence:
        return 6;
    case EncodedField::RtpTimestamp:
        return 8;
    case EncodedField::IpId:
    case EncodedField::IpIdOffset:
    case EncodedField::UdpChecksum:
    case EncodedField::UdpLiteCoverage:
        return natural_field_width(field);
    }
    return natural_field_width(field);
}

inline std::uint32_t mask_for_width(std::uint8_t width)
{
    return width >= 32 ? 0xFFFFFFFFU : ((1U << width) - 1U);
}

inline std::uint32_t least_significant_bits(std::uint32_t value, std::uint8_t width)
{
    return value & mask_for_width(width);
}

inline std::uint16_t lsb_u16(std::uint16_t value, std::uint8_t width)
{
    return static_cast<std::uint16_t>(least_significant_bits(value, width));
}

inline std::uint32_t lsb_u32(std::uint32_t value, std::uint8_t width)
{
    return least_significant_bits(value, width);
}

inline std::uint8_t minimal_lsb_width(std::uint32_t value, std::uint32_t reference, std::uint8_t min_width)
{
    for(std::uint8_t width = min_width; width < 32; ++width)
    {
        if(least_significant_bits(value, width) != least_significant_bits(reference, width))
            return width;
    }
    return 32;
}

inline std::uint64_t modulus_for_width(std::uint8_t width)
{
    return width >= 32 ? (1ULL << 32) : (1ULL << width);
}

inline bool decode_lsb_with_p(std::uint32_t lsb,
                              std::uint8_t width,
                              std::uint32_t reference,
                              std::uint32_t p,
                              std::uint8_t field_width,
                              std::uint32_t& decoded)
{
    decoded = 0;
    if(width == 0 || field_width == 0 || field_width > 32 || width > field_width)
        return false;

    const std::uint64_t range = modulus_for_width(width);
    const std::uint64_t modulus = modulus_for_width(field_width);
    if(static_cast<std::uint64_t>(p) >= range ||
       (static_cast<std::uint64_t>(lsb) & (range - 1U)) != static_cast<std::uint64_t>(lsb))
    {
        return false;
    }

    if(width == field_width)
    {
        decoded = lsb & mask_for_width(field_width);
        return true;
    }

    const std::uint64_t ref = static_cast<std::uint64_t>(reference) & (modulus - 1U);
    const std::uint64_t lower = (ref + modulus - (static_cast<std::uint64_t>(p) % modulus)) % modulus;
    std::uint64_t candidate = (lower & ~(range - 1U)) | static_cast<std::uint64_t>(lsb);
    if(((candidate + modulus - lower) % modulus) >= range)
        candidate = (candidate + range) % modulus;

    decoded = static_cast<std::uint32_t>(candidate & (modulus - 1U));
    return true;
}

inline std::uint16_t encode_offset_ip_id(std::uint16_t ip_id, std::uint16_t sequence)
{
    return static_cast<std::uint16_t>(ip_id - sequence);
}

inline std::uint16_t decode_offset_ip_id(std::uint16_t offset, std::uint16_t sequence)
{
    return static_cast<std::uint16_t>(sequence + offset);
}


inline std::uint32_t encode_field_lsb(EncodedField field,
                                      std::uint32_t value,
                                      std::uint8_t width = 0)
{
    const std::uint8_t effective_width = width == 0 ? default_lsb_width(field) : width;
    return least_significant_bits(value, effective_width);
}

inline bool decode_field_lsb_with_p(EncodedField field,
                                    std::uint32_t lsb,
                                    std::uint32_t reference,
                                    std::uint8_t width,
                                    std::uint32_t p,
                                    std::uint32_t& decoded)
{
    const std::uint8_t effective_width = width == 0 ? default_lsb_width(field) : width;
    return decode_lsb_with_p(lsb, effective_width, reference, p, natural_field_width(field), decoded);
}

inline std::uint32_t decode_field_lsb(EncodedField field,
                                      std::uint32_t lsb,
                                      std::uint32_t reference,
                                      std::uint8_t width = 0)
{
    const std::uint8_t effective_width = width == 0 ? default_lsb_width(field) : width;
    const std::uint32_t default_p = effective_width >= natural_field_width(field) ?
        0U : (1U << (effective_width - 1U));
    std::uint32_t decoded = 0;
    return decode_field_lsb_with_p(field, lsb, reference, effective_width, default_p, decoded) ? decoded : 0U;
}

inline bool decode_ip_id_offset_lsb_with_p(std::uint16_t offset_lsb,
                                           std::uint16_t sequence,
                                           std::uint16_t reference_offset,
                                           std::uint8_t width,
                                           std::uint32_t p,
                                           std::uint16_t& ip_id)
{
    std::uint32_t offset = 0;
    if(!decode_field_lsb_with_p(EncodedField::IpIdOffset, offset_lsb, reference_offset, width, p, offset))
        return false;
    ip_id = decode_offset_ip_id(static_cast<std::uint16_t>(offset), sequence);
    return true;
}

inline std::uint16_t encode_ip_id_offset_lsb(std::uint16_t ip_id,
                                             std::uint16_t sequence,
                                             std::uint8_t width = 0)
{
    const std::uint16_t offset = encode_offset_ip_id(ip_id, sequence);
    return static_cast<std::uint16_t>(encode_field_lsb(EncodedField::IpIdOffset, offset, width));
}

inline std::uint16_t decode_ip_id_offset_lsb(std::uint16_t offset_lsb,
                                             std::uint16_t sequence,
                                             std::uint16_t reference_offset,
                                             std::uint8_t width = 0)
{
    const std::uint16_t offset = static_cast<std::uint16_t>(
        decode_field_lsb(EncodedField::IpIdOffset, offset_lsb, reference_offset, width));
    return decode_offset_ip_id(offset, sequence);
}

struct ScaledTimestamp
{
    std::uint32_t scaled = 0;
    std::uint32_t residue = 0;
};

inline bool infer_timestamp_stride(std::uint16_t previous_seq,
                                   std::uint32_t previous_ts,
                                   std::uint16_t current_seq,
                                   std::uint32_t current_ts,
                                   std::uint32_t& stride,
                                   std::uint32_t& residue)
{
    const std::uint16_t seq_delta = static_cast<std::uint16_t>(current_seq - previous_seq);
    const std::uint32_t ts_delta = current_ts - previous_ts;
    if(seq_delta == 0 || ts_delta == 0 || (ts_delta % seq_delta) != 0)
        return false;

    stride = ts_delta / seq_delta;
    if(stride > 1000U)
        return false;
    residue = stride == 0 ? 0U : (current_ts % stride);
    return true;
}

inline bool can_scale_timestamp(std::uint32_t timestamp, std::uint32_t stride)
{
    return stride != 0 && (timestamp % stride) == 0;
}

inline bool can_scale_timestamp(std::uint32_t timestamp, std::uint32_t stride, std::uint32_t residue)
{
    return stride != 0 && (timestamp % stride) == (residue % stride);
}

inline ScaledTimestamp scale_timestamp(std::uint32_t timestamp, std::uint32_t stride)
{
    return { stride == 0 ? timestamp : (timestamp / stride), stride == 0 ? 0U : (timestamp % stride) };
}

inline std::uint32_t unscale_timestamp(std::uint32_t scaled, std::uint32_t stride, std::uint32_t residue)
{
    return stride == 0 ? scaled : (scaled * stride + residue);
}

inline TimerScaledTimestamp advance_timer_scaled_timestamp(std::uint32_t reference_timestamp,
                                                           std::uint32_t timestamp_stride,
                                                           std::uint32_t elapsed_timer_ticks)
{
    if(timestamp_stride == 0)
        return {};
    return { true, reference_timestamp + timestamp_stride * elapsed_timer_ticks };
}

inline bool write_sdvl_14(std::uint8_t*& p, const std::uint8_t* end, std::uint32_t value)
{
    return cid::write_large(p, end, value);
}

inline bool read_sdvl_14(const std::uint8_t* p, size_t len, std::uint32_t& value, size_t& consumed)
{
    return cid::read_large(p, len, value, consumed);
}

inline constexpr std::uint8_t empty_list_marker()
{
    return 0x00;
}

inline bool is_non_empty_list_marker(std::uint8_t marker)
{
    return marker != empty_list_marker();
}

inline bool is_empty_list(std::uint8_t marker)
{
    return marker == empty_list_marker();
}

inline ExtensionListKind classify_extension_list_marker(std::uint8_t marker)
{
    return is_empty_list(marker) ? ExtensionListKind::Empty : ExtensionListKind::NonEmpty;
}

inline bool write_empty_list(std::uint8_t*& p, const std::uint8_t* end)
{
    if(p >= end)
        return false;
    *p++ = empty_list_marker();
    return true;
}

inline bool read_empty_list(const std::uint8_t* in, size_t len, size_t& pos)
{
    if(pos >= len || !is_empty_list(in[pos]))
        return false;
    ++pos;
    return true;
}

inline bool write_extension_list(std::uint8_t*& p,
                                 const std::uint8_t* end,
                                 const ExtensionListItem* items,
                                 std::uint8_t count)
{
    if(count == 0)
        return write_empty_list(p, end);
    if(!items || count > 0x7FU || static_cast<size_t>(end - p) < (1U + static_cast<size_t>(count) * 2U))
        return false;

    *p++ = static_cast<std::uint8_t>(0x80U | count);
    for(std::uint8_t i = 0; i < count; ++i)
    {
        *p++ = items[i].type;
        *p++ = items[i].value;
    }
    return true;
}

inline bool read_extension_list(const std::uint8_t* in,
                                size_t len,
                                size_t& pos,
                                ExtensionListItem* items,
                                std::uint8_t capacity,
                                std::uint8_t& count)
{
    count = 0;
    if(pos >= len)
        return false;

    const std::uint8_t marker = in[pos];
    if(is_empty_list(marker))
    {
        ++pos;
        return true;
    }
    if((marker & 0x80U) == 0)
        return false;

    count = static_cast<std::uint8_t>(marker & 0x7FU);
    if(count == 0 || count > capacity || !items || len - pos - 1U < static_cast<size_t>(count) * 2U)
        return false;

    ++pos;
    for(std::uint8_t i = 0; i < count; ++i)
    {
        items[i].type = in[pos++];
        items[i].value = in[pos++];
    }
    return true;
}


inline bool write_profile_list(ProfileList,
                               std::uint8_t*& p,
                               const std::uint8_t* end,
                               const ExtensionListItem* items,
                               std::uint8_t count)
{
    return write_extension_list(p, end, items, count);
}

inline bool read_profile_list(ProfileList,
                              const std::uint8_t* in,
                              size_t len,
                              size_t& pos,
                              ExtensionListItem* items,
                              std::uint8_t capacity,
                              std::uint8_t& count)
{
    return read_extension_list(in, len, pos, items, capacity, count);
}

inline bool write_ipv4_options_list(std::uint8_t*& p,
                                    const std::uint8_t* end,
                                    const ExtensionListItem* items,
                                    std::uint8_t count)
{
    return write_profile_list(ProfileList::Ipv4Options, p, end, items, count);
}

inline bool read_ipv4_options_list(const std::uint8_t* in,
                                   size_t len,
                                   size_t& pos,
                                   ExtensionListItem* items,
                                   std::uint8_t capacity,
                                   std::uint8_t& count)
{
    return read_profile_list(ProfileList::Ipv4Options, in, len, pos, items, capacity, count);
}

inline bool write_rtp_csrc_list(std::uint8_t*& p,
                                const std::uint8_t* end,
                                const ExtensionListItem* items,
                                std::uint8_t count)
{
    return write_profile_list(ProfileList::RtpCsrc, p, end, items, count);
}

inline bool read_rtp_csrc_list(const std::uint8_t* in,
                               size_t len,
                               size_t& pos,
                               ExtensionListItem* items,
                               std::uint8_t capacity,
                               std::uint8_t& count)
{
    return read_profile_list(ProfileList::RtpCsrc, in, len, pos, items, capacity, count);
}


inline bool write_ipv6_extension_header_list(std::uint8_t*& p,
                                             const std::uint8_t* end,
                                             const ExtensionListItem* items,
                                             std::uint8_t count)
{
    return write_profile_list(ProfileList::Ipv6ExtensionHeaders, p, end, items, count);
}

inline bool read_ipv6_extension_header_list(const std::uint8_t* in,
                                            size_t len,
                                            size_t& pos,
                                            ExtensionListItem* items,
                                            std::uint8_t capacity,
                                            std::uint8_t& count)
{
    return read_profile_list(ProfileList::Ipv6ExtensionHeaders, in, len, pos, items, capacity, count);
}

inline bool is_ipv6_extension_header_type(std::uint8_t next_header)
{
    return next_header == 0 || next_header == 43 || next_header == 44 || next_header == 60;
}

inline bool ipv6_extension_header_length(const std::uint8_t* data,
                                         size_t len,
                                         std::uint8_t header_type,
                                         std::uint8_t& header_len)
{
    if(header_type == 44)
    {
        if(len < 8U)
            return false;
        header_len = 8;
        return true;
    }

    if(len < 2U)
        return false;

    const size_t computed = static_cast<size_t>(data[1] + 1U) * 8U;
    if(computed < 8U || computed > 0xFFU || len < computed)
        return false;
    header_len = static_cast<std::uint8_t>(computed);
    return true;
}

inline bool parse_ipv6_extension_header_items(const std::uint8_t* data,
                                              size_t len,
                                              std::uint8_t first_next_header,
                                              Ipv6ExtensionHeaderItem* items,
                                              std::uint8_t capacity,
                                              std::uint8_t& count,
                                              std::uint8_t& terminal_next_header)
{
    count = 0;
    terminal_next_header = first_next_header;
    if(len == 0)
        return !is_ipv6_extension_header_type(first_next_header);
    if(!data || !items || capacity == 0)
        return false;

    std::uint8_t current = first_next_header;
    size_t pos = 0;
    while(pos < len)
    {
        if(!is_ipv6_extension_header_type(current) || count >= capacity || pos > 0xFFU)
            return false;

        std::uint8_t header_len = 0;
        if(!ipv6_extension_header_length(data + pos, len - pos, current, header_len))
            return false;

        items[count++] = {current, data[pos], static_cast<std::uint8_t>(pos), header_len};
        current = data[pos];
        pos += header_len;
    }

    terminal_next_header = current;
    return true;
}

inline bool validate_ipv6_extension_header_list(const std::uint8_t* data,
                                                size_t len,
                                                std::uint8_t first_next_header,
                                                std::uint8_t& terminal_next_header)
{
    Ipv6ExtensionHeaderItem items[16] = {};
    std::uint8_t count = 0;
    return parse_ipv6_extension_header_items(data,
                                             len,
                                             first_next_header,
                                             items,
                                             static_cast<std::uint8_t>(sizeof(items) / sizeof(items[0])),
                                             count,
                                             terminal_next_header);
}

inline bool write_rtp_extension_header_list(std::uint8_t*& p,
                                            const std::uint8_t* end,
                                            const ExtensionListItem* items,
                                            std::uint8_t count)
{
    return write_profile_list(ProfileList::RtpExtensionHeaders, p, end, items, count);
}

inline bool read_rtp_extension_header_list(const std::uint8_t* in,
                                           size_t len,
                                           size_t& pos,
                                           ExtensionListItem* items,
                                           std::uint8_t capacity,
                                           std::uint8_t& count)
{
    return read_profile_list(ProfileList::RtpExtensionHeaders, in, len, pos, items, capacity, count);
}

inline std::uint32_t decode_scaled_lsb(std::uint32_t scaled_lsb,
                                       std::uint8_t width,
                                       std::uint32_t reference_timestamp,
                                       std::uint32_t stride,
                                       std::uint32_t residue)
{
    if(stride == 0)
    {
        LsbWindow<std::uint32_t, 8> window;
        window.init(reference_timestamp);
        return window.decode(scaled_lsb, width);
    }

    LsbWindow<std::uint32_t, 8> window;
    const std::uint32_t reference_scaled = reference_timestamp / stride;
    window.init(reference_scaled);
    const std::uint32_t decoded_scaled = window.decode(scaled_lsb, width);
    return unscale_timestamp(decoded_scaled, stride, residue);
}

inline std::uint32_t decode_scaled_lsb_with_timestamp_prediction(
    std::uint32_t scaled_lsb,
    std::uint8_t width,
    std::uint32_t predicted_timestamp,
    std::uint32_t fallback_reference_timestamp,
    std::uint32_t stride,
    std::uint32_t residue)
{
    const auto predicted_scaled = scale_timestamp(predicted_timestamp, stride);
    if(stride != 0U &&
       encode_field_lsb(EncodedField::RtpTimestamp,
                        predicted_scaled.scaled,
                        width) == scaled_lsb)
    {
        // Predict in the modulo-2^32 timestamp domain. Scaling first loses
        // wrap information when 2^32 is not divisible by the stride.
        return predicted_timestamp;
    }

    return decode_scaled_lsb(scaled_lsb,
                             width,
                             fallback_reference_timestamp,
                             stride,
                             residue);
}

inline TimerScaledTimestamp decode_timer_scaled_lsb(std::uint32_t scaled_lsb,
                                                    std::uint8_t width,
                                                    std::uint32_t reference_timestamp,
                                                    std::uint32_t timestamp_stride,
                                                    std::uint32_t elapsed_timer_ticks,
                                                    std::uint32_t residue)
{
    const auto advanced = advance_timer_scaled_timestamp(reference_timestamp, timestamp_stride, elapsed_timer_ticks);
    if(!advanced.valid)
        return {};
    return { true, decode_scaled_lsb_with_timestamp_prediction(scaled_lsb,
                                                                width,
                                                                advanced.timestamp,
                                                                advanced.timestamp,
                                                                timestamp_stride,
                                                                residue) };
}

} // namespace rohccxx::encoding
