// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/context.hpp"

namespace rohccxx
{

enum class FeedbackType : uint8_t
{
    NACK = 0,
    STATIC_NACK = 1,
    ACK = 2
};

enum class FeedbackOptionType : uint8_t
{
    Mode = 1,
    SequenceNumber = 2,
    Clock = 3,
    Crc = 4
};

struct FeedbackOption
{
    FeedbackOptionType type = FeedbackOptionType::Mode;
    uint8_t len = 0;
    uint8_t value[4] = {};
};

struct Feedback
{
    uint32_t cid = 0;
    FeedbackType type = FeedbackType::NACK;
    bool has_mode = false;
    Mode mode = Mode::Optimistic;
    uint8_t option_count = 0;
    FeedbackOption options[4] = {};
};

inline bool is_known_feedback_type(std::uint8_t value)
{
    return value <= static_cast<std::uint8_t>(FeedbackType::ACK);
}

inline bool is_known_mode(std::uint8_t value)
{
    return value <= static_cast<std::uint8_t>(Mode::Reliable);
}

inline bool feedback_has_options(std::uint8_t flags)
{
    return (flags & 0x10U) != 0;
}

inline bool feedback_has_mode(std::uint8_t flags)
{
    return (flags & 0x20U) != 0;
}

inline bool is_feedback_packet_start(std::uint8_t value)
{
    return (value & 0xF8U) == 0xF0U;
}

inline std::uint8_t feedback_ack_type(FeedbackType type)
{
    switch(type)
    {
    case FeedbackType::ACK:
        return 0U;
    case FeedbackType::NACK:
        return 1U;
    case FeedbackType::STATIC_NACK:
        return 2U;
    }
    return 3U;
}

inline bool feedback_type_from_ack_type(std::uint8_t ack_type, FeedbackType& type)
{
    switch(ack_type)
    {
    case 0U:
        type = FeedbackType::ACK;
        return true;
    case 1U:
        type = FeedbackType::NACK;
        return true;
    case 2U:
        type = FeedbackType::STATIC_NACK;
        return true;
    default:
        return false;
    }
}

inline bool add_feedback_option(Feedback& feedback,
                                FeedbackOptionType type,
                                const uint8_t* value,
                                uint8_t len)
{
    if(feedback.option_count >= 4 || len > 4U || (len > 0 && !value))
        return false;
    FeedbackOption& option = feedback.options[feedback.option_count++];
    option.type = type;
    option.len = len;
    option.value[0] = option.value[1] = option.value[2] = option.value[3] = 0;
    if(len > 0)
        std::memcpy(option.value, value, len);
    return true;
}

inline size_t feedback_options_wire_len(const Feedback& feedback)
{
    size_t len = 0;
    for(uint8_t i = 0; i < feedback.option_count; ++i)
        len += 2U + feedback.options[i].len;
    return len;
}

inline bool write_feedback_packet(std::uint8_t* out, size_t* out_len, const Feedback& feedback)
{
    if(!out || !out_len || feedback.cid > 0x0FU)
        return false;

    const size_t options_len = feedback_options_wire_len(feedback);
    const bool has_options = options_len > 0;
    const bool has_add_cid = feedback.cid > 0;
    const size_t feedback_data_len = 2U + (has_options ? 1U + options_len : 0U);
    const size_t body_len = (has_add_cid ? 1U : 0U) + feedback_data_len;
    const bool extended_size = body_len > 7U;
    const size_t required_len = 1U + (extended_size ? 1U : 0U) + body_len;
    if(options_len > 0xFFU || body_len > 0xFFU || *out_len < required_len)
        return false;

    std::memset(out, 0, *out_len);
    size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(0xF0U | (extended_size ? 0U : body_len));
    if(extended_size)
        out[pos++] = static_cast<std::uint8_t>(body_len);
    if(has_add_cid)
        out[pos++] = static_cast<std::uint8_t>(0xE0U | (feedback.cid & 0x0FU));

    out[pos++] = static_cast<std::uint8_t>(
        ((feedback_ack_type(feedback.type) & 0x03U) << 6U) |
        (feedback.has_mode ? 0x20U : 0U) |
        (has_options ? 0x10U : 0U) |
        (feedback.has_mode ? (static_cast<std::uint8_t>(feedback.mode) & 0x03U) : 0U));
    out[pos++] = 0;

    if(has_options)
    {
        out[pos++] = static_cast<std::uint8_t>(options_len);
        for(uint8_t i = 0; i < feedback.option_count; ++i)
        {
            const FeedbackOption& option = feedback.options[i];
            out[pos++] = static_cast<std::uint8_t>(option.type);
            out[pos++] = option.len;
            if(option.len > 0)
            {
                std::memcpy(out + pos, option.value, option.len);
                pos += option.len;
            }
        }
    }

    *out_len = pos;
    return true;
}

inline bool read_feedback_packet(const std::uint8_t* in, size_t len, Feedback& feedback, size_t* consumed = nullptr)
{
    feedback = {};
    if(!in || len < 2 || !is_feedback_packet_start(in[0]))
        return false;

    const std::uint8_t code = static_cast<std::uint8_t>(in[0] & 0x07U);
    size_t pos = 1;
    size_t body_len = code;
    if(code == 0)
    {
        if(pos >= len)
            return false;
        body_len = in[pos++];
    }
    if(body_len == 0 || len - pos < body_len)
        return false;

    const size_t body_end = pos + body_len;
    if(pos < body_end && (in[pos] & 0xF0U) == 0xE0U)
    {
        feedback.cid = static_cast<std::uint32_t>(in[pos] & 0x0FU);
        if(feedback.cid == 0)
            return false;
        ++pos;
    }

    if(body_end - pos < 2U)
        return false;

    const std::uint8_t feedback_code = in[pos++];
    ++pos; // reserved/profile-specific byte kept as zero by the writer

    const std::uint8_t ack_type = static_cast<std::uint8_t>((feedback_code >> 6U) & 0x03U);
    if(!feedback_type_from_ack_type(ack_type, feedback.type))
        return false;

    const bool has_options = (feedback_code & 0x10U) != 0;
    if((feedback_code & 0x20U) != 0)
    {
        const uint8_t mode = static_cast<uint8_t>(feedback_code & 0x03U);
        if(!is_known_mode(mode))
            return false;
        feedback.has_mode = true;
        feedback.mode = static_cast<Mode>(mode);
    }

    if(has_options)
    {
        if(pos >= body_end)
            return false;
        const uint8_t options_len = in[pos++];
        if(body_end - pos != options_len)
            return false;
        while(pos < body_end)
        {
            if(body_end - pos < 2U || feedback.option_count >= 4)
                return false;
            const auto type = static_cast<FeedbackOptionType>(in[pos++]);
            const uint8_t option_len = in[pos++];
            if(option_len > 4U || body_end - pos < option_len)
                return false;
            if(!add_feedback_option(feedback, type, in + pos, option_len))
                return false;
            pos += option_len;
        }
    }
    else if(pos != body_end)
    {
        return false;
    }

    if(consumed)
        *consumed = pos;
    else if(pos != len)
        return false;
    return true;
}

inline bool write_piggybacked_feedback(std::uint8_t* out,
                                       size_t* out_len,
                                       const Feedback& feedback,
                                       const std::uint8_t* packet,
                                       size_t packet_len)
{
    if(!out || !out_len || (!packet && packet_len > 0))
        return false;
    size_t feedback_len = *out_len;
    if(!write_feedback_packet(out, &feedback_len, feedback) || *out_len < feedback_len + packet_len)
        return false;
    if(packet_len > 0)
        std::memcpy(out + feedback_len, packet, packet_len);
    *out_len = feedback_len + packet_len;
    return true;
}

inline bool read_feedback_prefix(const std::uint8_t* in, size_t len, Feedback& feedback, size_t& consumed)
{
    return read_feedback_packet(in, len, feedback, &consumed);
}

inline void apply_feedback_to_context(Context& ctx, const Feedback& feedback)
{
    if(feedback.has_mode)
        ctx.mode = feedback.mode;

    if(feedback.type == FeedbackType::ACK)
    {
        ctx.nack_count = 0;
        if(ctx.rohc_state == RohcState::StaticEstablished ||
           ctx.rohc_state == RohcState::DynamicEstablished)
        {
            ctx.static_acked = true;
        }
        if(ctx.rohc_state == RohcState::DynamicEstablished)
            ctx.dynamic_acked = true;
        return;
    }

    if(feedback.type == FeedbackType::STATIC_NACK)
    {
        ctx.nack_count = 0;
        ctx.static_acked = false;
        ctx.dynamic_acked = false;
        ctx.rohc_state = RohcState::NoContext;
        ctx.tx_count = 0;
        return;
    }

    ++ctx.nack_count;
    ctx.dynamic_acked = false;
    if(ctx.nack_count > 1U)
    {
        ctx.static_acked = false;
        ctx.rohc_state = RohcState::NoContext;
        ctx.tx_count = 0;
    }
    else
    {
        ctx.rohc_state = RohcState::StaticEstablished;
        ctx.tx_count = 1;
    }
}

} // namespace rohccxx
