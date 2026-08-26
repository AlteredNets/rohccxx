// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "tunnel_protocol.hpp"

#include <cstring>
#include <limits>

namespace rohccxx::tun
{
namespace
{
constexpr std::uint8_t magic[4] = {'R', 'H', 'C', 'T'};

bool known_type(MessageType type)
{
    return type == MessageType::Compressed || type == MessageType::Feedback;
}

void append16(FlowKey& key, std::uint16_t value)
{
    key.bytes[key.length++] = static_cast<std::uint8_t>(value >> 8U);
    key.bytes[key.length++] = static_cast<std::uint8_t>(value);
}

void append32(FlowKey& key, const std::uint8_t* value)
{
    std::memcpy(key.bytes.data() + key.length, value, 4U);
    key.length = static_cast<std::uint8_t>(key.length + 4U);
}
}

Result identify_flow(const std::uint8_t* packet, std::size_t packet_len, FlowKey& key)
{
    key = {};
    const Result valid = validate_ipv4_packet(packet, packet_len, packet_len);
    if(valid != Result::Ok)
        return valid;
    const std::size_t ihl = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
    append32(key, packet + 12U);
    append32(key, packet + 16U);
    key.bytes[key.length++] = packet[9];
    const std::uint16_t fragments = static_cast<std::uint16_t>(packet[6] << 8U) | packet[7];
    if((fragments & 0x3fffU) != 0U)
    {
        key.bytes[key.length++] = 1U;
        append16(key, static_cast<std::uint16_t>(packet[4] << 8U) | packet[5]);
        return Result::Ok;
    }
    if(packet[9] == 17U)
    {
        if(packet_len < ihl + 8U)
            return Result::Malformed;
        const std::size_t udp_len = (static_cast<std::size_t>(packet[ihl + 4U]) << 8U) |
                                    packet[ihl + 5U];
        if(udp_len < 8U || udp_len != packet_len - ihl)
            return Result::Malformed;
        key.bytes[key.length++] = 2U;
        append16(key, static_cast<std::uint16_t>(packet[ihl] << 8U) | packet[ihl + 1U]);
        append16(key, static_cast<std::uint16_t>(packet[ihl + 2U] << 8U) | packet[ihl + 3U]);
        const std::uint8_t* payload = packet + ihl + 8U;
        const std::size_t payload_len = udp_len - 8U;
        if(payload_len >= 12U && (payload[0] >> 6U) == 2U)
        {
            const std::size_t base = 12U + static_cast<std::size_t>(payload[0] & 0x0fU) * 4U;
            bool valid_rtp = base <= payload_len;
            std::size_t header = base;
            if(valid_rtp && (payload[0] & 0x10U) != 0U)
            {
                valid_rtp = header + 4U <= payload_len;
                if(valid_rtp)
                {
                    const std::size_t words = (static_cast<std::size_t>(payload[header + 2U]) << 8U) |
                                              payload[header + 3U];
                    header += 4U + words * 4U;
                    valid_rtp = header <= payload_len;
                }
            }
            if(valid_rtp && (payload[0] & 0x20U) != 0U)
                valid_rtp = payload_len > header && payload[payload_len - 1U] != 0U &&
                            payload[payload_len - 1U] <= payload_len - header;
            if(valid_rtp)
            {
                key.bytes[9] = 3U;
                append32(key, payload + 8U);
            }
        }
        return Result::Ok;
    }
    if(packet[9] == 50U)
    {
        if(packet_len < ihl + 8U)
            return Result::Malformed;
        key.bytes[key.length++] = 4U;
        append32(key, packet + ihl);
        return Result::Ok;
    }
    key.bytes[key.length++] = 0U;
    return Result::Ok;
}

bool FlowKey::operator==(const FlowKey& other) const
{
    return length == other.length &&
           std::memcmp(bytes.data(), other.bytes.data(), length) == 0;
}

Result FlowTable::select(const std::uint8_t* packet, std::size_t packet_len,
                         FlowAssignment& assignment)
{
    assignment = {};
    FlowKey key{};
    const Result parsed = identify_flow(packet, packet_len, key);
    if(parsed != Result::Ok)
    {
        ++mapping_failures_;
        return parsed;
    }
    ++clock_;
    for(std::size_t cid = 0U; cid < entries_.size(); ++cid)
    {
        if(entries_[cid].used && entries_[cid].key == key)
        {
            entries_[cid].last_used = clock_;
            assignment.cid = static_cast<std::uint8_t>(cid);
            return Result::Ok;
        }
    }
    std::size_t selected = entries_.size();
    for(std::size_t cid = 0U; cid < entries_.size(); ++cid)
        if(!entries_[cid].used) { selected = cid; break; }
    if(selected == entries_.size())
    {
        selected = 0U;
        for(std::size_t cid = 1U; cid < entries_.size(); ++cid)
            if(entries_[cid].last_used < entries_[selected].last_used)
                selected = cid;
        assignment.evicted = true;
        ++evictions_;
    }
    entries_[selected] = Entry{key, clock_, true};
    assignment.cid = static_cast<std::uint8_t>(selected);
    assignment.newly_assigned = true;
    ++assignments_;
    return Result::Ok;
}

std::size_t FlowTable::active_contexts() const
{
    std::size_t count = 0U;
    for(const Entry& entry : entries_)
        if(entry.used) ++count;
    return count;
}

Result encode_frame(MessageType type, const std::uint8_t* payload,
                    std::size_t payload_len, std::uint8_t* output,
                    std::size_t output_capacity, std::size_t& output_len)
{
    output_len = 0U;
    if(!output || (payload_len != 0U && !payload) || !known_type(type))
        return Result::InvalidArgument;
    if(payload_len > std::numeric_limits<std::uint16_t>::max() ||
       output_capacity < envelope_size + payload_len)
        return Result::Oversized;
    std::memcpy(output, magic, sizeof(magic));
    output[4] = transport_version;
    output[5] = static_cast<std::uint8_t>(type);
    output[6] = static_cast<std::uint8_t>(payload_len >> 8U);
    output[7] = static_cast<std::uint8_t>(payload_len);
    if(payload_len != 0U)
        std::memcpy(output + envelope_size, payload, payload_len);
    output_len = envelope_size + payload_len;
    return Result::Ok;
}

Result decode_frame(const std::uint8_t* datagram, std::size_t datagram_len,
                    FrameView& frame)
{
    frame = {};
    if(!datagram)
        return Result::InvalidArgument;
    if(datagram_len < envelope_size || std::memcmp(datagram, magic, sizeof(magic)) != 0)
        return Result::Malformed;
    if(datagram[4] != transport_version)
        return Result::UnknownVersion;
    const auto type = static_cast<MessageType>(datagram[5]);
    if(!known_type(type))
        return Result::UnknownType;
    const std::size_t payload_len =
        (static_cast<std::size_t>(datagram[6]) << 8U) | datagram[7];
    if(payload_len != datagram_len - envelope_size)
        return Result::Malformed;
    if((type == MessageType::Compressed && payload_len == 0U) ||
       (type == MessageType::Feedback && payload_len != feedback_payload_size))
        return Result::Malformed;
    frame.type = type;
    frame.payload = datagram + envelope_size;
    frame.payload_len = payload_len;
    return Result::Ok;
}

Result encode_feedback(std::uint32_t cid, std::uint8_t feedback_type,
                       std::uint8_t* output, std::size_t output_capacity,
                       std::size_t& output_len)
{
    output_len = 0U;
    if(!output || output_capacity < feedback_payload_size || cid > 15U || feedback_type > 2U)
        return Result::InvalidArgument;
    output[0] = static_cast<std::uint8_t>(cid >> 24U);
    output[1] = static_cast<std::uint8_t>(cid >> 16U);
    output[2] = static_cast<std::uint8_t>(cid >> 8U);
    output[3] = static_cast<std::uint8_t>(cid);
    output[4] = feedback_type;
    output_len = feedback_payload_size;
    return Result::Ok;
}

Result decode_feedback(const std::uint8_t* payload, std::size_t payload_len,
                       std::uint32_t& cid, std::uint8_t& feedback_type)
{
    cid = 0U;
    feedback_type = 0U;
    if(!payload)
        return Result::InvalidArgument;
    if(payload_len != feedback_payload_size)
        return Result::Malformed;
    cid = (static_cast<std::uint32_t>(payload[0]) << 24U) |
          (static_cast<std::uint32_t>(payload[1]) << 16U) |
          (static_cast<std::uint32_t>(payload[2]) << 8U) |
          payload[3];
    feedback_type = payload[4];
    return cid <= 15U && feedback_type <= 2U ? Result::Ok : Result::Malformed;
}

Result validate_ipv4_packet(const std::uint8_t* packet, std::size_t packet_len,
                            std::size_t maximum_packet_size)
{
    if(!packet || maximum_packet_size < 20U)
        return Result::InvalidArgument;
    if(packet_len < 20U)
        return Result::Malformed;
    if(packet_len > maximum_packet_size)
        return Result::Oversized;
    if((packet[0] >> 4U) != 4U)
        return Result::UnknownVersion;
    const std::size_t header_len = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
    const std::size_t total_len =
        (static_cast<std::size_t>(packet[2]) << 8U) | packet[3];
    if(header_len < 20U || header_len > packet_len || total_len != packet_len)
        return Result::Malformed;
    return Result::Ok;
}

Result prepare_compressed_datagram(const Codec& codec,
                                   const std::uint8_t* packet,
                                   std::size_t packet_len,
                                   std::size_t maximum_packet_size,
                                   std::uint8_t* compressed,
                                   std::size_t compressed_capacity,
                                   std::uint8_t* datagram,
                                   std::size_t datagram_capacity,
                                   std::size_t& compressed_len,
                                   std::size_t& datagram_len)
{
    compressed_len = datagram_len = 0U;
    const Result validation = validate_ipv4_packet(packet, packet_len, maximum_packet_size);
    if(validation != Result::Ok)
        return validation;
    if(!codec.compress || !compressed || !datagram)
        return Result::InvalidArgument;
    compressed_len = compressed_capacity;
    if(codec.compress(codec.context, packet, packet_len, compressed, &compressed_len) != 0 ||
       compressed_len == 0U || compressed_len > compressed_capacity)
    {
        compressed_len = 0U;
        return Result::CodecFailure;
    }
    const Result framed = encode_frame(MessageType::Compressed, compressed,
                                       compressed_len, datagram,
                                       datagram_capacity, datagram_len);
    if(framed != Result::Ok)
        compressed_len = 0U;
    return framed;
}

Result consume_datagram(const Codec& codec, const std::uint8_t* datagram,
                        std::size_t datagram_len, std::size_t maximum_packet_size,
                        std::uint8_t* packet, std::size_t packet_capacity,
                        std::size_t& packet_len, MessageType& consumed_type)
{
    packet_len = 0U;
    FrameView frame{};
    const Result decoded = decode_frame(datagram, datagram_len, frame);
    if(decoded != Result::Ok)
        return decoded;
    consumed_type = frame.type;
    if(frame.type == MessageType::Feedback)
    {
        std::uint32_t cid = 0U;
        std::uint8_t type = 0U;
        const Result feedback = decode_feedback(frame.payload, frame.payload_len, cid, type);
        if(feedback != Result::Ok)
            return feedback;
        if(!codec.feedback)
            return Result::InvalidArgument;
        codec.feedback(codec.context, cid, type);
        return Result::Ok;
    }
    if(!codec.decompress || !packet)
        return Result::InvalidArgument;
    packet_len = packet_capacity;
    if(codec.decompress(codec.context, frame.payload, frame.payload_len,
                        packet, &packet_len) != 0 || packet_len > packet_capacity)
    {
        packet_len = 0U;
        return Result::CodecFailure;
    }
    const Result validation = validate_ipv4_packet(packet, packet_len, maximum_packet_size);
    if(validation != Result::Ok)
        packet_len = 0U;
    return validation;
}

} // namespace rohccxx::tun
