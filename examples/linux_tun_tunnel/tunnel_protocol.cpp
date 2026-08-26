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
