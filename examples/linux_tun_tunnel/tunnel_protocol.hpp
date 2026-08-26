// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <array>

namespace rohccxx::tun
{

constexpr std::size_t envelope_size = 8U;
constexpr std::size_t estimated_outer_ipv4_udp_size = 28U;
constexpr std::uint8_t transport_version = 1U;
constexpr std::size_t feedback_payload_size = 5U;

enum class MessageType : std::uint8_t
{
    Compressed = 1U,
    Feedback = 2U,
};

enum class Result
{
    Ok,
    InvalidArgument,
    Oversized,
    Malformed,
    UnknownVersion,
    UnknownType,
    CodecFailure,
};

struct FrameView
{
    MessageType type = MessageType::Compressed;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_len = 0U;
};

struct Codec
{
    void* context = nullptr;
    int (*compress)(void*, const std::uint8_t*, std::size_t,
                    std::uint8_t*, std::size_t*) = nullptr;
    int (*decompress)(void*, const std::uint8_t*, std::size_t,
                      std::uint8_t*, std::size_t*) = nullptr;
    void (*feedback)(void*, std::uint32_t, std::uint8_t) = nullptr;
};

struct FlowKey
{
    std::array<std::uint8_t, 20> bytes{};
    std::uint8_t length = 0U;

    bool operator==(const FlowKey& other) const;
};

struct FlowAssignment
{
    std::uint8_t cid = 0U;
    bool newly_assigned = false;
    bool evicted = false;
};

Result identify_flow(const std::uint8_t* packet, std::size_t packet_len,
                     FlowKey& key);

class FlowTable
{
public:
    Result select(const std::uint8_t* packet, std::size_t packet_len,
                  FlowAssignment& assignment);
    std::size_t active_contexts() const;
    std::uint64_t assignments() const { return assignments_; }
    std::uint64_t evictions() const { return evictions_; }
    std::uint64_t mapping_failures() const { return mapping_failures_; }

private:
    struct Entry
    {
        FlowKey key{};
        std::uint64_t last_used = 0U;
        bool used = false;
    };
    std::array<Entry, 16> entries_{};
    std::uint64_t clock_ = 0U;
    std::uint64_t assignments_ = 0U;
    std::uint64_t evictions_ = 0U;
    std::uint64_t mapping_failures_ = 0U;
};

Result encode_frame(MessageType type, const std::uint8_t* payload,
                    std::size_t payload_len, std::uint8_t* output,
                    std::size_t output_capacity, std::size_t& output_len);
Result decode_frame(const std::uint8_t* datagram, std::size_t datagram_len,
                    FrameView& frame);
Result encode_feedback(std::uint32_t cid, std::uint8_t feedback_type,
                       std::uint8_t* output, std::size_t output_capacity,
                       std::size_t& output_len);
Result decode_feedback(const std::uint8_t* payload, std::size_t payload_len,
                       std::uint32_t& cid, std::uint8_t& feedback_type);
Result validate_ipv4_packet(const std::uint8_t* packet, std::size_t packet_len,
                            std::size_t maximum_packet_size);
Result prepare_compressed_datagram(const Codec& codec,
                                   const std::uint8_t* packet,
                                   std::size_t packet_len,
                                   std::size_t maximum_packet_size,
                                   std::uint8_t* compressed,
                                   std::size_t compressed_capacity,
                                   std::uint8_t* datagram,
                                   std::size_t datagram_capacity,
                                   std::size_t& compressed_len,
                                   std::size_t& datagram_len);
Result consume_datagram(const Codec& codec, const std::uint8_t* datagram,
                        std::size_t datagram_len, std::size_t maximum_packet_size,
                        std::uint8_t* packet, std::size_t packet_capacity,
                        std::size_t& packet_len, MessageType& consumed_type);

} // namespace rohccxx::tun
