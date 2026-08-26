// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>

#include "tunnel_protocol.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
struct FakeCodec
{
    bool fail_compress = false;
    bool fail_decompress = false;
    std::uint32_t feedback_cid = 99U;
    std::uint8_t feedback_type = 99U;
};

int fake_compress(void* opaque, const std::uint8_t* input, std::size_t input_len,
                  std::uint8_t* output, std::size_t* output_len)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    if(fake.fail_compress || !output_len || *output_len < input_len)
        return -1;
    std::memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
}

int fake_decompress(void* opaque, const std::uint8_t* input, std::size_t input_len,
                    std::uint8_t* output, std::size_t* output_len)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    if(fake.fail_decompress || !output_len || *output_len < input_len)
        return -1;
    std::memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
}

void fake_feedback(void* opaque, std::uint32_t cid, std::uint8_t type)
{
    auto& fake = *static_cast<FakeCodec*>(opaque);
    fake.feedback_cid = cid;
    fake.feedback_type = type;
}

std::array<std::uint8_t, 20> ipv4_packet()
{
    std::array<std::uint8_t, 20> packet{};
    packet[0] = 0x45U;
    packet[2] = 0U;
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[8] = 64U;
    packet[9] = 253U;
    return packet;
}
}

TEST_CASE("Linux TUN transport envelope round-trips exact versioned frames")
{
    const std::array<std::uint8_t, 3> payload{{1U, 2U, 3U}};
    std::array<std::uint8_t, 32> wire{};
    std::size_t wire_len = 0U;
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Compressed,
        payload.data(), payload.size(), wire.data(), wire.size(), wire_len) ==
        rohccxx::tun::Result::Ok);
    REQUIRE(wire_len == rohccxx::tun::envelope_size + payload.size());
    REQUIRE(wire[0] == 'R'); REQUIRE(wire[1] == 'H');
    REQUIRE(wire[2] == 'C'); REQUIRE(wire[3] == 'T');
    REQUIRE(wire[4] == rohccxx::tun::transport_version);
    rohccxx::tun::FrameView decoded{};
    REQUIRE(rohccxx::tun::decode_frame(wire.data(), wire_len, decoded) ==
            rohccxx::tun::Result::Ok);
    REQUIRE(decoded.type == rohccxx::tun::MessageType::Compressed);
    REQUIRE(decoded.payload_len == payload.size());
    REQUIRE(std::memcmp(decoded.payload, payload.data(), payload.size()) == 0);
}

TEST_CASE("Linux TUN transport envelope rejects malformed inputs")
{
    std::array<std::uint8_t, 16> wire{{'R','H','C','T',1U,1U,0U,1U,0xaaU}};
    rohccxx::tun::FrameView frame{};
    for(std::size_t len = 0U; len < rohccxx::tun::envelope_size; ++len)
        REQUIRE(rohccxx::tun::decode_frame(wire.data(), len, frame) == rohccxx::tun::Result::Malformed);
    auto bad = wire;
    bad[0] ^= 1U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
    bad = wire; bad[4] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::UnknownVersion);
    bad = wire; bad[5] = 9U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::UnknownType);
    bad = wire; bad[7] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
    bad = wire; bad[5] = 2U;
    REQUIRE(rohccxx::tun::decode_frame(bad.data(), 9U, frame) == rohccxx::tun::Result::Malformed);
}

TEST_CASE("Linux TUN pump helpers validate packets and surface codec errors")
{
    FakeCodec fake{};
    const rohccxx::tun::Codec codec{&fake, fake_compress, fake_decompress, fake_feedback};
    auto packet = ipv4_packet();
    std::array<std::uint8_t, 128> compressed{}, datagram{}, output{};
    std::size_t compressed_len = 0U, datagram_len = 0U;
    REQUIRE(rohccxx::tun::prepare_compressed_datagram(codec, packet.data(), packet.size(),
        64U, compressed.data(), compressed.size(), datagram.data(), datagram.size(),
        compressed_len, datagram_len) == rohccxx::tun::Result::Ok);
    REQUIRE(compressed_len == packet.size());
    std::size_t output_len = 0U;
    rohccxx::tun::MessageType type{};
    REQUIRE(rohccxx::tun::consume_datagram(codec, datagram.data(), datagram_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::Ok);
    REQUIRE(type == rohccxx::tun::MessageType::Compressed);
    REQUIRE(output_len == packet.size());
    REQUIRE(std::memcmp(output.data(), packet.data(), packet.size()) == 0);

    fake.fail_compress = true;
    REQUIRE(rohccxx::tun::prepare_compressed_datagram(codec, packet.data(), packet.size(),
        64U, compressed.data(), compressed.size(), datagram.data(), datagram.size(),
        compressed_len, datagram_len) == rohccxx::tun::Result::CodecFailure);
    fake.fail_compress = false; fake.fail_decompress = true;
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Compressed,
        packet.data(), packet.size(), datagram.data(), datagram.size(), datagram_len) == rohccxx::tun::Result::Ok);
    REQUIRE(rohccxx::tun::consume_datagram(codec, datagram.data(), datagram_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::CodecFailure);
    REQUIRE(output_len == 0U);

    packet[0] = 0x60U;
    REQUIRE(rohccxx::tun::validate_ipv4_packet(packet.data(), packet.size(), 64U) ==
            rohccxx::tun::Result::UnknownVersion);
}

TEST_CASE("Linux TUN feedback frames validate CID and public feedback type")
{
    FakeCodec fake{};
    const rohccxx::tun::Codec codec{&fake, fake_compress, fake_decompress, fake_feedback};
    std::array<std::uint8_t, 32> payload{}, wire{}, output{};
    std::size_t payload_len = 0U, wire_len = 0U, output_len = 0U;
    REQUIRE(rohccxx::tun::encode_feedback(15U, 1U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::Ok);
    REQUIRE(rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Feedback,
        payload.data(), payload_len, wire.data(), wire.size(), wire_len) == rohccxx::tun::Result::Ok);
    rohccxx::tun::MessageType type{};
    REQUIRE(rohccxx::tun::consume_datagram(codec, wire.data(), wire_len, 64U,
        output.data(), output.size(), output_len, type) == rohccxx::tun::Result::Ok);
    REQUIRE(type == rohccxx::tun::MessageType::Feedback);
    REQUIRE(fake.feedback_cid == 15U);
    REQUIRE(fake.feedback_type == 1U);
    REQUIRE(rohccxx::tun::encode_feedback(16U, 0U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::InvalidArgument);
    REQUIRE(rohccxx::tun::encode_feedback(0U, 3U, payload.data(), payload.size(), payload_len) ==
            rohccxx::tun::Result::InvalidArgument);
}
