// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstring>

#include <rohccxx.h>

#include "rohccxx/core/context.hpp"
#include "rohccxx/core/decode_fo.hpp"
#include "rohccxx/core/emit_rtp_fo.hpp"
#include "rohccxx/core/encoding_methods.hpp"
#include "test_packet_helpers.hpp"

TEST_CASE("Encoding methods expose W-LSB extraction and width selection")
{
    REQUIRE(rohccxx::encoding::least_significant_bits(0x1234U, 8) == 0x34U);
    REQUIRE(rohccxx::encoding::lsb_u16(0x1234U, 6) == 0x34U);
    REQUIRE(rohccxx::encoding::minimal_lsb_width(0x1235U, 0x1234U, 1) == 1);
    REQUIRE(rohccxx::encoding::minimal_lsb_width(0x12F0U, 0x1230U, 4) == 7);
}

TEST_CASE("Encoding methods round-trip offset IP-ID")
{
    const std::uint16_t seq = 0x3456;
    const std::uint16_t ip_id = 0x34A0;
    const std::uint16_t offset = rohccxx::encoding::encode_offset_ip_id(ip_id, seq);
    REQUIRE(offset == 0x004A);
    REQUIRE(rohccxx::encoding::decode_offset_ip_id(offset, seq) == ip_id);
}


TEST_CASE("Encoding methods expose profile field variants")
{
    REQUIRE(rohccxx::encoding::default_lsb_width(rohccxx::encoding::EncodedField::RtpSequence) == 6);
    REQUIRE(rohccxx::encoding::default_lsb_width(rohccxx::encoding::EncodedField::RtpTimestamp) == 8);
    REQUIRE(rohccxx::encoding::default_lsb_width(rohccxx::encoding::EncodedField::IpIdOffset) == 16);

    const auto seq_lsb = rohccxx::encoding::encode_field_lsb(
        rohccxx::encoding::EncodedField::RtpSequence, 0x0432, 6);
    REQUIRE(seq_lsb == 0x32);
    REQUIRE(rohccxx::encoding::decode_field_lsb(
                rohccxx::encoding::EncodedField::RtpSequence, seq_lsb, 0x0430, 6) == 0x0432);

    const auto checksum_lsb = rohccxx::encoding::encode_field_lsb(
        rohccxx::encoding::EncodedField::UdpChecksum, 0x9ABC, 0);
    REQUIRE(checksum_lsb == 0x9ABC);
    REQUIRE(rohccxx::encoding::decode_field_lsb(
                rohccxx::encoding::EncodedField::UdpChecksum, checksum_lsb, 0x0000, 0) == 0x9ABC);

    const std::uint16_t offset_lsb = rohccxx::encoding::encode_ip_id_offset_lsb(0x2345, 0x2300, 8);
    REQUIRE(offset_lsb == 0x45);
    REQUIRE(rohccxx::encoding::decode_ip_id_offset_lsb(offset_lsb, 0x2301, 0x0044, 8) == 0x2346);
}


TEST_CASE("Encoding methods exhaust W-LSB p-values intervals and wraparound")
{
    constexpr std::uint64_t modulus = 1ULL << 16;
    const std::array<std::uint8_t, 7> widths = {{1, 2, 3, 6, 8, 15, 16}};
    const std::array<std::uint16_t, 6> references = {{0x0000, 0x0001, 0x003F, 0x0100, 0xFFF0, 0xFFFF}};

    for(const auto width : widths)
    {
        const std::uint64_t range = 1ULL << width;
        const std::array<std::uint32_t, 4> p_values = {{0U,
                                                        static_cast<std::uint32_t>(range / 4U),
                                                        static_cast<std::uint32_t>(range / 2U),
                                                        static_cast<std::uint32_t>(range - 1U)}};
        const std::array<std::uint64_t, 4> deltas = {{0U, range / 3U, range / 2U, range - 1U}};

        for(const auto reference : references)
        {
            for(const auto p : p_values)
            {
                const std::uint64_t lower = (static_cast<std::uint64_t>(reference) + modulus - p) % modulus;
                for(const auto delta : deltas)
                {
                    const std::uint32_t expected = static_cast<std::uint32_t>((lower + delta) % modulus);
                    const std::uint32_t lsb = rohccxx::encoding::least_significant_bits(expected, width);
                    std::uint32_t decoded = 0;
                    REQUIRE(rohccxx::encoding::decode_lsb_with_p(lsb, width, reference, p, 16, decoded));
                    REQUIRE(decoded == expected);
                }
            }
        }
    }

    std::uint32_t decoded = 0;
    REQUIRE_FALSE(rohccxx::encoding::decode_lsb_with_p(0, 0, 0, 0, 16, decoded));
    REQUIRE_FALSE(rohccxx::encoding::decode_lsb_with_p(0, 17, 0, 0, 16, decoded));
    REQUIRE_FALSE(rohccxx::encoding::decode_lsb_with_p(0x40, 6, 0, 0, 16, decoded));
    REQUIRE_FALSE(rohccxx::encoding::decode_lsb_with_p(0, 6, 0, 64, 16, decoded));
}

TEST_CASE("Encoding methods exhaust scaled RTP timestamp boundaries")
{
    std::uint32_t stride = 0;
    std::uint32_t residue = 0;
    REQUIRE(rohccxx::encoding::infer_timestamp_stride(1000, 50000, 1003, 50480, stride, residue));
    REQUIRE(stride == 160);
    REQUIRE(residue == 80);

    REQUIRE(rohccxx::encoding::infer_timestamp_stride(0xFFFE, 0xFFFFFFF0U, 0x0000, 0x00000130U, stride, residue));
    REQUIRE(stride == 160);
    REQUIRE(residue == 144);

    REQUIRE_FALSE(rohccxx::encoding::infer_timestamp_stride(1000, 50000, 1000, 50160, stride, residue));
    REQUIRE_FALSE(rohccxx::encoding::infer_timestamp_stride(1000, 50000, 1002, 50321, stride, residue));
    REQUIRE_FALSE(rohccxx::encoding::infer_timestamp_stride(1000, 50000, 1001, 52001, stride, residue));

    const std::array<std::uint32_t, 4> strides = {{1U, 20U, 160U, 1000U}};
    for(const auto candidate_stride : strides)
    {
        const std::array<std::uint32_t, 3> residues = {{0U, candidate_stride > 1U ? 1U : 0U, candidate_stride - 1U}};
        for(const auto candidate_residue : residues)
        {
            for(const auto scaled_value : {0U, 1U, 255U, 65535U})
            {
                const std::uint32_t timestamp = scaled_value * candidate_stride + candidate_residue;
                REQUIRE(rohccxx::encoding::can_scale_timestamp(timestamp, candidate_stride, candidate_residue));
                const auto scaled = rohccxx::encoding::scale_timestamp(timestamp, candidate_stride);
                REQUIRE(scaled.scaled == scaled_value);
                REQUIRE(scaled.residue == candidate_residue);
                REQUIRE(rohccxx::encoding::unscale_timestamp(scaled.scaled,
                                                             candidate_stride,
                                                             candidate_residue) == timestamp);
            }
        }
    }

    const std::uint32_t reference = rohccxx::encoding::unscale_timestamp(0x100FEU, 160, 80);
    const std::uint32_t target = rohccxx::encoding::unscale_timestamp(0x10100U, 160, 80);
    REQUIRE(rohccxx::encoding::decode_scaled_lsb(0x00, 8, reference, 160, 80) == target);
}

TEST_CASE("Encoding methods exhaust timer-based RTP timestamp boundaries")
{
    const auto advanced = rohccxx::encoding::advance_timer_scaled_timestamp(50000, 160, 3);
    REQUIRE(advanced.valid);
    REQUIRE(advanced.timestamp == 50480);

    const auto wrapped = rohccxx::encoding::advance_timer_scaled_timestamp(0xFFFFFFF0U, 16, 2);
    REQUIRE(wrapped.valid);
    REQUIRE(wrapped.timestamp == 0x00000010U);

    REQUIRE_FALSE(rohccxx::encoding::advance_timer_scaled_timestamp(50000, 0, 3).valid);

    const auto no_elapsed = rohccxx::encoding::decode_timer_scaled_lsb(0x39, 8, 50000, 160, 0, 80);
    REQUIRE(no_elapsed.valid);
    REQUIRE(no_elapsed.timestamp == 50160);

    const auto decoded = rohccxx::encoding::decode_timer_scaled_lsb(314, 8, 50160, 160, 1, 80);
    REQUIRE(decoded.valid);
    REQUIRE(decoded.timestamp == 50320);

    const auto disabled = rohccxx::encoding::decode_timer_scaled_lsb(314, 8, 50160, 0, 1, 80);
    REQUIRE_FALSE(disabled.valid);
    REQUIRE(disabled.timestamp == 0);
}

TEST_CASE("Encoding methods exhaust offset IP-ID behavior")
{
    struct OffsetCase
    {
        std::uint16_t sequence;
        std::uint16_t ip_id;
        std::uint16_t reference_offset;
        std::uint8_t width;
        std::uint32_t p;
    };

    const std::array<OffsetCase, 5> cases = {{
        {0x2001, 0x3011, 0x1010, 4, 8},
        {0xFFFE, 0x0004, 0x0005, 4, 8},
        {0x8000, 0x8000, 0x0000, 1, 1},
        {0x1234, 0x3412, 0x21D0, 8, 128},
        {0xAAAA, 0x1357, 0x0000, 16, 0},
    }};

    for(const auto& item : cases)
    {
        const std::uint16_t offset = rohccxx::encoding::encode_offset_ip_id(item.ip_id, item.sequence);
        const std::uint16_t offset_lsb = static_cast<std::uint16_t>(
            rohccxx::encoding::encode_field_lsb(rohccxx::encoding::EncodedField::IpIdOffset,
                                                offset,
                                                item.width));
        std::uint16_t decoded_ip_id = 0;
        REQUIRE(rohccxx::encoding::decode_ip_id_offset_lsb_with_p(offset_lsb,
                                                                  item.sequence,
                                                                  item.reference_offset,
                                                                  item.width,
                                                                  item.p,
                                                                  decoded_ip_id));
        REQUIRE(decoded_ip_id == item.ip_id);
    }

    std::uint16_t decoded_ip_id = 0;
    REQUIRE_FALSE(rohccxx::encoding::decode_ip_id_offset_lsb_with_p(0, 0, 0, 17, 0, decoded_ip_id));
    REQUIRE_FALSE(rohccxx::encoding::decode_ip_id_offset_lsb_with_p(0x100, 0, 0, 8, 0, decoded_ip_id));
}

TEST_CASE("Encoding methods exhaust SDVL boundaries and malformed forms")
{
    struct SdvlCase
    {
        std::uint32_t value;
        std::array<std::uint8_t, 2> bytes;
        size_t len;
    };

    const std::array<SdvlCase, 6> cases = {{
        {0x0000, {{0x00, 0x00}}, 1},
        {0x0001, {{0x01, 0x00}}, 1},
        {0x007F, {{0x7F, 0x00}}, 1},
        {0x0080, {{0x80, 0x80}}, 2},
        {0x1234, {{0x92, 0x34}}, 2},
        {0x3FFF, {{0xBF, 0xFF}}, 2},
    }};

    for(const auto& item : cases)
    {
        std::uint8_t out[2] = {};
        std::uint8_t* p = out;
        REQUIRE(rohccxx::encoding::write_sdvl_14(p, out + sizeof(out), item.value));
        REQUIRE(static_cast<size_t>(p - out) == item.len);
        REQUIRE(std::memcmp(out, item.bytes.data(), item.len) == 0);

        std::uint32_t decoded = 0;
        size_t consumed = 0;
        REQUIRE(rohccxx::encoding::read_sdvl_14(out, item.len, decoded, consumed));
        REQUIRE(decoded == item.value);
        REQUIRE(consumed == item.len);
    }

    std::uint8_t out[2] = {};
    std::uint8_t* p = out;
    REQUIRE_FALSE(rohccxx::encoding::write_sdvl_14(p, out + sizeof(out), 0x4000));
    p = out;
    REQUIRE_FALSE(rohccxx::encoding::write_sdvl_14(p, out + 1, 0x0080));

    std::uint32_t decoded = 0;
    size_t consumed = 0;
    const std::uint8_t truncated[] = {0x80};
    REQUIRE_FALSE(rohccxx::encoding::read_sdvl_14(truncated, sizeof(truncated), decoded, consumed));
    const std::uint8_t non_minimal[] = {0x80, 0x7F};
    REQUIRE_FALSE(rohccxx::encoding::read_sdvl_14(non_minimal, sizeof(non_minimal), decoded, consumed));
    const std::uint8_t bad_prefix[] = {0xC0, 0x00};
    REQUIRE_FALSE(rohccxx::encoding::read_sdvl_14(bad_prefix, sizeof(bad_prefix), decoded, consumed));
}

TEST_CASE("Encoding methods exhaust generic list compression helpers")
{
    std::array<rohccxx::encoding::ExtensionListItem, 127> items{};
    for(size_t i = 0; i < items.size(); ++i)
        items[i] = {static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(0xFFU - i)};

    std::uint8_t out[255] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), items.data(), 0));
    REQUIRE(static_cast<size_t>(p - out) == 1);
    REQUIRE(out[0] == rohccxx::encoding::empty_list_marker());

    p = out;
    REQUIRE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), items.data(), 127));
    REQUIRE(static_cast<size_t>(p - out) == sizeof(out));
    REQUIRE(out[0] == 0xFF);

    std::array<rohccxx::encoding::ExtensionListItem, 127> decoded{};
    std::uint8_t decoded_count = 0;
    size_t pos = 0;
    REQUIRE(rohccxx::encoding::read_extension_list(out, sizeof(out), pos, decoded.data(), 127, decoded_count));
    REQUIRE(pos == sizeof(out));
    REQUIRE(decoded_count == 127);
    for(size_t i = 0; i < decoded_count; ++i)
    {
        REQUIRE(decoded[i].type == items[i].type);
        REQUIRE(decoded[i].value == items[i].value);
    }

    const std::array<rohccxx::encoding::ExtensionListItem, 3> reordered = {{items[2], items[0], items[1]}};
    p = out;
    REQUIRE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), reordered.data(), 3));
    pos = 0;
    decoded_count = 0;
    REQUIRE(rohccxx::encoding::read_extension_list(out, static_cast<size_t>(p - out), pos, decoded.data(), 3, decoded_count));
    REQUIRE(decoded_count == 3);
    REQUIRE(decoded[0].type == items[2].type);
    REQUIRE(decoded[1].type == items[0].type);
    REQUIRE(decoded[2].type == items[1].type);

    p = out;
    REQUIRE_FALSE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), items.data(), 128));
    p = out;
    REQUIRE_FALSE(rohccxx::encoding::write_extension_list(p, out + 2, items.data(), 2));
    p = out;
    REQUIRE_FALSE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), nullptr, 1));

    const std::uint8_t invalid_marker[] = {0x01, 0xAA, 0xBB};
    pos = 0;
    REQUIRE_FALSE(rohccxx::encoding::read_extension_list(invalid_marker,
                                                         sizeof(invalid_marker),
                                                         pos,
                                                         decoded.data(),
                                                         3,
                                                         decoded_count));
    REQUIRE(pos == 0);

    const std::uint8_t zero_non_empty[] = {0x80};
    pos = 0;
    REQUIRE_FALSE(rohccxx::encoding::read_extension_list(zero_non_empty,
                                                         sizeof(zero_non_empty),
                                                         pos,
                                                         decoded.data(),
                                                         3,
                                                         decoded_count));

    const std::uint8_t truncated[] = {0x82, 0x01, 0x02};
    pos = 0;
    REQUIRE_FALSE(rohccxx::encoding::read_extension_list(truncated,
                                                         sizeof(truncated),
                                                         pos,
                                                         decoded.data(),
                                                         3,
                                                         decoded_count));

    pos = 0;
    REQUIRE_FALSE(rohccxx::encoding::read_extension_list(out,
                                                         sizeof(out),
                                                         pos,
                                                         decoded.data(),
                                                         1,
                                                         decoded_count));
}

TEST_CASE("Encoding methods expose SDVL and empty-list seams")
{
    std::uint8_t out[8] = {};
    std::uint8_t* p = out;
    REQUIRE(rohccxx::encoding::write_sdvl_14(p, out + sizeof(out), 0x1234));
    REQUIRE(static_cast<size_t>(p - out) == 2);

    std::uint32_t value = 0;
    size_t consumed = 0;
    REQUIRE(rohccxx::encoding::read_sdvl_14(out, 2, value, consumed));
    REQUIRE(value == 0x1234);
    REQUIRE(consumed == 2);
    REQUIRE(rohccxx::encoding::empty_list_marker() == 0x00);
    REQUIRE(rohccxx::encoding::is_empty_list(0x00));
    REQUIRE_FALSE(rohccxx::encoding::is_empty_list(0x80));
    REQUIRE(rohccxx::encoding::is_non_empty_list_marker(0x80));
    REQUIRE(rohccxx::encoding::classify_extension_list_marker(0x00) == rohccxx::encoding::ExtensionListKind::Empty);
    REQUIRE(rohccxx::encoding::classify_extension_list_marker(0x80) == rohccxx::encoding::ExtensionListKind::NonEmpty);

    p = out;
    REQUIRE(rohccxx::encoding::write_empty_list(p, out + 1));
    REQUIRE(p == out + 1);
    size_t pos = 0;
    REQUIRE(rohccxx::encoding::read_empty_list(out, 1, pos));
    REQUIRE(pos == 1);

    rohccxx::encoding::ExtensionListItem items[] = {{0x11, 0x22}, {0x33, 0x44}};
    p = out;
    REQUIRE(rohccxx::encoding::write_extension_list(p, out + sizeof(out), items, 2));
    REQUIRE(static_cast<size_t>(p - out) == 5);
    REQUIRE(out[0] == 0x82);

    rohccxx::encoding::ExtensionListItem decoded[2] = {};
    std::uint8_t decoded_count = 0;
    pos = 0;
    REQUIRE(rohccxx::encoding::read_extension_list(out, 5, pos, decoded, 2, decoded_count));
    REQUIRE(pos == 5);
    REQUIRE(decoded_count == 2);
    REQUIRE(decoded[0].type == 0x11);
    REQUIRE(decoded[0].value == 0x22);
    REQUIRE(decoded[1].type == 0x33);
    REQUIRE(decoded[1].value == 0x44);

    p = out;
    REQUIRE(rohccxx::encoding::write_ipv4_options_list(p, out + sizeof(out), items, 2));
    REQUIRE(static_cast<size_t>(p - out) == 5);
    pos = 0;
    decoded_count = 0;
    REQUIRE(rohccxx::encoding::read_ipv4_options_list(out, 5, pos, decoded, 2, decoded_count));
    REQUIRE(decoded_count == 2);

    p = out;
    REQUIRE(rohccxx::encoding::write_rtp_csrc_list(p, out + sizeof(out), items, 1));
    REQUIRE(static_cast<size_t>(p - out) == 3);
    pos = 0;
    decoded_count = 0;
    REQUIRE(rohccxx::encoding::read_rtp_csrc_list(out, 3, pos, decoded, 2, decoded_count));
    REQUIRE(decoded_count == 1);
    REQUIRE(decoded[0].type == 0x11);
    REQUIRE(decoded[0].value == 0x22);

    p = out;
    REQUIRE(rohccxx::encoding::write_ipv6_extension_header_list(p, out + sizeof(out), items, 1));
    pos = 0;
    decoded_count = 0;
    REQUIRE(rohccxx::encoding::read_ipv6_extension_header_list(out, 3, pos, decoded, 2, decoded_count));
    REQUIRE(decoded_count == 1);

    p = out;
    REQUIRE(rohccxx::encoding::write_rtp_extension_header_list(p, out + sizeof(out), items, 1));
    pos = 0;
    decoded_count = 0;
    REQUIRE(rohccxx::encoding::read_rtp_extension_header_list(out, 3, pos, decoded, 2, decoded_count));
    REQUIRE(decoded_count == 1);
}

TEST_CASE("Encoding methods parse typed IPv6 extension-header lists")
{
    const std::uint8_t extensions[] = {
        43, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        44, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        17, 0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
    };

    rohccxx::encoding::Ipv6ExtensionHeaderItem items[4] = {};
    std::uint8_t count = 0;
    std::uint8_t terminal = 0;
    REQUIRE(rohccxx::encoding::parse_ipv6_extension_header_items(
        extensions, sizeof(extensions), 0, items, 4, count, terminal));
    REQUIRE(count == 3);
    REQUIRE(terminal == 17);

    REQUIRE(items[0].type == 0);
    REQUIRE(items[0].next_header == 43);
    REQUIRE(items[0].offset == 0);
    REQUIRE(items[0].length == 8);

    REQUIRE(items[1].type == 43);
    REQUIRE(items[1].next_header == 44);
    REQUIRE(items[1].offset == 8);
    REQUIRE(items[1].length == 8);

    REQUIRE(items[2].type == 44);
    REQUIRE(items[2].next_header == 17);
    REQUIRE(items[2].offset == 16);
    REQUIRE(items[2].length == 8);

    REQUIRE(rohccxx::encoding::validate_ipv6_extension_header_list(
        extensions, sizeof(extensions), 0, terminal));
    REQUIRE(terminal == 17);
    REQUIRE_FALSE(rohccxx::encoding::parse_ipv6_extension_header_items(
        extensions, sizeof(extensions) - 1, 0, items, 4, count, terminal));
}

TEST_CASE("Encoding methods expose timer-scaled timestamp seam")
{
    const auto advanced = rohccxx::encoding::advance_timer_scaled_timestamp(50000, 160, 3);
    REQUIRE(advanced.valid);
    REQUIRE(advanced.timestamp == 50480);

    const auto decoded = rohccxx::encoding::decode_timer_scaled_lsb(314, 8, 50160, 160, 1, 80);
    REQUIRE(decoded.valid);
    REQUIRE(decoded.timestamp == 50320);

    const auto disabled = rohccxx::encoding::advance_timer_scaled_timestamp(50000, 0, 3);
    REQUIRE_FALSE(disabled.valid);
    REQUIRE(disabled.timestamp == 0);
}

TEST_CASE("Encoding methods scale RTP timestamps from inferred stride")
{
    std::uint32_t stride = 0;
    std::uint32_t residue = 0;
    REQUIRE(rohccxx::encoding::infer_timestamp_stride(1000, 50000, 1001, 50160, stride, residue));
    REQUIRE(stride == 160);
    REQUIRE(residue == 80);

    const auto scaled = rohccxx::encoding::scale_timestamp(50320, stride);
    REQUIRE(scaled.scaled == 314);
    REQUIRE(scaled.residue == 80);
    REQUIRE(rohccxx::encoding::unscale_timestamp(scaled.scaled, stride, residue) == 50320);
    REQUIRE(rohccxx::encoding::decode_scaled_lsb(scaled.scaled & 0xFFU, 8, 50160, stride, residue) == 50320);
}

TEST_CASE("RTP FO uses scaled timestamp LSBs when stride is known")
{
    rohccxx::Context tx{};
    tx.cid = 0;
    tx.profile = rohccxx::Profile::RTP;
    tx.mode = rohccxx::Mode::Optimistic;
    tx.rohc_state = rohccxx::RohcState::DynamicEstablished;
    tx.rtp.last_seq = 1002;
    tx.rtp.last_ts = 50320;
    tx.rtp.ts_stride = 160;
    tx.rtp.ts_residue = 80;

    std::uint8_t rohc[16] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_rtp_fo(rohc, &rohc_len, tx));

    rohccxx::Context rx{};
    rx.cid = 0;
    rx.profile = rohccxx::Profile::RTP;
    rx.rohc_state = rohccxx::RohcState::DynamicEstablished;
    rx.rtp.last_seq = 1001;
    rx.rtp.last_ts = 50160;
    rx.rtp.ts_stride = 160;
    rx.rtp.ts_residue = 80;
    rx.rtp.seq_window.init(rx.rtp.last_seq);
    rx.rtp.ts_window.init(rx.rtp.last_ts);

    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    REQUIRE(rohccxx::decode_fo_rtp(rohc, rohc_len, rx, seq, ts));
    REQUIRE(seq == tx.rtp.last_seq);
    REQUIRE(ts == tx.rtp.last_ts);
}



TEST_CASE("RTP FO can decode timer-scaled timestamps from packet context")
{
    rohccxx::Context tx{};
    tx.cid = 0;
    tx.profile = rohccxx::Profile::RTP;
    tx.mode = rohccxx::Mode::Optimistic;
    tx.rohc_state = rohccxx::RohcState::DynamicEstablished;
    tx.rtp.last_seq = 1002;
    tx.rtp.last_ts = 50320;
    tx.rtp.ts_stride = 160;
    tx.rtp.ts_residue = 80;

    std::uint8_t rohc[16] = {};
    size_t rohc_len = sizeof(rohc);
    REQUIRE(rohccxx::emit_rtp_fo(rohc, &rohc_len, tx));

    rohccxx::Context rx{};
    rx.cid = 0;
    rx.profile = rohccxx::Profile::RTP;
    rx.rohc_state = rohccxx::RohcState::DynamicEstablished;
    rx.rtp.last_seq = 1001;
    rx.rtp.last_ts = 50160;
    rx.rtp.ts_stride = 160;
    rx.rtp.ts_residue = 80;
    rx.rtp.timer_based_ts = true;
    rx.rtp.timer_elapsed_ticks = 1;
    rx.rtp.seq_window.init(rx.rtp.last_seq);
    rx.rtp.ts_window.init(rx.rtp.last_ts);

    std::uint16_t seq = 0;
    std::uint32_t ts = 0;
    REQUIRE(rohccxx::decode_fo_rtp(rohc, rohc_len, rx, seq, ts));
    REQUIRE(seq == tx.rtp.last_seq);
    REQUIRE(ts == tx.rtp.last_ts);
}

TEST_CASE("C API RTP parity preserves regular 160-clock timestamps through FO")
{
    rohc_comp* comp = rohc_comp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(4, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);

    for(int i = 0; i < 3; ++i)
    {
        std::uint8_t packet[64] = {};
        std::uint8_t rohc[128] = {};
        std::uint8_t out[128] = {};
        size_t rohc_len = sizeof(rohc);
        size_t out_len = sizeof(out);

        make_valid_rtp(packet,
                       static_cast<std::uint16_t>(1000 + i),
                       static_cast<std::uint32_t>(50000 + i * 160),
                       0x11223344);
        REQUIRE(rohc_compress4(comp, packet, sizeof(packet), rohc, &rohc_len) == 0);
        REQUIRE(rohc_decompress4(decomp, rohc, rohc_len, out, &out_len) == 0);
        REQUIRE(out_len == sizeof(packet));
        REQUIRE(out[30] == packet[30]);
        REQUIRE(out[31] == packet[31]);
        REQUIRE(std::memcmp(out + 32, packet + 32, 8) == 0);
        REQUIRE(std::memcmp(out + 40, packet + 40, 24) == 0);
    }

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}
