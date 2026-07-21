// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>
#include "test_packet_helpers.hpp"

#include <cstdint>
#include <cstring>

namespace
{

void add_profile(rohccxx_rohcoipsec_channel_t& channel, std::uint16_t profile)
{
    REQUIRE(channel.profile_count < ROHCCXX_ROHCOIPSEC_MAX_PROFILES);
    channel.profiles[channel.profile_count++] = profile;
}

void add_integrity(rohccxx_rohcoipsec_channel_t& channel, std::uint16_t algorithm)
{
    REQUIRE(channel.integrity_algorithm_count < ROHCCXX_ROHCOIPSEC_MAX_INTEGRITY_ALGORITHMS);
    channel.integrity_algorithms[channel.integrity_algorithm_count++] = algorithm;
}

rohccxx_rohcoipsec_channel_t make_local_channel()
{
    rohccxx_rohcoipsec_channel_t channel{};
    channel.max_cid = 31;
    add_profile(channel, 0x0101);
    add_profile(channel, 0x0102);
    add_profile(channel, 0x0103);
    add_profile(channel, 0x0104);
    add_profile(channel, 0x0107);
    add_profile(channel, 0x0108);
    add_integrity(channel, ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256);
    add_integrity(channel, ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE);
    channel.icv_len = 12;
    channel.has_icv_len = 1;
    channel.mrru = 256;
    channel.has_mrru = 1;
    return channel;
}

} // namespace

TEST_CASE("Embedding adapter can drive ROHCoIPsec negotiation and packet ownership")
{
    auto local = make_local_channel();
    auto peer = make_local_channel();
    peer.max_cid = 63;

    std::uint8_t notify[128] = {};
    std::size_t notify_len = sizeof(notify);
    REQUIRE(rohc_rohcoipsec_write_supported(&local, notify, &notify_len) == 0);

    rohccxx_rohcoipsec_channel_t parsed{};
    REQUIRE(rohc_rohcoipsec_parse_supported(notify, notify_len, &parsed) == 0);
    REQUIRE(parsed.profile_count == local.profile_count);
    REQUIRE(parsed.has_mrru == 1);
    REQUIRE(parsed.mrru == 256);

    rohccxx_rohcoipsec_channel_t negotiated{};
    REQUIRE(rohc_rohcoipsec_negotiate(&local, &peer, &negotiated) == 0);
    REQUIRE(negotiated.max_cid == peer.max_cid);
    REQUIRE(negotiated.has_mrru == 1);
    REQUIRE(negotiated.mrru == 256);

    const std::uint8_t keymat[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    std::uint8_t outbound_key[16] = {};
    std::uint8_t inbound_key[16] = {};
    std::size_t outbound_key_len = sizeof(outbound_key);
    std::size_t inbound_key_len = sizeof(inbound_key);
    REQUIRE(rohc_rohcoipsec_derive_directional_keys(keymat,
                                                    sizeof(keymat),
                                                    sizeof(outbound_key),
                                                    outbound_key,
                                                    &outbound_key_len,
                                                    inbound_key,
                                                    &inbound_key_len) == 0);
    REQUIRE(outbound_key_len == sizeof(outbound_key));
    REQUIRE(inbound_key_len == sizeof(inbound_key));
    REQUIRE(std::memcmp(outbound_key, inbound_key, sizeof(outbound_key)) != 0);

    rohccxx_rohcoipsec_sa_t outbound_sa{};
    REQUIRE(rohc_rohcoipsec_build_sa(&negotiated,
                                     ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256,
                                     outbound_key,
                                     outbound_key_len,
                                     7,
                                     1,
                                     &outbound_sa) == 0);
    REQUIRE(outbound_sa.large_cids == 1);
    REQUIRE(outbound_sa.has_mrru == 1);
    REQUIRE(outbound_sa.has_feedback_for == 1);
    REQUIRE(outbound_sa.feedback_for == 7);

    rohc_comp* comp = rohc_comp_new2(negotiated.max_cid, ROHCCXX_DIRECTION_UPLINK);
    rohc_decomp* decomp = rohc_decomp_new2(negotiated.max_cid, ROHCCXX_DIRECTION_UPLINK);
    REQUIRE(comp != nullptr);
    REQUIRE(decomp != nullptr);
    REQUIRE(rohc_comp_apply_rohcoipsec_sa(comp, &outbound_sa) == 0);
    REQUIRE(rohc_decomp_apply_rohcoipsec_sa(decomp, &outbound_sa) == 0);
    REQUIRE(rohc_comp_rohcoipsec_next_header(comp) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_rohcoipsec_outbound_next_header(1) == ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER);
    REQUIRE(rohc_rohcoipsec_inbound_requires_decompression(ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER) == 1);
    REQUIRE(rohc_decomp_rohcoipsec_requires_decompression(decomp, ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER) == 1);

    std::uint8_t ip[64] = {};
    make_valid_rtp(ip, 1000, 1234, 0xCAFEBABEU);
    std::uint8_t rohcoipsec_packet[160] = {};
    std::size_t rohcoipsec_len = sizeof(rohcoipsec_packet);
    REQUIRE(rohc_compress4(comp, ip, sizeof(ip), rohcoipsec_packet, &rohcoipsec_len) == 0);
    REQUIRE(rohcoipsec_len > outbound_sa.icv_len);

    std::uint8_t out[128] = {};
    std::size_t out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohcoipsec_packet, rohcoipsec_len, out, &out_len) == 0);
    REQUIRE(out_len == sizeof(ip));
    REQUIRE(std::memcmp(out, ip, sizeof(ip)) == 0);

    rohcoipsec_packet[rohcoipsec_len - 1] ^= 0x01;
    out_len = sizeof(out);
    REQUIRE(rohc_decompress4(decomp, rohcoipsec_packet, rohcoipsec_len, out, &out_len) != 0);
    REQUIRE(rohc_decomp_has_feedback(decomp) == 1);

    rohc_decomp_free(decomp);
    rohc_comp_free(comp);
}
