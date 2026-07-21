// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rohccxx/core/profile.hpp"

namespace rohccxx::rohcoipsec
{

constexpr std::uint8_t protocol_number = 142;
constexpr std::uint16_t max_cid_limit = 16383;
constexpr std::uint16_t tv_attribute_flag = 0x8000;
constexpr std::uint16_t attribute_type_mask = 0x7FFF;
constexpr std::uint16_t private_attribute_first = 16384;

constexpr std::size_t max_profiles = 16;
constexpr std::size_t max_integrity_algorithms = 8;

enum class AttributeType : std::uint16_t
{
    MaxCid = 1,
    Profile = 2,
    Integrity = 3,
    IcvLength = 4,
    Mrru = 5,
};

enum class IntegrityAlgorithm : std::uint16_t
{
    None = 0,
    HmacSha256 = 12,
};

constexpr std::size_t sha256_digest_len = 32;

inline bool is_supported_rohcv2_profile(std::uint16_t profile)
{
    switch(static_cast<Profile>(profile))
    {
    case Profile::Uncompressed:
    case Profile::RTP:
    case Profile::UDP:
    case Profile::ESP:
    case Profile::IP:
    case Profile::RTP_UDP_Lite:
    case Profile::UDP_Lite:
        return true;
    case Profile::LLA_RTP:
        return false;
    }
    return false;
}

inline bool is_supported_integrity_algorithm(std::uint16_t algorithm)
{
    return algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::None) ||
           algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::HmacSha256);
}

inline bool icv_length_is_valid_for_algorithm(std::uint16_t algorithm, std::uint16_t icv_len)
{
    return algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::None) ? icv_len == 0 :
           algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::HmacSha256) && icv_len > 0 &&
               icv_len <= sha256_digest_len;
}

struct ChannelParameters
{
    std::uint16_t max_cid = 0;
    std::uint16_t profiles[max_profiles] = {};
    std::size_t profile_count = 0;
    std::uint16_t integrity_algorithms[max_integrity_algorithms] = {};
    std::size_t integrity_algorithm_count = 0;
    std::uint16_t icv_len = 0;
    bool has_icv_len = false;
    std::uint16_t mrru = 0;
    bool has_mrru = false;

    bool valid() const
    {
        if(max_cid > max_cid_limit || profile_count == 0 || profile_count > max_profiles ||
           integrity_algorithm_count == 0 || integrity_algorithm_count > max_integrity_algorithms)
        {
            return false;
        }

        for(std::size_t i = 0; i < profile_count; ++i)
        {
            if(!is_supported_rohcv2_profile(profiles[i]))
                return false;
            for(std::size_t j = i + 1; j < profile_count; ++j)
            {
                if(profiles[i] == profiles[j])
                    return false;
            }
        }

        bool has_keyed_integrity = false;
        for(std::size_t i = 0; i < integrity_algorithm_count; ++i)
        {
            if(!is_supported_integrity_algorithm(integrity_algorithms[i]))
                return false;
            if(integrity_algorithms[i] != static_cast<std::uint16_t>(IntegrityAlgorithm::None))
                has_keyed_integrity = true;
            for(std::size_t j = i + 1; j < integrity_algorithm_count; ++j)
            {
                if(integrity_algorithms[i] == integrity_algorithms[j])
                    return false;
            }
        }

        if(!has_icv_len)
            return true;
        if(!has_keyed_integrity)
            return icv_len == 0;
        return icv_len > 0 && icv_len <= sha256_digest_len;
    }

    bool large_cids() const
    {
        return max_cid > 15;
    }
};

inline bool is_rohc_next_header(std::uint8_t next_header)
{
    return next_header == protocol_number;
}

inline bool supports_profile(const ChannelParameters& params, std::uint16_t profile)
{
    for(std::size_t i = 0; i < params.profile_count; ++i)
    {
        if(params.profiles[i] == profile)
            return true;
    }
    return false;
}

inline bool supports_integrity(const ChannelParameters& params, std::uint16_t algorithm)
{
    for(std::size_t i = 0; i < params.integrity_algorithm_count; ++i)
    {
        if(params.integrity_algorithms[i] == algorithm)
            return true;
    }
    return false;
}

inline bool append_profile(ChannelParameters& params, std::uint16_t profile)
{
    if(params.profile_count >= max_profiles || !is_supported_rohcv2_profile(profile) ||
       supports_profile(params, profile))
    {
        return false;
    }
    params.profiles[params.profile_count++] = profile;
    return true;
}

inline bool append_integrity(ChannelParameters& params, std::uint16_t algorithm)
{
    if(params.integrity_algorithm_count >= max_integrity_algorithms || !is_supported_integrity_algorithm(algorithm) ||
       supports_integrity(params, algorithm))
    {
        return false;
    }
    params.integrity_algorithms[params.integrity_algorithm_count++] = algorithm;
    return true;
}

inline bool write_u16(std::uint8_t* out, std::size_t capacity, std::size_t& pos, std::uint16_t value)
{
    if(!out || pos + 2 > capacity)
        return false;
    out[pos++] = static_cast<std::uint8_t>(value >> 8);
    out[pos++] = static_cast<std::uint8_t>(value & 0xFFU);
    return true;
}

inline bool read_u16(const std::uint8_t* data, std::size_t len, std::size_t pos, std::uint16_t& value)
{
    if(!data || pos + 2 > len)
        return false;
    value = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8U) |
                                      static_cast<std::uint16_t>(data[pos + 1]));
    return true;
}

inline bool write_tv_attribute(std::uint8_t* out,
                               std::size_t capacity,
                               std::size_t& pos,
                               AttributeType type,
                               std::uint16_t value)
{
    const auto typed = static_cast<std::uint16_t>(tv_attribute_flag | static_cast<std::uint16_t>(type));
    return write_u16(out, capacity, pos, typed) && write_u16(out, capacity, pos, value);
}

inline bool write_supported_notify_payload(const ChannelParameters& params,
                                           std::uint8_t* out,
                                           std::size_t* out_len)
{
    if(!out || !out_len || !params.valid())
        return false;

    std::size_t pos = 0;
    const std::size_t capacity = *out_len;
    if(!write_tv_attribute(out, capacity, pos, AttributeType::MaxCid, params.max_cid))
        return false;
    for(std::size_t i = 0; i < params.profile_count; ++i)
    {
        if(!write_tv_attribute(out, capacity, pos, AttributeType::Profile, params.profiles[i]))
            return false;
    }
    for(std::size_t i = 0; i < params.integrity_algorithm_count; ++i)
    {
        if(!write_tv_attribute(out, capacity, pos, AttributeType::Integrity, params.integrity_algorithms[i]))
            return false;
    }
    if(params.has_icv_len && !write_tv_attribute(out, capacity, pos, AttributeType::IcvLength, params.icv_len))
        return false;
    if(params.has_mrru && !write_tv_attribute(out, capacity, pos, AttributeType::Mrru, params.mrru))
        return false;

    *out_len = pos;
    return true;
}

inline bool parse_supported_notify_payload(const std::uint8_t* data,
                                           std::size_t len,
                                           ChannelParameters& params)
{
    params = ChannelParameters{};
    bool saw_max_cid = false;
    std::size_t pos = 0;

    while(pos + 4 <= len)
    {
        std::uint16_t type_field = 0;
        std::uint16_t value = 0;
        if(!read_u16(data, len, pos, type_field) || !read_u16(data, len, pos + 2, value))
            return false;
        pos += 4;

        const bool tv_format = (type_field & tv_attribute_flag) != 0;
        const std::uint16_t type = static_cast<std::uint16_t>(type_field & attribute_type_mask);
        if(!tv_format)
        {
            if(pos + value > len)
                return false;
            pos += value;
            continue;
        }

        switch(static_cast<AttributeType>(type))
        {
        case AttributeType::MaxCid:
            if(saw_max_cid || value > max_cid_limit)
                return false;
            params.max_cid = value;
            saw_max_cid = true;
            break;
        case AttributeType::Profile:
            if(!append_profile(params, value))
                return false;
            break;
        case AttributeType::Integrity:
            if(!append_integrity(params, value))
                return false;
            break;
        case AttributeType::IcvLength:
            if(params.has_icv_len)
                return false;
            params.icv_len = value;
            params.has_icv_len = true;
            break;
        case AttributeType::Mrru:
            if(params.has_mrru)
                return false;
            params.mrru = value;
            params.has_mrru = true;
            break;
        default:
            break;
        }
    }

    return pos == len && saw_max_cid && params.valid();
}

inline bool negotiate(const ChannelParameters& local,
                      const ChannelParameters& peer,
                      ChannelParameters& negotiated)
{
    if(!local.valid() || !peer.valid())
        return false;

    negotiated = ChannelParameters{};
    negotiated.max_cid = peer.max_cid;
    negotiated.mrru = peer.mrru;
    negotiated.has_mrru = peer.has_mrru;
    negotiated.icv_len = peer.has_icv_len ? peer.icv_len : 0;
    negotiated.has_icv_len = peer.has_icv_len;

    for(std::size_t i = 0; i < local.profile_count; ++i)
    {
        if(supports_profile(peer, local.profiles[i]) && !append_profile(negotiated, local.profiles[i]))
            return false;
    }

    for(std::size_t i = 0; i < local.integrity_algorithm_count; ++i)
    {
        if(supports_integrity(peer, local.integrity_algorithms[i]))
        {
            if(!append_integrity(negotiated, local.integrity_algorithms[i]))
                return false;
            break;
        }
    }

    if(!negotiated.valid())
        return false;
    if(supports_integrity(negotiated, static_cast<std::uint16_t>(IntegrityAlgorithm::None)))
        negotiated.icv_len = 0;
    return true;
}


namespace detail
{

inline std::uint32_t rotr(std::uint32_t value, std::uint32_t bits)
{
    return (value >> bits) | (value << (32U - bits));
}

inline std::uint32_t load_be32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
           (static_cast<std::uint32_t>(p[1]) << 16U) |
           (static_cast<std::uint32_t>(p[2]) << 8U) |
           static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t value)
{
    p[0] = static_cast<std::uint8_t>(value >> 24U);
    p[1] = static_cast<std::uint8_t>(value >> 16U);
    p[2] = static_cast<std::uint8_t>(value >> 8U);
    p[3] = static_cast<std::uint8_t>(value);
}

inline void sha256_transform(std::uint32_t state[8], const std::uint8_t block[64])
{
    static constexpr std::uint32_t k[64] = {
        0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
        0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
        0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
        0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
        0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
        0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
        0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
        0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
        0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
        0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
        0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
        0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
        0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
        0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
        0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
        0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U,
    };

    std::uint32_t w[64] = {};
    for(std::size_t i = 0; i < 16; ++i)
        w[i] = load_be32(block + (i * 4));
    for(std::size_t i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];

    for(std::size_t i = 0; i < 64; ++i)
    {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline void sha256(const std::uint8_t* data, std::size_t len, std::uint8_t out[sha256_digest_len])
{
    std::uint32_t state[8] = {
        0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
        0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
    };

    std::size_t pos = 0;
    while(pos + 64 <= len)
    {
        sha256_transform(state, data + pos);
        pos += 64;
    }

    std::uint8_t block[128] = {};
    const std::size_t rem = len - pos;
    if(rem > 0)
        std::memcpy(block, data + pos, rem);
    block[rem] = 0x80;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8U;
    const std::size_t total_pad_len = rem < 56 ? 64 : 128;
    for(std::size_t i = 0; i < 8; ++i)
        block[total_pad_len - 1 - i] = static_cast<std::uint8_t>(bit_len >> (8U * i));
    sha256_transform(state, block);
    if(total_pad_len == 128)
        sha256_transform(state, block + 64);

    for(std::size_t i = 0; i < 8; ++i)
        store_be32(out + (i * 4), state[i]);
}

inline bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t len)
{
    if(!a || !b)
        return false;
    std::uint8_t diff = 0;
    for(std::size_t i = 0; i < len; ++i)
        diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

} // namespace detail

inline std::size_t digest_len(std::uint16_t algorithm)
{
    switch(static_cast<IntegrityAlgorithm>(algorithm))
    {
    case IntegrityAlgorithm::None:
        return 0;
    case IntegrityAlgorithm::HmacSha256:
        return sha256_digest_len;
    }
    return 0;
}

inline bool compute_icv(std::uint16_t algorithm,
                        const std::uint8_t* key,
                        std::size_t key_len,
                        const std::uint8_t* data,
                        std::size_t data_len,
                        std::uint8_t* out,
                        std::size_t* out_len)
{
    if(!out || !out_len || (!data && data_len > 0))
        return false;

    if(algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::None))
    {
        if(*out_len != 0)
            *out_len = 0;
        return true;
    }

    if(algorithm != static_cast<std::uint16_t>(IntegrityAlgorithm::HmacSha256) || (!key && key_len > 0) ||
       *out_len > sha256_digest_len)
    {
        return false;
    }

    std::uint8_t key_block[64] = {};
    if(key_len > sizeof(key_block))
    {
        detail::sha256(key, key_len, key_block);
    }
    else if(key_len > 0)
    {
        std::memcpy(key_block, key, key_len);
    }

    std::uint8_t inner[64 + 4096] = {};
    if(data_len > 4096)
        return false;
    for(std::size_t i = 0; i < 64; ++i)
        inner[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36U);
    if(data_len > 0)
        std::memcpy(inner + 64, data, data_len);

    std::uint8_t inner_digest[sha256_digest_len] = {};
    detail::sha256(inner, 64 + data_len, inner_digest);

    std::uint8_t outer[64 + sha256_digest_len] = {};
    for(std::size_t i = 0; i < 64; ++i)
        outer[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5CU);
    std::memcpy(outer + 64, inner_digest, sizeof(inner_digest));

    std::uint8_t digest[sha256_digest_len] = {};
    detail::sha256(outer, sizeof(outer), digest);
    std::memcpy(out, digest, *out_len);
    return true;
}

inline bool append_icv(std::uint16_t algorithm,
                       const std::uint8_t* key,
                       std::size_t key_len,
                       const std::uint8_t* authenticated_packet,
                       std::size_t authenticated_packet_len,
                       const std::uint8_t* rohc_packet,
                       std::size_t rohc_packet_len,
                       std::uint8_t* out,
                       std::size_t* out_len,
                       std::size_t icv_len)
{
    if(!rohc_packet || !out || !out_len || (!authenticated_packet && authenticated_packet_len > 0))
        return false;
    const std::size_t full_len = digest_len(algorithm);
    if(algorithm != static_cast<std::uint16_t>(IntegrityAlgorithm::None) && (icv_len == 0 || icv_len > full_len))
        return false;
    if(algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::None))
        icv_len = 0;
    if(*out_len < rohc_packet_len + icv_len)
        return false;

    std::memcpy(out, rohc_packet, rohc_packet_len);
    std::uint8_t digest[sha256_digest_len] = {};
    std::size_t digest_len_value = icv_len;
    if(!compute_icv(algorithm, key, key_len, authenticated_packet, authenticated_packet_len, digest, &digest_len_value))
        return false;
    if(icv_len > 0)
        std::memcpy(out + rohc_packet_len, digest, icv_len);
    *out_len = rohc_packet_len + icv_len;
    return true;
}

inline bool strip_and_verify_icv(std::uint16_t algorithm,
                                 const std::uint8_t* key,
                                 std::size_t key_len,
                                 const std::uint8_t* authenticated_packet,
                                 std::size_t authenticated_packet_len,
                                 const std::uint8_t* rohcoipsec_packet,
                                 std::size_t rohcoipsec_packet_len,
                                 const std::uint8_t** rohc_packet,
                                 std::size_t* rohc_packet_len,
                                 std::size_t icv_len)
{
    if(!rohcoipsec_packet || !rohc_packet || !rohc_packet_len || (!authenticated_packet && authenticated_packet_len > 0))
        return false;
    const std::size_t full_len = digest_len(algorithm);
    if(algorithm != static_cast<std::uint16_t>(IntegrityAlgorithm::None) && (icv_len == 0 || icv_len > full_len))
        return false;
    if(algorithm == static_cast<std::uint16_t>(IntegrityAlgorithm::None))
        icv_len = 0;
    if(rohcoipsec_packet_len < icv_len)
        return false;

    const std::size_t packet_len = rohcoipsec_packet_len - icv_len;
    if(icv_len > 0)
    {
        std::uint8_t digest[sha256_digest_len] = {};
        std::size_t digest_len_value = icv_len;
        if(!compute_icv(algorithm, key, key_len, authenticated_packet, authenticated_packet_len, digest, &digest_len_value))
            return false;
        if(!detail::constant_time_equal(digest, rohcoipsec_packet + packet_len, icv_len))
            return false;
    }
    *rohc_packet = rohcoipsec_packet;
    *rohc_packet_len = packet_len;
    return true;
}

inline bool append_none_icv(const std::uint8_t* rohc_packet,
                            std::size_t rohc_packet_len,
                            std::uint8_t* out,
                            std::size_t* out_len)
{
    return append_icv(static_cast<std::uint16_t>(IntegrityAlgorithm::None),
                      nullptr,
                      0,
                      rohc_packet,
                      rohc_packet_len,
                      rohc_packet,
                      rohc_packet_len,
                      out,
                      out_len,
                      0);
}

inline bool strip_none_icv(const std::uint8_t* rohcoipsec_packet,
                           std::size_t rohcoipsec_packet_len,
                           const std::uint8_t** rohc_packet,
                           std::size_t* rohc_packet_len)
{
    return strip_and_verify_icv(static_cast<std::uint16_t>(IntegrityAlgorithm::None),
                                nullptr,
                                0,
                                rohcoipsec_packet,
                                rohcoipsec_packet_len,
                                rohcoipsec_packet,
                                rohcoipsec_packet_len,
                                rohc_packet,
                                rohc_packet_len,
                                0);
}

} // namespace rohccxx::rohcoipsec
