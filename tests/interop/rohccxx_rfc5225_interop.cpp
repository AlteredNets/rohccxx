// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "rfc5225_interop_corpus.hpp"

#include <rohccxx.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

int emit()
{
    rfc5225_interop::emit_header();
    for(const auto& profile : rfc5225_interop::profiles)
    {
        rohc_comp* compressor = rohc_comp_new2(15, ROHCCXX_DIRECTION_UPLINK);
        if(!compressor) return 2;
        if(rohc_comp_set_mode(compressor, ROHCCXX_MODE_R) != 0)
        {
            rohc_comp_free(compressor);
            return 2;
        }
        for(int step = 0; step < static_cast<int>(rfc5225_interop::packets_per_profile); ++step)
        {
            std::uint8_t ip[rfc5225_interop::packet_size] = {};
            std::uint8_t rohc[rfc5225_interop::max_rohc_size] = {};
            std::size_t rohc_length = sizeof(rohc);
            rfc5225_interop::make_packet(profile.profile, step, ip);
            if(rohc_compress4(compressor, ip, sizeof(ip), rohc, &rohc_length) != 0)
            {
                rohc_comp_free(compressor);
                return 3;
            }
            rfc5225_interop::emit_case(profile, step, ip, rohc, rohc_length);
        }
        rohc_comp_free(compressor);
    }
    return std::fflush(stdout) == 0 ? 0 : 4;
}

int emit_co()
{
    rfc5225_interop::emit_co_header();
    for(const auto& profile : rfc5225_interop::profiles)
    {
        rohc_comp* compressor = rohc_comp_new2(15, ROHCCXX_DIRECTION_UPLINK);
        if(!compressor || rohc_comp_set_mode(compressor, ROHCCXX_MODE_O) != 0) return 2;
        for(int step = 0; step < static_cast<int>(rfc5225_interop::co_packets_per_profile); ++step)
        {
            std::uint8_t ip[rfc5225_interop::packet_size] = {};
            std::uint8_t rohc[rfc5225_interop::max_rohc_size] = {};
            std::size_t rohc_length = sizeof(rohc);
            rfc5225_interop::make_co_packet(profile.profile, step, ip);
            if(rohc_compress4(compressor, ip, sizeof(ip), rohc, &rohc_length) != 0) return 3;
            rfc5225_interop::emit_case(profile, step, ip, rohc, rohc_length);
        }
        rohc_comp_free(compressor);
    }
    return std::fflush(stdout) == 0 ? 0 : 4;
}

int decode()
{
    std::array<rohc_decomp*, rfc5225_interop::profile_count> decompressors{};
    for(auto& decompressor : decompressors)
    {
        decompressor = rohc_decomp_new2(15, ROHCCXX_DIRECTION_UPLINK);
        if(!decompressor)
        {
            for(auto* item : decompressors) if(item) rohc_decomp_free(item);
            return 2;
        }
    }

    const bool ok = rfc5225_interop::consume_corpus([&](const rfc5225_interop::CorpusCase& corpus_case) {
        const std::size_t profile_index = static_cast<std::size_t>(corpus_case.profile->profile);
        std::uint8_t output[rfc5225_interop::packet_size + 64] = {};
        std::size_t output_length = sizeof(output);
        if(rohc_decompress4(decompressors[profile_index],
                            corpus_case.rohc.data(),
                            corpus_case.rohc_length,
                            output,
                            &output_length) != 0 ||
           output_length != corpus_case.ip.size() ||
           std::memcmp(output, corpus_case.ip.data(), corpus_case.ip.size()) != 0)
        {
            std::fprintf(stderr,
                         "rohccxx decode mismatch profile=%s step=%d output_len=%zu expected_len=%zu\n",
                         corpus_case.profile->name,
                         corpus_case.step,
                         output_length,
                         corpus_case.ip.size());
            return false;
        }
        return true;
    });

    for(auto* decompressor : decompressors) rohc_decomp_free(decompressor);
    return ok ? 0 : 3;
}

int decode_co()
{
    std::array<rohc_decomp*, rfc5225_interop::profile_count> decompressors{};
    std::array<rohc_comp*, rfc5225_interop::profile_count> collision_compressors{};
    std::array<std::size_t, rfc5225_interop::profile_count> decoded_co{};
    std::array<rfc5225_interop::CorpusCase, rfc5225_interop::profile_count> reordered{};
    for(auto& decompressor : decompressors)
    {
        decompressor = rohc_decomp_new2(15, ROHCCXX_DIRECTION_UPLINK);
        if(!decompressor) return 2;
    }
    auto decode_exact = [&](std::size_t index, const rfc5225_interop::CorpusCase& item) {
        std::uint8_t output[rfc5225_interop::packet_size + 64] = {};
        std::size_t output_length = sizeof(output);
        return rohc_decompress4(decompressors[index], item.rohc.data(), item.rohc_length,
                                output, &output_length) == 0 &&
               output_length == item.ip.size() &&
               std::memcmp(output, item.ip.data(), item.ip.size()) == 0;
    };
    auto reject = [&](std::size_t index, const std::uint8_t* packet, std::size_t length) {
        std::array<std::uint8_t, rfc5225_interop::packet_size + 96> guarded{};
        guarded.fill(0xa5U);
        const auto before = guarded;
        std::size_t output_length = rfc5225_interop::packet_size + 64U;
        return rohc_decompress4(decompressors[index], packet, length, guarded.data() + 16U,
                                &output_length) != 0 &&
               output_length == 0 && guarded == before;
    };
    auto reject_capacity = [&](std::size_t index, const rfc5225_interop::CorpusCase& item) {
        std::array<std::uint8_t, rfc5225_interop::packet_size + 32> guarded{};
        guarded.fill(0x5aU);
        const auto before = guarded;
        std::size_t output_length = item.ip.size() - 1U;
        return rohc_decompress4(decompressors[index], item.rohc.data(), item.rohc_length,
                                guarded.data() + 16U, &output_length) != 0 &&
               output_length == 0 && guarded == before;
    };
    auto establish_collision_context = [&](std::size_t index,
                                           const rfc5225_interop::ProfileSpec& profile) {
        rohc_comp*& compressor = collision_compressors[index];
        compressor = rohc_comp_new2(15, ROHCCXX_DIRECTION_UPLINK);
        if(!compressor || rohc_comp_set_cid(compressor, 1U) != 0) return false;
        for(int step = 0; step < 2; ++step)
        {
            rfc5225_interop::CorpusCase collision{};
            collision.profile = &profile;
            collision.step = step;
            rfc5225_interop::make_co_packet(profile.profile, step, collision.ip.data());
            collision.rohc_length = collision.rohc.size();
            if(rohc_compress4(compressor, collision.ip.data(), collision.ip.size(),
                              collision.rohc.data(), &collision.rohc_length) != 0 ||
               !decode_exact(index, collision))
                return false;
        }
        return true;
    };
    auto verify_collision_context = [&](std::size_t index,
                                        const rfc5225_interop::ProfileSpec& profile) {
        rfc5225_interop::CorpusCase collision{};
        collision.profile = &profile;
        collision.step = 2;
        rfc5225_interop::make_co_packet(profile.profile, 2, collision.ip.data());
        collision.rohc_length = collision.rohc.size();
        return collision_compressors[index] &&
               rohc_compress4(collision_compressors[index], collision.ip.data(), collision.ip.size(),
                              collision.rohc.data(), &collision.rohc_length) == 0 &&
               decode_exact(index, collision);
    };

    const bool ok = rfc5225_interop::consume_co_corpus([&](const rfc5225_interop::CorpusCase& item) {
        const std::size_t index = static_cast<std::size_t>(item.profile->profile);
        const bool is_ir = item.rohc[0] == 0xfdU ||
            ((item.rohc[0] & 0xf0U) == 0xe0U && item.rohc_length > 1U && item.rohc[1] == 0xfdU);
        if(item.profile->profile == rfc5225_interop::Profile::Rtp)
            return decode_exact(index, item); // pinned rohc-lib emits IR only for this stream

        const bool transition = item.rohc[0] == 0xfaU || item.rohc[0] == 0xfbU;
        if(transition)
        {
            // CO-COMMON/CO-REPAIR currently collide with the assisting-layer
            // namespace. This is an unsupported-family rejection, not a test
            // of the RFC 5225 reserved bits inside either packet family.
            return reject(index, item.rohc.data(), item.rohc_length);
        }
        if(is_ir)
        {
            const bool exact = decode_exact(index, item);
            if(!exact) std::fprintf(stderr, "rohccxx CO context decode failed profile=%s step=%d\n", item.profile->name, item.step);
            return exact;
        }

        if(item.step == 8) return true; // deliberate loss
        if(item.step == 12)
        {
            reordered[index] = item;
            return true;
        }
        if(item.step == 13)
        {
            if(!decode_exact(index, item) ||
               !reject(index, reordered[index].rohc.data(), reordered[index].rohc_length))
            {
                std::fprintf(stderr, "rohccxx CO reorder check failed profile=%s step=%d\n", item.profile->name, item.step);
                return false;
            }
            ++decoded_co[index];
            return true;
        }

        if(decoded_co[index] == 0)
        {
            if(!establish_collision_context(index, *item.profile)) return false;
            auto malformed = item.rohc;
            const std::size_t pt0_offset =
                (malformed[0] & 0xf0U) == 0xe0U ? 1U : 0U;
            malformed[pt0_offset] ^= 0x01U; // PT-0 CRC-3 corruption
            std::array<std::uint8_t, rfc5225_interop::max_rohc_size> bad_cid{};
            bad_cid[0] = 0xe2U;
            std::memcpy(bad_cid.data() + 1U, item.rohc.data(), item.rohc_length);
            const bool rejects_bad_crc = reject(index, malformed.data(), item.rohc_length);
            const bool rejects_truncated_header = reject(index, bad_cid.data(), 1U);
            const bool rejects_small_output = reject_capacity(index, item);
            const bool rejects_unknown_cid =
                reject(index, bad_cid.data(), item.rohc_length + 1U);
            const bool reports_feedback = rohc_decomp_has_feedback(decompressors[index]) == 1;
            if(!rejects_bad_crc || !rejects_truncated_header || !rejects_small_output ||
               !rejects_unknown_cid || !reports_feedback)
            {
                std::fprintf(stderr,
                             "rohccxx CO malformed check failed profile=%s step=%d "
                             "crc=%d truncated=%d capacity=%d cid=%d feedback=%d\n",
                             item.profile->name, item.step, rejects_bad_crc,
                             rejects_truncated_header, rejects_small_output,
                             rejects_unknown_cid, reports_feedback);
                return false;
            }
            rohc_decomp* fresh = rohc_decomp_new2(15, ROHCCXX_DIRECTION_UPLINK);
            if(!fresh) return false;
            std::uint8_t output[rfc5225_interop::packet_size + 64] = {};
            std::size_t output_length = sizeof(output);
            const bool no_context = rohc_decompress4(fresh, item.rohc.data(), item.rohc_length,
                                                     output, &output_length) != 0 && output_length == 0;
            rohc_decomp_free(fresh);
            if(!no_context)
            {
                std::fprintf(stderr, "rohccxx CO no-context check failed profile=%s step=%d\n", item.profile->name, item.step);
                return false;
            }
        }
        if(!decode_exact(index, item))
        {
            std::fprintf(stderr, "rohccxx CO exact decode failed profile=%s step=%d\n", item.profile->name, item.step);
            return false;
        }
        ++decoded_co[index];
        if(decoded_co[index] == 1 && !verify_collision_context(index, *item.profile))
        {
            std::fprintf(stderr, "rohccxx CID-0 PT-0 collision check failed profile=%s\n",
                         item.profile->name);
            return false;
        }
        if(decoded_co[index] == 1 && !reject(index, item.rohc.data(), item.rohc_length))
        {
            std::fprintf(stderr, "rohccxx CO duplicate check failed profile=%s step=%d\n", item.profile->name, item.step);
            return false; // duplicate is rejected without advancing context
        }
        return true;
    });
    for(auto* decompressor : decompressors) if(decompressor) rohc_decomp_free(decompressor);
    for(auto* compressor : collision_compressors) if(compressor) rohc_comp_free(compressor);
    const bool coverage =
        decoded_co[static_cast<std::size_t>(rfc5225_interop::Profile::Udp)] > 0 &&
        decoded_co[static_cast<std::size_t>(rfc5225_interop::Profile::Esp)] > 0 &&
        decoded_co[static_cast<std::size_t>(rfc5225_interop::Profile::Ip)] > 0;
    if(ok && coverage)
        std::fprintf(stderr, "external CO reverse: UDP, ESP, IP exact; RTP emitter and FA/FB transitions unavailable\n");
    return ok && coverage ? 0 : 3;
}

} // namespace

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        std::fprintf(stderr, "usage: %s emit|decode|emit-co|decode-co\n", argv[0]);
        return 1;
    }
    if(std::strcmp(argv[1], "emit") == 0) return emit();
    if(std::strcmp(argv[1], "emit-co") == 0) return emit_co();
    if(std::strcmp(argv[1], "decode") == 0) return decode();
    if(std::strcmp(argv[1], "decode-co") == 0) return decode_co();
    return 1;
}
