// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "interop_rohc_debug.hpp"
#include "rfc5225_interop_corpus.hpp"
#include "rohc_lib_compat.h"

extern "C" {
#include <rohc/rohc_comp.h>
}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{

bool is_rtp_packet(const unsigned char*,
                   const unsigned char*,
                   const unsigned char* payload,
                   const unsigned int payload_size,
                   void*)
{
    return payload_size >= 12U && (payload[0] >> 6) == 2;
}

rohc_profile_t rohclib_profile(const rfc5225_interop::ProfileSpec& profile)
{
    return static_cast<rohc_profile_t>(profile.id);
}

rohc_comp* make_compressor(const rfc5225_interop::ProfileSpec& profile)
{
    rohc_comp* compressor = rohc_comp_new2(ROHC_SMALL_CID,
                                           ROHC_SMALL_CID_MAX,
                                           interop_rohc_debug::random_cb,
                                           nullptr);
    if(!compressor) return nullptr;
    if(profile.profile == rfc5225_interop::Profile::Rtp &&
       !rohc_comp_set_rtp_detection_cb(compressor, is_rtp_packet, nullptr))
    {
        rohc_comp_free(compressor);
        return nullptr;
    }
    if(!rohc_comp_enable_profile(compressor, rohclib_profile(profile)))
    {
        rohc_comp_free(compressor);
        return nullptr;
    }
    return compressor;
}

rohc_decomp* make_decompressor(const rfc5225_interop::ProfileSpec& profile)
{
    rohc_decomp* decompressor = rohc_decomp_new2(ROHC_SMALL_CID,
                                                 ROHC_SMALL_CID_MAX,
                                                 ROHC_U_MODE);
    if(!decompressor) return nullptr;
    if(interop_debug::trace_enabled() &&
       !rohc_decomp_set_traces_cb2(decompressor, interop_rohc_debug::trace_cb, nullptr))
    {
        rohc_decomp_free(decompressor);
        return nullptr;
    }
    if(!rohc_decomp_enable_profile(decompressor, rohclib_profile(profile)))
    {
        rohc_decomp_free(decompressor);
        return nullptr;
    }
    return decompressor;
}

int emit()
{
    rfc5225_interop::emit_header();
    for(const auto& profile : rfc5225_interop::profiles)
    {
        rohc_comp* compressor = make_compressor(profile);
        if(!compressor) return 2;
        for(int step = 0; step < static_cast<int>(rfc5225_interop::packets_per_profile); ++step)
        {
            std::uint8_t ip[rfc5225_interop::packet_size] = {};
            std::uint8_t rohc[rfc5225_interop::max_rohc_size] = {};
            rfc5225_interop::make_packet(profile.profile, step, ip);
            rohc_buf ip_input = rohc_buf_init_full(ip, sizeof(ip), sizeof(ip));
            rohc_buf rohc_output = rohc_buf_init_empty(rohc, sizeof(rohc));
            if(rohc_compress4(compressor, ip_input, &rohc_output) != ROHC_STATUS_OK)
            {
                rohc_comp_free(compressor);
                return 3;
            }
            rfc5225_interop::emit_case(profile, step, ip, rohc_output.data, rohc_output.len);
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
        rohc_comp* compressor = make_compressor(profile);
        if(!compressor) return 2;
        for(int step = 0; step < static_cast<int>(rfc5225_interop::co_packets_per_profile); ++step)
        {
            std::uint8_t ip[rfc5225_interop::packet_size] = {};
            std::uint8_t rohc[rfc5225_interop::max_rohc_size] = {};
            rfc5225_interop::make_co_packet(profile.profile, step, ip);
            rohc_buf ip_input = rohc_buf_init_full(ip, sizeof(ip), sizeof(ip));
            rohc_buf rohc_output = rohc_buf_init_empty(rohc, sizeof(rohc));
            if(rohc_compress4(compressor, ip_input, &rohc_output) != ROHC_STATUS_OK) return 3;
            rfc5225_interop::emit_case(profile, step, ip, rohc_output.data, rohc_output.len);
        }
        rohc_comp_free(compressor);
    }
    return std::fflush(stdout) == 0 ? 0 : 4;
}

int decode()
{
    std::array<rohc_decomp*, rfc5225_interop::profile_count> decompressors{};
    for(std::size_t i = 0; i < decompressors.size(); ++i)
    {
        decompressors[i] = make_decompressor(rfc5225_interop::profiles[i]);
        if(!decompressors[i])
        {
            for(auto* item : decompressors) if(item) rohc_decomp_free(item);
            return 2;
        }
    }

    const bool ok = rfc5225_interop::consume_corpus([&](const rfc5225_interop::CorpusCase& corpus_case) {
        const std::size_t profile_index = static_cast<std::size_t>(corpus_case.profile->profile);
        std::uint8_t output[rfc5225_interop::packet_size + 64] = {};
        std::size_t output_length = sizeof(output);
        if(rohc_decompress_compat(decompressors[profile_index],
                                  corpus_case.rohc.data(),
                                  corpus_case.rohc_length,
                                  output,
                                  &output_length) != ROHC_STATUS_OK ||
           output_length != corpus_case.ip.size() ||
           std::memcmp(output, corpus_case.ip.data(), corpus_case.ip.size()) != 0)
        {
            std::fprintf(stderr,
                         "rohc-lib decode mismatch profile=%s step=%d output_len=%zu expected_len=%zu\n",
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
    std::array<std::size_t, rfc5225_interop::profile_count> co_packets{};
    for(std::size_t i = 0; i < decompressors.size(); ++i)
    {
        decompressors[i] = make_decompressor(rfc5225_interop::profiles[i]);
        if(!decompressors[i]) return 2;
    }
    const bool ok = rfc5225_interop::consume_co_corpus([&](const rfc5225_interop::CorpusCase& item) {
        const std::size_t index = static_cast<std::size_t>(item.profile->profile);
        const bool is_ir = item.rohc[0] == 0xfdU ||
            ((item.rohc[0] & 0xf0U) == 0xe0U && item.rohc_length > 1U && item.rohc[1] == 0xfdU);
        // The pinned rohc-lib RTP decompressor detects PT packets but its parser
        // deliberately rejects them ("TODO: handle other CO packets"). Record
        // no success for RTP: the private rohccxx FO packet is unvalidated.
        if(item.profile->profile == rfc5225_interop::Profile::Rtp && !is_ir)
            return true;
        if(!is_ir) ++co_packets[index];

        std::uint8_t output[rfc5225_interop::packet_size + 64] = {};
        std::size_t output_length = sizeof(output);
        if(rohc_decompress_compat(decompressors[index], item.rohc.data(), item.rohc_length,
                                  output, &output_length) != ROHC_STATUS_OK ||
           output_length != item.ip.size() ||
           std::memcmp(output, item.ip.data(), item.ip.size()) != 0)
        {
            std::fprintf(stderr, "rohc-lib CO decode mismatch profile=%s step=%d\n",
                         item.profile->name, item.step);
            return false;
        }
        if(item.step == 2 && !is_ir && item.rohc[0] != 0xfaU && item.rohc[0] != 0xfbU)
        {
            auto corrupted = item.rohc;
            corrupted[0] ^= 0x01U;
            std::size_t rejected_length = sizeof(output);
            if(rohc_decompress_compat(decompressors[index], corrupted.data(), item.rohc_length,
                                      output, &rejected_length) == ROHC_STATUS_OK)
                return false;
        }
        return true;
    });
    for(auto* decompressor : decompressors) if(decompressor) rohc_decomp_free(decompressor);
    const bool coverage =
        co_packets[static_cast<std::size_t>(rfc5225_interop::Profile::Udp)] > 0 &&
        co_packets[static_cast<std::size_t>(rfc5225_interop::Profile::Esp)] > 0 &&
        co_packets[static_cast<std::size_t>(rfc5225_interop::Profile::Ip)] > 0;
    if(ok && coverage)
        std::fprintf(stderr, "external CO: UDP, ESP, IP exact; RTP private FO unvalidated\n");
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
