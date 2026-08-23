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

} // namespace

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        std::fprintf(stderr, "usage: %s emit|decode\n", argv[0]);
        return 1;
    }
    if(std::strcmp(argv[1], "emit") == 0) return emit();
    if(std::strcmp(argv[1], "decode") == 0) return decode();
    return 1;
}
