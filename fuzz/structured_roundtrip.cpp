#include "fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace rohccxx::fuzz;
    if(size == 0U || size > max_input) return 0;
    Comp comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    Decomp decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_DOWNLINK));
    require(static_cast<bool>(comp) && static_cast<bool>(decomp), "codec allocation");
    std::array<std::uint8_t, max_packet> compressed{};
    for(std::size_t flow = 0U; flow < std::min<std::size_t>(16U, 1U + (data[0] & 15U)); ++flow)
    {
        const auto kind = static_cast<std::uint8_t>(data[0] + flow);
        auto packet = (data[0] & 0x80U) != 0U
            ? ipv6_packet(data + 1U, size - 1U, kind)
            : ipv4_packet(data + 1U, size - 1U, kind);
        require(rohc_comp_set_cid(comp.get(), static_cast<std::uint32_t>(flow)) == 0,
                "small CID selection");
        std::size_t compressed_len = compressed.size();
        if(rohc_compress4(comp.get(), packet.data(), packet.size(), compressed.data(), &compressed_len) != 0)
            continue;
        GuardedOutput output;
        std::size_t output_len = max_packet;
        const int result = rohc_decompress4(decomp.get(), compressed.data(), compressed_len,
                                            output.data(), &output_len);
        require(output.guards_ok() && output_len <= max_packet, "output bounds and guards");
        if(result == 0)
        {
            if(output_len != packet.size())
            {
                std::fprintf(stderr,
                             "ROHCCXX_FUZZ_ROUNDTRIP: flow=%zu kind=%u packet=%zu output=%zu compressed=%zu\n",
                             flow, static_cast<unsigned>(kind), packet.size(), output_len,
                             compressed_len);
                for(std::size_t i = 0; i < compressed_len; ++i)
                    std::fprintf(stderr, "%02x", static_cast<unsigned>(compressed[i]));
                std::fputc('\n', stderr);
            }
            require(output_len == packet.size(), "successful output length");
            require(std::memcmp(output.data(), packet.data(), packet.size()) == 0,
                    "successful output byte equality");
        }
        if(rohc_decomp_has_feedback(decomp.get()) == 1)
        {
            std::uint32_t cid = 0U; std::uint8_t type = 0U;
            if(rohc_decomp_get_feedback(decomp.get(), &cid, &type) == 0)
                rohc_comp_handle_feedback(comp.get(), cid, type);
        }
    }
    return 0;
}
