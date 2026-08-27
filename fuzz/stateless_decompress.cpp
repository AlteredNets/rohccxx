#include "fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace rohccxx::fuzz;
    if(size > max_input) return 0;
    for(std::uint32_t max_cid : {0U, 15U})
    {
        Decomp decomp(rohc_decomp_new2(max_cid, ROHCCXX_DIRECTION_DOWNLINK));
        require(static_cast<bool>(decomp));
        decompress_checked(decomp.get(), data, size, max_packet);
        decompress_checked(decomp.get(), data, size, std::min<std::size_t>(size, 64U));
    }
    return 0;
}
