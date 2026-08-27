#include "fuzz_support.hpp"
#include "tunnel_protocol.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace rohccxx::tun;
    if(size > rohccxx::fuzz::max_input) return 0;
    FrameView frame{};
    (void)decode_frame(data, size, frame);
    std::uint32_t cid = 0U; std::uint8_t feedback = 0U;
    (void)decode_feedback(data, size, cid, feedback);
    FlowKey key{};
    (void)identify_flow(data, size, key);
    FlowTable flows;
    FlowAssignment assignment{};
    for(std::size_t offset = 0U; offset < size && offset < 32U; ++offset)
        (void)flows.select(data + offset, size - offset, assignment);
    std::array<std::uint8_t, rohccxx::fuzz::max_packet + envelope_size> out{};
    std::size_t out_len = 0U;
    (void)encode_frame(MessageType::Compressed, data, size, out.data(), out.size(), out_len);
    return 0;
}
