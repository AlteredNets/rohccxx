#include "fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    using namespace rohccxx::fuzz;
    if(size > max_input || size == 0U) return 0;
    Decomp decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_DOWNLINK));
    Decomp control(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_DOWNLINK));
    Comp comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    require(static_cast<bool>(decomp) && static_cast<bool>(control) && static_cast<bool>(comp));

    // Establish identical real contexts, inject damage into only one, then require
    // the next valid packet to produce the same byte-exact result in both.
    auto packet = ipv4_packet(data + 1U, size - 1U, data[0]);
    std::array<std::uint8_t, max_packet> compressed{};
    std::size_t compressed_len = compressed.size();
    if(rohc_compress4(comp.get(), packet.data(), packet.size(), compressed.data(), &compressed_len) == 0)
    {
        decompress_checked(decomp.get(), compressed.data(), compressed_len, max_packet);
        decompress_checked(control.get(), compressed.data(), compressed_len, max_packet);
        packet[5] = static_cast<std::uint8_t>(packet[5] + 1U);
        packet[10] = packet[11] = 0U;
        const auto sum = checksum(packet.data(), 20U);
        packet[10] = static_cast<std::uint8_t>(sum >> 8U); packet[11] = static_cast<std::uint8_t>(sum);
        compressed_len = compressed.size();
        if(rohc_compress4(comp.get(), packet.data(), packet.size(), compressed.data(), &compressed_len) == 0 && compressed_len)
        {
            auto damaged = compressed;
            damaged[0] ^= 0x08U;
            decompress_checked(decomp.get(), damaged.data(), compressed_len, max_packet);
            GuardedOutput a; GuardedOutput b;
            std::size_t a_len = max_packet; std::size_t b_len = max_packet;
            const int ar = rohc_decompress4(decomp.get(), compressed.data(), compressed_len, a.data(), &a_len);
            const int br = rohc_decompress4(control.get(), compressed.data(), compressed_len, b.data(), &b_len);
            require(a.guards_ok() && b.guards_ok());
            if(ar == 0 && br == 0)
                require(a_len == b_len && std::memcmp(a.data(), b.data(), a_len) == 0);
        }
    }
    std::size_t cursor = 1U;
    for(unsigned step = 0U; step < 64U && cursor < size; ++step)
    {
        const std::uint8_t command = data[cursor++];
        const std::size_t remaining = size - cursor;
        const std::size_t chunk = std::min<std::size_t>(remaining, command & 0x3fU);
        switch(command >> 6U)
        {
        case 0U: decompress_checked(decomp.get(), data + cursor, chunk, max_packet); break;
        case 1U:
            rohc_comp_handle_feedback(comp.get(), command & 15U,
                                      static_cast<std::uint8_t>((command >> 4U) % 3U));
            break;
        case 2U:
            require(rohc_decomp_rfc4362_report_loss(decomp.get(), command & 15U) >= -1);
            break;
        default:
            decomp.reset(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_DOWNLINK));
            require(static_cast<bool>(decomp));
            break;
        }
        cursor += chunk;
    }
    return 0;
}
