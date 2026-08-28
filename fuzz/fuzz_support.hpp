#pragma once

#include <rohccxx.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <memory>
#include <vector>

namespace rohccxx::fuzz
{
constexpr std::size_t max_input = 65535U;
constexpr std::size_t max_packet = 65535U;
constexpr std::uint8_t guard = 0xa5U;

struct CompDelete { void operator()(rohc_comp* p) const { rohc_comp_free(p); } };
struct DecompDelete { void operator()(rohc_decomp* p) const { rohc_decomp_free(p); } };
using Comp = std::unique_ptr<rohc_comp, CompDelete>;
using Decomp = std::unique_ptr<rohc_decomp, DecompDelete>;

inline void require(bool value) { if(!value) std::abort(); }
inline void require(bool value, const char* invariant)
{
    if(!value)
    {
        std::fprintf(stderr, "ROHCCXX_FUZZ_INVARIANT: %s\n", invariant);
        std::abort();
    }
}

struct GuardedOutput
{
    static constexpr std::size_t guard_size = 32U;
    std::array<std::uint8_t, max_packet + 2U * guard_size> storage{};
    GuardedOutput() { storage.fill(guard); }
    std::uint8_t* data() { return storage.data() + guard_size; }
    bool guards_ok() const
    {
        return std::all_of(storage.begin(), storage.begin() + guard_size,
                           [](std::uint8_t v) { return v == guard; }) &&
               std::all_of(storage.end() - guard_size, storage.end(),
                           [](std::uint8_t v) { return v == guard; });
    }
};

inline void decompress_checked(rohc_decomp* decomp, const std::uint8_t* data,
                               std::size_t size, std::size_t capacity)
{
    GuardedOutput out;
    const auto before = out.storage;
    std::size_t out_len = capacity;
    const int result = rohc_decompress4(decomp, data, size, out.data(), &out_len);
    require(out.guards_ok());
    require(out_len <= capacity);
    if(result < 0)
        require(out.storage == before);
}

inline std::uint16_t checksum(const std::uint8_t* data, std::size_t size)
{
    std::uint32_t sum = 0U;
    for(std::size_t i = 0; i + 1U < size; i += 2U)
        sum += (static_cast<std::uint16_t>(data[i]) << 8U) | data[i + 1U];
    if((size & 1U) != 0U) sum += static_cast<std::uint16_t>(data[size - 1U]) << 8U;
    while(sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

inline std::uint16_t udp4_checksum(const std::vector<std::uint8_t>& packet)
{
    std::uint32_t sum = 17U + static_cast<std::uint32_t>(packet.size() - 20U);
    for(std::size_t i = 12U; i < 20U; i += 2U)
        sum += (static_cast<std::uint16_t>(packet[i]) << 8U) | packet[i + 1U];
    for(std::size_t i = 20U; i + 1U < packet.size(); i += 2U)
        sum += (static_cast<std::uint16_t>(packet[i]) << 8U) | packet[i + 1U];
    if((packet.size() & 1U) != 0U) sum += static_cast<std::uint16_t>(packet.back()) << 8U;
    while(sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    const auto result = static_cast<std::uint16_t>(~sum);
    return result == 0U ? 0xffffU : result;
}

inline std::vector<std::uint8_t> ipv4_packet(const std::uint8_t* data,
                                             std::size_t size, std::uint8_t kind)
{
    const bool rtp = (kind & 3U) == 0U;
    const std::size_t payload_len = std::max<std::size_t>(rtp ? 12U : 0U,
                                                          std::min<std::size_t>(size, 1200U));
    const bool udp = (kind & 3U) < 2U;
    const bool esp = (kind & 3U) == 2U;
    const std::size_t transport = udp ? 8U : (esp ? 8U : 0U);
    std::vector<std::uint8_t> packet(20U + transport + payload_len, 0U);
    packet[0] = 0x45U; packet[1] = static_cast<std::uint8_t>(kind << 2U);
    packet[2] = static_cast<std::uint8_t>(packet.size() >> 8U);
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[4] = kind; packet[5] = static_cast<std::uint8_t>(kind * 17U);
    packet[6] = 0x40U; packet[8] = 64U; packet[9] = udp ? 17U : (esp ? 50U : 253U);
    packet[12] = 10U; packet[15] = static_cast<std::uint8_t>(1U + (kind & 15U));
    packet[16] = 10U; packet[19] = static_cast<std::uint8_t>(129U + (kind & 15U));
    packet[10] = packet[11] = 0U;
    const auto ip_sum = checksum(packet.data(), 20U);
    packet[10] = static_cast<std::uint8_t>(ip_sum >> 8U); packet[11] = static_cast<std::uint8_t>(ip_sum);
    if(udp)
    {
        packet[20] = 0x40U; packet[21] = kind;
        packet[22] = 0x50U; packet[23] = kind;
        const auto udp_len = static_cast<std::uint16_t>(8U + payload_len);
        packet[24] = static_cast<std::uint8_t>(udp_len >> 8U); packet[25] = static_cast<std::uint8_t>(udp_len);
    }
    else if(esp)
    {
        packet[20] = 0x12U; packet[21] = 0x34U; packet[22] = 0x56U; packet[23] = kind;
        packet[27] = static_cast<std::uint8_t>(1U + kind);
    }
    if(size) std::memcpy(packet.data() + 20U + transport, data,
                         std::min(size, payload_len));
    if(rtp)
    {
        auto* payload = packet.data() + 28U;
        payload[0] = 0x80U; payload[1] = static_cast<std::uint8_t>(kind & 0x7fU);
        payload[2] = kind; payload[3] = static_cast<std::uint8_t>(kind + 1U);
        payload[7] = kind; payload[8] = 0x12U; payload[9] = 0x34U;
        payload[10] = 0x56U; payload[11] = kind;
    }
    if(udp && (kind & 1U) != 0U)
    {
        const auto udp_sum = udp4_checksum(packet);
        packet[26] = static_cast<std::uint8_t>(udp_sum >> 8U);
        packet[27] = static_cast<std::uint8_t>(udp_sum);
    }
    return packet;
}

inline std::vector<std::uint8_t> ipv6_packet(const std::uint8_t* data,
                                             std::size_t size, std::uint8_t kind)
{
    const bool udp = (kind & 1U) == 0U;
    const std::size_t payload_len = std::min<std::size_t>(size, 1200U);
    const std::size_t transport = udp ? 8U : 0U;
    std::vector<std::uint8_t> packet(40U + transport + payload_len, 0U);
    packet[0] = 0x60U; packet[4] = static_cast<std::uint8_t>((transport + payload_len) >> 8U);
    packet[5] = static_cast<std::uint8_t>(transport + payload_len);
    packet[6] = udp ? 17U : 253U; packet[7] = 64U;
    packet[8] = 0xfdU; packet[23] = static_cast<std::uint8_t>(1U + (kind & 15U));
    packet[24] = 0xfdU; packet[39] = static_cast<std::uint8_t>(129U + (kind & 15U));
    if(udp)
    {
        packet[40] = 0x40U; packet[41] = kind; packet[42] = 0x50U; packet[43] = kind;
        const auto udp_len = static_cast<std::uint16_t>(8U + payload_len);
        packet[44] = static_cast<std::uint8_t>(udp_len >> 8U); packet[45] = static_cast<std::uint8_t>(udp_len);
    }
    if(payload_len) std::memcpy(packet.data() + 40U + transport, data, payload_len);
    return packet;
}
}
