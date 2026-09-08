// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace
{

struct CompDelete { void operator()(rohc_comp* value) const { rohc_comp_free(value); } };
struct DecompDelete { void operator()(rohc_decomp* value) const { rohc_decomp_free(value); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

std::vector<std::uint8_t> from_hex(const char* text)
{
    const std::string input(text);
    REQUIRE((input.size() % 2U) == 0U);
    std::vector<std::uint8_t> output;
    output.reserve(input.size() / 2U);
    for(std::size_t pos = 0; pos < input.size(); pos += 2U)
    {
        output.push_back(static_cast<std::uint8_t>(
            std::stoul(input.substr(pos, 2U), nullptr, 16)));
    }
    return output;
}

std::string to_hex(const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for(const auto byte : bytes)
        output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

std::vector<std::uint8_t> compress(rohc_comp* comp,
                                   std::uint32_t cid,
                                   const std::vector<std::uint8_t>& packet)
{
    REQUIRE(rohc_comp_set_cid(comp, cid) == 0);
    std::array<std::uint8_t, 512> output{};
    std::size_t output_len = output.size();
    REQUIRE(rohc_compress4(comp, packet.data(), packet.size(),
                           output.data(), &output_len) == 0);
    return {output.begin(), output.begin() + static_cast<std::ptrdiff_t>(output_len)};
}

void require_exact_decode(rohc_decomp* decomp,
                          const std::vector<std::uint8_t>& compressed,
                          const std::vector<std::uint8_t>& expected)
{
    std::array<std::uint8_t, 514> guarded{};
    guarded.fill(0xa5U);
    guarded.front() = 0x3cU;
    guarded.back() = 0xc3U;
    std::size_t output_len = guarded.size() - 2U;
    const int rc = rohc_decompress4(decomp, compressed.data(), compressed.size(),
                                    guarded.data() + 1U, &output_len);
    INFO("COMPRESSED_HEX=" << to_hex(compressed));
    REQUIRE(rc == 0);
    REQUIRE(output_len == expected.size());
    REQUIRE(guarded.front() == 0x3cU);
    REQUIRE(guarded.back() == 0xc3U);
    REQUIRE(std::memcmp(guarded.data() + 1U, expected.data(), expected.size()) == 0);
}

const std::array<const char*, 7> captured_flow{{
    "4500002ac606000040019f340acb00020acb000100000c9ca901000049434d502d666f72776172642d30",
    "4500002ac607000040019f330acb00020acb000100000c9aa901000149434d502d666f72776172642d31",
    "4500002ac608000040019f320acb00020acb000100000c98a901000249434d502d666f72776172642d32",
    "4500002ac609000040019f310acb00020acb000100000c96a901000349434d502d666f72776172642d33",
    "4500002ac60a000040019f300acb00020acb000100000c94a901000449434d502d666f72776172642d34",
    "45c00058c60b000040019e410acb00020acb000103029be9000000004500003ce0014000403244f60acb00010acb0002a17e0001000000014553502d666f72776172642d3030303165656565656565656565656565656565",
    "45c00058c60d000040019e3f0acb00020acb000103029be7000000004500003ce0024000403244f50acb00010acb0002a17e0001000000024553502d666f72776172642d3030303265656565656565656565656565656565",
}};

const char* captured_ir =
    "e9fd044640010acb00020acb000100c040c60b000603029be9000000004500003ce0014000403244f60acb00010acb0002a17e0001000000014553502d666f72776172642d3030303165656565656565656565656565656565";
const char* captured_ambiguous_fo =
    "e97909c60d03029be7000000004500003ce0024000403244f50acb00010acb0002a17e0001000000024553502d666f72776172642d3030303265656565656565656565656565656565";
const char* captured_feedback = "f4e9400663";

const std::array<const char*, 9> captured_nonsequential_ip_id_flow{{
    "4500002a72bb00004001f27f0acb00020acb000100000c9ca901000049434d502d666f72776172642d30",
    "4500002a72bc00004001f27e0acb00020acb000100000c9aa901000149434d502d666f72776172642d31",
    "4500002a72bd00004001f27d0acb00020acb000100000c98a901000249434d502d666f72776172642d32",
    "4500002a72be00004001f27c0acb00020acb000100000c96a901000349434d502d666f72776172642d33",
    "4500002a72bf00004001f27b0acb00020acb000100000c94a901000449434d502d666f72776172642d34",
    "45c0005872c000004001f18c0acb00020acb000103029be9000000004500003ce0014000403244f60acb00010acb0002a17e0001000000014553502d666f72776172642d3030303165656565656565656565656565656565",
    "45c0005872c100004001f18b0acb00020acb000103029be7000000004500003ce0024000403244f50acb00010acb0002a17e0001000000024553502d666f72776172642d3030303265656565656565656565656565656565",
    "45c0005872c300004001f1890acb00020acb000103029be5000000004500003ce0034000403244f40acb00010acb0002a17e0001000000034553502d666f72776172642d3030303365656565656565656565656565656565",
    "45c0005872c600004001f1860acb00020acb000103029be3000000004500003ce0044000403244f30acb00010acb0002a17e0001000000044553502d666f72776172642d3030303465656565656565656565656565656565",
}};
const char* captured_nonsequential_ip_id_final_fo =
    "e9799572c603029be3000000004500003ce0044000403244f30acb00010acb0002a17e0001000000044553502d666f72776172642d3030303465656565656565656565656565656565";

} // namespace

TEST_CASE("issue 43 compressor refreshes instead of emitting ambiguous private IP FO")
{
    constexpr std::uint32_t cid = 9U;
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);

    for(std::size_t index = 0; index < captured_flow.size(); ++index)
    {
        const auto packet = from_hex(captured_flow[index]);
        const auto compressed = compress(comp.get(), cid, packet);
        if(index == 5U)
            REQUIRE(compressed == from_hex(captured_ir));
        require_exact_decode(decomp.get(), compressed, packet);
        if(index == 6U)
        {
            REQUIRE(compressed.size() > 1U);
            REQUIRE(compressed[0] == 0xe9U);
            REQUIRE(compressed[1] == 0xfdU);
        }
    }
}

TEST_CASE("issue 43 exact captured dual-valid IP FO remains transactionally rejected")
{
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(decomp);
    const auto first_expected = from_hex(captured_flow[5]);
    require_exact_decode(decomp.get(), from_hex(captured_ir), first_expected);

    const auto ambiguous = from_hex(captured_ambiguous_fo);
    std::array<std::uint8_t, 514> guarded{};
    guarded.fill(0xa5U);
    const auto before = guarded;
    std::size_t output_len = guarded.size() - 2U;
    REQUIRE(rohc_decompress4(decomp.get(), ambiguous.data(), ambiguous.size(),
                             guarded.data() + 1U, &output_len) == -1);
    REQUIRE(output_len == 0U);
    REQUIRE(guarded == before);

    rohccxx_feedback_v1_t feedback{};
    REQUIRE(rohc_decomp_get_feedback_v1(decomp.get(), &feedback) ==
            ROHCCXX_FEEDBACK_ACCEPTED);
    REQUIRE(feedback.cid == 9U);
    const auto expected_feedback = from_hex(captured_feedback);
    REQUIRE(feedback.raw_len == expected_feedback.size());
    REQUIRE(std::memcmp(feedback.raw, expected_feedback.data(), feedback.raw_len) == 0);
}

TEST_CASE("issue 43 compressor avoids formal collision for nonsequential IPv4 IDs")
{
    for(const std::uint32_t cid : {9U, 0U, 1U, 15U})
    {
        CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
        REQUIRE(comp);
        REQUIRE(decomp);
        REQUIRE(rohc_comp_set_mode(comp.get(), ROHCCXX_MODE_O) == 0);
        REQUIRE(rohc_decomp_set_mode(decomp.get(), ROHCCXX_MODE_O) == 0);

        for(std::size_t index = 0; index < captured_nonsequential_ip_id_flow.size(); ++index)
        {
            INFO("CID=" << cid << " INDEX=" << index);
            const auto packet = from_hex(captured_nonsequential_ip_id_flow[index]);
            const auto compressed = compress(comp.get(), cid, packet);
            require_exact_decode(decomp.get(), compressed, packet);
            if(cid == 9U && index + 1U == captured_nonsequential_ip_id_flow.size())
                REQUIRE(compressed == from_hex(captured_nonsequential_ip_id_final_fo));
        }
    }
}

TEST_CASE("issue 43 nonsequential IPv4 ID contexts remain isolated")
{
    CompPtr comp(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    REQUIRE(comp);
    REQUIRE(decomp);

    for(std::size_t index = 0; index < captured_nonsequential_ip_id_flow.size(); ++index)
    {
        for(const std::uint32_t cid : {1U, 15U})
        {
            INFO("CID=" << cid << " INDEX=" << index);
            const auto packet = from_hex(captured_nonsequential_ip_id_flow[index]);
            const auto compressed = compress(comp.get(), cid, packet);
            require_exact_decode(decomp.get(), compressed, packet);
        }
    }
}
