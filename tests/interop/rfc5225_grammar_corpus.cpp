// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "rohccxx/core/rfc5225_grammar.hpp"

#include <cstdint>
#include <cstdio>

namespace
{

void print_hex16(std::uint16_t value)
{
    std::printf("0x%04x", static_cast<unsigned>(value));
}

void print_mask_name(bool& first, const char* name)
{
    if(!first)
        std::putchar(',');
    std::fputs(name, stdout);
    first = false;
}

void print_cid_modes(std::uint32_t mask)
{
    bool first = true;
    if(mask & rohccxx::rfc5225::grammar::CidSmall)
        print_mask_name(first, "small");
    if(mask & rohccxx::rfc5225::grammar::CidAdd)
        print_mask_name(first, "add");
    if(mask & rohccxx::rfc5225::grammar::CidLarge)
        print_mask_name(first, "large");
    if(first)
        std::fputs("none", stdout);
}

void print_chains(std::uint32_t mask)
{
    namespace grammar = rohccxx::rfc5225::grammar;
    bool first = true;
    if(mask & grammar::ChainIPv4Static) print_mask_name(first, "ipv4_static");
    if(mask & grammar::ChainIPv4Dynamic) print_mask_name(first, "ipv4_dynamic");
    if(mask & grammar::ChainIPv4Options) print_mask_name(first, "ipv4_options");
    if(mask & grammar::ChainIPv6Static) print_mask_name(first, "ipv6_static");
    if(mask & grammar::ChainIPv6Dynamic) print_mask_name(first, "ipv6_dynamic");
    if(mask & grammar::ChainIPv6Extensions) print_mask_name(first, "ipv6_extensions");
    if(mask & grammar::ChainUDPStatic) print_mask_name(first, "udp_static");
    if(mask & grammar::ChainUDPDynamic) print_mask_name(first, "udp_dynamic");
    if(mask & grammar::ChainUDPLiteDynamic) print_mask_name(first, "udplite_dynamic");
    if(mask & grammar::ChainRTPStatic) print_mask_name(first, "rtp_static");
    if(mask & grammar::ChainRTPDynamic) print_mask_name(first, "rtp_dynamic");
    if(mask & grammar::ChainRTPCsrcList) print_mask_name(first, "rtp_csrc_list");
    if(mask & grammar::ChainRTPExtension) print_mask_name(first, "rtp_extension");
    if(mask & grammar::ChainRTPPadding) print_mask_name(first, "rtp_padding");
    if(mask & grammar::ChainESPFields) print_mask_name(first, "esp_fields");
    if(first)
        std::fputs("none", stdout);
}

void print_encodings(std::uint32_t mask)
{
    namespace grammar = rohccxx::rfc5225::grammar;
    bool first = true;
    if(mask & grammar::EncodingCRC3) print_mask_name(first, "crc3");
    if(mask & grammar::EncodingCRC7) print_mask_name(first, "crc7");
    if(mask & grammar::EncodingCRC8) print_mask_name(first, "crc8");
    if(mask & grammar::EncodingWLSB) print_mask_name(first, "w_lsb");
    if(mask & grammar::EncodingScaledTimestamp) print_mask_name(first, "scaled_timestamp");
    if(mask & grammar::EncodingTimerTimestamp) print_mask_name(first, "timer_timestamp");
    if(mask & grammar::EncodingOffsetIpId) print_mask_name(first, "offset_ip_id");
    if(mask & grammar::EncodingSDVL) print_mask_name(first, "sdvl");
    if(mask & grammar::EncodingListCompression) print_mask_name(first, "list_compression");
    if(first)
        std::fputs("none", stdout);
}

const char* profile_name(rohccxx::Profile profile)
{
    const auto* row = rohccxx::rfc5225::grammar::find_profile(profile);
    return row ? row->name : "framework";
}

bool validate_manifest()
{
    namespace grammar = rohccxx::rfc5225::grammar;
    if(grammar::profile_count() != 6 || grammar::case_count() != 36)
        return false;
    if(grammar::co_variant_count() != 52 ||
       grammar::count_co_variants(grammar::CaseStatus::Implemented) != 52 ||
       grammar::count_co_variants(grammar::CaseStatus::Planned) != 0)
    {
        return false;
    }
    if((grammar::manifest_cid_mode_mask() & grammar::CidAll) != grammar::CidAll)
        return false;
    if((grammar::manifest_encoding_mask() & grammar::all_required_encodings) != grammar::all_required_encodings)
        return false;
    for(const auto& profile : grammar::profile_manifest)
    {
        if(!grammar::has_case(profile.profile, grammar::PacketFamily::IR, grammar::CaseStatus::Implemented) ||
           !grammar::has_case(profile.profile, grammar::PacketFamily::IR_DYN, grammar::CaseStatus::Implemented) ||
           !grammar::has_case(profile.profile, grammar::PacketFamily::CO, grammar::CaseStatus::Implemented))
        {
            return false;
        }
    }
    return true;
}

} // namespace

int main()
{
    namespace grammar = rohccxx::rfc5225::grammar;
    if(!validate_manifest())
        return 1;

    std::printf("rohccxx-rfc5225-grammar-corpus-v2 profiles=%zu cases=%zu co_variants=%zu encoding=text\n",
                grammar::profile_count(),
                grammar::case_count(),
                grammar::co_variant_count());

    for(const auto& row : grammar::case_manifest)
    {
        std::printf("case id=%s profile=%s profile_id=", row.id, profile_name(row.profile));
        print_hex16(static_cast<std::uint16_t>(row.profile));
        std::printf(" family=%s kind=%s status=%s packet_type=0x%02x section=%s cid_modes=",
                    grammar::to_string(row.family),
                    grammar::to_string(row.kind),
                    grammar::to_string(row.status),
                    static_cast<unsigned>(row.packet_type),
                    row.rfc_section);
        print_cid_modes(row.cid_modes);
        std::printf(" chains=");
        print_chains(row.chains);
        std::printf(" encodings=");
        print_encodings(row.encodings);
        std::printf(" description=\"");
        std::fputs(row.description, stdout);
        std::printf("\"\n");
    }

    for(const auto& row : grammar::co_variant_manifest)
    {
        std::printf("co_variant id=%s profile=%s profile_id=", row.id, profile_name(row.profile));
        print_hex16(static_cast<std::uint16_t>(row.profile));
        std::printf(" status=%s packet_type=0x%02x discriminator=%s section=%s cid_modes=",
                    grammar::to_string(row.status),
                    static_cast<unsigned>(row.packet_type),
                    row.discriminator,
                    row.rfc_section);
        print_cid_modes(row.cid_modes);
        std::printf(" chains=");
        print_chains(row.chains);
        std::printf(" encodings=");
        print_encodings(row.encodings);
        std::printf(" description=\"");
        std::fputs(row.description, stdout);
        std::printf("\"\n");
    }

    return 0;
}
