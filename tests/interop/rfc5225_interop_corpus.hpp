// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#pragma once

#include "test_packet_helpers.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rfc5225_interop
{

constexpr std::size_t packet_size = 64;
constexpr std::size_t max_rohc_size = 512;
constexpr std::size_t profile_count = 4;
constexpr std::size_t packets_per_profile = 3;
constexpr std::size_t co_packets_per_profile = 20;

enum class Profile : std::size_t
{
    Rtp = 0,
    Udp,
    Esp,
    Ip,
};

struct ProfileSpec
{
    Profile profile;
    const char* name;
    std::uint16_t id;
};

constexpr std::array<ProfileSpec, profile_count> profiles{{
    {Profile::Rtp, "rtp_udp_ip", 0x0101},
    {Profile::Udp, "udp_ip", 0x0102},
    {Profile::Esp, "esp_ip", 0x0103},
    {Profile::Ip, "ip_only", 0x0104},
}};

inline void finish_ipv4(std::uint8_t* packet)
{
    packet[10] = 0;
    packet[11] = 0;
    const std::uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = static_cast<std::uint8_t>(checksum >> 8);
    packet[11] = static_cast<std::uint8_t>(checksum & 0xffU);
}

inline void make_packet(Profile profile, int step, std::uint8_t* packet)
{
    make_valid_rtp(packet,
                   static_cast<std::uint16_t>(1000 + step),
                   static_cast<std::uint32_t>(160000 + step * 160),
                   0x11223344U);
    packet[4] = static_cast<std::uint8_t>(0x12U + step);
    packet[5] = static_cast<std::uint8_t>(0x30U + step);
    for(std::size_t i = 40; i < packet_size; ++i)
        packet[i] = static_cast<std::uint8_t>(0xa0U + ((i + static_cast<std::size_t>(step)) & 0x0fU));

    switch(profile)
    {
    case Profile::Rtp:
        break;
    case Profile::Udp:
        packet[28] = 0x01;
        packet[29] = static_cast<std::uint8_t>(0x20U + step);
        break;
    case Profile::Esp:
        packet[9] = 50;
        packet[20] = 0xde;
        packet[21] = 0xad;
        packet[22] = 0xbe;
        packet[23] = 0xef;
        packet[24] = 0x00;
        packet[25] = 0x00;
        packet[26] = 0x00;
        packet[27] = static_cast<std::uint8_t>(1 + step);
        break;
    case Profile::Ip:
        packet[9] = 6;
        packet[20] = 0x45;
        packet[21] = static_cast<std::uint8_t>(0x10U + step);
        break;
    }
    finish_ipv4(packet);
}

inline void make_co_packet(Profile profile, int step, std::uint8_t* packet)
{
    make_packet(profile, step, packet);
    const std::uint16_t ip_id = static_cast<std::uint16_t>(0x7230U + step);
    packet[4] = static_cast<std::uint8_t>(ip_id >> 8U);
    packet[5] = static_cast<std::uint8_t>(ip_id & 0xffU);
    if(profile == Profile::Esp)
    {
        const std::uint32_t sequence = static_cast<std::uint32_t>(0xfffffff8U +
                                                                  static_cast<std::uint32_t>(step));
        packet[24] = static_cast<std::uint8_t>(sequence >> 24U);
        packet[25] = static_cast<std::uint8_t>(sequence >> 16U);
        packet[26] = static_cast<std::uint8_t>(sequence >> 8U);
        packet[27] = static_cast<std::uint8_t>(sequence);
    }
    finish_ipv4(packet);
}

inline void print_hex(const std::uint8_t* data, std::size_t length)
{
    static constexpr char digits[] = "0123456789abcdef";
    for(std::size_t i = 0; i < length; ++i)
    {
        std::putchar(digits[data[i] >> 4]);
        std::putchar(digits[data[i] & 0x0fU]);
    }
}

inline void emit_header()
{
    std::puts("rohccxx-rohclib-rfc5225-corpus-v1 profiles=4 packets_per_profile=3 encoding=hex");
}

inline void emit_co_header()
{
    std::puts("rohccxx-rohclib-rfc5225-co-corpus-v1 profiles=4 packets_per_profile=20 encoding=hex");
}

inline void emit_case(const ProfileSpec& profile,
                      int step,
                      const std::uint8_t* ip,
                      const std::uint8_t* rohc,
                      std::size_t rohc_length)
{
    std::printf("case profile=%s step=%d ip_len=%zu rohc_len=%zu ip=",
                profile.name,
                step,
                packet_size,
                rohc_length);
    print_hex(ip, packet_size);
    std::printf(" rohc=");
    print_hex(rohc, rohc_length);
    std::putchar('\n');
}

struct CorpusCase
{
    const ProfileSpec* profile = nullptr;
    int step = -1;
    std::array<std::uint8_t, packet_size> ip{};
    std::array<std::uint8_t, max_rohc_size> rohc{};
    std::size_t rohc_length = 0;
};

inline int hex_value(char ch)
{
    if(ch >= '0' && ch <= '9') return ch - '0';
    if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

inline bool parse_size(const char* text, std::size_t& value)
{
    if(!text || *text == '\0') return false;
    value = 0;
    for(const char* pos = text; *pos != '\0'; ++pos)
    {
        if(*pos < '0' || *pos > '9') return false;
        const std::size_t digit = static_cast<std::size_t>(*pos - '0');
        if(value > (static_cast<std::size_t>(-1) - digit) / 10U) return false;
        value = value * 10U + digit;
    }
    return true;
}

inline bool decode_hex(const char* text, std::uint8_t* output, std::size_t expected_length)
{
    if(!text || std::strlen(text) != expected_length * 2U) return false;
    for(std::size_t i = 0; i < expected_length; ++i)
    {
        const int high = hex_value(text[i * 2U]);
        const int low = hex_value(text[i * 2U + 1U]);
        if(high < 0 || low < 0) return false;
        output[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

inline bool parse_case_line(char* line,
                            const ProfileSpec& expected_profile,
                            int expected_step,
                            CorpusCase& result)
{
    const std::size_t length = std::strlen(line);
    if(length == 0 || line[length - 1] != '\n') return false;
    line[length - 1] = '\0';
    if(length > 1 && line[length - 2] == '\r') line[length - 2] = '\0';

    const char* tokens[7] = {};
    std::size_t token_count = 0;
    char* cursor = line;
    while(*cursor != '\0')
    {
        if(*cursor == ' ' || token_count == 7) return false;
        tokens[token_count++] = cursor;
        while(*cursor != '\0' && *cursor != ' ') ++cursor;
        if(*cursor == ' ')
        {
            *cursor++ = '\0';
            if(*cursor == '\0') return false;
        }
    }
    if(token_count != 7 || std::strcmp(tokens[0], "case") != 0) return false;

    constexpr const char* prefixes[] = {"profile=", "step=", "ip_len=", "rohc_len=", "ip=", "rohc="};
    for(std::size_t i = 0; i < 6; ++i)
    {
        if(std::strncmp(tokens[i + 1], prefixes[i], std::strlen(prefixes[i])) != 0) return false;
    }

    const char* profile_name = tokens[1] + std::strlen(prefixes[0]);
    if(std::strcmp(profile_name, expected_profile.name) != 0) return false;

    std::size_t step = 0;
    std::size_t ip_length = 0;
    std::size_t rohc_length = 0;
    if(!parse_size(tokens[2] + std::strlen(prefixes[1]), step) ||
       !parse_size(tokens[3] + std::strlen(prefixes[2]), ip_length) ||
       !parse_size(tokens[4] + std::strlen(prefixes[3]), rohc_length) ||
       step != static_cast<std::size_t>(expected_step) ||
       ip_length != packet_size || rohc_length == 0 || rohc_length > max_rohc_size)
    {
        return false;
    }

    result.profile = &expected_profile;
    result.step = expected_step;
    result.rohc_length = rohc_length;
    return decode_hex(tokens[5] + std::strlen(prefixes[4]), result.ip.data(), ip_length) &&
           decode_hex(tokens[6] + std::strlen(prefixes[5]), result.rohc.data(), rohc_length);
}

template<typename Consumer>
bool consume_corpus(Consumer&& consumer)
{
    char line[4096] = {};
    if(!std::fgets(line, sizeof(line), stdin) ||
       std::strcmp(line, "rohccxx-rohclib-rfc5225-corpus-v1 profiles=4 packets_per_profile=3 encoding=hex\n") != 0)
    {
        std::fprintf(stderr, "invalid RFC 5225 interoperability corpus header\n");
        return false;
    }

    for(const auto& profile : profiles)
    {
        for(int step = 0; step < static_cast<int>(packets_per_profile); ++step)
        {
            if(!std::fgets(line, sizeof(line), stdin))
            {
                std::fprintf(stderr, "missing case for profile=%s step=%d\n", profile.name, step);
                return false;
            }
            CorpusCase corpus_case{};
            if(!parse_case_line(line, profile, step, corpus_case))
            {
                std::fprintf(stderr, "invalid or out-of-order case for profile=%s step=%d\n", profile.name, step);
                return false;
            }
            if(!consumer(corpus_case)) return false;
        }
    }

    if(std::fgets(line, sizeof(line), stdin) != nullptr)
    {
        std::fprintf(stderr, "unexpected trailing corpus input\n");
        return false;
    }
    return !std::ferror(stdin);
}

template<typename Consumer>
bool consume_co_corpus(Consumer&& consumer)
{
    char line[4096] = {};
    if(!std::fgets(line, sizeof(line), stdin) ||
       std::strcmp(line, "rohccxx-rohclib-rfc5225-co-corpus-v1 profiles=4 packets_per_profile=20 encoding=hex\n") != 0)
    {
        std::fprintf(stderr, "invalid RFC 5225 CO interoperability corpus header\n");
        return false;
    }
    for(const auto& profile : profiles)
    {
        for(int step = 0; step < static_cast<int>(co_packets_per_profile); ++step)
        {
            if(!std::fgets(line, sizeof(line), stdin)) return false;
            CorpusCase corpus_case{};
            if(!parse_case_line(line, profile, step, corpus_case) || !consumer(corpus_case))
                return false;
        }
    }
    return std::fgets(line, sizeof(line), stdin) == nullptr && !std::ferror(stdin);
}

} // namespace rfc5225_interop
