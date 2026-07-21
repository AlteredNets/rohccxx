// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include <catch2/catch_test_macros.hpp>
#include <rohccxx.h>
#include <rohccxx/version.h>

#include <cctype>
#include <cstring>

TEST_CASE("rohccxx exposes the configured library version", "[version][api]")
{
    const char* version = rohccxx_version_string();
    REQUIRE(version != nullptr);
    REQUIRE(std::strcmp(version, ROHCCXX_VERSION_STRING) == 0);
    REQUIRE(rohccxx_version_major() == ROHCCXX_VERSION_MAJOR);
    REQUIRE(rohccxx_version_minor() == ROHCCXX_VERSION_MINOR);
    REQUIRE(rohccxx_version_patch() == ROHCCXX_VERSION_PATCH);

    size_t dot_count = 0;
    size_t digit_count = 0;
    for(const char* p = version; *p != '\0'; ++p)
    {
        const unsigned char ch = static_cast<unsigned char>(*p);
        if(*p == '.')
        {
            ++dot_count;
        }
        else
        {
            REQUIRE(std::isdigit(ch) != 0);
            ++digit_count;
        }
    }

    REQUIRE(dot_count == 2);
    REQUIRE(digit_count >= 3);
}
