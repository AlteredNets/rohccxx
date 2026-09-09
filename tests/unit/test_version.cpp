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

    size_t core_dot_count = 0;
    size_t digit_count = 0;
    size_t prerelease_count = 0;
    bool in_prerelease = false;
    for(const char* p = version; *p != '\0'; ++p)
    {
        const unsigned char ch = static_cast<unsigned char>(*p);
        if(!in_prerelease && *p == '-')
        {
            in_prerelease = true;
        }
        else if(!in_prerelease && *p == '.')
        {
            ++core_dot_count;
        }
        else if(!in_prerelease)
        {
            REQUIRE(std::isdigit(ch) != 0);
            ++digit_count;
        }
        else
        {
            REQUIRE(std::isalnum(ch) != 0 || *p == '.' || *p == '-');
            ++prerelease_count;
        }
    }

    REQUIRE(core_dot_count == 2);
    REQUIRE(digit_count >= 3);
    if(in_prerelease)
    {
        REQUIRE(prerelease_count > 0);
    }
}
