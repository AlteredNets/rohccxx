# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

add_executable(test_rfc3243_conformance
    test_rfc3243_conformance.cpp
)

target_link_libraries(test_rfc3243_conformance
    Catch2::Catch2WithMain
    rohccxx
)

target_include_directories(test_rfc3243_conformance PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/tests/rfc3243
)

include(Catch)
catch_discover_tests(test_rfc3243_conformance
    DISCOVERY_MODE PRE_TEST
)
