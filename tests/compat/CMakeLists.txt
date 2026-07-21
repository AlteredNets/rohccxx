# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

add_executable(test_compat_rtp test_rtp_compat.cpp)
add_executable(test_embedding_adapter test_embedding_adapter.cpp)

target_include_directories(test_compat_rtp PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/tests
    ${PROJECT_SOURCE_DIR}/tests/unit
    ${PROJECT_SOURCE_DIR}/tests/third_party/rohc-lib/src/common
    ${PROJECT_SOURCE_DIR}/tests/third_party/rohc-lib/src/common/protocols
)

target_link_libraries(test_compat_rtp
    Catch2::Catch2WithMain
    rohccxx
)

target_include_directories(test_embedding_adapter PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_embedding_adapter
    Catch2::Catch2WithMain
    rohccxx
)

include(Catch)
catch_discover_tests(test_compat_rtp
    DISCOVERY_MODE PRE_TEST
)

catch_discover_tests(test_embedding_adapter
    DISCOVERY_MODE PRE_TEST
)
