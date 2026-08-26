# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

add_executable(stub_test dummy.cpp)


# -----------------------------
# Unit Tests (existing)
# -----------------------------
add_executable(unit_tests 
    unit/test_packet_parse.cpp
    unit/test_pt0_dispatch.cpp
    unit/test_rfc5225_grammar.cpp
    unit/test_encoding_methods.cpp
    unit/test_version.cpp
    unit/test_rfc3243_zero_byte.cpp
    unit/test_context_table.cpp
    unit/test_sprint5_basic.cpp
    unit/test_sprint6_roundtrip.cpp
    unit/test_sprint7_crcs.cpp
    unit/test_sliding_windows.cpp
    unit/test_linux_tun_tunnel.cpp
)

target_link_libraries(unit_tests
    Catch2::Catch2WithMain
    rohccxx
    rohccxx_tunnel_support
)

include(Catch)
catch_discover_tests(unit_tests
    DISCOVERY_MODE PRE_TEST
)

# -----------------------------
# Sprint 10 Interop Tests
# -----------------------------

add_subdirectory(third_party)
add_subdirectory(interop)
add_subdirectory(compat)
add_subdirectory(rfc3243)

add_test(NAME version_resolution_and_source_package_metadata
    COMMAND ${CMAKE_COMMAND}
        -DROHCCXX_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -DROHCCXX_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/version-resolution
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_version_resolution.cmake
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME linux_tun_tunnel_network_namespaces
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/integration/linux_tun_tunnel_netns.sh
                $<TARGET_FILE:rohccxx-tun-tunnel>)
    set_tests_properties(linux_tun_tunnel_network_namespaces PROPERTIES
        LABELS "linux;integration;privileged"
        SKIP_RETURN_CODE 77
        TIMEOUT 60)
endif()
set_tests_properties(version_resolution_and_source_package_metadata PROPERTIES
    LABELS "version;packaging"
    TIMEOUT 120
)


# -----------------------------
# Quality Gates: TSAN and Valgrind
# -----------------------------

set(ROHCCXX_THREAD_SAFETY_TEST_SPECS
    "ROHC C API supports independent instances on concurrent threads"
    "ROHC C API serializes shared instance configuration and compression"
    "ROHCCXX C++ API supports independent instances on concurrent threads"
    "ROHCCXX C++ API serializes shared compressor and decompressor instances"
    "ROHC thread safety handles one independent traffic source per CPU core"
)

if(ROHCCXX_THREAD_SANITIZER)
    set(_tsan_index 0)
    foreach(_test_spec IN LISTS ROHCCXX_THREAD_SAFETY_TEST_SPECS)
        math(EXPR _tsan_index "${_tsan_index} + 1")
        add_test(NAME quality_tsan_thread_safety_${_tsan_index}
            COMMAND $<TARGET_FILE:unit_tests> "${_test_spec}"
        )
        set_tests_properties(quality_tsan_thread_safety_${_tsan_index} PROPERTIES
            LABELS "quality;tsan;thread-safety"
            ENVIRONMENT "TSAN_OPTIONS=halt_on_error=1:history_size=7:second_deadlock_stack=1"
        )
    endforeach()
endif()

if(ROHCCXX_ENABLE_VALGRIND_TESTS)
    set(ROHCCXX_VALGRIND_COMMON_OPTIONS
        --tool=memcheck
        --leak-check=full
        --show-leak-kinds=definite,indirect
        --errors-for-leak-kinds=definite,indirect
        --track-origins=yes
        --error-exitcode=99
        --quiet
    )

    function(rohccxx_add_valgrind_unit_test name test_spec)
        add_test(NAME ${name}
            COMMAND ${VALGRIND_EXECUTABLE} ${ROHCCXX_VALGRIND_COMMON_OPTIONS}
                    $<TARGET_FILE:unit_tests> "${test_spec}"
        )
        set_tests_properties(${name} PROPERTIES
            LABELS "quality;valgrind;memcheck"
            TIMEOUT 180
        )
    endfunction()

    rohccxx_add_valgrind_unit_test(quality_valgrind_parse_minimal
        "Parse minimal IPv4/UDP/RTP packet")
    rohccxx_add_valgrind_unit_test(quality_valgrind_uncompressed_roundtrip
        "ROHC uncompressed profile round-trips IPv4 and IPv6 packets")
    rohccxx_add_valgrind_unit_test(quality_valgrind_segmentation_reassembly
        "ROHC RFC 5795 segmentation reassembles negotiated streams")
    rohccxx_add_valgrind_unit_test(quality_valgrind_rfc4362_context_packets
        "ROHC RFC 4362 CSP and CCP synchronize and verify context")
    rohccxx_add_valgrind_unit_test(quality_valgrind_rohcoipsec_icv
        "ROHCoIPsec keyed ICV uses HMAC-SHA-256 and verifies truncation")

    set(_valgrind_thread_index 0)
    foreach(_test_spec IN LISTS ROHCCXX_THREAD_SAFETY_TEST_SPECS)
        math(EXPR _valgrind_thread_index "${_valgrind_thread_index} + 1")
        add_test(NAME quality_valgrind_thread_safety_${_valgrind_thread_index}
            COMMAND ${VALGRIND_EXECUTABLE} ${ROHCCXX_VALGRIND_COMMON_OPTIONS}
                    $<TARGET_FILE:unit_tests> "${_test_spec}"
        )
        set_tests_properties(quality_valgrind_thread_safety_${_valgrind_thread_index} PROPERTIES
            LABELS "quality;valgrind;memcheck;thread-safety"
            TIMEOUT 240
        )
    endforeach()

    add_test(NAME quality_valgrind_rfc3243_conformance
        COMMAND ${VALGRIND_EXECUTABLE} ${ROHCCXX_VALGRIND_COMMON_OPTIONS}
                $<TARGET_FILE:test_rfc3243_conformance>
    )
    set_tests_properties(quality_valgrind_rfc3243_conformance PROPERTIES
        LABELS "quality;valgrind;memcheck;rfc3243"
        TIMEOUT 180
    )
endif()
