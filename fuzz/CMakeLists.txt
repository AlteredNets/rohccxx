# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set(ROHCCXX_FUZZER_FLAGS
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all
    -g
    -O1
)

function(rohccxx_add_fuzzer name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE rohccxx rohccxx_tunnel_support)
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_options(${name} PRIVATE ${ROHCCXX_FUZZER_FLAGS} -Wall -Wextra -Wpedantic)
    target_link_options(${name} PRIVATE ${ROHCCXX_FUZZER_FLAGS})
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)
endfunction()

rohccxx_add_fuzzer(fuzz_stateless_decompress stateless_decompress.cpp)
rohccxx_add_fuzzer(fuzz_stateful_decompress stateful_decompress.cpp)
rohccxx_add_fuzzer(fuzz_structured_roundtrip structured_roundtrip.cpp)
rohccxx_add_fuzzer(fuzz_tunnel_parser tunnel_parser.cpp)
