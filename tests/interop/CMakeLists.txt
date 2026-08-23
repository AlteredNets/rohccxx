# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.


add_executable(rohccxx_emit rohccxx_emit.cpp)
target_link_libraries(rohccxx_emit rohccxx)
target_include_directories(rohccxx_emit PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/core
    ${PROJECT_SOURCE_DIR}/tests
    ${PROJECT_SOURCE_DIR}/tests/unit
)

add_executable(rohclib_decode rohclib_decode.cpp)
target_include_directories(rohclib_decode PRIVATE
    ${ROHC_LIB_INCLUDE_DIR}
)
target_link_libraries(rohclib_decode
    ${ROHC_LIB_ARCHIVE}
)
add_dependencies(rohclib_decode rohc_lib)

add_executable(rohclib_emit rohclib_emit.cpp)
target_include_directories(rohclib_emit PRIVATE
    ${PROJECT_SOURCE_DIR}/tests
    ${PROJECT_SOURCE_DIR}/tests/unit
    ${ROHC_LIB_INCLUDE_DIR}
)
target_link_libraries(rohclib_emit
    ${ROHC_LIB_ARCHIVE}
)
add_dependencies(rohclib_emit rohc_lib)

add_executable(rohccxx_decode rohccxx_decode.cpp)
target_link_libraries(rohccxx_decode rohccxx)

add_test(NAME interop_rohcxx_to_rohclib
    COMMAND sh -c "$<TARGET_FILE:rohccxx_emit> | $<TARGET_FILE:rohclib_decode>"
)

add_test(NAME interop_rohclib_to_rohcxx
    COMMAND sh -c "$<TARGET_FILE:rohclib_emit> | $<TARGET_FILE:rohccxx_decode>"
)

add_executable(rohccxx_rfc5225_interop rohccxx_rfc5225_interop.cpp)
target_link_libraries(rohccxx_rfc5225_interop rohccxx)
target_include_directories(rohccxx_rfc5225_interop PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/tests/unit
)

add_executable(rohclib_rfc5225_interop rohclib_rfc5225_interop.cpp)
target_include_directories(rohclib_rfc5225_interop PRIVATE
    ${PROJECT_SOURCE_DIR}/tests
    ${PROJECT_SOURCE_DIR}/tests/unit
    ${ROHC_LIB_INCLUDE_DIR}
)
target_link_libraries(rohclib_rfc5225_interop ${ROHC_LIB_ARCHIVE})
add_dependencies(rohclib_rfc5225_interop rohc_lib)

add_test(NAME interop_rfc5225_rohccxx_to_rohclib
    COMMAND sh -c "$<TARGET_FILE:rohccxx_rfc5225_interop> emit | $<TARGET_FILE:rohclib_rfc5225_interop> decode"
)

add_test(NAME interop_rfc5225_rohclib_to_rohccxx
    COMMAND sh -c "$<TARGET_FILE:rohclib_rfc5225_interop> emit | $<TARGET_FILE:rohccxx_rfc5225_interop> decode"
)

add_test(NAME interop_rfc5225_co_rohccxx_to_rohclib
    COMMAND ${CMAKE_COMMAND}
        -DGENERATOR=$<TARGET_FILE:rohccxx_rfc5225_interop>
        -DGENERATOR_MODE=emit-co
        -DORACLE=$<TARGET_FILE:rohclib_rfc5225_interop>
        -DORACLE_MODE=decode-co
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_corpus_oracle.cmake
)

add_test(NAME interop_rfc5225_co_rohclib_to_rohccxx
    COMMAND ${CMAKE_COMMAND}
        -DGENERATOR=$<TARGET_FILE:rohclib_rfc5225_interop>
        -DGENERATOR_MODE=emit-co
        -DORACLE=$<TARGET_FILE:rohccxx_rfc5225_interop>
        -DORACLE_MODE=decode-co
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_corpus_oracle.cmake
)

# Keep mandatory interoperability launchers independent of shell pipeline
# semantics. In particular, /bin/sh is dash on GitHub's Linux runners.
file(READ "${CMAKE_CURRENT_LIST_FILE}" _interop_cmake_source)
if(_interop_cmake_source MATCHES "set[ \t]+-o[ \t]+pipefail" OR
   _interop_cmake_source MATCHES
       "add_test\\(NAME[ \t]+interop_rfc5225_co_[^)]*COMMAND[ \t]+sh")
    message(FATAL_ERROR
        "Mandatory CO interop tests must use run_corpus_oracle.cmake, not a shell pipeline")
endif()

add_executable(rohccxx_oracle_corpus rohccxx_oracle_corpus.cpp)
target_link_libraries(rohccxx_oracle_corpus rohccxx)
target_include_directories(rohccxx_oracle_corpus PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/tests/unit
)

add_test(NAME interop_rohcv2_oracle_corpus
    COMMAND $<TARGET_FILE:rohccxx_oracle_corpus>
)

add_test(NAME interop_external_rohcv2_oracle_optional
    COMMAND sh -c "if [ -z \"$ROHCCXX_EXTERNAL_ORACLE\" ]; then exit 77; fi; \"$1\" | $ROHCCXX_EXTERNAL_ORACLE" sh $<TARGET_FILE:rohccxx_oracle_corpus>
)
set_tests_properties(interop_external_rohcv2_oracle_optional PROPERTIES
    SKIP_RETURN_CODE 77
)


add_executable(rfc5225_grammar_corpus rfc5225_grammar_corpus.cpp)
target_link_libraries(rfc5225_grammar_corpus rohccxx)
target_include_directories(rfc5225_grammar_corpus PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

add_test(NAME interop_rfc5225_grammar_corpus
    COMMAND $<TARGET_FILE:rfc5225_grammar_corpus>
)


add_executable(rfc5225_ir_corpus rfc5225_ir_corpus.cpp)
target_link_libraries(rfc5225_ir_corpus rohccxx)
target_include_directories(rfc5225_ir_corpus PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

add_test(NAME interop_rfc5225_ir_corpus
    COMMAND $<TARGET_FILE:rfc5225_ir_corpus>
)


add_executable(rfc5225_co_corpus rfc5225_co_corpus.cpp)
target_link_libraries(rfc5225_co_corpus rohccxx)
target_include_directories(rfc5225_co_corpus PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

add_test(NAME interop_rfc5225_co_corpus
    COMMAND $<TARGET_FILE:rfc5225_co_corpus>
)

add_test(NAME interop_external_rfc5225_co_oracle_optional
    COMMAND sh -c "if [ -z \"$ROHCCXX_RFC5225_CO_ORACLE\" ]; then exit 77; fi; \"$1\" | $ROHCCXX_RFC5225_CO_ORACLE" sh $<TARGET_FILE:rfc5225_co_corpus>
)
set_tests_properties(interop_external_rfc5225_co_oracle_optional PROPERTIES
    SKIP_RETURN_CODE 77
)


add_executable(rfc4362_oracle_corpus rfc4362_oracle_corpus.cpp)
target_link_libraries(rfc4362_oracle_corpus rohccxx)
target_include_directories(rfc4362_oracle_corpus PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

add_test(NAME interop_rfc4362_oracle_corpus
    COMMAND $<TARGET_FILE:rfc4362_oracle_corpus>
)

add_test(NAME interop_external_rfc4362_oracle_optional
    COMMAND sh -c "if [ -z \"$ROHCCXX_RFC4362_ORACLE\" ]; then exit 77; fi; \"$1\" | $ROHCCXX_RFC4362_ORACLE" sh $<TARGET_FILE:rfc4362_oracle_corpus>
)
set_tests_properties(interop_external_rfc4362_oracle_optional PROPERTIES
    SKIP_RETURN_CODE 77
)
