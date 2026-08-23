# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

foreach(_required IN ITEMS GENERATOR GENERATOR_MODE ORACLE ORACLE_MODE)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "Missing required launcher argument: ${_required}")
    endif()
endforeach()

string(RANDOM LENGTH 32 ALPHABET 0123456789abcdef _nonce)
set(_temporary_root "${CMAKE_CURRENT_BINARY_DIR}/Testing/Temporary")
set(_temporary_dir "${_temporary_root}/rohccxx-interop-${_nonce}")
set(_corpus_file "${_temporary_dir}/corpus.bin")

if(EXISTS "${_temporary_dir}")
    message(FATAL_ERROR "Refusing to reuse interoperability temporary path")
endif()
file(MAKE_DIRECTORY "${_temporary_dir}")

function(_cleanup_and_fail _summary)
    file(REMOVE_RECURSE "${_temporary_dir}")
    message(FATAL_ERROR "${_summary}")
endfunction()

execute_process(
    COMMAND "${GENERATOR}" "${GENERATOR_MODE}"
    RESULT_VARIABLE _generator_result
    OUTPUT_FILE "${_corpus_file}"
    ERROR_VARIABLE _generator_stderr
)

if(NOT _generator_result MATCHES "^-?[0-9]+$" OR
   NOT _generator_result EQUAL 0)
    if(EXISTS "${_corpus_file}")
        file(SIZE "${_corpus_file}" _generator_output_size)
    else()
        set(_generator_output_size 0)
    endif()
    string(CONCAT _generator_failure
        "Corpus generator failed (${_generator_result}); produced "
        "${_generator_output_size} bytes. Generator stderr:\n"
        "${_generator_stderr}")
    _cleanup_and_fail("${_generator_failure}")
endif()

execute_process(
    COMMAND "${ORACLE}" "${ORACLE_MODE}"
    RESULT_VARIABLE _oracle_result
    INPUT_FILE "${_corpus_file}"
    OUTPUT_VARIABLE _oracle_stdout
    ERROR_VARIABLE _oracle_stderr
)

if(NOT _oracle_result MATCHES "^-?[0-9]+$" OR NOT _oracle_result EQUAL 0)
    string(CONCAT _oracle_failure
        "External oracle failed (${_oracle_result}).\n"
        "Generator stderr:\n${_generator_stderr}\n"
        "Oracle stdout:\n${_oracle_stdout}\n"
        "Oracle stderr:\n${_oracle_stderr}")
    _cleanup_and_fail("${_oracle_failure}")
endif()

file(REMOVE_RECURSE "${_temporary_dir}")
if(EXISTS "${_temporary_dir}")
    message(FATAL_ERROR
        "Failed to clean interoperability temporary path: ${_temporary_dir}")
endif()

if(NOT _generator_stderr STREQUAL "")
    message(STATUS "Generator diagnostics:\n${_generator_stderr}")
endif()
if(NOT _oracle_stdout STREQUAL "")
    message(STATUS "Oracle output:\n${_oracle_stdout}")
endif()
if(NOT _oracle_stderr STREQUAL "")
    message(STATUS "Oracle diagnostics:\n${_oracle_stderr}")
endif()
