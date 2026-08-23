# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

if(NOT DEFINED ROHCCXX_SOURCE_DIR OR NOT DEFINED ROHCCXX_TEST_ROOT)
    message(FATAL_ERROR "ROHCCXX_SOURCE_DIR and ROHCCXX_TEST_ROOT are required")
endif()

function(assert_file_contains path expected)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Expected generated file does not exist: ${path}")
    endif()
    file(READ "${path}" contents)
    string(FIND "${contents}" "${expected}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "${path} does not contain expected text: ${expected}")
    endif()
endfunction()

function(configure_and_verify name source_dir expected_version)
    set(build_dir "${ROHCCXX_TEST_ROOT}/${name}-build")
    file(REMOVE_RECURSE "${build_dir}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${source_dir}"
            -B "${build_dir}"
            -DROHCCXX_BUILD_TESTS=OFF
            ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${name} configuration failed:\n${output}\n${error}")
    endif()

    string(FIND "${output}${error}" "rohccxx version: ${expected_version}" version_message)
    if(version_message EQUAL -1)
        message(FATAL_ERROR "${name} did not configure as ${expected_version}:\n${output}\n${error}")
    endif()

    string(REPLACE "." ";" version_parts "${expected_version}")
    list(GET version_parts 0 version_major)
    list(GET version_parts 1 version_minor)
    list(GET version_parts 2 version_patch)
    assert_file_contains("${build_dir}/generated/include/rohccxx/version.h"
        "#define ROHCCXX_VERSION_STRING \"${expected_version}\"")
    assert_file_contains("${build_dir}/generated/include/rohccxx/version.h"
        "#define ROHCCXX_VERSION_MAJOR ${version_major}")
    assert_file_contains("${build_dir}/generated/include/rohccxx/version.h"
        "#define ROHCCXX_VERSION_MINOR ${version_minor}")
    assert_file_contains("${build_dir}/generated/include/rohccxx/version.h"
        "#define ROHCCXX_VERSION_PATCH ${version_patch}")
    assert_file_contains("${build_dir}/rohccxxConfigVersion.cmake"
        "set(PACKAGE_VERSION \"${expected_version}\")")
    assert_file_contains("${build_dir}/CPackConfig.cmake"
        "set(CPACK_PACKAGE_VERSION \"${expected_version}\")")
    assert_file_contains("${build_dir}/CPackConfig.cmake"
        "set(CPACK_PACKAGE_FILE_NAME \"librohccxx-${expected_version}\")")
endfunction()

function(configure_must_fail name source_dir expected_error)
    set(build_dir "${ROHCCXX_TEST_ROOT}/${name}-build")
    file(REMOVE_RECURSE "${build_dir}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${source_dir}"
            -B "${build_dir}"
            -DROHCCXX_BUILD_TESTS=OFF
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(result EQUAL 0)
        message(FATAL_ERROR "${name} unexpectedly configured successfully")
    endif()
    string(FIND "${output}${error}" "${expected_error}" error_position)
    if(error_position EQUAL -1)
        message(FATAL_ERROR "${name} did not report expected error '${expected_error}':\n${output}\n${error}")
    endif()
endfunction()

file(REMOVE_RECURSE "${ROHCCXX_TEST_ROOT}")
file(MAKE_DIRECTORY "${ROHCCXX_TEST_ROOT}")

# The current checkout must resolve through its checked-in release metadata.
configure_and_verify(checkout "${ROHCCXX_SOURCE_DIR}" "0.2.2")

# Build the subset present in a source package without copying repository metadata.
set(source_copy "${ROHCCXX_TEST_ROOT}/source-copy")
file(MAKE_DIRECTORY "${source_copy}")
file(COPY
    "${ROHCCXX_SOURCE_DIR}/CMakeLists.txt"
    "${ROHCCXX_SOURCE_DIR}/VERSION"
    "${ROHCCXX_SOURCE_DIR}/LICENSE.md"
    "${ROHCCXX_SOURCE_DIR}/cmake"
    "${ROHCCXX_SOURCE_DIR}/include"
    "${ROHCCXX_SOURCE_DIR}/packaging"
    "${ROHCCXX_SOURCE_DIR}/src"
    DESTINATION "${source_copy}"
)
if(EXISTS "${source_copy}/.git")
    message(FATAL_ERROR "Source-package fixture unexpectedly contains .git")
endif()
configure_and_verify(source_package "${source_copy}" "0.2.2")

# An explicit value must retain highest precedence over checked-in metadata.
configure_and_verify(explicit_override "${source_copy}" "9.8.7"
    -DROHCCXX_VERSION=9.8.7
)

set(invalid_source "${ROHCCXX_TEST_ROOT}/invalid-source")
file(COPY "${source_copy}/" DESTINATION "${invalid_source}")
file(WRITE "${invalid_source}/VERSION" "not-a-version\n")
configure_must_fail(invalid_version "${invalid_source}"
    "Invalid rohccxx version 'not-a-version' from top-level VERSION file")

set(missing_source "${ROHCCXX_TEST_ROOT}/missing-source")
file(COPY "${source_copy}/" DESTINATION "${missing_source}")
file(REMOVE "${missing_source}/VERSION")
configure_must_fail(missing_version "${missing_source}"
    "Unable to determine rohccxx version")
