# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

cmake_minimum_required(VERSION 3.16)

set(ROHCCXX_VERSION "" CACHE STRING "Override the rohccxx release version; otherwise use an exact git tag or VERSION file")
set(_rohccxx_version_source "explicit ROHCCXX_VERSION override")

if(ROHCCXX_VERSION STREQUAL "")
    set(_rohccxx_version_source "")
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --exact-match HEAD
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE _rohccxx_git_tag_result
            OUTPUT_VARIABLE _rohccxx_git_tag
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )

        if(_rohccxx_git_tag_result EQUAL 0)
            string(REGEX REPLACE "^v" "" _rohccxx_git_version "${_rohccxx_git_tag}")
            if(_rohccxx_git_version MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
                set(ROHCCXX_VERSION "${_rohccxx_git_version}")
                set(_rohccxx_version_source "exact git tag '${_rohccxx_git_tag}'")
            else()
                message(WARNING "Ignoring non-semver rohccxx git tag '${_rohccxx_git_tag}'")
            endif()
        endif()
    endif()

    if(ROHCCXX_VERSION STREQUAL "")
        set(_rohccxx_version_file "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
        if(EXISTS "${_rohccxx_version_file}")
            file(READ "${_rohccxx_version_file}" ROHCCXX_VERSION)
            string(STRIP "${ROHCCXX_VERSION}" ROHCCXX_VERSION)
            set(_rohccxx_version_source "top-level VERSION file")
        endif()
    endif()

    if(ROHCCXX_VERSION STREQUAL "")
        message(FATAL_ERROR
            "Unable to determine rohccxx version: provide -DROHCCXX_VERSION=X.Y.Z, "
            "an exact semantic version git tag at HEAD, or a valid top-level VERSION file"
        )
    endif()
endif()

if(NOT ROHCCXX_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR
        "Invalid rohccxx version '${ROHCCXX_VERSION}' from ${_rohccxx_version_source}; "
        "expected numeric semantic version X.Y.Z"
    )
endif()

project(rohccxx VERSION ${ROHCCXX_VERSION} LANGUAGES C CXX)
message(STATUS "rohccxx version: ${PROJECT_VERSION}")

include(GNUInstallDirs)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(ROHCCXX_BUILD_SHARED "Build shared library" ON)
option(ROHCCXX_BUILD_STATIC "Build static library" ON)
option(ROHCCXX_BUILD_TESTS "Build tests" OFF)
option(ROHCCXX_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ROHCCXX_THREAD_SANITIZER "Build with ThreadSanitizer" OFF)
option(ROHCCXX_ENABLE_VALGRIND_TESTS "Add Valgrind-backed CTest memory tests" OFF)

if(ROHCCXX_SANITIZERS AND ROHCCXX_THREAD_SANITIZER)
    message(FATAL_ERROR "ROHCCXX_SANITIZERS and ROHCCXX_THREAD_SANITIZER are mutually exclusive")
endif()

if((ROHCCXX_SANITIZERS OR ROHCCXX_THREAD_SANITIZER) AND NOT MSVC)
    if(ROHCCXX_THREAD_SANITIZER)
        add_compile_options(-fsanitize=thread -g -O1)
        add_link_options(-fsanitize=thread)
    else()
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/rohccxx_version.h.in
    ${PROJECT_BINARY_DIR}/generated/include/rohccxx/version.h
    @ONLY
)

add_subdirectory(src)
if(ROHCCXX_BUILD_TESTS)
    if(ROHCCXX_ENABLE_VALGRIND_TESTS)
        find_program(VALGRIND_EXECUTABLE NAMES valgrind)
        if(NOT VALGRIND_EXECUTABLE)
            message(FATAL_ERROR "ROHCCXX_ENABLE_VALGRIND_TESTS requires valgrind in PATH")
        endif()
    endif()

    # Test-only dependencies (Catch2, rohc-lib interop)
    include(FetchContent)

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.3  # known stable as of 2025/2026
    )

    FetchContent_MakeAvailable(Catch2)
    enable_testing()
    add_subdirectory(tests)
endif()

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/rohccxxConfig.cmake.in
    ${PROJECT_BINARY_DIR}/rohccxxConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rohccxx
)

write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/rohccxxConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${PROJECT_BINARY_DIR}/rohccxxConfig.cmake
    ${PROJECT_BINARY_DIR}/rohccxxConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rohccxx
)

# ---- Add support for creating installable packages ----
include(InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_NAME "librohccxx")
set(CPACK_PACKAGE_VENDOR "AlteredNets Cyber Solutions, Inc.")
set(CPACK_PACKAGE_CONTACT "sales@alterednets.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Modern C++ ROHC compression library")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_LICENSE "AlteredNets Non-Commercial / Commercial")
set(CPACK_PACKAGE_FILE_NAME "librohccxx-${PROJECT_VERSION}")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr" CACHE STRING "Install prefix used inside generated binary packages")

# ---- Debian ----
set(CPACK_DEBIAN_PACKAGE_NAME "librohccxx")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "AlteredNets Cyber Solutions, Inc. <sales@alterednets.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
set(CPACK_DEBIAN_PACKAGE_REPLACES "rohccxx")
set(CPACK_DEBIAN_PACKAGE_CONFLICTS "rohccxx")
set(CPACK_DEBIAN_PACKAGE_PROVIDES "rohccxx")
set(CPACK_DEBIAN_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.deb")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${PROJECT_SOURCE_DIR}/packaging/debian/postinst;${PROJECT_SOURCE_DIR}/packaging/debian/postrm"
)

# ---- RPM ----
set(CPACK_RPM_PACKAGE_NAME "librohccxx")
set(CPACK_RPM_PACKAGE_LICENSE "AlteredNets-Commercial")
set(CPACK_RPM_PACKAGE_GROUP "System/Libraries")
set(CPACK_RPM_PACKAGE_REQUIRES "glibc")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_GENERATOR "DEB")

include(CPack)

# ---- DistClean to remove build dir ----
add_custom_target(distclean
  COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}"
  COMMENT "Remove entire build directory"
)
