# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set(ROHCCXX_SOURCES
    core/compressor.cpp
    core/decompressor.cpp
    c_api/rohc_c_api.cpp
)

#
# ---- Object library (compilation only) ----
#
add_library(rohccxx_obj OBJECT ${ROHCCXX_SOURCES})

# Needed so rohc_c_api.cpp can include <rohccxx.h>
target_include_directories(rohccxx_obj
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_BINARY_DIR}/generated/include
        ${PROJECT_SOURCE_DIR}/src/core
)

target_compile_definitions(rohccxx_obj
    PRIVATE ROHCCXX_ENABLE_TRACE)

# Validation / interop-only compilation flags
if(ROHCCXX_BUILD_TESTS)
    target_compile_definitions(rohccxx_obj
        PRIVATE
            ROHCCXX_ENABLE_VALIDATION_MODE
    )
endif()

# Hide all symbols by default (ABI hygiene)
if(NOT MSVC)
    target_compile_options(rohccxx_obj PRIVATE -fvisibility=hidden)
endif()

#
# ---- Static library ----
#
add_library(rohccxx STATIC $<TARGET_OBJECTS:rohccxx_obj>)
set_target_properties(rohccxx PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME rohccxx_static
)

target_include_directories(rohccxx
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

#
# ---- Shared library ----
#
add_library(rohccxx_shared SHARED $<TARGET_OBJECTS:rohccxx_obj>)
target_compile_definitions(rohccxx_shared PRIVATE ROHCCXX_BUILD_DLL)

set_target_properties(rohccxx_shared PROPERTIES
    OUTPUT_NAME rohccxx
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    EXPORT_NAME rohccxx
)

target_include_directories(rohccxx_shared
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

#
# ---- Installation ----
#
include(GNUInstallDirs)

install(TARGETS rohccxx rohccxx_shared
    EXPORT rohccxxTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    ${PROJECT_SOURCE_DIR}/include/rohccxx.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    ${PROJECT_BINARY_DIR}/generated/include/rohccxx/version.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rohccxx
)

install(EXPORT rohccxxTargets
    FILE rohccxxTargets.cmake
    NAMESPACE rohccxx::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rohccxx
)