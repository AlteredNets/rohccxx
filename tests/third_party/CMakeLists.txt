# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set(ROHC_LIB_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rohc-lib)
set(ROHC_LIB_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/rohc-lib-build)
set(ROHC_LIB_ARCHIVE ${ROHC_LIB_BUILD_DIR}/src/.libs/librohc.a)
set(ROHC_LIB_ARCHIVE ${ROHC_LIB_ARCHIVE} PARENT_SCOPE)

set(ROHC_LIB_INCLUDE_DIR
    ${ROHC_LIB_BUILD_DIR}/src/common
    ${ROHC_LIB_BUILD_DIR}/src/common/rohc
    ${ROHC_LIB_BUILD_DIR}/src/common/protocols
    ${ROHC_LIB_BUILD_DIR}/src/comp
    ${ROHC_LIB_BUILD_DIR}/src/comp/rohc
    ${ROHC_LIB_BUILD_DIR}/src/decomp
    ${ROHC_LIB_BUILD_DIR}/src/decomp/rohc
    PARENT_SCOPE
)

add_custom_command(
    OUTPUT ${ROHC_LIB_ARCHIVE}
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${ROHC_LIB_BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${ROHC_LIB_SOURCE_DIR} ${ROHC_LIB_BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E chdir ${ROHC_LIB_BUILD_DIR} autoreconf -fi
    COMMAND ${CMAKE_COMMAND} -E chdir ${ROHC_LIB_BUILD_DIR} ./configure --disable-shared --enable-static --disable-fail-on-warning
    COMMAND ${CMAKE_COMMAND} -E chdir ${ROHC_LIB_BUILD_DIR} ${CMAKE_MAKE_PROGRAM} -C src all
    DEPENDS ${ROHC_LIB_SOURCE_DIR}/configure.ac
    COMMENT [[Building rohc-lib static library for interop tests]]
    VERBATIM
)

add_custom_target(rohc_lib DEPENDS ${ROHC_LIB_ARCHIVE})
