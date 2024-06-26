#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0057 NEW)


find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

cm_workspace(solana)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

option(BUILD_TESTS "Build unit tests" TRUE)
option(BUILD_BENCH_TESTS "Build performance benchmark tests" FALSE)

add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/marshalling")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/actor")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/bin")

add_custom_target(verifier
                  COMMAND truffle compile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/share/evm-proof-verify)

configure_file(${CMAKE_CURRENT_LIST_DIR}/docs/doxygen/${CMAKE_WORKSPACE_NAME}.doxyfile.in
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_WORKSPACE_NAME}.doxyfile @ONLY)

configure_file(${CMAKE_SOURCE_DIR}/share/scripts/run.sh.in ${CMAKE_BINARY_DIR}/benchmark/run.sh @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/share/evm-proof-verify/package.json ${CMAKE_BINARY_DIR}/benchmark/package.json @ONLY)
file(COPY ${CMAKE_SOURCE_DIR}/share/evm-proof-verify/src/ DESTINATION ${CMAKE_BINARY_DIR}/benchmark)
