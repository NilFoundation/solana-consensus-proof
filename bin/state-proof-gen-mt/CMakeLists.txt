cmake_minimum_required(VERSION 3.5)

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_project(state-proof-gen-mt WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

option(ZK_PLACEHOLDER_PROFILING_ENABLED "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG_ENABLED "Build with placeholder testing inside" FALSE)

if(ZK_PLACEHOLDER_PROFILING)
    add_definitions(-DZK_PLACEHOLDER_PROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

if (NOT Boost_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_package(Boost COMPONENTS REQUIRED filesystem log log_setup program_options thread system)
elseif (CMAKE_CROSSCOMPILING)
    if (NOT TARGET boost)
        include(ExternalProject)
        set(Boost_LIBRARIES boost_random)
        externalproject_add(boost
                PREFIX ${CMAKE_BINARY_DIR}/libs/boost
                GIT_REPOSITORY git@github.com:boostorg/boost.git
                GIT_TAG boost-1.77.0
                BUILD_IN_SOURCE TRUE
                CMAKE_ARGS -DCMAKE_CROSSCOMPILING_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR} -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
                BUILD_COMMAND cmake --build . --target ${Boost_LIBRARIES}
                INSTALL_COMMAND "")
    else ()
        set(Boost_LIBRARIES boost_random)
    endif ()
endif ()

cm_setup_version(VERSION 0.1.0)

# get header files; only needed by CMake generators,
# e.g., for creating proper Xcode projects
set(${CURRENT_PROJECT_NAME}_HEADERS)

# list cpp files excluding platform-dependent files
list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
        src/main.cpp
        src/aspects/args.cpp
        src/aspects/configuration.cpp
        src/aspects/actor.cpp
        src/aspects/path.cpp
        src/aspects/proof.cpp)

set(${CURRENT_PROJECT_NAME}_HEADERS
        include/nil/state-proof-gen-mt/aspects/args.hpp
        include/nil/state-proof-gen-mt/aspects/configuration.hpp
        include/nil/state-proof-gen-mt/aspects/path.hpp
        include/nil/state-proof-gen-mt/aspects/actor.hpp
        include/nil/state-proof-gen-mt/aspects/proof.hpp

        include/nil/state-proof-gen-mt/detail/configurable.hpp
        )

add_executable(${CURRENT_PROJECT_NAME}
        ${${CURRENT_PROJECT_NAME}_HEADERS}
        ${${CURRENT_PROJECT_NAME}_SOURCES})

set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
        LINKER_LANGUAGE CXX
        EXPORT_NAME ${CURRENT_PROJECT_NAME}
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE)

target_link_libraries(${CURRENT_PROJECT_NAME}
        actor::core
        actor::math
        actor::zk

        crypto3::algebra
        crypto3::block
        crypto3::codec
        crypto3::multiprecision
        crypto3::pkpad
        crypto3::pubkey
        crypto3::random

        marshalling::core
        marshalling::crypto3_algebra
        marshalling::crypto3_multiprecision
        marshalling::crypto3_zk

        dbms::plugin
        boost::application

        ${Boost_LIBRARIES})

target_include_directories(${CURRENT_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

        $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

if (APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
    set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
            XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
elseif (CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    if (CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
        set_target_properties(${CURRENT_PROJECT_NAME} PROPERTIES
                COMPILE_FLAGS "-s USE_BOOST_HEADERS=1 -s USE_PTHREADS -s PROXY_TO_PTHREAD"
                LINK_FLAGS "-s USE_BOOST_HEADERS=1 -s USE_PTHREADS -s PROXY_TO_PTHREAD"
                LINK_DIRECTORIES "${CMAKE_BINARY_DIR}/libs/boost/src/boost/stage/lib")
    endif ()

    add_dependencies(${CURRENT_PROJECT_NAME} boost)
endif ()
