cmake_minimum_required(VERSION 3.24)

project(
    binwalk_cpp
    VERSION 0.1.0
    DESCRIPTION "C++17 firmware analysis library and CLI"
    HOMEPAGE_URL "https://github.com/ReFirmLabs/binwalk"
    LANGUAGES C CXX
)

include(CTest)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BINWALK_BUILD_CLI "Build the binwalk command-line interface" ON)
option(BINWALK_BUILD_TESTS "Build the GoogleTest test suite" ${BUILD_TESTING})
option(BINWALK_BUILD_BENCH "Build the throughput benchmark harness" OFF)
option(BINWALK_PROFILE_COUNTERS "Emit scanner hot-path counters to stderr" OFF)
option(BINWALK_FETCH_DEPENDENCIES "Fetch missing C/C++ dependencies" ON)
option(BINWALK_WITH_ZLIB "Enable the native C zlib backend" ON)
option(BINWALK_WITH_BZIP2 "Enable the native C bzip2 backend" ON)
option(BINWALK_WITH_LZMA  "Enable the native C xz/liblzma backend" ON)
option(BINWALK_WITH_LZ4   "Enable the native C lz4 backend" ON)
option(BINWALK_WITH_ZSTD  "Enable the native C zstd backend" ON)
option(BINWALK_WITH_LZFSE "Enable the native C lzfse backend" ON)
option(BINWALK_WITH_LZO   "Enable the built-in LZO1X block decoder" ON)
option(BINWALK_ENABLE_IPO "Enable link-time optimisation for optimised builds" ON)
option(BUILD_SHARED_LIBS "Build libraries as shared libraries" OFF)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckIPOSupported)
set(BINWALK_IPO_AVAILABLE OFF)
if(BINWALK_ENABLE_IPO)
    check_ipo_supported(RESULT BINWALK_IPO_AVAILABLE OUTPUT BINWALK_IPO_MESSAGE)
    if(NOT BINWALK_IPO_AVAILABLE)
        message(STATUS "Link-time optimisation unavailable: ${BINWALK_IPO_MESSAGE}")
    endif()
endif()

function(binwalk_enable_optimisation target)
    if(BINWALK_IPO_AVAILABLE)
        set_property(
            TARGET ${target}
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        )
        set_property(
            TARGET ${target}
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE
        )
    endif()
endfunction()

function(binwalk_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /EHsc)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endfunction()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/binwalk/version.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binwalk/version.hpp"
    @ONLY
)

include(cmake/Dependencies.cmake)

add_subdirectory(lib)

if(BINWALK_BUILD_CLI)
    add_subdirectory(cli)
endif()

if(BINWALK_BUILD_BENCH)
    add_subdirectory(bench)
endif()

if(BINWALK_BUILD_TESTS)
    if(NOT BUILD_TESTING)
        enable_testing()
    endif()
    add_subdirectory(tests)
endif()

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/binwalkConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/binwalkConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/binwalkConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/binwalk"
)

if(NOT BUILD_SHARED_LIBS AND BINWALK_BUNDLED_CODEC_TARGETS)
    install(
        TARGETS ${BINWALK_BUNDLED_CODEC_TARGETS}
        EXPORT binwalkTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/binwalk"
    )
endif()

install(
    EXPORT binwalkTargets
    FILE binwalkTargets.cmake
    NAMESPACE binwalk::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/binwalk"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/binwalkConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/binwalkConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/binwalk"
)
