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
option(BINWALK_FETCH_DEPENDENCIES "Fetch missing C/C++ dependencies" ON)
option(BINWALK_WITH_ZLIB "Enable the native C zlib backend" ON)
option(BUILD_SHARED_LIBS "Build libraries as shared libraries" OFF)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
