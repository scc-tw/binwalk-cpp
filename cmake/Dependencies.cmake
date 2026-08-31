include(FetchContent)

function(binwalk_find_or_fetch package target repository tag)
    find_package(${package} CONFIG QUIET)
    if(TARGET ${target})
        return()
    endif()

    if(NOT BINWALK_FETCH_DEPENDENCIES)
        message(FATAL_ERROR
            "${package} was not found. Install it or configure with "
            "-DBINWALK_FETCH_DEPENDENCIES=ON."
        )
    endif()

    string(TOLOWER "${package}" dependency_name)
    FetchContent_Declare(
        ${dependency_name}
        GIT_REPOSITORY "${repository}"
        GIT_TAG "${tag}"
        GIT_SHALLOW TRUE
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(${dependency_name})

    if(NOT TARGET ${target})
        message(FATAL_ERROR "${package} did not provide the expected target ${target}")
    endif()
endfunction()

if(BINWALK_BUILD_CLI)
    find_package(Threads REQUIRED)

    set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    binwalk_find_or_fetch(
        CLI11
        CLI11::CLI11
        https://github.com/CLIUtils/CLI11.git
        v2.7.2
    )

    set(JSON_BuildTests OFF CACHE INTERNAL "")
    set(JSON_Install OFF CACHE INTERNAL "")
    binwalk_find_or_fetch(
        nlohmann_json
        nlohmann_json::nlohmann_json
        https://github.com/nlohmann/json.git
        v3.12.0
    )
endif()

if(BINWALK_BUILD_TESTS)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    binwalk_find_or_fetch(
        GTest
        GTest::gtest_main
        https://github.com/google/googletest.git
        v1.18.0
    )
endif()

if(BINWALK_WITH_ZLIB)
    find_package(ZLIB QUIET)
    if(TARGET ZLIB::ZLIB)
        set(BINWALK_ZLIB_TARGET ZLIB::ZLIB)
        set(BINWALK_ZLIB_USE_CONFIG_PACKAGE OFF)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
        set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
        set(ZLIB_INSTALL ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
            zlib
            GIT_REPOSITORY https://github.com/madler/zlib.git
            GIT_TAG v1.3.2
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(zlib)
        set_target_properties(zlibstatic PROPERTIES EXPORT_NAME ZLIB)
        if(NOT TARGET ZLIB::ZLIB)
            add_library(ZLIB::ZLIB ALIAS zlibstatic)
        endif()
        set(BINWALK_ZLIB_TARGET ZLIB::ZLIB)
        set(BINWALK_ZLIB_USE_CONFIG_PACKAGE ON)
    else()
        message(FATAL_ERROR
            "ZLIB was not found. Install it, disable BINWALK_WITH_ZLIB, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()
