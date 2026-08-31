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

# --------------------------------------------------------------------------
# WP3 compression backends (contract §7).
#
# Every one of these follows the ZLIB precedent above: find_package first, a
# pinned release-tag FetchContent fallback gated on BINWALK_FETCH_DEPENDENCIES,
# and a FATAL_ERROR naming the three ways out. Each sets BINWALK_<LIB>_TARGET,
# which lib/CMakeLists.txt links behind its BINWALK_WITH_<LIB> guard.
#
# Two shared notes:
#
#  * The fetched libraries are declared EXCLUDE_FROM_ALL so their CLIs, tests and
#    install rules stay out of our build. That also keeps them out of every
#    export set, so binwalk_core must link them through $<BUILD_INTERFACE:...>
#    or install(EXPORT binwalkTargets) rejects the private dependency.
#  * BUILD_TESTING is shadowed with a directory-scope variable around each
#    add_subdirectory and then unset. It is deliberately never written to the
#    cache: BINWALK_BUILD_TESTS defaults to ${BUILD_TESTING}, so forcing it would
#    silently disable our own test suite on the next configure.
# --------------------------------------------------------------------------

# Several of these projects declare a cmake_minimum_required below the floor
# CMake 4 accepts. This is the documented escape hatch and is scoped to the
# subprojects, not to us.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

if(BINWALK_WITH_BZIP2)
    find_package(BZip2 QUIET)
    if(TARGET BZip2::BZip2)
        set(BINWALK_BZIP2_TARGET BZip2::BZip2)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        # bzip2 1.0.8 is an autotools/Makefile release: NO release tag of any
        # bzip2 repository ships a CMakeLists.txt. libarchive/bzip2 grew CMake
        # support only after 1.0.8, so consuming it would mean pinning a commit
        # SHA, which contract §7 forbids ("pinned to a release tag").
        #
        # So we fetch the source at the release tag and compile the seven
        # library objects ourselves. This is the standard treatment for a
        # CMake-less C library, and it keeps the pin a real release tag.
        #
        # SOURCE_SUBDIR names a directory that deliberately does not exist:
        # FetchContent_MakeAvailable only calls add_subdirectory() when it finds
        # a CMakeLists.txt there, so this populates the source and adds no
        # targets. It is the documented, non-deprecated way to get a
        # source-only fetch (FetchContent_Populate is deprecated in CMake 3.30).
        FetchContent_Declare(
            bzip2
            GIT_REPOSITORY https://github.com/libarchive/bzip2.git
            GIT_TAG bzip2-1.0.8
            GIT_SHALLOW TRUE
            SOURCE_SUBDIR binwalk-source-only-no-cmakelists
        )
        FetchContent_MakeAvailable(bzip2)

        if(NOT EXISTS "${bzip2_SOURCE_DIR}/bzlib.c")
            message(FATAL_ERROR
                "bzip2 source at ${bzip2_SOURCE_DIR} does not look like a bzip2 "
                "release (bzlib.c is missing)."
            )
        endif()

        # LIBBZ2_OBJS from bzip2's own Makefile. bzip2recover and the bzip2 CLI
        # are deliberately not built.
        add_library(binwalk_bz2 STATIC
            "${bzip2_SOURCE_DIR}/blocksort.c"
            "${bzip2_SOURCE_DIR}/huffman.c"
            "${bzip2_SOURCE_DIR}/crctable.c"
            "${bzip2_SOURCE_DIR}/randtable.c"
            "${bzip2_SOURCE_DIR}/compress.c"
            "${bzip2_SOURCE_DIR}/decompress.c"
            "${bzip2_SOURCE_DIR}/bzlib.c"
        )
        target_include_directories(binwalk_bz2
            PUBLIC "$<BUILD_INTERFACE:${bzip2_SOURCE_DIR}>"
        )
        # Deliberately NO -DBZ_EXPORT here. bzlib.h lines 69-71 already do
        #   #ifndef BZ_IMPORT
        #   #define BZ_EXPORT
        #   #endif
        # and line 84 then selects `#define BZ_API(func) WINAPI func`, the
        # direct-call form we want. The function-pointer declarations are the
        # BZ_IMPORT (dynamic-loading) branch, which nobody takes unless they ask
        # for it. Defining BZ_EXPORT=1 ourselves collided with the header's own
        # valueless #define and produced C4005 in binwalk_core.
        set_target_properties(binwalk_bz2 PROPERTIES POSITION_INDEPENDENT_CODE ON)
        # Third-party C we do not own and must not "fix": silence its warnings
        # rather than let them dilute our own zero-warning output. This target is
        # deliberately NOT passed to binwalk_enable_warnings.
        if(MSVC)
            target_compile_options(binwalk_bz2 PRIVATE /W0)
            target_compile_definitions(binwalk_bz2 PRIVATE _CRT_SECURE_NO_WARNINGS=1)
        else()
            target_compile_options(binwalk_bz2 PRIVATE -w)
        endif()
        set(BINWALK_BZIP2_TARGET binwalk_bz2)
    else()
        message(FATAL_ERROR
            "BZip2 was not found. Install it, disable BINWALK_WITH_BZIP2, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()

if(BINWALK_WITH_LZMA)
    find_package(LibLZMA QUIET)
    if(TARGET LibLZMA::LibLZMA)
        set(BINWALK_LZMA_TARGET LibLZMA::LibLZMA)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        # liblzma's core is 0BSD / public domain, which contract §7 allows.
        set(ENABLE_NLS OFF CACHE BOOL "" FORCE)
        set(ENABLE_DOXYGEN OFF CACHE BOOL "" FORCE)
        set(ENABLE_SMALL OFF CACHE BOOL "" FORCE)
        set(CREATE_XZ_SYMLINKS OFF CACHE BOOL "" FORCE)
        set(CREATE_LZMA_SYMLINKS OFF CACHE BOOL "" FORCE)
        # The 5.8-era option names; setting an option a project does not declare
        # is harmless, and this keeps the pin bumpable without edits here.
        set(XZ_NLS OFF CACHE BOOL "" FORCE)
        set(XZ_DOC OFF CACHE BOOL "" FORCE)
        set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
        set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
        set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
        set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
        set(XZ_TOOL_SCRIPTS OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(
            xz
            GIT_REPOSITORY https://github.com/tukaani-project/xz.git
            GIT_TAG v5.6.4
            GIT_SHALLOW TRUE
            EXCLUDE_FROM_ALL
        )
        set(BUILD_TESTING OFF)
        FetchContent_MakeAvailable(xz)
        unset(BUILD_TESTING)
        if(NOT TARGET liblzma)
            message(FATAL_ERROR "xz did not provide the expected target liblzma")
        endif()
        if(NOT TARGET LibLZMA::LibLZMA)
            add_library(LibLZMA::LibLZMA ALIAS liblzma)
        endif()
        # Genuinely required, unlike the lz4 and zstd cases. Verified against
        # xz v5.6.4's own CMakeLists line 529, which reads
        #   target_include_directories(liblzma PRIVATE src/liblzma/api ...)
        # PRIVATE, so lzma.h never reaches a consumer; its only other exposure is
        # install(DIRECTORY src/liblzma/api/ ...) at line 1508, which is the
        # install side only. $<BUILD_INTERFACE:>-wrapped so the absolute path
        # cannot leak into an install interface.
        target_include_directories(liblzma
            PUBLIC "$<BUILD_INTERFACE:${xz_SOURCE_DIR}/src/liblzma/api>"
        )
        set(BINWALK_LZMA_TARGET liblzma)
    else()
        message(FATAL_ERROR
            "LibLZMA was not found. Install it, disable BINWALK_WITH_LZMA, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()

if(BINWALK_WITH_LZ4)
    find_package(lz4 CONFIG QUIET)
    if(TARGET lz4::lz4)
        set(BINWALK_LZ4_TARGET lz4::lz4)
    elseif(TARGET LZ4::lz4_static)
        set(BINWALK_LZ4_TARGET LZ4::lz4_static)
    elseif(TARGET LZ4::lz4_shared)
        set(BINWALK_LZ4_TARGET LZ4::lz4_shared)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        # lz4's library is BSD-2-Clause; only the CLI is GPL-2.0, and it is not
        # built (LZ4_BUILD_CLI OFF plus EXCLUDE_FROM_ALL). Contract §7 allows it.
        set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(LZ4_BUILD_LEGACY_LZ4C OFF CACHE BOOL "" FORCE)
        set(LZ4_POSITION_INDEPENDENT_LIB ON CACHE BOOL "" FORCE)
        set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
            lz4
            GIT_REPOSITORY https://github.com/lz4/lz4.git
            GIT_TAG v1.10.0
            GIT_SHALLOW TRUE
            SOURCE_SUBDIR build/cmake
            EXCLUDE_FROM_ALL
        )
        set(BUILD_TESTING OFF)
        FetchContent_MakeAvailable(lz4)
        unset(BUILD_TESTING)
        if(NOT TARGET lz4_static)
            message(FATAL_ERROR "lz4 did not provide the expected target lz4_static")
        endif()
        # No target_include_directories() here on purpose. lz4 already does
        #   target_include_directories(lz4_static
        #       PUBLIC $<BUILD_INTERFACE:${LZ4_LIB_SOURCE_DIR}>
        #       INTERFACE $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        # A "defensive" raw path added on top would be both redundant and
        # actively harmful: an unwrapped absolute build-tree path in a PUBLIC
        # include interface makes CMake's export-consistency check fail at the
        # GENERATE step for any target in an install(EXPORT) set.
        set(BINWALK_LZ4_TARGET lz4_static)
    else()
        message(FATAL_ERROR
            "lz4 was not found. Install it, disable BINWALK_WITH_LZ4, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()

if(BINWALK_WITH_ZSTD)
    find_package(zstd CONFIG QUIET)
    if(TARGET zstd::libzstd_static)
        set(BINWALK_ZSTD_TARGET zstd::libzstd_static)
    elseif(TARGET zstd::libzstd_shared)
        set(BINWALK_ZSTD_TARGET zstd::libzstd_shared)
    elseif(TARGET zstd::libzstd)
        set(BINWALK_ZSTD_TARGET zstd::libzstd)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        # zstd is BSD-3-Clause / GPL-2.0 dual licensed; we take the BSD-3 arm,
        # which contract §7 allows.
        set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
        set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
        set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(
            zstd
            GIT_REPOSITORY https://github.com/facebook/zstd.git
            GIT_TAG v1.5.7
            GIT_SHALLOW TRUE
            SOURCE_SUBDIR build/cmake
            EXCLUDE_FROM_ALL
        )
        set(BUILD_TESTING OFF)
        FetchContent_MakeAvailable(zstd)
        unset(BUILD_TESTING)
        if(NOT TARGET libzstd_static)
            message(FATAL_ERROR "zstd did not provide the expected target libzstd_static")
        endif()
        # No target_include_directories() here on purpose. zstd already does
        #   target_include_directories(libzstd_static
        #       INTERFACE $<BUILD_INTERFACE:${PUBLIC_INCLUDE_DIRS}>)
        # and its install(TARGETS ... EXPORT zstdExports INCLUDES DESTINATION
        # ${CMAKE_INSTALL_INCLUDEDIR}) supplies the install side. Adding a raw
        # absolute path on top is what made the GENERATE step fail with
        # "INTERFACE_INCLUDE_DIRECTORIES property contains path ... which is
        # prefixed in the build directory": zstd's own install(EXPORT) is still
        # processed (EXCLUDE_FROM_ALL does not suppress install() rules), and an
        # unwrapped build-tree path is meaningless after install.
        #
        # Overwriting INTERFACE_INCLUDE_DIRECTORIES wholesale would also work but
        # would discard zstd's own BUILD_INTERFACE and INSTALL_INTERFACE entries.
        # Removing the redundant line is the minimal, non-destructive fix.
        set(BINWALK_ZSTD_TARGET libzstd_static)
    else()
        message(FATAL_ERROR
            "zstd was not found. Install it, disable BINWALK_WITH_ZSTD, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()

if(BINWALK_WITH_LZFSE)
    find_package(lzfse CONFIG QUIET)
    if(TARGET lzfse::lzfse)
        set(BINWALK_LZFSE_TARGET lzfse::lzfse)
    elseif(BINWALK_FETCH_DEPENDENCIES)
        # Apple's reference implementation, BSD-3-Clause, which contract §7
        # allows. LZFSE_BUNDLE_MODE suppresses its install rules.
        set(LZFSE_BUNDLE_MODE ON CACHE BOOL "" FORCE)
        # add_test() is NOT affected by EXCLUDE_FROM_ALL, so without this lzfse
        # registers 15 round-trip tests into OUR ctest suite. They can never
        # pass: each invokes $<TARGET_FILE:lzfse_cli>, and lzfse_cli is
        # EXCLUDE_FROM_ALL and therefore never built. This is lzfse's own
        # documented opt-out (its CMakeLists guards include(CTest),
        # enable_testing(), the input glob and every add_test with
        # `if(NOT LZFSE_DISABLE_TESTS)` at lines 109 and 120), not a workaround.
        #
        # Swept the other four: xz and lz4 contain no add_test at all, zstd's
        # four are inside `if (ZSTD_BUILD_TESTS)` which is forced OFF above, and
        # bzip2 ships no CMake for us to inherit. lzfse was the only leak.
        set(LZFSE_DISABLE_TESTS TRUE CACHE BOOL "" FORCE)
        FetchContent_Declare(
            lzfse
            GIT_REPOSITORY https://github.com/lzfse/lzfse.git
            GIT_TAG lzfse-1.0
            GIT_SHALLOW TRUE
            EXCLUDE_FROM_ALL
        )
        set(BUILD_TESTING OFF)
        FetchContent_MakeAvailable(lzfse)
        unset(BUILD_TESTING)
        if(NOT TARGET lzfse)
            message(FATAL_ERROR "lzfse did not provide the expected target lzfse")
        endif()
        # Only lzfse.h is a public header, and lzfse-1.0 uses a directory-scope
        # include_directories() that does not propagate to consumers, so unlike
        # lz4 and zstd this one genuinely has to be added. It is wrapped in
        # $<BUILD_INTERFACE:> so the absolute build-tree path never reaches an
        # install interface — the defect that made zstd fail at GENERATE.
        target_include_directories(lzfse PUBLIC "$<BUILD_INTERFACE:${lzfse_SOURCE_DIR}/src>")
        # Third-party C we do not own and must not "fix", same rationale as
        # binwalk_bz2. lzfse's own CMakeLists enables /Wall-class diagnostics
        # (~40 lines of C4711 auto-inline and C5045 Spectre notes); left alone
        # they would bury a future real warning of ours in noise.
        if(MSVC)
            target_compile_options(lzfse PRIVATE /W0)
        endif()
        set(BINWALK_LZFSE_TARGET lzfse)
    else()
        message(FATAL_ERROR
            "lzfse was not found. Install it, disable BINWALK_WITH_LZFSE, or enable "
            "BINWALK_FETCH_DEPENDENCIES."
        )
    endif()
endif()

if(BINWALK_WITH_LZO)
    # Deliberately no dependency. LZO1X decompression is implemented natively in
    # lib/src/codec/lzo_codec.cpp: liblzo2 is GPL-2.0 and minilzo carries the
    # same licence with a commercial exception, and contract §7 keeps copyleft
    # out of the core. The LZO1X format itself is unencumbered.
    #
    # BINWALK_LZO_TARGET is intentionally empty, so lib/CMakeLists.txt must set
    # BINWALK_HAS_LZO without a target_link_libraries line.
    set(BINWALK_LZO_TARGET "")
endif()

unset(CMAKE_POLICY_VERSION_MINIMUM)
