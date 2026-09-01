add_library(binwalk_core)
add_library(binwalk::core ALIAS binwalk_core)

target_sources(
    binwalk_core
    PRIVATE
        src/builtin.cpp
        src/builtin_extractors.cpp
        src/carving.cpp
        src/chroot.cpp
        src/common.cpp
        src/detail/cpu_topology.cpp
        src/detail/literal_matcher.cpp
        src/detail/task_pool.cpp
        src/entropy.cpp
        src/extractor.cpp
        src/process.cpp
        src/scanner.cpp
        src/codec/codec.cpp
        src/codec/bzip2_codec.cpp
        src/codec/lz4_codec.cpp
        src/codec/lzfse_codec.cpp
        src/codec/lzo_codec.cpp
        src/codec/xz_codec.cpp
        src/codec/zlib_codec.cpp
        src/codec/zstd_codec.cpp
        src/formats/b1_compression.cpp
        src/formats/b2_media.cpp
        src/formats/b3_constants.cpp
        src/formats/b4_encrypted.cpp
        src/formats/b5_vendorhdr.cpp
        src/formats/b6_vendorcarve.cpp
        src/formats/b7_archives.cpp
        src/formats/b8a_filesystems.cpp
        src/formats/b8b_volumes.cpp
        src/formats/b9a_squashfs.cpp
        src/formats/b9b_jffs2_yaffs.cpp
        src/formats/b9c_ubi.cpp
        src/formats/b10a_kernels.cpp
        src/formats/b10b_executables.cpp
)

target_compile_features(binwalk_core PUBLIC cxx_std_17)
target_link_libraries(binwalk_core PUBLIC Threads::Threads)

if(BINWALK_PROFILE_COUNTERS)
    target_compile_definitions(binwalk_core PRIVATE BINWALK_PROFILE_COUNTERS=1)
endif()

if(BINWALK_WITH_ZLIB)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_ZLIB_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_ZLIB=1)
endif()

# Private dependencies of a static library remain link requirements for its
# consumers. System codec targets are rediscovered by binwalkConfig.cmake, and
# FetchContent-built codec targets are installed in binwalk's export set.
if(BINWALK_WITH_BZIP2)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_BZIP2_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_BZIP2=1)
endif()
if(BINWALK_WITH_LZMA)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_LZMA_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_LZMA=1)
endif()
if(BINWALK_WITH_LZ4)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_LZ4_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_LZ4=1)
endif()
if(BINWALK_WITH_ZSTD)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_ZSTD_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_ZSTD=1)
endif()
if(BINWALK_WITH_LZFSE)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_LZFSE_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_LZFSE=1)
endif()
if(BINWALK_WITH_LZO)
    # No link line on purpose: the LZO1X decoder is our own code, written from
    # scratch because liblzo2 and minilzo are both GPL-2.0 and barred from the
    # core by contract §7b. BINWALK_LZO_TARGET is deliberately empty.
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_LZO=1)
endif()
target_include_directories(
    binwalk_core
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(binwalk_core PUBLIC BINWALK_CORE_SHARED)
endif()

set_target_properties(
    binwalk_core
    PROPERTIES
        EXPORT_NAME core
        OUTPUT_NAME binwalk
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
)

binwalk_enable_warnings(binwalk_core)
binwalk_enable_optimisation(binwalk_core)

install(
    TARGETS binwalk_core
    EXPORT binwalkTargets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/binwalk"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.hpp"
    PATTERN "version.hpp.in" EXCLUDE
)

install(
    FILES "${PROJECT_BINARY_DIR}/generated/include/binwalk/version.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/binwalk"
)
