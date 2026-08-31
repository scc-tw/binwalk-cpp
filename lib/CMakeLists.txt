add_library(binwalk_core)
add_library(binwalk::core ALIAS binwalk_core)

target_sources(
    binwalk_core
    PRIVATE
        src/builtin.cpp
        src/builtin_extractors.cpp
        src/carving.cpp
        src/entropy.cpp
        src/extractor.cpp
        src/scanner.cpp
)

target_compile_features(binwalk_core PUBLIC cxx_std_17)

if(BINWALK_WITH_ZLIB)
    target_link_libraries(binwalk_core PRIVATE ${BINWALK_ZLIB_TARGET})
    target_compile_definitions(binwalk_core PRIVATE BINWALK_HAS_ZLIB=1)
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
