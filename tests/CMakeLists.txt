# Globbed on purpose. Roughly a dozen independent black-box test agents across
# three coordinators drop files into unit/, and an explicit list would make this
# manifest a three-way write conflict. CONFIGURE_DEPENDS re-globs on build, so a
# new test file is picked up without a manual reconfigure.
file(
    GLOB BINWALK_UNIT_TEST_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/*_test.cpp"
)

if(NOT BINWALK_UNIT_TEST_SOURCES)
    message(FATAL_ERROR "No unit test sources found under tests/unit")
endif()

add_executable(binwalk_tests ${BINWALK_UNIT_TEST_SOURCES})

target_compile_features(binwalk_tests PRIVATE cxx_std_17)
target_link_libraries(binwalk_tests PRIVATE binwalk::core GTest::gtest_main)

if(BINWALK_BUILD_CLI)
    target_sources(binwalk_tests PRIVATE integration/cli_test.cpp)
    target_link_libraries(binwalk_tests PRIVATE nlohmann_json::nlohmann_json)
    target_compile_definitions(
        binwalk_tests
        PRIVATE BINWALK_CLI_PATH="$<TARGET_FILE:binwalk_cli>"
    )
    add_dependencies(binwalk_tests binwalk_cli)
endif()

if(BINWALK_WITH_ZLIB)
    target_compile_definitions(binwalk_tests PRIVATE BINWALK_TEST_HAS_ZLIB=1)
endif()

binwalk_enable_warnings(binwalk_tests)

if(WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
        TARGET binwalk_tests
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:binwalk_tests>
            $<TARGET_FILE_DIR:binwalk_tests>
        COMMAND_EXPAND_LISTS
        VERBATIM
    )
endif()

include(GoogleTest)
gtest_discover_tests(binwalk_tests)
