add_executable(
    binwalk_tests
    unit/binary_reader_test.cpp
    unit/carving_test.cpp
    unit/entropy_test.cpp
    unit/scanner_test.cpp
)

target_compile_features(binwalk_tests PRIVATE cxx_std_17)
target_link_libraries(binwalk_tests PRIVATE binwalk::core GTest::gtest_main)
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
