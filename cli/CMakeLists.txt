add_executable(binwalk_cli src/main.cpp)
set_target_properties(binwalk_cli PROPERTIES OUTPUT_NAME binwalk)

target_compile_features(binwalk_cli PRIVATE cxx_std_17)
target_link_libraries(
    binwalk_cli
    PRIVATE
        binwalk::core
        CLI11::CLI11
        nlohmann_json::nlohmann_json
)

binwalk_enable_warnings(binwalk_cli)

if(WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
        TARGET binwalk_cli
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:binwalk_cli>
            $<TARGET_FILE_DIR:binwalk_cli>
        COMMAND_EXPAND_LISTS
        VERBATIM
    )
endif()

install(TARGETS binwalk_cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
