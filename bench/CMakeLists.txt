add_executable(binwalk_bench src/bench_scan.cpp)
add_executable(binwalk_bench_matcher src/bench_matcher.cpp)
add_executable(binwalk_bench_io src/bench_io.cpp)

foreach(target binwalk_bench binwalk_bench_matcher binwalk_bench_io)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_link_libraries(${target} PRIVATE binwalk::core Threads::Threads)
    target_include_directories(${target} PRIVATE "${PROJECT_SOURCE_DIR}/lib/src")
    binwalk_enable_warnings(${target})
    binwalk_enable_optimisation(${target})
endforeach()

if(BINWALK_PROFILE_COUNTERS)
    target_compile_definitions(binwalk_bench PRIVATE BINWALK_PROFILE_COUNTERS=1)
endif()

