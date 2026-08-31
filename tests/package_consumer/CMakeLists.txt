cmake_minimum_required(VERSION 3.24)
project(binwalk_package_consumer LANGUAGES CXX)

find_package(binwalk CONFIG REQUIRED)

add_executable(binwalk_package_consumer main.cpp)
target_compile_features(binwalk_package_consumer PRIVATE cxx_std_17)
target_link_libraries(binwalk_package_consumer PRIVATE binwalk::core)
