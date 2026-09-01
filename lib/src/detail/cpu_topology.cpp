#include "cpu_topology.hpp"

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <vector>
#elif defined(__linux__)
#    include <cstdlib>
#    include <fstream>
#    include <set>
#    include <string>
#    include <utility>
#endif

#include <thread>

namespace binwalk {
namespace detail {
namespace {

[[nodiscard]] std::size_t hardware_thread_count() noexcept {
    const auto threads = static_cast<std::size_t>(std::thread::hardware_concurrency());
    return threads == 0 ? std::size_t{1} : threads;
}

#if defined(_WIN32)

[[nodiscard]] std::size_t count_cores_from_processor_relationships() noexcept {
    DWORD length = 0;
    if(GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length) != FALSE
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER || length == 0) {
        return 0;
    }

    std::vector<unsigned char> buffer(length);
    auto* const records = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(
        buffer.data()
    );
    if(GetLogicalProcessorInformationEx(RelationProcessorCore, records, &length) == FALSE) {
        return 0;
    }

    std::size_t cores = 0;
    DWORD offset = 0;
    while(offset < length) {
        const auto* const record = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(
            buffer.data() + offset
        );
        if(record->Size == 0) {
            break;
        }
        if(record->Relationship == RelationProcessorCore) {
            ++cores;
        }
        offset += record->Size;
    }
    return cores;
}

#elif defined(__linux__)

[[nodiscard]] std::size_t count_distinct_package_and_core_ids() noexcept {
    std::ifstream processors("/proc/cpuinfo");
    if(!processors) {
        return 0;
    }

    std::set<std::pair<int, int>> cores;
    std::string line;
    int package_id = 0;
    int core_id = -1;

    while(std::getline(processors, line)) {
        const auto separator = line.find(':');
        if(separator == std::string::npos) {
            if(core_id >= 0) {
                cores.emplace(package_id, core_id);
                package_id = 0;
                core_id = -1;
            }
            continue;
        }
        const auto field = line.substr(0, separator);
        const auto value = std::atoi(line.c_str() + static_cast<std::ptrdiff_t>(separator) + 1);
        if(field.rfind("physical id", 0) == 0) {
            package_id = value;
        } else if(field.rfind("core id", 0) == 0) {
            core_id = value;
        }
    }
    if(core_id >= 0) {
        cores.emplace(package_id, core_id);
    }
    return cores.size();
}

#endif

[[nodiscard]] std::size_t count_physical_cores() noexcept {
#if defined(_WIN32)
    const auto cores = count_cores_from_processor_relationships();
#elif defined(__linux__)
    const auto cores = count_distinct_package_and_core_ids();
#else
    const std::size_t cores = 0;
#endif
    return cores == 0 ? hardware_thread_count() : cores;
}

}

std::size_t physical_core_count() noexcept {
    static const std::size_t cores = count_physical_cores();
    return cores;
}

}
}
