#include "detail/literal_matcher.hpp"

#include <binwalk/binwalk.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

using clock_type = std::chrono::steady_clock;
using binwalk::detail::literal_matcher;

std::vector<std::uint8_t> load(const std::string& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if(!input) {
        return {};
    }
    const auto size = static_cast<std::size_t>(input.tellg());
    input.seekg(0);
    std::vector<std::uint8_t> data(size);
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    return data;
}

std::vector<std::vector<std::uint8_t>> registry_patterns(bool search_all) {
    binwalk::scan_options options;
    options.search_all = search_all;
    const binwalk::scanner scanner(options);

    std::vector<std::vector<std::uint8_t>> patterns;
    for(const auto& definition : scanner.signatures()) {
        if(definition.short_signature && !search_all) {
            continue;
        }
        for(const auto& pattern : definition.magic) {
            if(!pattern.empty()) {
                patterns.push_back(pattern);
            }
        }
    }
    return patterns;
}

struct run_result {
    double milliseconds = 0.0;
    std::vector<std::uint64_t> digest;
};

run_result run(const literal_matcher& matcher, binwalk::byte_view data) {
    run_result result;
    const auto start = clock_type::now();
    matcher.search(data, 0, [&](std::size_t pattern_index, std::size_t match_end) {
        result.digest.push_back((static_cast<std::uint64_t>(match_end) << 16U) | pattern_index);
        return true;
    });
    result.milliseconds =
        std::chrono::duration<double, std::milli>(clock_type::now() - start).count();
    return result;
}

std::vector<std::uint64_t> measure(
    const char* label,
    literal_matcher::backend backend,
    const std::vector<std::vector<std::uint8_t>>& patterns,
    binwalk::byte_view data,
    int repeats
) {
    const literal_matcher matcher(patterns, backend);

    double best = 1e30;
    run_result last;
    for(int index = 0; index < repeats; ++index) {
        last = run(matcher, data);
        best = std::min(best, last.milliseconds);
    }
    std::printf(
        "%-14s %10.2f ms  %9.1f MiB/s  %8zu matches  %6zu states\n",
        label, best,
        static_cast<double>(data.size()) / (best / 1000.0) / (1024.0 * 1024.0),
        last.digest.size(), matcher.state_count()
    );
    std::fflush(stdout);
    return last.digest;
}

}

int main(int argc, char** argv) {
    if(argc < 2) {
        std::fprintf(stderr, "usage: binwalk_bench_matcher <file> [repeats] [--search-all]\n");
        return 2;
    }
    const std::string path = argv[1];
    int repeats = argc > 2 ? std::atoi(argv[2]) : 3;
    if(repeats < 1) {
        repeats = 1;
    }
    bool search_all = false;
    for(int index = 1; index < argc; ++index) {
        if(std::strcmp(argv[index], "--search-all") == 0) {
            search_all = true;
        }
    }

    const auto data = load(path);
    if(data.empty()) {
        std::fprintf(stderr, "failed to read %s\n", path.c_str());
        return 1;
    }
    const binwalk::byte_view view(data);
    const auto patterns = registry_patterns(search_all);

    std::printf(
        "patterns %zu  corpus %.2f MiB\n",
        patterns.size(), static_cast<double>(data.size()) / (1024.0 * 1024.0)
    );

    const auto scalar = measure("scalar", literal_matcher::backend::scalar, patterns, view, repeats);
    const auto interleaved =
        measure("interleaved", literal_matcher::backend::interleaved, patterns, view, repeats);

    std::printf(
        "interleaved vs scalar: %s\n",
        interleaved == scalar ? "identical" : "DIFFERENT"
    );
    if(interleaved != scalar) {
        for(std::size_t index = 0; index < std::min(scalar.size(), interleaved.size()); ++index) {
            if(scalar[index] != interleaved[index]) {
                std::printf(
                    "  first divergence at %zu: scalar end=%llu pattern=%llu, "
                    "interleaved end=%llu pattern=%llu\n",
                    index,
                    static_cast<unsigned long long>(scalar[index] >> 16U),
                    static_cast<unsigned long long>(scalar[index] & 0xFFFFU),
                    static_cast<unsigned long long>(interleaved[index] >> 16U),
                    static_cast<unsigned long long>(interleaved[index] & 0xFFFFU)
                );
                break;
            }
        }
        return 1;
    }
    return 0;
}
