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

struct sample {
    double milliseconds = 0.0;
    std::size_t results = 0;
};

template<typename Body>
sample time_once(Body&& body) {
    const auto start = clock_type::now();
    const auto results = body();
    const auto end = clock_type::now();
    return {std::chrono::duration<double, std::milli>(end - start).count(), results};
}

void report(const char* label, std::size_t bytes, std::vector<sample>& samples) {
    std::sort(samples.begin(), samples.end(), [](const sample& left, const sample& right) {
        return left.milliseconds < right.milliseconds;
    });
    const auto best = samples.front().milliseconds;
    const auto median = samples[samples.size() / 2].milliseconds;
    const auto throughput = static_cast<double>(bytes) / (best / 1000.0) / (1024.0 * 1024.0);
    std::printf(
        "%-22s %10.2f ms best %10.2f ms median %9.1f MiB/s %8zu results\n",
        label, best, median, throughput, samples.front().results
    );
    std::fflush(stdout);
}

void dump_patterns() {
    const binwalk::scanner scanner;
    std::vector<std::size_t> histogram(65, 0);
    std::size_t shortest = 4096;
    std::size_t longest = 0;
    std::size_t short_signature_definitions = 0;
    std::size_t pattern_count = 0;

    for(const auto& definition : scanner.signatures()) {
        if(definition.short_signature) {
            ++short_signature_definitions;
        }
        for(const auto& pattern : definition.magic) {
            if(pattern.empty()) {
                continue;
            }
            ++pattern_count;
            ++histogram[std::min<std::size_t>(pattern.size(), histogram.size() - 1)];
            shortest = std::min(shortest, pattern.size());
            longest = std::max(longest, pattern.size());
            if(pattern.size() < 4) {
                std::printf(
                    "  under 4 bytes: len=%zu name=%s short_signature=%d magic_offset=%zu\n",
                    pattern.size(), definition.name.c_str(),
                    definition.short_signature ? 1 : 0, definition.magic_offset
                );
            }
        }
    }

    std::printf(
        "patterns=%zu shortest=%zu longest=%zu short_signature_definitions=%zu\n",
        pattern_count, shortest, longest, short_signature_definitions
    );
    for(std::size_t length = 0; length < histogram.size(); ++length) {
        if(histogram[length] != 0) {
            std::printf("  len %2zu : %zu\n", length, histogram[length]);
        }
    }
}

}

int main(int argc, char** argv) {
    if(argc >= 2 && std::strcmp(argv[1], "--patterns") == 0) {
        dump_patterns();
        return 0;
    }
    if(argc < 2) {
        std::fprintf(stderr, "usage: binwalk_bench <file> [repeats] [--search-all]\n");
        std::fprintf(stderr, "       binwalk_bench --patterns\n");
        return 2;
    }

    const std::string path = argv[1];
    int repeats = argc > 2 ? std::atoi(argv[2]) : 3;
    if(repeats < 1) {
        repeats = 1;
    }
    bool search_all = false;
    std::size_t worker_threads = 0;
    for(int index = 1; index < argc; ++index) {
        if(std::strcmp(argv[index], "--search-all") == 0) {
            search_all = true;
        }
        if(std::strncmp(argv[index], "--threads=", 10) == 0) {
            worker_threads = static_cast<std::size_t>(std::atoi(argv[index] + 10));
        }
    }

    const auto data = load(path);
    if(data.empty()) {
        std::fprintf(stderr, "failed to read %s\n", path.c_str());
        return 1;
    }
    const binwalk::byte_view view(data);

    binwalk::scan_options options;
    options.search_all = search_all;
    options.worker_threads = worker_threads;

    const auto build_start = clock_type::now();
    const binwalk::scanner scanner(options);
    const auto build_milliseconds =
        std::chrono::duration<double, std::milli>(clock_type::now() - build_start).count();

    std::printf(
        "corpus %.2f MiB  signatures %zu  patterns %zu  build %.2f ms  search_all %d  threads %zu\n",
        static_cast<double>(data.size()) / (1024.0 * 1024.0),
        scanner.signature_count(), scanner.pattern_count(), build_milliseconds,
        search_all ? 1 : 0, worker_threads
    );

    std::vector<sample> scan_samples;
    for(int index = 0; index < repeats; ++index) {
        scan_samples.push_back(time_once([&] { return scanner.scan(view).size(); }));
    }
    report("scan", data.size(), scan_samples);

    std::vector<sample> entropy_samples;
    for(int index = 0; index < repeats; ++index) {
        entropy_samples.push_back(time_once([&] { return binwalk::entropy_blocks(view).size(); }));
    }
    report("entropy_blocks", data.size(), entropy_samples);

    std::vector<sample> crc_samples;
    for(int index = 0; index < repeats; ++index) {
        crc_samples.push_back(time_once([&] {
            return static_cast<std::size_t>(binwalk::crc32(view));
        }));
    }
    report("crc32", data.size(), crc_samples);

    return 0;
}
