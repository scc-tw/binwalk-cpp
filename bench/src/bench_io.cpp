#include "../../cli/src/mapped_file.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

using clock_type = std::chrono::steady_clock;

std::uint64_t checksum(const std::uint8_t* bytes, std::size_t size) {
    std::uint64_t total = 0;
    for(std::size_t index = 0; index < size; index += 64) {
        total += bytes[index];
    }
    return total;
}

template<typename Body>
void measure(const char* label, std::size_t size, int repeats, Body&& body) {
    double best = 1e30;
    std::uint64_t sink = 0;
    for(int index = 0; index < repeats; ++index) {
        const auto start = clock_type::now();
        sink += body();
        best = std::min(
            best, std::chrono::duration<double, std::milli>(clock_type::now() - start).count()
        );
    }
    std::printf(
        "%-22s %9.2f ms  %9.1f MiB/s   (%llu)\n",
        label, best,
        static_cast<double>(size) / (best / 1000.0) / (1024.0 * 1024.0),
        static_cast<unsigned long long>(sink)
    );
    std::fflush(stdout);
}

}

int main(int argc, char** argv) {
    if(argc < 2) {
        std::fprintf(stderr, "usage: binwalk_bench_io <file> [repeats]\n");
        return 2;
    }
    const std::string path = argv[1];
    int repeats = argc > 2 ? std::atoi(argv[2]) : 5;
    if(repeats < 1) {
        repeats = 1;
    }

    std::size_t size = 0;
    {
        std::ifstream probe(path, std::ios::binary | std::ios::ate);
        if(!probe) {
            std::fprintf(stderr, "failed to read %s\n", path.c_str());
            return 1;
        }
        size = static_cast<std::size_t>(probe.tellg());
    }
    std::printf("corpus %.2f MiB\n", static_cast<double>(size) / (1024.0 * 1024.0));

    measure("istreambuf_iterator", size, std::min(repeats, 2), [&] {
        std::ifstream input(path, std::ios::binary);
        const std::vector<std::uint8_t> data{
            std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()
        };
        return checksum(data.data(), data.size());
    });

    measure("bulk read", size, repeats, [&] {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        const auto length = static_cast<std::size_t>(input.tellg());
        input.seekg(0);
        std::vector<std::uint8_t> data(length);
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(length));
        return checksum(data.data(), data.size());
    });

    measure("mapped_file", size, repeats, [&] {
        binwalk_cli::mapped_file contents;
        if(!binwalk_cli::mapped_file::open(path, contents)) {
            return std::uint64_t{0};
        }
        return checksum(contents.view().data(), contents.view().size());
    });

    return 0;
}
