#include "detail/literal_matcher.hpp"
#include "detail/task_pool.hpp"

#include <binwalk/binwalk.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using binwalk::detail::literal_matcher;
using binwalk::detail::task_pool;

constexpr std::size_t interleaved_slice = 8192;
constexpr std::size_t interleaved_window = 8 * interleaved_slice;

struct reported_match {
    std::size_t pattern_index = 0;
    std::size_t match_end = 0;

    friend bool operator==(const reported_match& left, const reported_match& right) noexcept {
        return left.pattern_index == right.pattern_index && left.match_end == right.match_end;
    }
};

std::vector<reported_match> collect(
    const literal_matcher& matcher,
    const std::vector<std::uint8_t>& data,
    std::size_t from = 0,
    std::size_t stop_after = 0,
    task_pool* pool = nullptr
) {
    std::vector<reported_match> found;
    const auto visit = [&](std::size_t pattern_index, std::size_t match_end) {
        found.push_back({pattern_index, match_end});
        return stop_after == 0 || found.size() < stop_after;
    };
    matcher.find(
        binwalk::byte_view(data),
        from,
        [](void* raw, std::size_t pattern_index, std::size_t match_end) {
            return (*static_cast<decltype(visit)*>(raw))(pattern_index, match_end);
        },
        const_cast<void*>(static_cast<const void*>(&visit)),
        pool
    );
    return found;
}

std::vector<std::vector<std::uint8_t>> registry_patterns() {
    const binwalk::scanner scanner;
    std::vector<std::vector<std::uint8_t>> patterns;
    for(const auto& definition : scanner.signatures()) {
        for(const auto& pattern : definition.magic) {
            if(!pattern.empty()) {
                patterns.push_back(pattern);
            }
        }
    }
    return patterns;
}

std::vector<std::uint8_t> pseudo_random(std::size_t size, std::uint32_t seed) {
    std::mt19937 generator(seed);
    std::vector<std::uint8_t> data(size);
    for(auto& value : data) {
        value = static_cast<std::uint8_t>(generator() & 0xFFU);
    }
    return data;
}

void plant(
    std::vector<std::uint8_t>& data,
    const std::vector<std::uint8_t>& pattern,
    std::size_t offset
) {
    if(offset + pattern.size() <= data.size()) {
        std::copy(
            pattern.begin(), pattern.end(), data.begin() + static_cast<std::ptrdiff_t>(offset)
        );
    }
}

std::vector<std::uint8_t> random_bytes_with_magics_on_boundaries(
    std::size_t size,
    const std::vector<std::vector<std::uint8_t>>& patterns,
    std::uint32_t seed
) {
    auto data = pseudo_random(size, seed);
    std::mt19937 generator(seed ^ 0x5EEDU);

    const std::size_t boundaries[] = {
        0, 1, 7,
        interleaved_slice - 1, interleaved_slice, interleaved_slice + 1, interleaved_slice + 38,
        2 * interleaved_slice - 1, 2 * interleaved_slice,
        interleaved_window - 2, interleaved_window - 1, interleaved_window,
        interleaved_window + 1, 2 * interleaved_window - 1, 2 * interleaved_window
    };
    std::size_t which = 0;
    for(const auto offset : boundaries) {
        plant(data, patterns[which++ % patterns.size()], offset);
    }
    for(std::size_t placed = 0; placed < 400; ++placed) {
        plant(data, patterns[generator() % patterns.size()], generator() % size);
    }
    return data;
}

void expect_backends_agree(
    const std::vector<std::vector<std::uint8_t>>& patterns,
    const std::vector<std::uint8_t>& data,
    std::size_t from = 0
) {
    const literal_matcher reference(patterns, literal_matcher::backend::scalar);
    const literal_matcher interleaved(patterns, literal_matcher::backend::interleaved);

    const auto expected = collect(reference, data, from);
    EXPECT_EQ(collect(interleaved, data, from), expected);

    task_pool pool(4);
    EXPECT_EQ(collect(interleaved, data, from, 0, &pool), expected);
}

}

TEST(LiteralMatcherTest, InterleavedWalkAgreesWithSingleWalkOnRandomData) {
    const auto patterns = registry_patterns();
    expect_backends_agree(patterns, pseudo_random(400 * 1024, 1));
}

TEST(LiteralMatcherTest, InterleavedWalkAgreesWithSingleWalkOnRepetitiveData) {
    const auto patterns = registry_patterns();
    expect_backends_agree(patterns, std::vector<std::uint8_t>(400 * 1024, 0));
    expect_backends_agree(patterns, std::vector<std::uint8_t>(400 * 1024, 0xFF));
}

TEST(LiteralMatcherTest, InterleavedWalkAgreesWhenMatchesStraddleSliceBoundaries) {
    const auto patterns = registry_patterns();
    expect_backends_agree(
        patterns, random_bytes_with_magics_on_boundaries(400 * 1024, patterns, 7)
    );
}

TEST(LiteralMatcherTest, InterleavedWalkAgreesForEveryStartingOffset) {
    const auto patterns = registry_patterns();
    const auto data = random_bytes_with_magics_on_boundaries(200 * 1024, patterns, 11);
    for(const std::size_t from : {std::size_t{0}, std::size_t{1},
                                  interleaved_slice - 1, interleaved_slice,
                                  interleaved_window, std::size_t{199 * 1024}}) {
        expect_backends_agree(patterns, data, from);
    }
}

TEST(LiteralMatcherTest, InterleavedWalkAgreesOnInputsTooSmallForAWindow) {
    const auto patterns = registry_patterns();
    for(const std::size_t size : {std::size_t{1}, std::size_t{2}, std::size_t{39},
                                  std::size_t{40}, std::size_t{511}, std::size_t{4096},
                                  interleaved_window - 1}) {
        expect_backends_agree(patterns, random_bytes_with_magics_on_boundaries(size, patterns, 13));
    }
}

TEST(LiteralMatcherTest, EveryPlantedPatternIsFoundExactlyOnce) {
    const std::vector<std::vector<std::uint8_t>> patterns{
        {'X', 'Y', 'Z', '1', '2', '3', '4', '5'}
    };

    std::vector<std::uint8_t> data(300 * 1024, '.');
    const std::size_t non_overlapping_offsets[] = {
        0,
        interleaved_slice - 8,
        interleaved_slice,
        interleaved_window - 8,
        interleaved_window,
        2 * interleaved_window,
        300 * 1024 - 8
    };
    for(const auto offset : non_overlapping_offsets) {
        plant(data, patterns[0], offset);
    }

    const literal_matcher matcher(patterns, literal_matcher::backend::interleaved);
    EXPECT_EQ(collect(matcher, data).size(), std::size(non_overlapping_offsets));
}

TEST(LiteralMatcherTest, ShorterSuffixEndingEarlierIsReportedFirst) {
    const std::vector<std::vector<std::uint8_t>> patterns{{'A', 'B', 'C', 'D'}, {'B', 'C'}};

    std::vector<std::uint8_t> data(300 * 1024, '.');
    plant(data, patterns[0], 4096);

    const literal_matcher matcher(patterns, literal_matcher::backend::interleaved);
    const auto found = collect(matcher, data);

    ASSERT_EQ(found.size(), 2U);
    EXPECT_EQ(found[0].pattern_index, 1U);
    EXPECT_EQ(found[0].match_end, 4099U);
    EXPECT_EQ(found[1].pattern_index, 0U);
    EXPECT_EQ(found[1].match_end, 4100U);
}

TEST(LiteralMatcherTest, StopsWhenTheCallbackAsksItTo) {
    const auto patterns = registry_patterns();
    const auto data = random_bytes_with_magics_on_boundaries(400 * 1024, patterns, 17);

    const literal_matcher matcher(patterns, literal_matcher::backend::interleaved);
    const auto everything = collect(matcher, data);
    ASSERT_GT(everything.size(), 3U);

    const auto truncated = collect(matcher, data, 0, 3);
    EXPECT_EQ(truncated.size(), 3U);
    EXPECT_EQ(truncated, std::vector<reported_match>(everything.begin(), everything.begin() + 3));
}

TEST(LiteralMatcherTest, ReportsNothingForAnEmptyPatternSetOrEmptyInput) {
    const literal_matcher empty_patterns({}, literal_matcher::backend::interleaved);
    EXPECT_TRUE(collect(empty_patterns, pseudo_random(100 * 1024, 19)).empty());

    const literal_matcher matcher(registry_patterns(), literal_matcher::backend::interleaved);
    EXPECT_TRUE(collect(matcher, {}).empty());
}

TEST(TaskPoolTest, RunsEveryIndexExactlyOnce) {
    for(const std::size_t width : {std::size_t{1}, std::size_t{2}, std::size_t{8}}) {
        task_pool pool(width);
        EXPECT_EQ(pool.width(), width);

        constexpr std::size_t count = 5000;
        std::vector<std::atomic<int>> visits(count);
        for(auto& visit : visits) {
            visit.store(0);
        }
        pool.run(count, [&](std::size_t index) { visits[index].fetch_add(1); });

        for(std::size_t index = 0; index < count; ++index) {
            EXPECT_EQ(visits[index].load(), 1) << "index " << index << " width " << width;
        }
    }
}

TEST(TaskPoolTest, ReusesItsThreadsAcrossBatches) {
    task_pool pool(4);
    std::atomic<int> total{0};
    for(int batch = 0; batch < 200; ++batch) {
        pool.run(64, [&](std::size_t) { total.fetch_add(1); });
    }
    EXPECT_EQ(total.load(), 200 * 64);
}

TEST(TaskPoolTest, RethrowsWhatTheWorkThrew) {
    task_pool pool(4);
    EXPECT_THROW(
        pool.run(64, [](std::size_t index) {
            if(index == 17) {
                throw std::runtime_error("failed");
            }
        }),
        std::runtime_error
    );
}

TEST(TaskPoolTest, StaysUsableAfterTheWorkThrew) {
    task_pool pool(4);
    EXPECT_THROW(
        pool.run(64, [](std::size_t) { throw std::runtime_error("failed"); }),
        std::runtime_error
    );

    std::atomic<int> total{0};
    pool.run(64, [&](std::size_t) { total.fetch_add(1); });
    EXPECT_EQ(total.load(), 64);
}

TEST(ParallelScanTest, ThreadCountDoesNotChangeTheFileMap) {
    const auto patterns = registry_patterns();
    const auto data = random_bytes_with_magics_on_boundaries(2 * 1024 * 1024, patterns, 23);
    const binwalk::byte_view view(data);

    const binwalk::scan_options serial;
    const auto expected = binwalk::scanner(serial).scan(view);

    for(const std::size_t threads : {std::size_t{2}, std::size_t{4}, std::size_t{8}}) {
        binwalk::scan_options parallel;
        parallel.worker_threads = threads;
        const auto actual = binwalk::scanner(parallel).scan(view);

        ASSERT_EQ(actual.size(), expected.size()) << "threads " << threads;
        for(std::size_t index = 0; index < actual.size(); ++index) {
            EXPECT_EQ(actual[index].offset, expected[index].offset) << "threads " << threads;
            EXPECT_EQ(actual[index].size, expected[index].size) << "threads " << threads;
            EXPECT_EQ(actual[index].name, expected[index].name) << "threads " << threads;
            EXPECT_EQ(actual[index].confidence, expected[index].confidence)
                << "threads " << threads;
            EXPECT_EQ(actual[index].description, expected[index].description)
                << "threads " << threads;
        }
    }
}

TEST(ParallelScanTest, RecommendedThreadCountIsUsable) {
    const auto threads = binwalk::recommended_scan_threads();
    EXPECT_GE(threads, 1U);
    EXPECT_LE(threads, 4096U);
}
