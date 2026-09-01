#include "detail/cstring_length_memo.hpp"

#include <binwalk/common.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using binwalk::byte_view;
using binwalk::cstring_length;
using binwalk::detail::cstring_length_memo;

std::size_t length_by_scanning_for_nul(byte_view data) {
    for(std::size_t index = 0; index < data.size(); ++index) {
        if(data[index] == 0) {
            return index;
        }
    }
    return data.size();
}

std::vector<std::uint8_t> buffer_of_runs_of_every_shape() {
    std::vector<std::uint8_t> data;
    const auto append = [&data](const std::string& text) {
        data.insert(data.end(), text.begin(), text.end());
    };

    append("Linux version 4.14.0 (gcc 7.3) @builder");
    data.push_back(0);
    append(std::string(5000, 'A'));
    data.push_back(0);
    data.push_back(0);
    append("short");
    data.push_back(0);
    data.insert(data.end(), 300, 0xFF);
    data.push_back(0);
    append(std::string(1000, 'z'));
    return data;
}

}

TEST(CstringLengthMemoTest, LengthMatchesANaiveScanAtEveryOffset) {
    const auto data = buffer_of_runs_of_every_shape();
    const byte_view whole(data);

    for(std::size_t offset = 0; offset < data.size(); ++offset) {
        const auto tail = whole.subview(offset, data.size() - offset);
        EXPECT_EQ(cstring_length(tail), length_by_scanning_for_nul(tail)) << "offset " << offset;
    }
}

TEST(CstringLengthMemoTest, MemoisedAnswersMatchUnmemoisedOnes) {
    const auto data = buffer_of_runs_of_every_shape();
    const byte_view whole(data);

    std::vector<std::size_t> without_memo;
    for(std::size_t offset = 0; offset < data.size(); ++offset) {
        without_memo.push_back(cstring_length(whole.subview(offset, data.size() - offset)));
    }

    std::vector<std::size_t> with_memo;
    {
        const cstring_length_memo memo(whole);
        for(std::size_t offset = 0; offset < data.size(); ++offset) {
            with_memo.push_back(cstring_length(whole.subview(offset, data.size() - offset)));
        }
    }
    EXPECT_EQ(with_memo, without_memo);
}

TEST(CstringLengthMemoTest, HoldsForShortenedAndWidenedQueriesOverOneRun) {
    const auto data = buffer_of_runs_of_every_shape();
    const byte_view whole(data);
    const cstring_length_memo memo(whole);

    for(std::size_t offset = 0; offset + 1 < data.size(); offset += 7) {
        for(const std::size_t length : {std::size_t{1}, std::size_t{8}, std::size_t{64},
                                        std::size_t{4096}, data.size() - offset}) {
            const auto bounded = std::min(length, data.size() - offset);
            const auto tail = whole.subview(offset, bounded);
            EXPECT_EQ(cstring_length(tail), length_by_scanning_for_nul(tail))
                << "offset " << offset << " length " << bounded;
        }
    }
}

TEST(CstringLengthMemoTest, NestedMemosRestoreTheOuterOne) {
    const auto outer = buffer_of_runs_of_every_shape();
    std::vector<std::uint8_t> inner(2048, 'q');
    inner.push_back(0);

    const byte_view outer_view(outer);
    const byte_view inner_view(inner);

    const cstring_length_memo outer_memo(outer_view);
    EXPECT_EQ(cstring_length(outer_view), length_by_scanning_for_nul(outer_view));
    {
        const cstring_length_memo inner_memo(inner_view);
        EXPECT_EQ(cstring_length(inner_view), length_by_scanning_for_nul(inner_view));
        EXPECT_EQ(
            cstring_length(inner_view.subview(100, inner.size() - 100)),
            length_by_scanning_for_nul(inner_view.subview(100, inner.size() - 100))
        );
    }
    for(std::size_t offset = 0; offset < outer.size(); offset += 13) {
        const auto tail = outer_view.subview(offset, outer.size() - offset);
        EXPECT_EQ(cstring_length(tail), length_by_scanning_for_nul(tail)) << "offset " << offset;
    }
}

TEST(CstringLengthMemoTest, IsNotConsultedForBuffersOutsideIt) {
    const auto memoised = buffer_of_runs_of_every_shape();
    std::vector<std::uint8_t> other(500, 'k');
    other[120] = 0;

    const cstring_length_memo memo{byte_view{memoised}};
    EXPECT_EQ(cstring_length(byte_view{memoised}), length_by_scanning_for_nul(byte_view{memoised}));

    const byte_view other_view(other);
    EXPECT_EQ(cstring_length(other_view), 120U);
    EXPECT_EQ(cstring_length(other_view.subview(200, 300)), 300U);
}

TEST(CstringLengthMemoTest, HandlesEmptyAndFullyTerminatedViews) {
    EXPECT_EQ(cstring_length(byte_view{}), 0U);

    const std::vector<std::uint8_t> zeros(64, 0);
    const byte_view zero_view(zeros);
    const cstring_length_memo memo(zero_view);
    for(std::size_t offset = 0; offset < zeros.size(); ++offset) {
        EXPECT_EQ(cstring_length(zero_view.subview(offset, zeros.size() - offset)), 0U);
    }
}

TEST(CstringLengthMemoTest, GetCstringStillStopsAtTheTerminator) {
    std::vector<std::uint8_t> data;
    const std::string first = "first";
    data.insert(data.end(), first.begin(), first.end());
    data.push_back(0);
    const std::string second = "second";
    data.insert(data.end(), second.begin(), second.end());
    data.push_back(0);

    const byte_view whole(data);
    const cstring_length_memo memo(whole);

    EXPECT_EQ(binwalk::get_cstring(whole), "first");
    EXPECT_EQ(binwalk::get_cstring(whole, 6, data.size() - 6), "second");
    EXPECT_EQ(binwalk::get_cstring_bytes(whole).size(), first.size());
}
