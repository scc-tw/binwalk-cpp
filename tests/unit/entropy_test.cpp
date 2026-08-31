#include <binwalk/entropy.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(Entropy, ReturnsZeroForAConstantBlock) {
    const std::vector<std::uint8_t> data(128, 0xaa);
    const auto blocks = binwalk::entropy_blocks(binwalk::byte_view(data));

    ASSERT_EQ(blocks.size(), 1U);
    EXPECT_FLOAT_EQ(blocks[0].entropy, 0.0F);
    EXPECT_EQ(blocks[0].start, 0U);
    EXPECT_EQ(blocks[0].end, data.size());
}

TEST(Entropy, ReturnsEightForAllByteValues) {
    std::vector<std::uint8_t> data;
    for(std::size_t value = 0; value < 256; ++value) {
        data.push_back(static_cast<std::uint8_t>(value));
    }
    const auto blocks = binwalk::entropy_blocks(binwalk::byte_view(data));

    ASSERT_EQ(blocks.size(), 1U);
    EXPECT_FLOAT_EQ(blocks[0].entropy, 8.0F);
}

TEST(Entropy, HandlesEmptyInput) {
    EXPECT_TRUE(binwalk::entropy_blocks({}).empty());
}
