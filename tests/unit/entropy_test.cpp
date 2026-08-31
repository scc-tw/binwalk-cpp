#include <binwalk/entropy.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
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

#if defined(BINWALK_TEST_HAS_ZLIB)
TEST(Entropy, WritesAValidPngGraph) {
    const std::vector<std::uint8_t> data{0, 0, 0, 0, 1, 2, 3, 4};
    const auto blocks = binwalk::entropy_blocks(binwalk::byte_view(data), 2);
    const auto output = std::filesystem::temp_directory_path()
        / "binwalk_cpp_entropy_test.png";
    std::error_code error;
    std::filesystem::remove(output, error);

    ASSERT_TRUE(binwalk::write_entropy_png(blocks, output.string(), 256, 128));
    std::ifstream input(output, std::ios::binary);
    const std::vector<std::uint8_t> bytes{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()
    };
    const std::vector<std::uint8_t> expected_signature{
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    ASSERT_GT(bytes.size(), 100U);
    EXPECT_TRUE(std::equal(
        expected_signature.begin(), expected_signature.end(), bytes.begin()
    ));

    std::filesystem::remove(output, error);
}
#endif
