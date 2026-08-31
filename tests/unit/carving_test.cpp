#include <binwalk/carving.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

TEST(Carving, WritesKnownAndUnknownBlocks) {
    const auto output_directory = std::filesystem::temp_directory_path()
        / "binwalk_cpp_carving_test";
    std::error_code error;
    std::filesystem::remove_all(output_directory, error);

    const std::vector<std::uint8_t> data{0, 1, 2, 3, 4, 5};
    binwalk::signature_result signature;
    signature.offset = 2;
    signature.size = 2;
    signature.name = "test";

    const auto carved = binwalk::carve_file_map(
        binwalk::byte_view(data), {signature}, "fixture.bin", output_directory.string()
    );

    ASSERT_EQ(carved.size(), 3U);
    EXPECT_FALSE(carved[0].known);
    EXPECT_TRUE(carved[1].known);
    EXPECT_FALSE(carved[2].known);
    for(const auto& result : carved) {
        EXPECT_TRUE(result.success);
        EXPECT_EQ(std::filesystem::file_size(result.path), 2U);
    }

    std::filesystem::remove_all(output_directory, error);
}
