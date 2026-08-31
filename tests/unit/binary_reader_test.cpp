#include <binwalk/binary_reader.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(BinaryReader, ReadsBigAndLittleEndianIntegers) {
    const std::vector<std::uint8_t> data{0x01, 0x02, 0x03, 0x04};
    const binwalk::binary_reader<binwalk::byte_order::big> big{binwalk::byte_view(data)};
    const binwalk::binary_reader<binwalk::byte_order::little> little{binwalk::byte_view(data)};

    EXPECT_EQ(big.read<std::uint32_t>(0), 0x01020304U);
    EXPECT_EQ(little.read<std::uint32_t>(0), 0x04030201U);
    EXPECT_EQ(big.read_u24(0), 0x010203U);
    EXPECT_EQ(little.read_u24(0), 0x030201U);
}

TEST(BinaryReader, RejectsOutOfBoundsReads) {
    const std::vector<std::uint8_t> data{0x01};
    const binwalk::binary_reader<binwalk::byte_order::big> reader{binwalk::byte_view(data)};

    EXPECT_FALSE(reader.read<std::uint32_t>(0).has_value());
    EXPECT_FALSE(reader.read_u24(0).has_value());
}
