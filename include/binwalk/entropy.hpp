#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
namespace binwalk {

struct entropy_block {
    std::size_t end = 0;
    std::size_t start = 0;
    float entropy = 0.0F;
};

[[nodiscard]] BINWALK_API std::vector<entropy_block> entropy_blocks(
    byte_view data,
    std::size_t target_block_count = 2048
);

[[nodiscard]] BINWALK_API bool write_entropy_png(
    const std::vector<entropy_block>& blocks,
    const std::string& output_path,
    std::uint32_t width = 2048,
    std::uint32_t height = 1024
);

}
