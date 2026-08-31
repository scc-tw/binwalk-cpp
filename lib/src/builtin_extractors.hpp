#pragma once

#include <binwalk/extractor.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace binwalk::detail {

struct gzip_info {
    std::size_t header_size = 0;
    std::size_t deflate_size = 0;
    std::string operating_system;
    std::string original_name;
    std::uint32_t timestamp = 0;
};

struct zlib_info {
    std::size_t deflate_size = 0;
    std::size_t total_size = 0;
};

[[nodiscard]] std::optional<gzip_info> inspect_gzip(byte_view data, std::size_t offset);
[[nodiscard]] std::optional<zlib_info> inspect_zlib(byte_view data, std::size_t offset);

[[nodiscard]] extraction_result extract_bmp(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_jpeg(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_gzip(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_mbr(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_png(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_riff(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);
[[nodiscard]] extraction_result extract_zlib(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
);

} // namespace binwalk::detail
