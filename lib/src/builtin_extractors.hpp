#pragma once

#include <binwalk/extractor.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
namespace binwalk::detail {

[[nodiscard]] inline std::filesystem::path native_long_path(
    const std::filesystem::path& value
) {
#if defined(_WIN32)

    constexpr std::size_t prefix_threshold = 240;
    if(!value.is_absolute()) {
        return value;
    }
    auto native = value.lexically_normal().make_preferred().wstring();
    if(native.size() < prefix_threshold) {
        return value;
    }
    if(native.compare(0, 4, L"\\\\?\\") == 0) {
        return value;
    }
    if(native.compare(0, 2, L"\\\\") == 0) {

        return std::filesystem::path(L"\\\\?\\UNC" + native.substr(1));
    }
    return std::filesystem::path(L"\\\\?\\" + native);
#else
    return value;
#endif
}

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
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_jpeg(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_gzip(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_mbr(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_png(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_riff(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);
[[nodiscard]] extraction_result extract_zlib(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

}
