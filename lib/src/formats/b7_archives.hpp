#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>
#include <binwalk/signature.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk::formats {

[[nodiscard]] BINWALK_API std::vector<signature> b7_archives_signatures();

struct matter_ota_header {
    std::uint64_t total_size = 0;
    std::uint64_t header_size = 0;
    std::uint64_t payload_size = 0;
    std::uint64_t vendor_id = 0;
    std::uint64_t product_id = 0;
    std::uint64_t image_digest_type = 0;
    std::string version;
    std::string image_digest;
};

inline constexpr std::size_t matter_ota_fixed_header_size = 16;

[[nodiscard]] BINWALK_API std::optional<matter_ota_header> inspect_matter_ota(
    byte_view data,
    std::size_t offset
);

[[nodiscard]] BINWALK_API extraction_result extract_matter_ota(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

}
