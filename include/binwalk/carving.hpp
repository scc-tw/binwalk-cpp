#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>

#include <cstdint>
#include <string>
#include <vector>
namespace binwalk {

struct carved_result {
    std::string path;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    bool known = false;
    bool success = false;
};

[[nodiscard]] BINWALK_API std::vector<carved_result> carve_file_map(
    byte_view data,
    const std::vector<signature_result>& file_map,
    const std::string& source_name,
    const std::string& output_directory
);

}
