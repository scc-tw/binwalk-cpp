#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace binwalk {

inline constexpr std::uint8_t confidence_low = 0;
inline constexpr std::uint8_t confidence_medium = 128;
inline constexpr std::uint8_t confidence_high = 250;

struct signature_result {
    std::uint64_t offset = 0;
    std::string id;
    std::uint64_t size = 0;
    std::string name;
    std::uint8_t confidence = confidence_low;
    std::string description;
    bool always_display = false;
    bool extraction_declined = false;

    friend bool operator<(const signature_result& left, const signature_result& right) noexcept {
        return left.offset < right.offset;
    }
};

struct extraction_result {
    std::optional<std::uint64_t> size;
    bool success = false;
    std::string extractor;
    bool do_not_recurse = false;
    std::string output_directory;
};

struct analysis_results {
    std::string file_path;
    std::vector<signature_result> file_map;
    std::unordered_map<std::string, extraction_result> extractions;
};

} // namespace binwalk
