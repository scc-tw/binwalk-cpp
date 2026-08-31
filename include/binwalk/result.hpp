#pragma once

#include <binwalk/byte_view.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
namespace binwalk {

inline constexpr std::uint8_t confidence_low = 0;
inline constexpr std::uint8_t confidence_medium = 128;
inline constexpr std::uint8_t confidence_high = 250;

enum class extraction_failure {
    none,
    unsupported,
    invalid_data,
    utility_not_found,

    utility_failed,

    timed_out,
    no_output,
    write_error
};

struct extraction_result {
    std::optional<std::uint64_t> size;
    bool success = false;
    std::string extractor;
    bool do_not_recurse = false;
    std::string output_directory;
    extraction_failure failure = extraction_failure::none;
};

struct signature_result;

enum class extractor_type { none, internal, external };

using internal_extractor = extraction_result (*)(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

struct extractor {
    extractor_type type = extractor_type::none;
    std::string name;
    internal_extractor internal = nullptr;
    std::string command;
    std::string extension;
    std::vector<std::string> arguments;
    std::vector<std::int32_t> exit_codes;
    bool do_not_recurse = false;
};

struct signature_result {
    std::uint64_t offset = 0;
    std::string id;
    std::uint64_t size = 0;
    std::string name;
    std::uint8_t confidence = confidence_low;
    std::string description;
    bool always_display = false;
    bool extraction_declined = false;

    std::optional<extractor> preferred_extractor;

    friend bool operator<(const signature_result& left, const signature_result& right) noexcept {
        return left.offset < right.offset;
    }
};

struct analysis_results {
    std::string file_path;
    std::vector<signature_result> file_map;
    std::unordered_map<std::string, extraction_result> extractions;
};

}
