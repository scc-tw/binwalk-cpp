#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace binwalk {

enum class extractor_type { none, internal, external };

using internal_extractor = extraction_result (*)(
    byte_view,
    const signature_result&,
    const std::string&
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

[[nodiscard]] BINWALK_API extraction_result execute_extractor(
    byte_view data,
    const std::string& source_path,
    const signature_result& signature,
    const extractor& definition,
    const std::string& output_root
);

} // namespace binwalk
