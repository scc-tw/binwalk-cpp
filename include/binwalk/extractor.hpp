#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>

#include <cstdint>
#include <string>
#include <vector>
namespace binwalk {

[[nodiscard]] BINWALK_API extraction_result execute_extractor(
    byte_view data,
    const std::string& source_path,
    const signature_result& signature,
    const extractor& definition,
    const std::string& output_root
);

[[nodiscard]] BINWALK_API extraction_result dry_run_extractor(
    internal_extractor function,
    byte_view data,
    const signature_result& signature
);

[[nodiscard]] BINWALK_API extraction_result dry_run_extractor(
    const extractor& definition,
    byte_view data,
    const signature_result& signature
);

[[nodiscard]] BINWALK_API bool external_utility_available(const extractor& definition);

}
