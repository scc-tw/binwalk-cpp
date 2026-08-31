#include <binwalk/extractor.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <system_error>

namespace binwalk {
namespace {

[[nodiscard]] std::string safe_component(std::string value) {
    for(auto& character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if(std::isalnum(byte) == 0 && character != '-' && character != '_' && character != '.') {
            character = '_';
        }
    }
    return value.empty() ? "input" : value;
}

[[nodiscard]] bool contains_nonempty_output(const std::filesystem::path& directory) {
    std::error_code error;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        if(iterator->is_regular_file(error) && iterator->file_size(error) > 0) {
            return true;
        }
    }
    return false;
}

} // namespace

extraction_result execute_extractor(
    byte_view data,
    const std::string& source_path,
    const signature_result& signature,
    const extractor& definition,
    const std::string& output_root
) {
    extraction_result result;
    if(output_root.empty()) {
        return result;
    }

    std::ostringstream offset_name;
    offset_name << std::uppercase << std::hex << signature.offset;
    const auto source_name = safe_component(std::filesystem::path(source_path).filename().string());
    const auto output_directory = std::filesystem::path(output_root)
        / (source_name + ".extracted")
        / offset_name.str();

    std::error_code error;
    std::filesystem::remove_all(output_directory, error);
    error.clear();
    std::filesystem::create_directories(output_directory, error);
    if(error) {
        return result;
    }

    if(definition.type == extractor_type::internal && definition.internal != nullptr) {
        result = definition.internal(data, signature, output_directory.string());
        result.extractor = signature.name + "_built_in";
    } else if(definition.type == extractor_type::external) {
        result.extractor = definition.command;
    }
    result.output_directory = output_directory.string();
    result.do_not_recurse = definition.do_not_recurse;

    if(result.success && !contains_nonempty_output(output_directory)) {
        result.success = false;
    }
    if(!result.success) {
        error.clear();
        std::filesystem::remove_all(output_directory, error);
    }
    return result;
}

} // namespace binwalk
