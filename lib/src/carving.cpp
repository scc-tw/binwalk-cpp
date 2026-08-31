#include <binwalk/carving.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace binwalk {
namespace {

[[nodiscard]] std::string safe_component(std::string value) {
    for(auto& character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if(std::isalnum(byte) == 0 && character != '-' && character != '_' && character != '.') {
            character = '_';
        }
    }
    return value.empty() ? "unknown" : value;
}

[[nodiscard]] carved_result carve_one(
    byte_view data,
    const std::filesystem::path& output_directory,
    const std::string& source_name,
    const std::string& type_name,
    std::uint64_t offset,
    std::uint64_t size,
    bool known
) {
    carved_result result;
    result.offset = offset;
    result.size = size;
    result.known = known;

    if(offset > data.size() || size > data.size() - offset) {
        return result;
    }

    const auto base_name = safe_component(std::filesystem::path(source_name).filename().string());
    const auto file_name = base_name + "_" + std::to_string(offset) + "_"
        + safe_component(type_name) + ".raw";
    const auto output_path = output_directory / file_name;
    result.path = output_path.string();

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if(!output) {
        return result;
    }
    constexpr std::size_t write_chunk_size = 1024U * 1024U * 1024U;
    auto cursor = static_cast<std::size_t>(offset);
    auto remaining = static_cast<std::size_t>(size);
    while(remaining > 0 && output) {
        const auto chunk = std::min(remaining, write_chunk_size);
        output.write(
            reinterpret_cast<const char*>(data.data() + cursor),
            static_cast<std::streamsize>(chunk)
        );
        cursor += chunk;
        remaining -= chunk;
    }
    result.success = static_cast<bool>(output);
    return result;
}

[[nodiscard]] bool is_within(
    const std::filesystem::path& child,
    const std::filesystem::path& parent
) {
    const auto relative = child.lexically_relative(parent);
    if(relative.empty() || relative.is_absolute()) {
        return false;
    }
    const auto first = relative.begin();
    return first != relative.end() && *first != "..";
}

} // namespace

std::vector<carved_result> carve_file_map(
    byte_view data,
    const std::vector<signature_result>& file_map,
    const std::string& source_name,
    const std::string& output_directory
) {
    std::vector<carved_result> results;
    if(file_map.empty()) {
        return results;
    }

    std::error_code error;
    const auto root = std::filesystem::absolute(output_directory, error).lexically_normal();
    if(error) {
        return results;
    }
    error.clear();
    const auto source = std::filesystem::absolute(source_name, error).lexically_normal();
    if(error) {
        return results;
    }
    const auto target_directory = is_within(source, root) ? source.parent_path() : root;
    std::filesystem::create_directories(target_directory, error);
    if(error) {
        return results;
    }

    std::uint64_t last_known_offset = 0;
    for(const auto& signature : file_map) {
        if(signature.offset > data.size() || signature.size > data.size() - signature.offset) {
            carved_result invalid;
            invalid.offset = signature.offset;
            invalid.size = signature.size;
            invalid.known = true;
            results.push_back(std::move(invalid));
            continue;
        }
        if(signature.offset > last_known_offset) {
            results.push_back(carve_one(
                data,
                target_directory,
                source_name,
                "unknown",
                last_known_offset,
                signature.offset - last_known_offset,
                false
            ));
        }
        results.push_back(carve_one(
            data,
            target_directory,
            source_name,
            signature.name,
            signature.offset,
            signature.size,
            true
        ));
        last_known_offset = std::max(last_known_offset, signature.offset + signature.size);
    }

    if(last_known_offset < data.size()) {
        results.push_back(carve_one(
            data,
            target_directory,
            source_name,
            "unknown",
            last_known_offset,
            data.size() - last_known_offset,
            false
        ));
    }
    return results;
}

} // namespace binwalk
