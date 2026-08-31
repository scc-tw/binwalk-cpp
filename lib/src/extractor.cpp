#include <binwalk/extractor.hpp>

#include "builtin_extractors.hpp"

#include <binwalk/process.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <system_error>
namespace binwalk {
namespace {

constexpr std::uint32_t external_extractor_timeout_ms = 300000;

[[nodiscard]] std::string safe_component(std::string value) {
    for(auto& character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if(std::isalnum(byte) == 0 && character != '-' && character != '_' && character != '.') {
            character = '_';
        }
    }
    return value.empty() ? "input" : value;
}

[[nodiscard]] std::string uppercase_hex(std::uint64_t value) {
    std::ostringstream stream;
    stream << std::uppercase << std::hex << value;
    return stream.str();
}

[[nodiscard]] bool contains_nonempty_output(const std::filesystem::path& directory) {
    std::error_code error;

    for(std::filesystem::recursive_directory_iterator
            iterator(detail::native_long_path(directory), error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        if(iterator->is_regular_file(error) && iterator->file_size(error) > 0) {
            return true;
        }
    }
    return false;
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

[[nodiscard]] bool carve_to_file(
    byte_view data,
    std::uint64_t offset,
    std::uint64_t size,
    const std::filesystem::path& path
) {
    if(offset > data.size() || size > data.size() - offset) {
        return false;
    }
    std::ofstream output(
        detail::native_long_path(path), std::ios::binary | std::ios::trunc
    );
    if(!output) {
        return false;
    }

    constexpr std::size_t chunk_limit = 1024U * 1024U * 1024U;
    auto cursor = static_cast<std::size_t>(offset);
    auto remaining = static_cast<std::size_t>(size);
    while(remaining > 0 && output) {
        const auto chunk = std::min(remaining, chunk_limit);
        output.write(
            reinterpret_cast<const char*>(data.data() + cursor),
            static_cast<std::streamsize>(chunk)
        );
        cursor += chunk;
        remaining -= chunk;
    }
    return static_cast<bool>(output);
}

[[nodiscard]] bool exit_code_accepted(
    std::int32_t code,
    const std::vector<std::int32_t>& accepted
) {

    if(code == 0) {
        return true;
    }
    return std::find(accepted.begin(), accepted.end(), code) != accepted.end();
}

[[nodiscard]] extraction_result run_external_extractor(
    byte_view data,
    const signature_result& signature,
    const extractor& definition,
    const std::filesystem::path& output_directory
) {
    extraction_result result;

    if(definition.command.empty() || !executable_available(definition.command)) {
        result.failure = extraction_failure::utility_not_found;
        return result;
    }
    if(signature.size == 0) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    auto carved_name = safe_component(signature.name) + "_" + uppercase_hex(signature.offset);
    if(!definition.extension.empty()) {

        carved_name += "." + safe_component(definition.extension);
    }
    const auto carved_file = output_directory / carved_name;

    if(!carve_to_file(data, signature.offset, signature.size, carved_file)) {
        std::error_code remove_error;
        std::filesystem::remove(carved_file, remove_error);
        result.failure = extraction_failure::write_error;
        return result;
    }

    process_request request;
    request.program = definition.command;

    request.arguments = substitute_source_file(definition.arguments, carved_file.string());

    request.working_directory = output_directory.string();
    request.timeout_ms = external_extractor_timeout_ms;
    request.discard_output = true;

    const auto process = run_process(request);

    std::error_code remove_error;
    std::filesystem::remove(carved_file, remove_error);

    switch(process.status) {
    case process_status::not_found:
        result.failure = extraction_failure::utility_not_found;
        return result;
    case process_status::timed_out:
        result.failure = extraction_failure::timed_out;
        return result;
    case process_status::spawn_failed:
        result.failure = extraction_failure::utility_failed;
        return result;
    case process_status::completed:
        break;
    }

    result.extractor = definition.command;

    if(!exit_code_accepted(process.exit_code, definition.exit_codes)) {
        result.failure = extraction_failure::utility_failed;
        return result;
    }
    result.success = true;
    return result;
}

}

extraction_result execute_extractor(
    byte_view data,
    const std::string& source_path,
    const signature_result& signature,
    const extractor& definition,
    const std::string& output_root
) {

    const extractor& selected = signature.preferred_extractor
        ? *signature.preferred_extractor
        : definition;

    extraction_result result;
    if(output_root.empty()) {
        result.failure = extraction_failure::write_error;
        return result;
    }

    std::error_code error;
    const auto root = std::filesystem::absolute(output_root, error).lexically_normal();
    if(error) {
        result.failure = extraction_failure::write_error;
        return result;
    }
    error.clear();
    const auto source = std::filesystem::absolute(source_path, error).lexically_normal();
    if(error) {
        result.failure = extraction_failure::write_error;
        return result;
    }

    const auto offset_name = uppercase_hex(signature.offset);
    const auto source_name = safe_component(source.filename().string());
    const auto extraction_base = is_within(source, root)
        ? std::filesystem::path(source.string() + ".extracted")
        : root / (source_name + ".extracted");
    const auto output_directory = extraction_base / offset_name;

    std::filesystem::remove_all(detail::native_long_path(output_directory), error);
    error.clear();
    std::filesystem::create_directories(detail::native_long_path(output_directory), error);
    if(error) {
        result.failure = extraction_failure::write_error;
        return result;
    }

    if(selected.type == extractor_type::internal && selected.internal != nullptr) {
        const auto output_directory_string = output_directory.string();
        result = selected.internal(data, signature, &output_directory_string);
        result.extractor = signature.name + "_built_in";
    } else if(selected.type == extractor_type::external) {

        result = run_external_extractor(data, signature, selected, output_directory);
    } else {

        result.failure = extraction_failure::unsupported;
    }
    result.output_directory = output_directory.string();
    result.do_not_recurse = selected.do_not_recurse;

    if(result.success && !contains_nonempty_output(output_directory)) {
        result.success = false;
        result.failure = extraction_failure::no_output;
    }
    if(!result.success) {
        error.clear();
        std::filesystem::remove_all(output_directory, error);
    }
    return result;
}

extraction_result dry_run_extractor(
    internal_extractor function,
    byte_view data,
    const signature_result& signature
) {
    extraction_result result;
    if(function == nullptr) {
        result.failure = extraction_failure::unsupported;
        return result;
    }
    return function(data, signature, nullptr);
}

extraction_result dry_run_extractor(
    const extractor& definition,
    byte_view data,
    const signature_result& signature
) {

    const extractor& selected = signature.preferred_extractor
        ? *signature.preferred_extractor
        : definition;

    if(selected.type != extractor_type::internal) {
        extraction_result result;
        result.failure = extraction_failure::unsupported;
        return result;
    }
    return dry_run_extractor(selected.internal, data, signature);
}

bool external_utility_available(const extractor& definition) {
    if(definition.type != extractor_type::external || definition.command.empty()) {
        return false;
    }
    return executable_available(definition.command);
}

}
