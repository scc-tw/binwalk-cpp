#pragma once

#include <binwalk/export.hpp>

#include <cstdint>
#include <string>
#include <vector>
namespace binwalk {

inline constexpr const char* source_file_placeholder = "%e";

enum class process_status {

    completed,

    not_found,

    spawn_failed,

    timed_out
};

struct process_result {
    process_status status = process_status::spawn_failed;
    std::int32_t exit_code = -1;

    std::string error_message;

    [[nodiscard]] bool completed() const noexcept {
        return status == process_status::completed;
    }
    [[nodiscard]] bool utility_missing() const noexcept {
        return status == process_status::not_found;
    }
};

struct process_request {

    std::string program;

    std::vector<std::string> arguments;

    std::string working_directory;

    std::uint32_t timeout_ms = 0;

    bool discard_output = true;
};

[[nodiscard]] BINWALK_API process_result run_process(const process_request& request);

[[nodiscard]] BINWALK_API bool executable_available(const std::string& program);

[[nodiscard]] BINWALK_API std::vector<std::string> substitute_source_file(
    const std::vector<std::string>& arguments,
    const std::string& replacement
);

}
