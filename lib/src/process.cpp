#include <binwalk/process.hpp>

#include <algorithm>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#else
#    include <cerrno>
#    include <chrono>
#    include <fcntl.h>
#    include <signal.h>
#    include <spawn.h>
#    include <sys/wait.h>
#    include <thread>
#    include <unistd.h>

#    if defined(__GLIBC__)
#        include <features.h>
#        if defined(__GLIBC_PREREQ)
#            if __GLIBC_PREREQ(2, 29)
#                define BINWALK_HAS_SPAWN_CHDIR 1
#            endif
#        endif
#    elif defined(__APPLE__)
#        define BINWALK_HAS_SPAWN_CHDIR 1
#    endif
extern "C" char** environ;
#endif
namespace binwalk {
namespace {

#if defined(_WIN32)

class handle_guard {
public:
    handle_guard() noexcept = default;
    explicit handle_guard(HANDLE value) noexcept : value_(value) {}
    handle_guard(const handle_guard&) = delete;
    handle_guard& operator=(const handle_guard&) = delete;
    handle_guard(handle_guard&&) = delete;
    handle_guard& operator=(handle_guard&&) = delete;

    ~handle_guard() {
        if(valid()) {
            CloseHandle(value_);
        }
    }

    [[nodiscard]] bool valid() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] HANDLE inheritable() const noexcept { return valid() ? value_ : nullptr; }

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

[[nodiscard]] std::wstring widen(const std::string& value) {
    if(value.empty()) {
        return {};
    }
    if(value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return {};
    }
    const auto length = static_cast<int>(value.size());
    const auto needed = MultiByteToWideChar(CP_UTF8, 0, value.data(), length, nullptr, 0);
    if(needed <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    const auto written = MultiByteToWideChar(CP_UTF8, 0, value.data(), length, result.data(), needed);
    if(written != needed) {
        return {};
    }
    return result;
}

[[nodiscard]] std::wstring environment_variable(const wchar_t* name) {
    const auto needed = GetEnvironmentVariableW(name, nullptr, 0);
    if(needed == 0) {
        return {};
    }
    std::wstring buffer(needed, L'\0');
    const auto written = GetEnvironmentVariableW(name, buffer.data(), needed);
    if(written == 0 || written >= needed) {
        return {};
    }
    buffer.resize(written);
    return buffer;
}

[[nodiscard]] std::vector<std::wstring> split(const std::wstring& value, wchar_t separator) {
    std::vector<std::wstring> parts;
    std::size_t start = 0;
    for(;;) {
        const auto end = value.find(separator, start);
        auto piece = end == std::wstring::npos
            ? value.substr(start)
            : value.substr(start, end - start);
        if(piece.size() >= 2 && piece.front() == L'"' && piece.back() == L'"') {
            piece = piece.substr(1, piece.size() - 2);
        }
        if(!piece.empty()) {
            parts.push_back(std::move(piece));
        }
        if(end == std::wstring::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

[[nodiscard]] bool equal_ignoring_case(const std::wstring& left, const std::wstring& right) {
    if(left.size() != right.size()) {
        return false;
    }
    for(std::size_t index = 0; index < left.size(); ++index) {
        if(towlower(left[index]) != towlower(right[index])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::vector<std::wstring> executable_extensions() {
    auto value = environment_variable(L"PATHEXT");
    if(value.empty()) {
        value = L".COM;.EXE;.BAT;.CMD";
    }
    auto parts = split(value, L';');
    static const wchar_t* const required[] = {L".EXE", L".COM", L".BAT", L".CMD"};
    for(const auto* candidate : required) {
        const std::wstring wanted(candidate);
        const auto present = std::any_of(
            parts.begin(),
            parts.end(),
            [&](const std::wstring& entry) { return equal_ignoring_case(entry, wanted); }
        );
        if(!present) {
            parts.push_back(wanted);
        }
    }
    return parts;
}

[[nodiscard]] bool is_regular_file(const std::wstring& path) {
    std::error_code error;
    return std::filesystem::is_regular_file(std::filesystem::path(path), error);
}

[[nodiscard]] bool has_file_extension(const std::wstring& path) {
    const auto dot = path.find_last_of(L'.');
    if(dot == std::wstring::npos) {
        return false;
    }
    const auto separator = path.find_last_of(L"\\/:");
    return separator == std::wstring::npos || dot > separator;
}

[[nodiscard]] bool has_directory_component(const std::string& program) {
    return program.find('\\') != std::string::npos
        || program.find('/') != std::string::npos
        || program.find(':') != std::string::npos;
}

[[nodiscard]] std::wstring resolve_program(const std::string& program) {
    if(program.empty()) {
        return {};
    }
    const auto wide = widen(program);
    if(wide.empty()) {
        return {};
    }

    const auto extensions = executable_extensions();
    const auto match = [&extensions](const std::wstring& base) -> std::wstring {
        if(is_regular_file(base)) {
            return base;
        }

        if(!has_file_extension(base)) {
            for(const auto& extension : extensions) {
                auto candidate = base + extension;
                if(is_regular_file(candidate)) {
                    return candidate;
                }
            }
        }
        return {};
    };

    const auto absolute_form = [](const std::wstring& path) -> std::wstring {
        std::error_code error;
        const auto resolved = std::filesystem::absolute(std::filesystem::path(path), error);
        return error ? path : resolved.wstring();
    };

    if(has_directory_component(program)) {
        const auto found = match(wide);
        return found.empty() ? std::wstring{} : absolute_form(found);
    }

    for(const auto& directory : split(environment_variable(L"PATH"), L';')) {
        const auto base = (std::filesystem::path(directory) / wide).wstring();
        const auto found = match(base);
        if(!found.empty()) {
            return absolute_form(found);
        }
    }
    return {};
}

void append_argument(std::wstring& command_line, const std::wstring& argument) {
    if(!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        command_line += argument;
        return;
    }

    command_line.push_back(L'"');
    for(auto cursor = argument.begin();; ++cursor) {
        std::size_t backslashes = 0;
        while(cursor != argument.end() && *cursor == L'\\') {
            ++cursor;
            ++backslashes;
        }
        if(cursor == argument.end()) {

            command_line.append(backslashes * 2, L'\\');
            break;
        }
        if(*cursor == L'"') {
            command_line.append(backslashes * 2 + 1, L'\\');
        } else {
            command_line.append(backslashes, L'\\');
        }
        command_line.push_back(*cursor);
    }
    command_line.push_back(L'"');
}

[[nodiscard]] HANDLE open_null_device(bool for_writing) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = nullptr;
    attributes.bInheritHandle = TRUE;
    return CreateFileW(
        L"NUL",
        for_writing ? GENERIC_WRITE : GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
}

#else

[[nodiscard]] std::vector<std::string> split(const std::string& value, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for(;;) {
        const auto end = value.find(separator, start);
        auto piece = end == std::string::npos
            ? value.substr(start)
            : value.substr(start, end - start);
        if(!piece.empty()) {
            parts.push_back(std::move(piece));
        }
        if(end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

[[nodiscard]] bool is_executable_file(const std::string& path) {
    std::error_code error;
    if(!std::filesystem::is_regular_file(std::filesystem::path(path), error)) {
        return false;
    }
    return access(path.c_str(), X_OK) == 0;
}

[[nodiscard]] std::string resolve_program(const std::string& program) {
    if(program.empty()) {
        return {};
    }
    if(program.find('/') != std::string::npos) {
        return is_executable_file(program) ? program : std::string{};
    }
    const char* path = getenv("PATH");
    if(path == nullptr) {
        return {};
    }
    for(const auto& directory : split(std::string(path), ':')) {
        const auto candidate = (std::filesystem::path(directory) / program).string();
        if(is_executable_file(candidate)) {
            return candidate;
        }
    }
    return {};
}

#endif

}

std::vector<std::string> substitute_source_file(
    const std::vector<std::string>& arguments,
    const std::string& replacement
) {
    std::vector<std::string> substituted;
    substituted.reserve(arguments.size());
    for(const auto& argument : arguments) {

        substituted.push_back(argument == source_file_placeholder ? replacement : argument);
    }
    return substituted;
}

bool executable_available(const std::string& program) {
    return !resolve_program(program).empty();
}

#if defined(_WIN32)

process_result run_process(const process_request& request) {
    process_result result;

    const auto program = resolve_program(request.program);
    if(program.empty()) {
        result.status = process_status::not_found;
        result.error_message = "executable not found: " + request.program;
        return result;
    }

    std::wstring command_line;
    append_argument(command_line, program);
    for(const auto& argument : request.arguments) {
        const auto wide = widen(argument);
        if(wide.empty() && !argument.empty()) {
            result.status = process_status::spawn_failed;
            result.error_message = "failed to convert an argument to UTF-16";
            return result;
        }
        command_line.push_back(L' ');
        append_argument(command_line, wide);
    }

    const auto working_directory = widen(request.working_directory);
    if(working_directory.empty() && !request.working_directory.empty()) {
        result.status = process_status::spawn_failed;
        result.error_message = "failed to convert the working directory to UTF-16";
        return result;
    }

    const handle_guard null_input(open_null_device(false));
    const handle_guard null_output(open_null_device(true));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;

    startup.hStdInput = null_input.inheritable();
    if(request.discard_output) {
        startup.hStdOutput = null_output.inheritable();
        startup.hStdError = null_output.inheritable();
    } else {
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }

    const handle_guard job(CreateJobObjectW(nullptr, nullptr));
    if(job.valid()) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job.get(),
            JobObjectExtendedLimitInformation,
            &limits,
            static_cast<DWORD>(sizeof(limits))
        );
    }

    std::vector<wchar_t> mutable_command_line(command_line.begin(), command_line.end());
    mutable_command_line.push_back(L'\0');

    PROCESS_INFORMATION information{};
    const auto spawned = CreateProcessW(
        program.c_str(),
        mutable_command_line.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr,
        working_directory.empty() ? nullptr : working_directory.c_str(),
        &startup,
        &information
    );
    if(spawned == FALSE) {
        const auto error = GetLastError();
        result.status = process_status::spawn_failed;
        result.error_message = "CreateProcessW failed with error "
            + std::to_string(static_cast<unsigned long>(error));
        return result;
    }

    const handle_guard process_handle(information.hProcess);
    const handle_guard thread_handle(information.hThread);

    if(job.valid()) {
        AssignProcessToJobObject(job.get(), information.hProcess);
    }
    if(ResumeThread(information.hThread) == static_cast<DWORD>(-1)) {
        TerminateProcess(information.hProcess, 1);
        WaitForSingleObject(information.hProcess, 5000);
        result.status = process_status::spawn_failed;
        result.error_message = "ResumeThread failed for the spawned process";
        return result;
    }

    const auto timeout = request.timeout_ms == 0
        ? INFINITE
        : static_cast<DWORD>(request.timeout_ms);
    const auto wait_status = WaitForSingleObject(information.hProcess, timeout);
    if(wait_status == WAIT_TIMEOUT) {
        if(job.valid()) {
            TerminateJobObject(job.get(), 1);
        }
        TerminateProcess(information.hProcess, 1);
        WaitForSingleObject(information.hProcess, 5000);
        result.status = process_status::timed_out;
        result.error_message = "process exceeded " + std::to_string(request.timeout_ms)
            + " ms and was terminated";
        return result;
    }
    if(wait_status != WAIT_OBJECT_0) {
        const auto error = GetLastError();
        result.status = process_status::spawn_failed;
        result.error_message = "WaitForSingleObject failed with error "
            + std::to_string(static_cast<unsigned long>(error));
        return result;
    }

    DWORD exit_code = 0;
    if(GetExitCodeProcess(information.hProcess, &exit_code) == FALSE) {
        const auto error = GetLastError();
        result.status = process_status::spawn_failed;
        result.error_message = "GetExitCodeProcess failed with error "
            + std::to_string(static_cast<unsigned long>(error));
        return result;
    }

    result.status = process_status::completed;
    result.exit_code = static_cast<std::int32_t>(exit_code);
    return result;
}

#else

process_result run_process(const process_request& request) {
    process_result result;

    const auto program = resolve_program(request.program);
    if(program.empty()) {
        result.status = process_status::not_found;
        result.error_message = "executable not found: " + request.program;
        return result;
    }

    std::vector<std::string> storage;
    storage.reserve(request.arguments.size() + 1);
    storage.push_back(program);
    storage.insert(storage.end(), request.arguments.begin(), request.arguments.end());

    std::vector<char*> argv;
    argv.reserve(storage.size() + 1);
    for(auto& value : storage) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions{};
    if(posix_spawn_file_actions_init(&actions) != 0) {
        result.status = process_status::spawn_failed;
        result.error_message = "posix_spawn_file_actions_init failed";
        return result;
    }

    bool prepared = true;
    if(!request.working_directory.empty()) {
#if defined(BINWALK_HAS_SPAWN_CHDIR)
        prepared = posix_spawn_file_actions_addchdir_np(
            &actions, request.working_directory.c_str()
        ) == 0;
#else
        prepared = false;
        result.error_message = "this platform cannot set a child working directory";
#endif
    }

    if(prepared) {
        prepared = posix_spawn_file_actions_addopen(
            &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0
        ) == 0;
    }
    if(prepared && request.discard_output) {
        prepared = posix_spawn_file_actions_addopen(
                       &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0
                   ) == 0
            && posix_spawn_file_actions_addopen(
                   &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0
               ) == 0;
    }

    pid_t child = 0;
    const int spawn_status = prepared
        ? posix_spawn(&child, program.c_str(), &actions, nullptr, argv.data(), environ)
        : -1;
    posix_spawn_file_actions_destroy(&actions);

    if(!prepared || spawn_status != 0) {
        result.status = process_status::spawn_failed;
        if(result.error_message.empty()) {
            result.error_message = "posix_spawn failed for " + program;
        }
        return result;
    }

    const auto report = [&result](int status) {
        result.status = process_status::completed;
        if(WIFEXITED(status)) {
            result.exit_code = static_cast<std::int32_t>(WEXITSTATUS(status));
        } else if(WIFSIGNALED(status)) {
            result.exit_code = static_cast<std::int32_t>(128 + WTERMSIG(status));
        } else {
            result.exit_code = -1;
        }
    };

    if(request.timeout_ms == 0) {
        int status = 0;
        while(waitpid(child, &status, 0) < 0) {
            if(errno != EINTR) {
                result.status = process_status::spawn_failed;
                result.error_message = "waitpid failed";
                return result;
            }
        }
        report(status);
        return result;
    }

    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(request.timeout_ms);
    for(;;) {
        int status = 0;
        const pid_t finished = waitpid(child, &status, WNOHANG);
        if(finished == child) {
            report(status);
            return result;
        }
        if(finished < 0 && errno != EINTR) {
            result.status = process_status::spawn_failed;
            result.error_message = "waitpid failed";
            return result;
        }
        if(std::chrono::steady_clock::now() >= deadline) {
            kill(child, SIGKILL);
            int discarded = 0;
            while(waitpid(child, &discarded, 0) < 0 && errno == EINTR) {
            }
            result.status = process_status::timed_out;
            result.error_message = "process exceeded " + std::to_string(request.timeout_ms)
                + " ms and was terminated";
            return result;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

#endif

}
