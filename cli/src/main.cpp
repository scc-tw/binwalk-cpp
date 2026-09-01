#include <binwalk/binwalk.hpp>

#include "mapped_file.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
namespace {

using json = nlohmann::json;

constexpr char delimiter_character = '-';
constexpr std::size_t default_terminal_width = 200;
constexpr std::size_t column1_width = 35;
constexpr std::size_t column2_width = 35;
constexpr std::size_t description_prefix_width = column1_width + column2_width;

constexpr std::size_t minimum_wrap_width = 20;

[[nodiscard]] std::size_t detect_terminal_width() {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info) != 0) {
        const int columns = static_cast<int>(info.srWindow.Right) - static_cast<int>(info.srWindow.Left) + 1;
        if(columns > 0) {
            return static_cast<std::size_t>(columns);
        }
    }
#else
    winsize size{};
    if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0) {
        return static_cast<std::size_t>(size.ws_col);
    }
#endif
    return default_terminal_width;
}

[[nodiscard]] std::size_t terminal_width() {
    static const std::size_t width = detect_terminal_width();
    return width;
}

[[nodiscard]] std::string line_delimiter() {
    return std::string(terminal_width(), delimiter_character);
}

void print_delimiter() {
    std::cout << line_delimiter() << '\n';
}

[[nodiscard]] std::string pad_to_length(std::string text, std::size_t length) {
    if(text.size() < length) {
        text.append(length - text.size(), ' ');
    }
    return text;
}

[[nodiscard]] std::string line_wrap(const std::string& text, std::size_t prefix_size) {
    const auto width = terminal_width();
    const auto max_line_size = width > prefix_size + minimum_wrap_width
        ? width - prefix_size
        : minimum_wrap_width;

    std::string wrapped;
    std::string current;
    std::istringstream input(text);
    std::string word;
    while(input >> word) {
        if(!current.empty() && current.size() + word.size() >= max_line_size) {
            while(!current.empty() && current.back() == ' ') {
                current.pop_back();
            }
            wrapped += current;
            wrapped += '\n';
            wrapped.append(prefix_size, ' ');
            current.clear();
        }
        current += word;
        current += ' ';
    }
    wrapped += current;

    const auto first = wrapped.find_first_not_of(" \t\n");
    if(first == std::string::npos) {
        return {};
    }
    const auto last = wrapped.find_last_not_of(" \t\n");
    return wrapped.substr(first, last - first + 1);
}

[[nodiscard]] std::string hex_offset(std::uint64_t offset) {
    std::ostringstream output;
    output << "0x" << std::uppercase << std::hex << offset;
    return output.str();
}

[[nodiscard]] std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

[[nodiscard]] std::vector<std::uint8_t> read_stdin() {
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()
    );
}

[[nodiscard]] std::vector<std::string> split_csv(const std::string& values) {
    std::vector<std::string> result;
    std::istringstream input(values);
    std::string value;
    while(std::getline(input, value, ',')) {
        if(!value.empty()) {
            result.push_back(std::move(value));
        }
    }
    return result;
}

[[nodiscard]] bool is_bare_filter_flag(const std::string& token) {
    return token == "-x" || token == "--exclude" || token == "-y" || token == "--include";
}

[[nodiscard]] bool names_only_signatures(
    const std::string& token,
    const std::unordered_set<std::string>& registry_names
) {
    const auto parts = split_csv(token);
    if(parts.empty()) {
        return false;
    }
    return std::all_of(parts.begin(), parts.end(), [&](const std::string& part) {
        return registry_names.count(to_lower(part)) != 0;
    });
}

[[nodiscard]] std::vector<std::string> expand_filter_arguments(
    int argc,
    char** argv,
    const std::unordered_set<std::string>& registry_names
) {
    std::vector<std::string> expanded;
    expanded.reserve(static_cast<std::size_t>(argc));

    for(int index = 0; index < argc; ++index) {
        std::string token = argv[index];
        expanded.push_back(token);

        if(token == "--") {

            for(int rest = index + 1; rest < argc; ++rest) {
                expanded.emplace_back(argv[rest]);
            }
            break;
        }
        if(index == 0 || !is_bare_filter_flag(token)) {
            continue;
        }
        if(index + 1 >= argc) {
            continue;
        }

        ++index;
        expanded.emplace_back(argv[index]);

        while(index + 1 < argc) {
            const std::string next = argv[index + 1];
            if(next.empty() || next.front() == '-') {
                break;
            }
            if(!names_only_signatures(next, registry_names)) {
                break;
            }
            expanded.push_back(token);
            expanded.push_back(next);
            ++index;
        }
    }

    return expanded;
}

[[nodiscard]] std::vector<std::string> resolve_filters(
    const std::vector<std::string>& values,
    const std::unordered_map<std::string, std::string>& canonical_names
) {
    std::vector<std::string> resolved;
    for(const auto& value : values) {
        for(auto& token : split_csv(value)) {
            const auto match = canonical_names.find(to_lower(token));
            resolved.push_back(match != canonical_names.end() ? match->second : std::move(token));
        }
    }
    return resolved;
}

[[nodiscard]] json to_json(const binwalk::analysis_results& analysis) {
    json file_map = json::array();
    for(const auto& result : analysis.file_map) {
        file_map.push_back({
            {"offset", result.offset},
            {"id", result.id},
            {"size", result.size},
            {"name", result.name},
            {"confidence", result.confidence},
            {"description", result.description},
            {"always_display", result.always_display},
            {"extraction_declined", result.extraction_declined}
        });
    }
    json extractions = json::object();
    for(const auto& [id, result] : analysis.extractions) {
        extractions[id] = {
            {"size", result.size ? json(*result.size) : json(nullptr)},
            {"success", result.success},
            {"extractor", result.extractor},
            {"do_not_recurse", result.do_not_recurse},
            {"output_directory", result.output_directory}
        };
    }
    return {
        {"Analysis", {
            {"file_path", analysis.file_path},
            {"file_map", std::move(file_map)},
            {"extractions", std::move(extractions)}
        }}
    };
}

[[nodiscard]] json entropy_to_json(
    const std::string& path,
    const std::vector<binwalk::entropy_block>& blocks
) {
    json json_blocks = json::array();
    for(const auto& block : blocks) {
        json_blocks.push_back({
            {"end", block.end},
            {"start", block.start},
            {"entropy", block.entropy}
        });
    }
    return {{"Entropy", {{"file", path}, {"blocks", std::move(json_blocks)}}}};
}

class json_logger {
public:
    void open(std::string path) {
        path_ = std::move(path);
    }

    [[nodiscard]] bool enabled() const {
        return !path_.empty();
    }

    [[nodiscard]] bool log(const json& record) {
        if(!enabled()) {
            return true;
        }
        if(!started_) {
            started_ = true;
            if(!write("[\n")) {
                return false;
            }
        } else if(!write(",\n")) {
            return false;
        }
        return write(record.dump(2));
    }

    [[nodiscard]] bool close() {
        if(!enabled() || !started_ || closed_) {
            return true;
        }
        closed_ = true;
        return write("\n]\n");
    }

private:
    [[nodiscard]] bool write(const std::string& text) {
        if(path_ == "-") {
            std::cout << text << std::flush;
            return static_cast<bool>(std::cout);
        }
        if(!stream_.is_open()) {
            stream_.open(path_, std::ios::binary | std::ios::app);
            if(!stream_) {
                return false;
            }
        }
        stream_ << text << std::flush;
        return static_cast<bool>(stream_);
    }

    std::string path_;
    std::ofstream stream_;
    bool started_ = false;
    bool closed_ = false;
};

[[nodiscard]] bool should_display(
    const binwalk::analysis_results& analysis,
    std::size_t file_count,
    bool verbose
) {
    if(file_count == 1 || verbose || !analysis.extractions.empty()) {
        return true;
    }
    return std::any_of(
        analysis.file_map.begin(), analysis.file_map.end(), [](const auto& result) {
            return result.always_display;
        }
    );
}

[[nodiscard]] std::string failure_reason(const binwalk::extraction_result& result) {
    switch(result.failure) {
        case binwalk::extraction_failure::unsupported:
            return "not supported by this build";
        case binwalk::extraction_failure::invalid_data:
            return "the data was rejected as invalid";
        case binwalk::extraction_failure::utility_not_found:
            return result.extractor.empty()
                ? "the extraction utility is not installed"
                : "the extraction utility '" + result.extractor + "' is not installed";
        case binwalk::extraction_failure::utility_failed:
            return "the extraction utility rejected the data";
        case binwalk::extraction_failure::timed_out:
            return "the extraction utility timed out";
        case binwalk::extraction_failure::no_output:
            return "the extractor produced no output";
        case binwalk::extraction_failure::write_error:
            return "the extracted data could not be written";
        case binwalk::extraction_failure::none:
            break;
    }
    return {};
}

void print_extraction(
    const binwalk::signature_result& signature,
    const binwalk::extraction_result* extraction
) {
    if(extraction == nullptr) {
        std::cout << "[#] Extraction of " << signature.name << " data at offset "
                  << hex_offset(signature.offset) << " declined\n";
        return;
    }
    if(extraction->success) {
        std::cout << "[+] Extraction of " << signature.name << " data at offset "
                  << hex_offset(signature.offset) << " completed successfully\n";
        return;
    }
    const auto reason = failure_reason(*extraction);
    std::cout << "[-] Extraction of " << signature.name << " data at offset "
              << hex_offset(signature.offset) << " failed!";
    if(!reason.empty()) {
        std::cout << " (" << reason << ")";
    }
    std::cout << '\n';
}

void print_extractions(const binwalk::analysis_results& analysis) {
    bool delimiter_printed = false;
    for(const auto& signature : analysis.file_map) {
        const binwalk::extraction_result* extraction = nullptr;
        bool printable = false;

        if(signature.extraction_declined) {
            printable = true;
        } else {
            const auto match = analysis.extractions.find(signature.id);
            if(match != analysis.extractions.end()) {
                printable = true;
                extraction = &match->second;
            }
        }

        if(!printable) {
            continue;
        }
        if(!delimiter_printed) {
            print_delimiter();
            delimiter_printed = true;
        }
        print_extraction(signature, extraction);
    }
}

void print_analysis(
    const binwalk::analysis_results& analysis,
    bool quiet,
    bool extraction_attempted
) {
    if(quiet) {
        return;
    }

    std::cout << '\n' << analysis.file_path << '\n';
    print_delimiter();
    std::cout << pad_to_length("DECIMAL", column1_width)
              << pad_to_length("HEXADECIMAL", column2_width)
              << "DESCRIPTION\n";
    print_delimiter();

    for(const auto& result : analysis.file_map) {
        std::cout << pad_to_length(std::to_string(result.offset), column1_width)
                  << pad_to_length(hex_offset(result.offset), column2_width)
                  << line_wrap(result.description, description_prefix_width) << '\n';
    }

    if(extraction_attempted) {
        print_extractions(analysis);
    }

    print_delimiter();
    std::cout << '\n';
}

void print_signature_list(bool quiet, const std::vector<binwalk::signature>& signatures) {
    if(quiet) {
        return;
    }

    struct row {
        std::string description;
        std::string name;
        std::string extractor;
        std::string sort_key;
    };

    std::vector<row> rows;
    rows.reserve(signatures.size());
    std::size_t extractor_count = 0;

    for(const auto& definition : signatures) {
        std::string extractor = "None";
        if(definition.extractor_definition) {
            ++extractor_count;
            switch(definition.extractor_definition->type) {
                case binwalk::extractor_type::internal:
                    extractor = "Built-in";
                    break;
                case binwalk::extractor_type::external:
                    extractor = definition.extractor_definition->command;
                    break;
                case binwalk::extractor_type::none:
                    break;
            }
        }
        rows.push_back({
            definition.description,
            definition.name,
            std::move(extractor),
            to_lower(definition.description)
        });
    }

    std::stable_sort(rows.begin(), rows.end(), [](const row& left, const row& right) {
        return left.sort_key < right.sort_key;
    });

    print_delimiter();
    std::cout << pad_to_length("Signature Description", column1_width)
              << pad_to_length("Signature Name", column2_width)
              << "Extraction Utility\n";
    print_delimiter();

    for(const auto& entry : rows) {
        std::cout << pad_to_length(entry.description, column1_width)
                  << pad_to_length(entry.name, column2_width)
                  << entry.extractor << '\n';
    }

    print_delimiter();
    std::cout << '\n'
              << "Total signatures: " << rows.size() << '\n'
              << "Extractable signatures: " << extractor_count << '\n';
}

void print_stats(
    bool quiet,
    double elapsed_milliseconds,
    std::size_t file_count,
    std::size_t signature_count,
    std::size_t pattern_count
) {
    if(quiet) {
        return;
    }

    constexpr double milliseconds_in_a_second = 1000.0;
    constexpr double seconds_in_a_minute = 60.0;
    constexpr double minutes_in_an_hour = 60.0;

    const char* units = "milliseconds";
    double display_time = elapsed_milliseconds;
    if(display_time >= milliseconds_in_a_second) {
        display_time /= milliseconds_in_a_second;
        units = "seconds";
        if(display_time >= seconds_in_a_minute) {
            display_time /= seconds_in_a_minute;
            units = "minutes";
            if(display_time >= minutes_in_an_hour) {
                display_time /= minutes_in_an_hour;
                units = "hours";
            }
        }
    }

    std::ostringstream output;
    output << "Analyzed " << file_count << " file" << (file_count != 1 ? "s" : "")
           << " for " << signature_count << " file signatures ("
           << pattern_count << " magic patterns) in "
           << std::fixed << std::setprecision(1) << display_time << ' ' << units;
    std::cout << output.str() << '\n';
}

[[nodiscard]] bool carve_analysis(
    binwalk::byte_view data,
    const binwalk::analysis_results& analysis,
    const std::string& output_directory
) {
    const auto carved = binwalk::carve_file_map(
        data, analysis.file_map, analysis.file_path, output_directory
    );
    return std::none_of(carved.begin(), carved.end(), [](const auto& result) {
        return !result.success;
    });
}

[[nodiscard]] std::vector<std::string> extracted_files(
    const binwalk::analysis_results& analysis
) {
    std::vector<std::string> files;
    for(const auto& [id, extraction] : analysis.extractions) {
        (void)id;
        if(!extraction.success || extraction.do_not_recurse || extraction.output_directory.empty()) {
            continue;
        }

        std::error_code error;
        const auto options = std::filesystem::directory_options::skip_permission_denied;
        for(std::filesystem::recursive_directory_iterator iterator(
                extraction.output_directory, options, error
            ), end;
            !error && iterator != end;
            iterator.increment(error)) {
            const auto status = iterator->symlink_status(error);
            if(error || !std::filesystem::is_regular_file(status)) {
                continue;
            }
            if(iterator->file_size(error) > 0 && !error) {
                files.push_back(iterator->path().string());
            }
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

[[nodiscard]] std::string path_key(const std::string& value) {
    std::error_code error;
    auto path = std::filesystem::weakly_canonical(value, error);
    if(error) {
        error.clear();
        path = std::filesystem::absolute(value, error).lexically_normal();
    }
    auto key = path.generic_string();
#if defined(_WIN32)
    key = to_lower(std::move(key));
#endif
    return key;
}

struct worker_result {
    bool success = false;
    bool carve_success = true;
    std::string error;
    binwalk::analysis_results analysis;
};

[[nodiscard]] worker_result analyze_file(
    const binwalk::scanner& scanner,
    const std::string& path,
    bool extract,
    bool carve,
    const std::string& analysis_directory,
    const std::string& carve_directory
) {
    worker_result result;
    binwalk_cli::mapped_file contents;
    if(!binwalk_cli::mapped_file::open(path, contents)) {
        result.error = "Failed to read " + path;
        return result;
    }
    result.analysis = scanner.analyze(contents.view(), path, extract, analysis_directory);
    if(carve) {
        result.carve_success =
            carve_analysis(contents.view(), result.analysis, carve_directory);
    }
    result.success = true;
    return result;
}

}

int main(int argc, char** argv) {
    const auto run_time = std::chrono::steady_clock::now();

    CLI::App app{"Analyzes data for embedded file types", "binwalk"};
    app.set_version_flag("-V,--version", BINWALK_VERSION_STRING);

    bool list = false;
    bool use_stdin = false;
    bool quiet = false;
    bool verbose = false;
    bool extract = false;
    bool carve = false;
    bool matryoshka = false;
    bool search_all = false;
    bool entropy = false;
    std::string png;
    std::string log_path;
    std::size_t threads = 0;
    std::vector<std::string> exclude;
    std::vector<std::string> include;
    std::string directory = "extractions";
    std::string file_name;

    app.add_flag("-L,--list", list, "List supported signatures and extractors");
    app.add_flag("-s,--stdin", use_stdin, "Read data from standard input");
    app.add_flag("-q,--quiet", quiet, "Suppress normal stdout output");
    app.add_flag("-v,--verbose", verbose, "During recursive extraction display all results");
    auto* extract_option = app.add_flag(
        "-e,--extract", extract, "Automatically extract known file types"
    );
    app.add_flag("-c,--carve", carve, "Carve known and unknown file contents to disk");
    app.add_flag("-M,--matryoshka", matryoshka, "Recursively scan extracted files");
    app.add_flag("-a,--search-all", search_all, "Search for all signatures at all offsets");
    auto* entropy_option = app.add_flag("-E,--entropy", entropy, "Generate an entropy graph");
    app.add_option("-p,--png", png, "Save entropy graph as a PNG file");
    app.add_option("-l,--log", log_path, "Log JSON results to a file ('-' for stdout)");
    app.add_option("-t,--threads", threads, "Number of worker threads")
        ->check(CLI::PositiveNumber);
    auto* exclude_option = app.add_option(
        "-x,--exclude", exclude, "Signatures to exclude (comma- or space-separated)"
    )->allow_extra_args(false);
    auto* include_option = app.add_option(
        "-y,--include", include, "Signatures to include (comma- or space-separated)"
    )->allow_extra_args(false);
    app.add_option("-d,--directory", directory, "Extraction directory");
    app.add_option("file_name", file_name, "Path to the file to analyze");
    include_option->excludes(exclude_option);
    entropy_option->excludes(extract_option);

    auto registry = binwalk::builtin_signatures();
    std::unordered_set<std::string> registry_names;
    std::unordered_map<std::string, std::string> canonical_names;
    registry_names.reserve(registry.size());
    canonical_names.reserve(registry.size());
    for(const auto& definition : registry) {
        auto key = to_lower(definition.name);
        registry_names.insert(key);
        canonical_names.emplace(std::move(key), definition.name);
    }

    auto expanded = expand_filter_arguments(argc, argv, registry_names);
    std::vector<char*> expanded_argv;
    expanded_argv.reserve(expanded.size());
    for(auto& token : expanded) {
        expanded_argv.push_back(token.data());
    }

    try {
        app.parse(static_cast<int>(expanded_argv.size()), expanded_argv.data());
    } catch(const CLI::ParseError& error) {

        const auto code = app.exit(error);
        return code == 0 ? 0 : 2;
    }

    if(argc == 1) {
        std::cout << app.help();
        return 0;
    }

    if(list) {
        print_signature_list(quiet, registry);
        return 0;
    }

    const auto worker_count = threads > 0 ? threads : binwalk::recommended_scan_threads();

    binwalk::scanner scanner(
        std::move(registry),
        {
            resolve_filters(include, canonical_names),
            resolve_filters(exclude, canonical_names),
            search_all,
            worker_count
        }
    );

    json_logger logger;
    logger.open(log_path);
    bool log_failed = false;
    const auto log_record = [&](const json& record) {
        if(!logger.log(record)) {
            if(!log_failed) {
                std::cerr << "Failed to write JSON log file " << log_path << "\n";
            }
            log_failed = true;
        }
    };

    std::vector<std::uint8_t> piped;
    binwalk_cli::mapped_file contents;
    std::string display_name = file_name;
    if(use_stdin) {
        display_name = "stdin";
        piped = read_stdin();
    } else {
        if(file_name.empty()) {
            std::cerr << "A file path or --stdin is required.\n";
            return 2;
        }
        if(!binwalk_cli::mapped_file::open(file_name, contents)) {
            std::cerr << "Failed to read " << file_name << "\n";
            return 1;
        }
    }
    const binwalk::byte_view data = use_stdin ? binwalk::byte_view(piped) : contents.view();

    if(entropy) {
        const auto blocks = binwalk::entropy_blocks(data);
        if(!png.empty() && !binwalk::write_entropy_png(blocks, png)) {
            std::cerr << "Failed to write entropy graph to " << png << "\n";
            return 1;
        }
        if(!quiet) {
            std::cout << "Calculated entropy for " << blocks.size() << " blocks.\n";
        }
        log_record(entropy_to_json(display_name, blocks));
        if(!logger.close()) {
            log_failed = true;
        }
        return log_failed ? 1 : 0;
    }

    const std::string analysis_directory = (extract || carve) ? directory : std::string{};

    std::size_t file_count = 0;
    bool carve_failed = false;

    std::deque<std::string> pending;
    std::unordered_set<std::string> seen;
    if(!use_stdin) {
        seen.insert(path_key(file_name));
    }
    const auto enqueue_extractions = [&](const binwalk::analysis_results& completed) {
        if(!matryoshka) {
            return;
        }
        for(auto& path : extracted_files(completed)) {
            if(seen.insert(path_key(path)).second) {
                pending.push_back(std::move(path));
            }
        }
    };

    const auto process_result = [&](const binwalk::analysis_results& completed) {
        ++file_count;
        log_record(to_json(completed));
        if(completed.file_map.empty()) {
            return;
        }
        if(should_display(completed, file_count, verbose)) {
            print_analysis(completed, quiet, extract);
        }
        enqueue_extractions(completed);
    };

    auto analysis = scanner.analyze(
        data, display_name, extract, analysis_directory
    );
    if(carve && !carve_analysis(data, analysis, directory)) {
        std::cerr << "One or more data blocks could not be carved.\n";
        carve_failed = true;
    }
    process_result(analysis);

    while(!pending.empty()) {
        const auto batch_size = std::min(worker_count, pending.size());
        std::vector<std::future<worker_result>> workers;
        workers.reserve(batch_size);
        for(std::size_t index = 0; index < batch_size; ++index) {
            auto path = std::move(pending.front());
            pending.pop_front();
            workers.push_back(std::async(
                std::launch::async,
                [scanner, path = std::move(path), extract, carve, analysis_directory, directory] {
                    return analyze_file(
                        scanner, path, extract, carve, analysis_directory, directory
                    );
                }
            ));
        }

        for(auto& worker : workers) {
            auto completed = worker.get();
            if(!completed.success) {
                std::cerr << completed.error << '\n';
                continue;
            }
            if(!completed.carve_success) {
                std::cerr << "One or more data blocks could not be carved from "
                          << completed.analysis.file_path << ".\n";
                carve_failed = true;
            }
            process_result(completed.analysis);
        }
    }

    if(!logger.close()) {
        log_failed = true;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - run_time
    );
    print_stats(
        quiet,
        static_cast<double>(elapsed.count()),
        file_count,
        scanner.signature_count(),
        scanner.pattern_count()
    );

    if(carve_failed || log_failed) {
        return 1;
    }
    return 0;
}
