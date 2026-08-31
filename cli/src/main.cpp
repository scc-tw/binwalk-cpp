#include <binwalk/binwalk.hpp>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using json = nlohmann::json;

[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if(!input) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()
    );
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

[[nodiscard]] bool write_json_log(const std::string& path, const json& values) {
    const auto output = values.dump(2);
    if(path == "-") {
        std::cout << output << '\n';
        return true;
    }
    std::ofstream log(path, std::ios::binary | std::ios::app);
    if(!log) {
        return false;
    }
    log << output << '\n';
    return static_cast<bool>(log);
}

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

void print_analysis(const binwalk::analysis_results& analysis, bool quiet) {
    if(quiet) {
        return;
    }
    std::cout << "\n" << analysis.file_path << "\n"
              << "DECIMAL       HEXADECIMAL     DESCRIPTION\n";
    for(const auto& result : analysis.file_map) {
        std::cout << std::left << std::setw(14) << result.offset
                  << "0x" << std::hex << std::setw(14) << result.offset
                  << std::dec << result.description << '\n';
    }
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
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
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
    const std::string& output_directory
) {
    worker_result result;
    const auto data = read_file(path);
    if(!data) {
        result.error = "Failed to read " + path;
        return result;
    }
    result.analysis = scanner.analyze(
        binwalk::byte_view(*data), path, extract, output_directory
    );
    if(carve) {
        result.carve_success = carve_analysis(
            binwalk::byte_view(*data), result.analysis, output_directory
        );
    }
    result.success = true;
    return result;
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"Analyzes data for embedded file types", "binwalk"};
    app.set_version_flag("--version", BINWALK_VERSION_STRING);

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
    std::string exclude;
    std::string include;
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
        "-x,--exclude", exclude, "Comma-separated signatures to exclude"
    );
    auto* include_option = app.add_option(
        "-y,--include", include, "Comma-separated signatures to include"
    );
    app.add_option("-d,--directory", directory, "Extraction directory");
    app.add_option("file_name", file_name, "Path to the file to analyze");
    include_option->excludes(exclude_option);
    entropy_option->excludes(extract_option);

    try {
        app.parse(argc, argv);
    } catch(const CLI::ParseError& error) {
        return app.exit(error);
    }

    if(argc == 1) {
        std::cout << app.help();
        return 0;
    }

    binwalk::scanner scanner({split_csv(include), split_csv(exclude), search_all});
    if(list) {
        if(!quiet) {
            for(const auto& definition : scanner.signatures()) {
                std::cout << definition.name << "\t" << definition.description << '\n';
            }
        }
        return 0;
    }

    std::vector<std::uint8_t> data;
    std::string display_name = file_name;
    if(use_stdin) {
        display_name = "stdin";
        data = read_stdin();
    } else {
        if(file_name.empty()) {
            std::cerr << "A file path or --stdin is required.\n";
            return 2;
        }
        auto file_data = read_file(file_name);
        if(!file_data) {
            std::cerr << "Failed to read " << file_name << "\n";
            return 1;
        }
        data = std::move(*file_data);
    }

    if(entropy) {
        const auto blocks = binwalk::entropy_blocks(binwalk::byte_view(data));
        if(!png.empty() && !binwalk::write_entropy_png(blocks, png)) {
            std::cerr << "Failed to write entropy graph to " << png << "\n";
            return 1;
        }
        if(!quiet) {
            std::cout << "Calculated entropy for " << blocks.size() << " blocks.\n";
        }
        json values = json::array();
        values.push_back(entropy_to_json(display_name, blocks));
        if(!log_path.empty() && !write_json_log(log_path, values)) {
            std::cerr << "Failed to write JSON log file " << log_path << "\n";
            return 1;
        }
        return 0;
    }

    auto analysis = scanner.analyze(
        binwalk::byte_view(data), display_name, extract, directory
    );
    std::vector<binwalk::analysis_results> analyses;
    analyses.push_back(analysis);
    std::size_t file_count = 1;
    print_analysis(analysis, quiet);

    if(carve && !carve_analysis(binwalk::byte_view(data), analysis, directory)) {
        std::cerr << "One or more data blocks could not be carved.\n";
        return 1;
    }

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
    enqueue_extractions(analysis);

    const auto worker_count = threads > 0
        ? threads
        : std::max<std::size_t>(1, std::thread::hardware_concurrency());
    while(!pending.empty()) {
        const auto batch_size = std::min(worker_count, pending.size());
        std::vector<std::future<worker_result>> workers;
        workers.reserve(batch_size);
        for(std::size_t index = 0; index < batch_size; ++index) {
            auto path = std::move(pending.front());
            pending.pop_front();
            workers.push_back(std::async(
                std::launch::async,
                [scanner, path = std::move(path), extract, carve, directory] {
                    return analyze_file(scanner, path, extract, carve, directory);
                }
            ));
        }

        for(auto& worker : workers) {
            auto completed = worker.get();
            if(!completed.success) {
                std::cerr << completed.error << '\n';
                continue;
            }
            ++file_count;
            if(!completed.carve_success) {
                std::cerr << "One or more data blocks could not be carved from "
                          << completed.analysis.file_path << ".\n";
            }
            if(should_display(completed.analysis, file_count, verbose)) {
                print_analysis(completed.analysis, quiet);
            }
            enqueue_extractions(completed.analysis);
            analyses.push_back(std::move(completed.analysis));
        }
    }

    if(!log_path.empty()) {
        json values = json::array();
        for(const auto& completed : analyses) {
            values.push_back(to_json(completed));
        }
        if(!write_json_log(log_path, values)) {
            std::cerr << "Failed to write JSON log file " << log_path << "\n";
            return 1;
        }
    }

    return 0;
}
