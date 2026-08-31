#include <binwalk/binwalk.hpp>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
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

[[nodiscard]] bool write_json_log(const std::string& path, const json& value) {
    const auto output = json::array({value}).dump(2);
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
    app.add_option("-t,--threads", threads, "Number of worker threads");
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

    if(matryoshka) {
        std::cerr << "This compatibility feature has not been ported yet.\n";
        return 1;
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
        if(!png.empty()) {
            std::cerr << "PNG entropy graph output has not been ported yet.\n";
            return 1;
        }
        const auto blocks = binwalk::entropy_blocks(binwalk::byte_view(data));
        if(!quiet) {
            std::cout << "Calculated entropy for " << blocks.size() << " blocks.\n";
        }
        if(!log_path.empty() && !write_json_log(log_path, entropy_to_json(display_name, blocks))) {
            std::cerr << "Failed to write JSON log file " << log_path << "\n";
            return 1;
        }
        return 0;
    }

    const auto analysis = scanner.analyze(
        binwalk::byte_view(data), display_name, extract, directory
    );
    const auto& results = analysis.file_map;
    if(!quiet) {
        std::cout << "DECIMAL       HEXADECIMAL     DESCRIPTION\n";
        for(const auto& result : results) {
            std::cout << std::left << std::setw(14) << result.offset
                      << "0x" << std::hex << std::setw(14) << result.offset
                      << std::dec << result.description << '\n';
        }
    }

    if(carve) {
        const auto carved = binwalk::carve_file_map(
            binwalk::byte_view(data), results, display_name, directory
        );
        if(std::any_of(carved.begin(), carved.end(), [](const auto& result) {
            return !result.success;
        })) {
            std::cerr << "One or more data blocks could not be carved.\n";
            return 1;
        }
    }

    if(!log_path.empty()) {
        if(!write_json_log(log_path, to_json(analysis))) {
            std::cerr << "Failed to write JSON log file " << log_path << "\n";
            return 1;
        }
    }

    (void)verbose;
    (void)threads;
    (void)directory;
    return 0;
}
