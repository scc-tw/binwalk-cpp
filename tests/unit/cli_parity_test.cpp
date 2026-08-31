
#ifdef BINWALK_CLI_PATH

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>
namespace {

class scratch_dir {
public:
    explicit scratch_dir(const std::string& name)
        : path_(std::filesystem::temp_directory_path() / ("bwcliparity_" + name)) {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
        std::filesystem::create_directories(path_, error);
    }

    ~scratch_dir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    scratch_dir(const scratch_dir&) = delete;
    scratch_dir& operator=(const scratch_dir&) = delete;
    scratch_dir(scratch_dir&&) = delete;
    scratch_dir& operator=(scratch_dir&&) = delete;

    const std::filesystem::path& path() const { return path_; }

    std::filesystem::path child(const std::string& name) const { return path_ / name; }

private:
    std::filesystem::path path_;
};

std::string quote(const std::filesystem::path& path) {
    return "\"" + path.string() + "\"";
}

std::string trim(const std::string& text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return std::string();
    }
    const auto last = text.find_last_not_of(" \t");
    return text.substr(first, last - first + 1);
}

std::string lowercase(const std::string& text) {
    std::string result(text);
    for (char& character : result) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return result;
}

std::vector<std::string> tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    std::istringstream stream(text);
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

bool starts_with(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool contains(const std::string& text, const std::string& needle) {
    return text.find(needle) != std::string::npos;
}

std::string strip_ansi(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    std::size_t index = 0;
    while (index < text.size()) {
        if (text[index] != '\x1b') {
            result.push_back(text[index]);
            ++index;
            continue;
        }
        std::size_t scan = index + 1;
        if (scan < text.size() && text[scan] == '[') {
            ++scan;
            while (scan < text.size() && (text[scan] < '@' || text[scan] > '~')) {
                ++scan;
            }
            if (scan < text.size()) {
                ++scan;
            }
        }
        index = scan;
    }
    return result;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (const char character : text) {
        if (character == '\n') {
            lines.push_back(current);
            current.clear();
        } else if (character != '\r') {
            current.push_back(character);
        }
    }
    if (!current.empty()) {
        lines.push_back(current);
    }
    return lines;
}

struct cli_run {
    int exit_code = -1;
    std::string out;
    std::vector<std::string> lines;
};

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::string();
    }
    return std::string{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()
    };
}

cli_run run_cli(const std::string& arguments, const std::filesystem::path& stdout_path) {
    const std::filesystem::path stderr_path(stdout_path.string() + ".err");

    std::string command = quote(std::filesystem::path(BINWALK_CLI_PATH));
    if (!arguments.empty()) {
        command += " " + arguments;
    }
    command += " > " + quote(stdout_path) + " 2> " + quote(stderr_path);
#if defined(_WIN32)
    command = "\"" + command + "\"";
#endif

    cli_run run;
    run.exit_code = std::system(command.c_str());
    run.out = strip_ansi(read_text_file(stdout_path));
    run.lines = split_lines(run.out);
    return run;
}

void push_ascii(std::vector<std::uint8_t>& bytes, const char* text) {
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        bytes.push_back(static_cast<std::uint8_t>(*cursor));
    }
}

void push_le32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void push_fill(std::vector<std::uint8_t>& bytes, std::size_t count, std::uint8_t value) {
    bytes.insert(bytes.end(), count, value);
}

#ifdef BINWALK_TEST_HAS_ZLIB

void push_gzip_payload(std::vector<std::uint8_t>& bytes) {
    const std::vector<std::uint8_t> payload{
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00,
        0x86, 0xa6, 0x10, 0x36,
        0x05, 0x00, 0x00, 0x00
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
}

std::vector<std::uint8_t> gzip_member() {
    std::vector<std::uint8_t> bytes{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
    };
    push_gzip_payload(bytes);
    return bytes;
}

std::vector<std::uint8_t> gzip_member_with_original_name(const std::string& original_name) {
    std::vector<std::uint8_t> bytes{
        0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
    };
    for (const char character : original_name) {
        bytes.push_back(static_cast<std::uint8_t>(character));
    }
    bytes.push_back(0x00);
    push_gzip_payload(bytes);
    return bytes;
}

std::vector<std::uint8_t> nested_gzip_member() {
    const std::vector<std::uint8_t> inner = gzip_member();
    const auto length = static_cast<std::uint16_t>(inner.size());
    const auto inverted_length = static_cast<std::uint16_t>(~length);

    std::vector<std::uint8_t> outer{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x01,
        static_cast<std::uint8_t>(length & 0xffU),
        static_cast<std::uint8_t>(length >> 8U),
        static_cast<std::uint8_t>(inverted_length & 0xffU),
        static_cast<std::uint8_t>(inverted_length >> 8U)
    };
    outer.insert(outer.end(), inner.begin(), inner.end());
    push_fill(outer, 8, static_cast<std::uint8_t>(0x00));
    return outer;
}

#endif

std::vector<std::uint8_t> riff_container(std::size_t payload_size) {
    std::vector<std::uint8_t> bytes;
    push_ascii(bytes, "RIFF");
    push_le32(bytes, static_cast<std::uint32_t>(payload_size + 4U));
    push_ascii(bytes, "WAVE");
    push_fill(bytes, payload_size, static_cast<std::uint8_t>(0x5a));
    return bytes;
}

std::vector<std::uint8_t> rar_archive() {
    std::vector<std::uint8_t> bytes;
    push_ascii(bytes, "Rar!");
    bytes.push_back(static_cast<std::uint8_t>(0x1a));
    bytes.push_back(static_cast<std::uint8_t>(0x07));
    bytes.push_back(static_cast<std::uint8_t>(0x00));
    push_fill(bytes, 32, static_cast<std::uint8_t>(0x58));
    const std::vector<std::uint8_t> eof_marker{0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00};
    bytes.insert(bytes.end(), eof_marker.begin(), eof_marker.end());
    return bytes;
}

std::vector<std::uint8_t> riff_then_rar() {
    std::vector<std::uint8_t> bytes = riff_container(20);
    const std::vector<std::uint8_t> rar = rar_archive();
    bytes.insert(bytes.end(), rar.begin(), rar.end());
    return bytes;
}

std::vector<std::uint8_t> unrecognisable_bytes() {
    std::vector<std::uint8_t> bytes;
    push_fill(bytes, 512, static_cast<std::uint8_t>(0x51));
    return bytes;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(output) << path.string();
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size())
    );
    ASSERT_TRUE(output) << path.string();
}

struct feedback_line {
    char kind = '\0';
    std::string name;
    std::uint64_t offset = 0;
    std::string verb;
    std::string tail;
};

bool looks_like_feedback(const std::string& line) {
    return line.size() >= 3 && line[0] == '['
        && (line[1] == '+' || line[1] == '-' || line[1] == '#')
        && line[2] == ']';
}

std::vector<std::string> feedback_lines(const cli_run& run) {
    std::vector<std::string> found;
    for (const std::string& line : run.lines) {
        if (looks_like_feedback(line)) {
            found.push_back(line);
        }
    }
    return found;
}

bool parse_feedback(const std::string& line, feedback_line& parsed) {
    static const std::regex pattern(
        R"(^\[([-+#])\] Extraction of (\S+) data at offset 0[xX]([0-9A-Fa-f]+) (completed successfully|failed!|declined)(.*)$)"
    );
    std::smatch match;
    if (!std::regex_match(line, match, pattern)) {
        return false;
    }
    parsed.kind = match[1].str()[0];
    parsed.name = match[2].str();
    parsed.offset = std::stoull(match[3].str(), nullptr, 16);
    parsed.verb = match[4].str();
    parsed.tail = match[5].str();
    return true;
}

void expect_well_formed_feedback(const std::string& line) {
    feedback_line parsed;
    ASSERT_TRUE(parse_feedback(line, parsed)) << "malformed extraction feedback: " << line;

    if (parsed.kind == '+') {
        EXPECT_EQ(parsed.verb, "completed successfully") << line;
        EXPECT_TRUE(trim(parsed.tail).empty()) << line;
    } else if (parsed.kind == '#') {
        EXPECT_EQ(parsed.verb, "declined") << line;
        EXPECT_TRUE(trim(parsed.tail).empty()) << line;
    } else {
        EXPECT_EQ(parsed.verb, "failed!") << line;
        std::string reason = trim(parsed.tail);
        if (!reason.empty()) {
            if (reason.size() >= 2 && reason.front() == '(' && reason.back() == ')') {
                reason = trim(reason.substr(1, reason.size() - 2));
            }
            EXPECT_FALSE(reason.empty()) << "empty failure reason: " << line;
            EXPECT_NE(reason.find_first_of("abcdefghijklmnopqrstuvwxyz"), std::string::npos)
                << "failure reason carries no words: " << line;
        }
    }
}

void expect_all_feedback_well_formed(const cli_run& run) {
    for (const std::string& line : feedback_lines(run)) {
        expect_well_formed_feedback(line);
    }
}

struct table_row {
    std::uint64_t decimal = 0;
    std::uint64_t hexadecimal = 0;
    std::string description;
};

std::vector<table_row> table_rows(const cli_run& run) {
    static const std::regex pattern(R"(^([0-9]+)[ \t]+0[xX]([0-9A-Fa-f]+)[ \t]+(\S.*)$)");
    std::vector<table_row> rows;
    for (const std::string& line : run.lines) {
        std::smatch match;
        if (!std::regex_match(line, match, pattern)) {
            continue;
        }
        table_row row;
        row.decimal = std::stoull(match[1].str());
        row.hexadecimal = std::stoull(match[2].str(), nullptr, 16);
        row.description = match[3].str();
        rows.push_back(row);
    }
    return rows;
}

std::set<std::uint64_t> table_offsets(const cli_run& run) {
    std::set<std::uint64_t> offsets;
    for (const table_row& row : table_rows(run)) {

        EXPECT_EQ(row.decimal, row.hexadecimal)
            << "DECIMAL and HEXADECIMAL columns disagree: " << row.description;
        offsets.insert(row.decimal);
    }
    return offsets;
}

struct stats_line {
    long long files = 0;
    std::string file_word;
    long long signatures = 0;
    long long patterns = 0;
    std::string elapsed;
    std::string units;
    std::string raw;
};

bool find_stats_line(const cli_run& run, stats_line& parsed) {
    static const std::regex pattern(
        R"(^Analyzed ([0-9]+) (file|files) for ([0-9]+) file signatures \(([0-9]+) magic patterns\) in ([0-9]+\.[0-9]) (milliseconds|seconds|minutes|hours)$)"
    );
    for (const std::string& line : run.lines) {
        std::smatch match;
        const std::string candidate = trim(line);
        if (!std::regex_match(candidate, match, pattern)) {
            continue;
        }
        parsed.files = std::stoll(match[1].str());
        parsed.file_word = match[2].str();
        parsed.signatures = std::stoll(match[3].str());
        parsed.patterns = std::stoll(match[4].str());
        parsed.elapsed = match[5].str();
        parsed.units = match[6].str();
        parsed.raw = candidate;
        return true;
    }
    return false;
}

bool has_stats_line(const cli_run& run) {
    stats_line parsed;
    return find_stats_line(run, parsed);
}

struct list_row {
    std::string description;
    std::string name;
    std::string utility;
};

struct signature_list {
    std::vector<list_row> rows;
    long long total = -1;
    long long extractable = -1;
};

long long number_after_colon(const std::string& line) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
        return -1;
    }
    const std::string tail = trim(line.substr(colon + 1));
    if (tail.empty() || tail.find_first_not_of("0123456789") != std::string::npos) {
        return -1;
    }
    return std::stoll(tail);
}

signature_list parse_signature_list(const cli_run& run) {
    signature_list parsed;
    for (const std::string& raw : run.lines) {
        const std::string line = trim(raw);
        if (line.empty()) {
            continue;
        }
        if (line.find_first_not_of('-') == std::string::npos) {
            continue;
        }
        if (starts_with(line, "Total signatures:")) {
            parsed.total = number_after_colon(line);
            continue;
        }
        if (starts_with(line, "Extractable signatures:")) {
            parsed.extractable = number_after_colon(line);
            continue;
        }
        if (contains(line, "Description") && contains(line, "Utility")) {
            continue;
        }
        const std::vector<std::string> tokens = tokenize(line);
        if (tokens.size() < 3) {
            continue;
        }
        list_row row;
        row.utility = tokens.back();
        row.name = tokens[tokens.size() - 2];
        for (std::size_t index = 0; index + 2 < tokens.size(); ++index) {
            if (index > 0) {
                row.description += " ";
            }
            row.description += tokens[index];
        }
        parsed.rows.push_back(row);
    }
    return parsed;
}

bool list_has_signature(const signature_list& list, const std::string& name) {
    for (const list_row& row : list.rows) {
        if (row.name == name) {
            return true;
        }
    }
    return false;
}

std::set<std::string> key_set(const nlohmann::json& value) {
    std::set<std::string> keys;
    if (!value.is_object()) {
        return keys;
    }
    for (auto entry = value.begin(); entry != value.end(); ++entry) {
        keys.insert(entry.key());
    }
    return keys;
}

const std::set<std::string>& analysis_keys() {
    static const std::set<std::string> keys{"file_path", "file_map", "extractions"};
    return keys;
}

const std::set<std::string>& signature_result_keys() {
    static const std::set<std::string> keys{
        "offset", "id", "size", "name", "confidence",
        "description", "always_display", "extraction_declined"
    };
    return keys;
}

const std::set<std::string>& extraction_result_keys() {
    static const std::set<std::string> keys{
        "size", "success", "extractor", "do_not_recurse", "output_directory"
    };
    return keys;
}

const std::set<std::string>& entropy_keys() {
    static const std::set<std::string> keys{"file", "blocks"};
    return keys;
}

const std::set<std::string>& entropy_block_keys() {
    static const std::set<std::string> keys{"end", "start", "entropy"};
    return keys;
}

void expect_analysis_record(const nlohmann::json& record) {
    ASSERT_TRUE(record.is_object());
    ASSERT_EQ(key_set(record), std::set<std::string>{"Analysis"}) << record.dump();

    const nlohmann::json& analysis = record.at("Analysis");
    ASSERT_TRUE(analysis.is_object());
    EXPECT_EQ(key_set(analysis), analysis_keys()) << analysis.dump();

    ASSERT_TRUE(analysis.at("file_path").is_string());
    ASSERT_TRUE(analysis.at("file_map").is_array());
    ASSERT_TRUE(analysis.at("extractions").is_object());

    std::set<std::string> identifiers;
    for (const nlohmann::json& signature : analysis.at("file_map")) {
        ASSERT_TRUE(signature.is_object());
        EXPECT_EQ(key_set(signature), signature_result_keys()) << signature.dump();
        EXPECT_TRUE(signature.at("offset").is_number_unsigned());
        EXPECT_TRUE(signature.at("size").is_number_unsigned());
        EXPECT_TRUE(signature.at("confidence").is_number());
        EXPECT_TRUE(signature.at("name").is_string());
        EXPECT_TRUE(signature.at("description").is_string());
        EXPECT_TRUE(signature.at("always_display").is_boolean());
        EXPECT_TRUE(signature.at("extraction_declined").is_boolean());
        ASSERT_TRUE(signature.at("id").is_string());
        identifiers.insert(signature.at("id").get<std::string>());
    }

    const nlohmann::json& extractions = analysis.at("extractions");
    for (auto entry = extractions.begin(); entry != extractions.end(); ++entry) {

        EXPECT_EQ(identifiers.count(entry.key()), 1U)
            << "extraction key is not a file_map id: " << entry.key();
        const nlohmann::json& extraction = entry.value();
        ASSERT_TRUE(extraction.is_object());
        EXPECT_EQ(key_set(extraction), extraction_result_keys()) << extraction.dump();
        EXPECT_TRUE(extraction.at("size").is_number_unsigned() || extraction.at("size").is_null());
        EXPECT_TRUE(extraction.at("success").is_boolean());
        EXPECT_TRUE(extraction.at("extractor").is_string());
        EXPECT_TRUE(extraction.at("do_not_recurse").is_boolean());
        EXPECT_TRUE(extraction.at("output_directory").is_string());
    }
}

void expect_entropy_record(const nlohmann::json& record) {
    ASSERT_TRUE(record.is_object());
    ASSERT_EQ(key_set(record), std::set<std::string>{"Entropy"}) << record.dump();

    const nlohmann::json& entropy = record.at("Entropy");
    ASSERT_TRUE(entropy.is_object());
    EXPECT_EQ(key_set(entropy), entropy_keys()) << entropy.dump();
    EXPECT_TRUE(entropy.at("file").is_string());
    ASSERT_TRUE(entropy.at("blocks").is_array());
    EXPECT_FALSE(entropy.at("blocks").empty());

    for (const nlohmann::json& block : entropy.at("blocks")) {
        ASSERT_TRUE(block.is_object());
        EXPECT_EQ(key_set(block), entropy_block_keys()) << block.dump();
        EXPECT_TRUE(block.at("start").is_number_unsigned());
        EXPECT_TRUE(block.at("end").is_number_unsigned());
        EXPECT_TRUE(block.at("entropy").is_number());
    }
}

nlohmann::json parse_json_array(const std::string& text) {
    const auto first = text.find('[');
    const auto last = text.rfind(']');
    if (first == std::string::npos || last == std::string::npos || last < first) {
        return nlohmann::json();
    }
    return nlohmann::json::parse(text.substr(first, last - first + 1), nullptr, false);
}

nlohmann::json load_json_log(const std::filesystem::path& path) {
    return parse_json_array(read_text_file(path));
}

std::vector<std::string> signature_names(const nlohmann::json& log) {
    std::vector<std::string> names;
    for (const nlohmann::json& record : log) {
        if (!record.is_object() || !record.contains("Analysis")) {
            continue;
        }
        for (const nlohmann::json& signature : record.at("Analysis").at("file_map")) {
            names.push_back(signature.at("name").get<std::string>());
        }
    }
    return names;
}

bool has_name(const std::vector<std::string>& names, const std::string& wanted) {
    for (const std::string& name : names) {
        if (name == wanted) {
            return true;
        }
    }
    return false;
}

}

#ifdef BINWALK_TEST_HAS_ZLIB
TEST(CliParity, ExtractionSuccessLineForABuiltInExtractor) {
    const scratch_dir scratch("extract_success");
    const auto input = scratch.child("hello.gz");
    write_bytes(input, gzip_member());

    const cli_run run = run_cli(
        "-e -d " + quote(scratch.child("out")) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    const std::vector<std::string> lines = feedback_lines(run);
    ASSERT_EQ(lines.size(), 1U) << run.out;
    expect_all_feedback_well_formed(run);

    feedback_line parsed;
    ASSERT_TRUE(parse_feedback(lines[0], parsed)) << lines[0];
    EXPECT_EQ(parsed.kind, '+') << lines[0];
    EXPECT_EQ(parsed.name, "gzip");
    EXPECT_EQ(parsed.offset, 0U);
    EXPECT_EQ(parsed.verb, "completed successfully");
}
#endif

TEST(CliParity, ExtractionDeclinedLine) {

    const scratch_dir scratch("extract_declined");
    const auto input = scratch.child("whole.riff");
    write_bytes(input, riff_container(48));

    const cli_run run = run_cli(
        "-e -d " + quote(scratch.child("out")) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    const std::vector<std::string> lines = feedback_lines(run);
    ASSERT_EQ(lines.size(), 1U) << run.out;
    expect_all_feedback_well_formed(run);

    feedback_line parsed;
    ASSERT_TRUE(parse_feedback(lines[0], parsed)) << lines[0];
    EXPECT_EQ(parsed.kind, '#') << lines[0];
    EXPECT_EQ(parsed.name, "riff");
    EXPECT_EQ(parsed.offset, 0U);
    EXPECT_EQ(parsed.verb, "declined");
}

TEST(CliParity, ExtractionFailureLineShapeAndOptionalReason) {

    const scratch_dir scratch("extract_failed");
    const auto input = scratch.child("stub.rar");
    write_bytes(input, rar_archive());

    const cli_run run = run_cli(
        "-e -d " + quote(scratch.child("out")) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    const std::vector<std::string> lines = feedback_lines(run);
    ASSERT_EQ(lines.size(), 1U) << run.out;
    expect_all_feedback_well_formed(run);

    feedback_line parsed;
    ASSERT_TRUE(parse_feedback(lines[0], parsed)) << lines[0];
    EXPECT_EQ(parsed.kind, '-') << lines[0];
    EXPECT_EQ(parsed.name, "rar");
    EXPECT_EQ(parsed.offset, 0U);
    EXPECT_EQ(parsed.verb, "failed!");
}

TEST(CliParity, ExtractionFeedbackIsAbsentWithoutTheExtractFlag) {
    const scratch_dir scratch("no_feedback");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(quote(input), scratch.child("stdout.txt"));

    EXPECT_TRUE(feedback_lines(run).empty()) << run.out;
    EXPECT_TRUE(has_stats_line(run)) << run.out;
}

TEST(CliParity, ExtractionFeedbackIsAbsentUnderQuiet) {
    const scratch_dir scratch("quiet_feedback");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(
        "-q -e -d " + quote(scratch.child("out")) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    EXPECT_TRUE(feedback_lines(run).empty()) << run.out;
    EXPECT_TRUE(trim(run.out).empty()) << run.out;
}

TEST(CliParity, ListPrintsThreeColumnsAndConsistentTotals) {
    const scratch_dir scratch("list_columns");
    const cli_run run = run_cli("--list", scratch.child("stdout.txt"));
    EXPECT_EQ(run.exit_code, 0);

    const signature_list list = parse_signature_list(run);
    ASSERT_GT(list.total, 0) << run.out;
    ASSERT_GT(list.extractable, 0) << run.out;
    EXPECT_LE(list.extractable, list.total);
    EXPECT_EQ(list.rows.size(), static_cast<std::size_t>(list.total));

    long long extractable_rows = 0;
    bool saw_builtin = false;
    bool saw_none = false;
    for (const list_row& row : list.rows) {
        EXPECT_FALSE(row.description.empty());
        EXPECT_FALSE(row.name.empty());
        ASSERT_FALSE(row.utility.empty()) << row.name;
        if (row.utility == "None") {
            saw_none = true;
        } else {
            ++extractable_rows;
            if (row.utility == "Built-in") {
                saw_builtin = true;
            }
        }
    }
    EXPECT_EQ(extractable_rows, list.extractable);
    EXPECT_TRUE(saw_none) << "no signature reported an absent extractor";
    EXPECT_TRUE(saw_builtin) << "no signature reported a built-in extractor";

    const cli_run short_run = run_cli("-L", scratch.child("stdout_short.txt"));
    EXPECT_EQ(short_run.exit_code, 0);
    const signature_list short_list = parse_signature_list(short_run);
    EXPECT_EQ(short_list.total, list.total);
    EXPECT_EQ(short_list.extractable, list.extractable);
}

TEST(CliParity, ListRowsAreSortedByDescriptionCaseInsensitively) {
    const scratch_dir scratch("list_sorted");
    const cli_run run = run_cli("--list", scratch.child("stdout.txt"));

    const signature_list list = parse_signature_list(run);
    ASSERT_GT(list.rows.size(), 1U) << run.out;

    for (std::size_t index = 1; index < list.rows.size(); ++index) {
        const std::string previous = lowercase(list.rows[index - 1].description);
        const std::string current = lowercase(list.rows[index].description);
        EXPECT_LE(previous, current)
            << "row " << index << " is out of order: '"
            << list.rows[index - 1].description << "' then '"
            << list.rows[index].description << "'";
    }
}

TEST(CliParity, ListIsNotFilteredByIncludeOrExclude) {

    const scratch_dir scratch("list_unfiltered");

    const cli_run plain = run_cli("--list", scratch.child("plain.txt"));
    const cli_run excluded = run_cli("--list -x gzip", scratch.child("excluded.txt"));
    const cli_run included = run_cli("--list -y rar", scratch.child("included.txt"));

    const signature_list plain_list = parse_signature_list(plain);
    const signature_list excluded_list = parse_signature_list(excluded);
    const signature_list included_list = parse_signature_list(included);

    ASSERT_GT(plain_list.total, 0) << plain.out;
    EXPECT_EQ(excluded_list.total, plain_list.total);
    EXPECT_EQ(excluded_list.extractable, plain_list.extractable);
    EXPECT_EQ(excluded_list.rows.size(), plain_list.rows.size());
    EXPECT_EQ(included_list.total, plain_list.total);
    EXPECT_EQ(included_list.extractable, plain_list.extractable);
    EXPECT_EQ(included_list.rows.size(), plain_list.rows.size());

    EXPECT_TRUE(list_has_signature(plain_list, "gzip")) << plain.out;
    EXPECT_TRUE(list_has_signature(excluded_list, "gzip")) << excluded.out;
    EXPECT_TRUE(list_has_signature(included_list, "gzip")) << included.out;
}

TEST(CliParity, ListNeedsNoInputFileAndIsSuppressedByQuiet) {
    const scratch_dir scratch("list_quiet");

    const cli_run run = run_cli("--list -q", scratch.child("stdout.txt"));
    EXPECT_EQ(run.exit_code, 0);
    EXPECT_TRUE(trim(run.out).empty()) << run.out;

    const cli_run loud = run_cli("--list", scratch.child("loud.txt"));
    EXPECT_EQ(loud.exit_code, 0);
    EXPECT_FALSE(trim(loud.out).empty());
}

TEST(CliParity, StatsLineIsTheLastLineAndIsWellFormed) {
    const scratch_dir scratch("stats_format");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(quote(input), scratch.child("stdout.txt"));

    stats_line stats;
    ASSERT_TRUE(find_stats_line(run, stats)) << run.out;
    EXPECT_EQ(stats.files, 1);
    EXPECT_EQ(stats.file_word, "file") << "one file must not be pluralised";
    EXPECT_GT(stats.signatures, 0);
    EXPECT_GT(stats.patterns, 0);
    EXPECT_GE(stats.patterns, stats.signatures);

    ASSERT_NE(stats.elapsed.find('.'), std::string::npos);
    EXPECT_EQ(stats.elapsed.size() - stats.elapsed.find('.') - 1, 1U) << stats.raw;

    std::string last_non_empty;
    for (const std::string& line : run.lines) {
        if (!trim(line).empty()) {
            last_non_empty = trim(line);
        }
    }
    EXPECT_EQ(last_non_empty, stats.raw) << run.out;
}

TEST(CliParity, StatsLineIsSuppressedByQuiet) {
    const scratch_dir scratch("stats_quiet");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli("-q " + quote(input), scratch.child("stdout.txt"));

    EXPECT_FALSE(has_stats_line(run)) << run.out;
    EXPECT_TRUE(trim(run.out).empty()) << run.out;
}

TEST(CliParity, StatsLineIsAbsentForListAndEntropyRuns) {
    const scratch_dir scratch("stats_absent");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run listing = run_cli("--list", scratch.child("list.txt"));
    EXPECT_FALSE(has_stats_line(listing)) << listing.out;

    const cli_run entropy = run_cli("-E " + quote(input), scratch.child("entropy.txt"));
    EXPECT_FALSE(has_stats_line(entropy)) << entropy.out;
}

TEST(CliParity, PlainScanDoesNotCreateTheExtractionDirectory) {
    const scratch_dir scratch("no_output_dir");
    const auto input = scratch.child("mixed.bin");
    const auto output = scratch.child("out");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(
        "-d " + quote(output) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    EXPECT_TRUE(has_stats_line(run)) << run.out;
    EXPECT_FALSE(std::filesystem::exists(output))
        << "a scan without --extract/--carve created " << output.string();
}

#ifdef BINWALK_TEST_HAS_ZLIB
TEST(CliParity, ExtractionCreatesTheExtractionDirectory) {
    const scratch_dir scratch("output_dir");
    const auto input = scratch.child("hello.gz");
    const auto output = scratch.child("out2");
    write_bytes(input, gzip_member());

    const cli_run run = run_cli(
        "-e -d " + quote(output) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    EXPECT_TRUE(has_stats_line(run)) << run.out;
    EXPECT_TRUE(std::filesystem::exists(output))
        << "--extract did not create " << output.string();
}
#endif

TEST(CliParity, EmptyResultsPrintOnlyTheStatsLine) {
    const scratch_dir scratch("empty_results");
    const auto input = scratch.child("nothing.bin");
    write_bytes(input, unrecognisable_bytes());

    const cli_run run = run_cli(quote(input), scratch.child("stdout.txt"));

    stats_line stats;
    ASSERT_TRUE(find_stats_line(run, stats)) << run.out;
    EXPECT_EQ(stats.files, 1);

    for (const std::string& line : run.lines) {
        EXPECT_FALSE(contains(line, "DECIMAL")) << line;
        EXPECT_FALSE(contains(line, "HEXADECIMAL")) << line;
        EXPECT_FALSE(contains(line, "DESCRIPTION")) << line;
        EXPECT_FALSE(contains(line, "nothing.bin")) << "file path header printed: " << line;
    }
}

namespace {

std::vector<std::string> filtered_names(
    const scratch_dir& scratch,
    const std::string& flags,
    const std::string& tag
) {
    const auto input = scratch.child("mixed.bin");
    const auto log = scratch.child(tag + ".json");
    const cli_run run = run_cli(
        "--log " + quote(log) + " " + flags + " " + quote(input),
        scratch.child(tag + ".txt")
    );

    EXPECT_TRUE(has_stats_line(run)) << run.out;

    const nlohmann::json parsed = load_json_log(log);
    EXPECT_TRUE(parsed.is_array()) << "log for '" << flags << "' is not a JSON array";
    if (!parsed.is_array() || parsed.empty()) {
        return std::vector<std::string>();
    }
    EXPECT_EQ(parsed.size(), 1U);
    expect_analysis_record(parsed[0]);
    EXPECT_EQ(
        std::filesystem::path(parsed[0]["Analysis"]["file_path"].get<std::string>()).filename(),
        input.filename()
    ) << "the positional file path was not analysed";

    std::set<std::uint64_t> logged_offsets;
    for (const nlohmann::json& signature : parsed[0]["Analysis"]["file_map"]) {
        logged_offsets.insert(signature.at("offset").get<std::uint64_t>());
    }
    EXPECT_EQ(table_offsets(run), logged_offsets)
        << "the printed table and the JSON log disagree:\n" << run.out;

    return signature_names(parsed);
}

}

TEST(CliParity, ExcludeAcceptsCommaSeparatedValuesAndKeepsThePositionalPath) {
    const scratch_dir scratch("exclude_comma");
    write_bytes(scratch.child("mixed.bin"), riff_then_rar());

    const std::vector<std::string> names = filtered_names(scratch, "-x riff,zip,pdf", "comma");
    EXPECT_FALSE(has_name(names, "riff")) << "--exclude did not take effect";
    EXPECT_TRUE(has_name(names, "rar")) << "--exclude removed too much";
}

TEST(CliParity, ExcludeAcceptsSpaceSeparatedValuesAndKeepsThePositionalPath) {
    const scratch_dir scratch("exclude_space");
    write_bytes(scratch.child("mixed.bin"), riff_then_rar());

    const std::vector<std::string> names = filtered_names(scratch, "-x riff zip pdf", "space");
    EXPECT_FALSE(has_name(names, "riff")) << "--exclude did not take effect";
    EXPECT_TRUE(has_name(names, "rar")) << "--exclude removed too much";
}

TEST(CliParity, IncludeAcceptsASingleValueAndKeepsThePositionalPath) {
    const scratch_dir scratch("include_single");
    write_bytes(scratch.child("mixed.bin"), riff_then_rar());

    const std::vector<std::string> names = filtered_names(scratch, "-y rar", "single");
    EXPECT_TRUE(has_name(names, "rar")) << "--include dropped the requested signature";
    EXPECT_FALSE(has_name(names, "riff")) << "--include did not restrict the scan";
}

TEST(CliParity, IncludeMatchesSignatureNamesCaseInsensitively) {

    const scratch_dir scratch("include_case");
    write_bytes(scratch.child("mixed.bin"), riff_then_rar());

    const std::vector<std::string> names = filtered_names(scratch, "-y RAR", "upper");
    EXPECT_TRUE(has_name(names, "rar")) << "--include is case sensitive";
    EXPECT_FALSE(has_name(names, "riff")) << "--include did not restrict the scan";
}

TEST(CliParity, ShortVersionFlagMatchesLongVersionFlag) {
    const scratch_dir scratch("version");

    const cli_run long_form = run_cli("--version", scratch.child("long.txt"));
    const cli_run short_form = run_cli("-V", scratch.child("short.txt"));

    EXPECT_EQ(long_form.exit_code, 0);
    EXPECT_EQ(short_form.exit_code, 0);
    EXPECT_FALSE(trim(long_form.out).empty()) << "--version printed nothing";
    EXPECT_EQ(trim(short_form.out), trim(long_form.out));
}

TEST(CliParity, LogJsonAnalysisKeySetIsFrozen) {
    const scratch_dir scratch("log_analysis");
    const auto input = scratch.child("mixed.bin");
    const auto log = scratch.child("results.json");
    const auto output = scratch.child("out");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(
        "-e -d " + quote(output) + " --log " + quote(log) + " " + quote(input),
        scratch.child("stdout.txt")
    );
    EXPECT_TRUE(has_stats_line(run)) << run.out;

    const nlohmann::json parsed = load_json_log(log);
    ASSERT_TRUE(parsed.is_array()) << read_text_file(log);
    ASSERT_FALSE(parsed.empty()) << read_text_file(log);

    bool saw_signature = false;
    bool saw_extraction = false;
    for (const nlohmann::json& record : parsed) {
        expect_analysis_record(record);
        if (!record["Analysis"]["file_map"].empty()) {
            saw_signature = true;
        }
        if (!record["Analysis"]["extractions"].empty()) {
            saw_extraction = true;
        }
    }
    EXPECT_TRUE(saw_signature) << "no file_map entry was produced to key-check";
    EXPECT_TRUE(saw_extraction) << "no extractions entry was produced to key-check";
}

TEST(CliParity, LogJsonEntropyKeySetIsFrozen) {
    const scratch_dir scratch("log_entropy");
    const auto input = scratch.child("mixed.bin");
    const auto log = scratch.child("entropy.json");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(
        "-E -q --log " + quote(log) + " " + quote(input),
        scratch.child("stdout.txt")
    );
    EXPECT_EQ(run.exit_code, 0) << run.out;

    const nlohmann::json parsed = load_json_log(log);
    ASSERT_TRUE(parsed.is_array()) << read_text_file(log);
    ASSERT_EQ(parsed.size(), 1U) << read_text_file(log);
    expect_entropy_record(parsed[0]);
}

TEST(CliParity, LogDashWritesJsonToStdoutInsteadOfAFile) {
    const scratch_dir scratch("log_stdout");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run run = run_cli(
        "-q --log - " + quote(input),
        scratch.child("stdout.txt")
    );

    const nlohmann::json parsed = parse_json_array(run.out);
    ASSERT_TRUE(parsed.is_array()) << run.out;
    ASSERT_EQ(parsed.size(), 1U) << run.out;
    expect_analysis_record(parsed[0]);
}

TEST(CliParity, QuietSuppressesStdoutButLogDashStillEmitsJson) {
    const scratch_dir scratch("quiet_log");
    const auto input = scratch.child("mixed.bin");
    write_bytes(input, riff_then_rar());

    const cli_run silent = run_cli("-q " + quote(input), scratch.child("silent.txt"));
    EXPECT_TRUE(trim(silent.out).empty()) << silent.out;

    const cli_run logged = run_cli("-q --log - " + quote(input), scratch.child("logged.txt"));
    EXPECT_FALSE(trim(logged.out).empty()) << "--log - was silenced by --quiet";
    EXPECT_TRUE(parse_json_array(logged.out).is_array()) << logged.out;
}

#ifdef BINWALK_TEST_HAS_ZLIB
TEST(CliParity, LogHoldsOneWellFormedRecordPerAnalysedFile) {

    const scratch_dir scratch("log_incremental");
    const auto input = scratch.child("nested.gz");
    const auto log = scratch.child("results.json");
    const auto output = scratch.child("out");
    write_bytes(input, nested_gzip_member());

    const cli_run run = run_cli(
        "-e -M -d " + quote(output) + " --log " + quote(log) + " " + quote(input),
        scratch.child("stdout.txt")
    );

    const nlohmann::json parsed = load_json_log(log);
    ASSERT_TRUE(parsed.is_array()) << read_text_file(log);
    ASSERT_GT(parsed.size(), 1U) << "a recursive run logged only one record";
    for (const nlohmann::json& record : parsed) {
        expect_analysis_record(record);
    }

    stats_line stats;
    ASSERT_TRUE(find_stats_line(run, stats)) << run.out;
    EXPECT_GT(stats.files, 1);
    EXPECT_EQ(stats.file_word, "files") << "file count > 1 must be pluralised";
    EXPECT_EQ(static_cast<std::size_t>(stats.files), parsed.size())
        << "one JSON record per analysed file";
}
#endif

#ifdef BINWALK_TEST_HAS_ZLIB
TEST(CliParity, LongDescriptionsAreWrappedAndContinuationLinesAreIndented) {

    const scratch_dir scratch("wrap");
    std::string original_name;
    for (int repeat = 0; repeat < 60; ++repeat) {
        if (repeat > 0) {
            original_name += " ";
        }
        original_name += "wrap";
    }

    const auto input = scratch.child("long.gz");
    write_bytes(input, gzip_member_with_original_name(original_name));

    const cli_run run = run_cli(quote(input), scratch.child("stdout.txt"));

    std::size_t widest = 0;
    for (const std::string& line : run.lines) {
        widest = std::max(widest, line.size());
        EXPECT_LE(line.size(), 200U) << "unwrapped output line: " << line;
    }
    EXPECT_GT(widest, 0U);

    std::vector<std::size_t> description_lines;
    for (std::size_t index = 0; index < run.lines.size(); ++index) {
        if (contains(run.lines[index], "wrap wrap")) {
            description_lines.push_back(index);
        }
    }
    ASSERT_GT(description_lines.size(), 1U)
        << "a " << original_name.size() << "-character description was not wrapped:\n" << run.out;

    for (std::size_t index = 1; index < description_lines.size(); ++index) {
        const std::string& line = run.lines[description_lines[index]];
        ASSERT_FALSE(line.empty());
        EXPECT_EQ(line[0], ' ') << "continuation line is not indented: " << line;
    }
}
#endif

TEST(CliParity, NoArgumentsPrintsHelpAndExitsZero) {
    const scratch_dir scratch("help");
    const cli_run run = run_cli("", scratch.child("stdout.txt"));

    EXPECT_EQ(run.exit_code, 0);
    EXPECT_FALSE(trim(run.out).empty()) << "no arguments printed nothing";
    EXPECT_TRUE(contains(run.out, "--help")) << run.out;
}

TEST(CliParity, MissingInputFileDoesNotCreateTheExtractionDirectory) {

    const scratch_dir scratch("missing");
    const auto missing = scratch.child("does_not_exist.bin");
    const auto output = scratch.child("out");

    const cli_run run = run_cli(
        "-d " + quote(output) + " " + quote(missing),
        scratch.child("stdout.txt")
    );

    EXPECT_FALSE(std::filesystem::exists(missing));
    EXPECT_FALSE(std::filesystem::exists(output))
        << "a failed scan created " << output.string();
    EXPECT_TRUE(feedback_lines(run).empty()) << run.out;
}

#endif
