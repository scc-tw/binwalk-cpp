
#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/process.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32) && defined(_MSC_VER)
#include <stdlib.h>
#endif
namespace {

bool path_exists(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::exists(path, error);
}

std::size_t count_entries(const std::filesystem::path& directory) {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        ++count;
    }
    return count;
}

std::size_t count_non_empty_files(const std::filesystem::path& directory) {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        std::error_code probe;
        if(std::filesystem::is_regular_file(iterator->path(), probe)
           && std::filesystem::file_size(iterator->path(), probe) > 0) {
            ++count;
        }
    }
    return count;
}

std::optional<std::filesystem::path> find_entry_named_with(
    const std::filesystem::path& directory,
    const std::string& needle
) {
    std::error_code error;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        if(iterator->path().filename().string().find(needle) != std::string::npos) {
            return iterator->path();
        }
    }
    return std::nullopt;
}

std::filesystem::path make_test_root() {
    std::error_code error;
    auto base = std::filesystem::temp_directory_path(error);
    if(error) {
        base = std::filesystem::path(".");
    }

    std::string name = "binwalk_extframework_";
    const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
    if(information != nullptr) {
        name += information->test_suite_name();
        name += '_';
        name += information->name();
    }

    for(auto& character : name) {
        if(std::isalnum(static_cast<unsigned char>(character)) == 0 && character != '_') {
            character = '_';
        }
    }
    return base / name;
}

void write_batch_file(const std::filesystem::path& path, const std::vector<std::string>& lines) {
    std::ofstream stream(path);
    for(const auto& line : lines) {
        stream << line << '\n';
    }
}

void put_u16_le(std::vector<std::uint8_t>& data, std::size_t offset, std::uint16_t value) {
    data[offset] = static_cast<std::uint8_t>(value & 0xffU);
    data[offset + 1] = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xffU);
}

void put_u32_le(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        data[offset + index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU);
    }
}

std::vector<std::uint8_t> minimal_png() {
    return {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D',
        0xae, 0x42, 0x60, 0x82
    };
}

std::vector<std::uint8_t> minimal_jpeg() {
    return {0xff, 0xd8, 0xff, 0xdb, 0x00, 0x04, 0x00, 0x00, 0xff, 0xd9};
}

std::vector<std::uint8_t> minimal_gzip() {
    return {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00,
        0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00
    };
}

std::vector<std::uint8_t> minimal_zlib() {
    return {
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00,
        0x06, 0x2c, 0x02, 0x15
    };
}

std::vector<std::uint8_t> minimal_riff() {
    return {'R', 'I', 'F', 'F', 0x04, 0x00, 0x00, 0x00, 'W', 'A', 'V', 'E'};
}

std::vector<std::uint8_t> minimal_mbr() {
    std::vector<std::uint8_t> data(2048, 0);
    data[446 + 4] = 0x83;
    data[446 + 8] = 1;
    data[446 + 12] = 3;
    data[510] = 0x55;
    data[511] = 0xaa;
    return data;
}

std::vector<std::uint8_t> minimal_bmp() {
    std::vector<std::uint8_t> data(58, 0);
    data[0] = 'B';
    data[1] = 'M';
    put_u32_le(data, 2, 58);
    put_u32_le(data, 10, 54);
    put_u32_le(data, 14, 40);
    put_u32_le(data, 18, 1);
    put_u32_le(data, 22, 1);
    put_u16_le(data, 26, 1);
    put_u16_le(data, 28, 24);
    put_u32_le(data, 30, 0);
    put_u32_le(data, 34, 4);
    return data;
}

std::vector<std::uint8_t> mbr_with_a_zero_length_partition() {
    std::vector<std::uint8_t> data(4096, 0);

    data[446] = 0x80;
    data[446 + 4] = 0x83;
    put_u32_le(data, 446 + 8, 2);
    put_u32_le(data, 446 + 12, 2);

    data[462] = 0x00;
    data[462 + 4] = 0x83;
    put_u32_le(data, 462 + 8, 4);
    put_u32_le(data, 462 + 12, 0);

    data[510] = 0x55;
    data[511] = 0xaa;

    for(std::size_t index = 1024; index < 2048; ++index) {
        data[index] = 0x41;
    }
    return data;
}

std::vector<std::uint8_t> riff_wave() {
    std::vector<std::uint8_t> data(44, 0);
    data[0] = 'R'; data[1] = 'I'; data[2] = 'F'; data[3] = 'F';
    put_u32_le(data, 4, 36);
    data[8] = 'W'; data[9] = 'A'; data[10] = 'V'; data[11] = 'E';
    data[12] = 'f'; data[13] = 'm'; data[14] = 't'; data[15] = ' ';
    for(std::size_t index = 16; index < 44; ++index) {
        data[index] = 0x5a;
    }
    return data;
}

std::uintmax_t file_size_of(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return error ? static_cast<std::uintmax_t>(-1) : size;
}

#if defined(_WIN32)

std::filesystem::path always_prefixed(const std::filesystem::path& path) {
    auto text = path.lexically_normal().make_preferred().wstring();
    if(text.compare(0, 4, L"\\\\?\\") == 0) {
        return path;
    }
    return std::filesystem::path(L"\\\\?\\" + text);
}

std::filesystem::path prefixed(const std::filesystem::path& path) {
    return path.native().size() < 240 ? path : always_prefixed(path);
}

std::filesystem::path long_path_stem() {
    std::error_code error;
    auto base = std::filesystem::temp_directory_path(error);
    if(error) {
        base = std::filesystem::path(".");
    }
    std::filesystem::path stem = base / "binwalk_extframework_longpath";
    stem.make_preferred();
    return stem;
}

struct long_path_guard {
    ~long_path_guard() {
        std::error_code error;
        std::filesystem::remove_all(always_prefixed(long_path_stem()), error);
    }
};

std::optional<std::filesystem::path> make_long_root(std::size_t target_length) {
    if(target_length >= 248) {
        return std::nullopt;
    }

    const auto stem = long_path_stem();
    const auto stem_length = stem.string().size();
    if(stem_length + 2 >= target_length) {
        return std::nullopt;
    }

    const auto filler_length = target_length - stem_length - 1;
    if(filler_length > 240) {
        return std::nullopt;
    }
    return stem / std::string(filler_length, 'x');
}
#endif

const binwalk::signature_result* find_in_file_map(
    const std::vector<binwalk::signature_result>& file_map,
    const std::string& name
) {
    for(const auto& entry : file_map) {
        if(entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

bool zlib_backend_enabled() {
#if defined(BINWALK_TEST_HAS_ZLIB)
    return true;
#else
    return false;
#endif
}

struct parity_fixture {
    const char* format;
    std::vector<std::uint8_t> data;
    bool needs_zlib;

    bool proven;
};

std::vector<parity_fixture> parity_fixtures() {
    return {
        {"png", minimal_png(), false, true},
        {"jpeg", minimal_jpeg(), false, true},
        {"riff", minimal_riff(), false, true},
        {"mbr", minimal_mbr(), false, true},
        {"gzip", minimal_gzip(), true, true},
        {"zlib", minimal_zlib(), true, true},
        {"bmp", minimal_bmp(), false, true}
    };
}

std::optional<binwalk::extractor> internal_extractor_for(const std::string& format) {
    for(const auto& signature : binwalk::builtin_signatures()) {
        if(signature.name != format || !signature.extractor_definition.has_value()) {
            continue;
        }
        const auto& definition = *signature.extractor_definition;
        if(definition.type == binwalk::extractor_type::internal && definition.internal != nullptr) {
            return definition;
        }
    }
    return std::nullopt;
}

std::optional<binwalk::signature_result> scan_for(
    const std::vector<std::uint8_t>& data,
    const std::string& format
) {
    const binwalk::scanner scanner;
    for(const auto& result : scanner.scan(binwalk::byte_view(data))) {
        if(result.name == format) {
            return result;
        }
    }
    return std::nullopt;
}

enum class fixture_state { ready, no_internal_extractor, not_recognised };

fixture_state resolve_fixture(
    const parity_fixture& fixture,
    binwalk::extractor& definition,
    binwalk::signature_result& signature
) {
    const auto found = internal_extractor_for(fixture.format);
    if(!found.has_value()) {
        return fixture_state::no_internal_extractor;
    }
    const auto scanned = scan_for(fixture.data, fixture.format);
    if(!scanned.has_value()) {
        return fixture_state::not_recognised;
    }
    definition = *found;
    signature = *scanned;
    return fixture_state::ready;
}

binwalk::signature_result whole_buffer_signature(const std::vector<std::uint8_t>& data) {
    binwalk::signature_result signature;
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());
    signature.name = "extframework_fake";
    signature.id = "extframework_fake_0";
    signature.confidence = binwalk::confidence_medium;
    return signature;
}

void expect_only_placeholders_substituted(
    const std::vector<std::string>& arguments,
    const std::string& replacement
) {
    const auto substituted = binwalk::substitute_source_file(arguments, replacement);
    ASSERT_EQ(substituted.size(), arguments.size()) << "argument count must be preserved";
    for(std::size_t index = 0; index < arguments.size(); ++index) {
        if(arguments[index] == binwalk::source_file_placeholder) {
            EXPECT_EQ(substituted[index], replacement) << "argument " << index;
        } else {
            EXPECT_EQ(substituted[index], arguments[index])
                << "argument " << index << " must survive byte for byte";
        }
    }
}

constexpr const char* missing_program = "binwalk_no_such_program_zzz";

struct extractor_probe {
    int calls = 0;
    std::vector<std::uint64_t> observed_sizes;
    std::vector<std::uint64_t> observed_offsets;
    std::vector<std::size_t> observed_data_sizes;
    int dry_runs = 0;

    bool can_succeed = false;
    std::uint64_t success_threshold = 0;
    binwalk::extraction_failure first_failure = binwalk::extraction_failure::invalid_data;
    binwalk::extraction_failure later_failure = binwalk::extraction_failure::invalid_data;
};

extractor_probe probe_a;
extractor_probe probe_b;

binwalk::extraction_result run_probe(
    extractor_probe& state,
    const std::string& name,
    binwalk::byte_view data,
    const binwalk::signature_result& signature,
    const std::string* output_directory
) {
    ++state.calls;
    state.observed_sizes.push_back(signature.size);
    state.observed_offsets.push_back(signature.offset);
    state.observed_data_sizes.push_back(data.size());
    if(output_directory == nullptr) {
        ++state.dry_runs;
    }

    binwalk::extraction_result result;
    result.extractor = name;
    if(!state.can_succeed || signature.size < state.success_threshold) {
        result.success = false;
        result.failure = (state.calls == 1) ? state.first_failure : state.later_failure;
        return result;
    }

    result.success = true;
    result.size = signature.size;
    result.failure = binwalk::extraction_failure::none;
    if(output_directory != nullptr) {

        std::ofstream stream(
            std::filesystem::path(*output_directory) / "probe_output.bin", std::ios::binary
        );
        const std::string payload = "probe output";
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    }
    return result;
}

binwalk::extraction_result probe_a_extractor(
    binwalk::byte_view data,
    const binwalk::signature_result& signature,
    const std::string* output_directory
) {
    return run_probe(probe_a, "probe_a", data, signature, output_directory);
}

binwalk::extraction_result probe_b_extractor(
    binwalk::byte_view data,
    const binwalk::signature_result& signature,
    const std::string* output_directory
) {
    return run_probe(probe_b, "probe_b", data, signature, output_directory);
}

std::optional<binwalk::signature_result> probe_parser(binwalk::byte_view, std::size_t) {
    return std::nullopt;
}

binwalk::signature make_probe_signature(
    const std::string& name,
    binwalk::internal_extractor function
) {
    binwalk::signature value;
    value.name = name;
    value.description = "extraction framework probe";
    value.magic = {{'P', 'R', 'O', 'B', 'E', '!', '!', '!'}};
    value.parser = &probe_parser;

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::internal;
    definition.name = name + "_builtin";
    definition.internal = function;
    value.extractor_definition = definition;

    return value;
}

binwalk::signature make_counting_signature(
    const std::string& name,
    std::uint8_t tag,
    std::size_t magic_patterns,
    bool short_signature
) {
    binwalk::signature value;
    value.name = name;
    value.description = "counting probe";
    value.short_signature = short_signature;
    value.parser = &probe_parser;
    for(std::size_t index = 0; index < magic_patterns; ++index) {
        value.magic.push_back({
            'C', 'N', 'T', tag, static_cast<std::uint8_t>(index)
        });
    }
    return value;
}

std::vector<binwalk::signature> counting_registry() {
    return {
        make_counting_signature("gzip", 0x01, 2, false),
        make_counting_signature("PNG", 0x02, 2, false),
        make_counting_signature("shorty", 0x03, 2, true)
    };
}

std::size_t total_magic_patterns() {
    std::size_t total = 0;
    for(const auto& value : counting_registry()) {
        total += value.magic.size();
    }
    return total;
}

std::optional<binwalk::signature_result> past_eof_parser(
    binwalk::byte_view,
    std::size_t offset
) {
    binwalk::signature_result result;
    result.name = "past_eof_probe";
    result.id = "past_eof_probe_result";
    result.offset = static_cast<std::uint64_t>(offset);
    result.size = 9999;
    result.confidence = binwalk::confidence_medium;
    return result;
}

std::optional<binwalk::signature_result> in_range_parser(
    binwalk::byte_view data,
    std::size_t offset
) {
    binwalk::signature_result result;
    result.name = "in_range_probe";
    result.id = "in_range_probe_result";
    result.offset = static_cast<std::uint64_t>(offset);
    result.size = data.contains(offset)
        ? static_cast<std::uint64_t>(data.size() - offset)
        : 0;
    result.confidence = binwalk::confidence_medium;
    return result;
}

binwalk::signature make_short_probe_signature(
    const std::string& name,
    binwalk::signature_parser parser
) {
    binwalk::signature value;
    value.name = name;
    value.description = "short signature probe";
    value.short_signature = true;
    value.magic_offset = 0;
    value.magic = {{0x5b, 0x5d}};
    value.parser = parser;
    return value;
}

std::size_t magic_count_of(const std::string& name) {
    for(const auto& value : counting_registry()) {
        if(value.name == name) {
            return value.magic.size();
        }
    }
    return 0;
}

binwalk::signature_result probe_signature_result(
    const std::string& name,
    std::uint64_t offset,
    std::uint64_t size
) {
    binwalk::signature_result signature;
    signature.name = name;
    signature.id = name + "_result";
    signature.offset = offset;
    signature.size = size;
    signature.confidence = binwalk::confidence_medium;
    return signature;
}

#if defined(_WIN32) && defined(_MSC_VER)

constexpr const char* argv_oracle_flag = "--binwalk-extframework-argv-oracle";
constexpr const char* argv_oracle_filter = "--gtest_filter=ExtractionFrameworkArgvOracle.*";

std::vector<std::string> argv_oracle_values() {
    return {
        "-i",
        "-o.",
        "-p''",
        "-output",
        "s-record.bin",
        "one argument with spaces",
        "a\"b",
        "quote\"in\"middle",
        "--out=%e",
        "%e"
    };
}

bool own_argv_contains(const char* needle) {
    for(int index = 1; index < __argc; ++index) {
        if(__argv[index] != nullptr && std::string(__argv[index]) == needle) {
            return true;
        }
    }
    return false;
}

std::optional<std::filesystem::path> own_executable_path() {
    if(__argc < 1 || __argv[0] == nullptr) {
        return std::nullopt;
    }
    std::error_code error;
    auto candidate = std::filesystem::absolute(std::filesystem::path(__argv[0]), error);
    if(error) {
        return std::nullopt;
    }
    if(path_exists(candidate)) {
        return candidate;
    }
    candidate += ".exe";
    if(path_exists(candidate)) {
        return candidate;
    }
    return std::nullopt;
}
#endif

}

class extraction_framework_test : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = make_test_root();
        ASSERT_FALSE(root_.empty());
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
        ASSERT_EQ(count_entries(root_), std::size_t{0});
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        EXPECT_FALSE(path_exists(root_)) << "temp directory survived: " << root_.string();
    }

    std::filesystem::path root_;
};

class extraction_parity_test
    : public extraction_framework_test,
      public ::testing::WithParamInterface<parity_fixture> {};

class extraction_retry_test : public extraction_framework_test {
protected:
    void SetUp() override {
        extraction_framework_test::SetUp();
        probe_a = extractor_probe{};
        probe_b = extractor_probe{};
        data_.assign(4096, 0x5a);
    }

    [[nodiscard]] std::uint64_t available_from(std::uint64_t offset) const {
        return static_cast<std::uint64_t>(data_.size()) - offset;
    }

    [[nodiscard]] std::unordered_map<std::string, binwalk::extraction_result> extract_with(
        const binwalk::signature& registered,
        const binwalk::signature_result& signature
    ) const {
        const binwalk::scanner scanner({registered});
        return scanner.extract(
            binwalk::byte_view(data_), "fixture.bin", {signature}, (root_ / "out").string()
        );
    }

    std::vector<std::uint8_t> data_;
};

TEST(ExtractionFrameworkPlaceholder, IsTheTwoCharacterLiteralPercentE) {
    EXPECT_EQ(std::string(binwalk::source_file_placeholder), "%e");
}

TEST(ExtractionFrameworkPlaceholder, SubstitutesAnArgumentThatIsExactlyThePlaceholder) {
    const std::vector<std::string> arguments{"-d", "%e", "--verbose"};
    const auto substituted = binwalk::substitute_source_file(arguments, "carved.bin");

    ASSERT_EQ(substituted.size(), arguments.size());
    EXPECT_EQ(substituted[0], "-d");
    EXPECT_EQ(substituted[1], "carved.bin");
    EXPECT_EQ(substituted[2], "--verbose");
}

TEST(ExtractionFrameworkPlaceholder, LeavesThePlaceholderEmbeddedInALongerArgumentAlone) {
    const std::vector<std::string> arguments{
        "--out=%e", "%extra", "x%e", "%e%e", "%E", "%", "e", " %e", "%e "
    };
    const auto substituted = binwalk::substitute_source_file(arguments, "carved.bin");

    ASSERT_EQ(substituted.size(), arguments.size());
    for(std::size_t index = 0; index < arguments.size(); ++index) {
        EXPECT_EQ(substituted[index], arguments[index])
            << "argument " << index << " (" << arguments[index] << ") must not be substituted";
    }
}

TEST(ExtractionFrameworkPlaceholder, SubstitutesEveryExactPlaceholderOccurrence) {
    const std::vector<std::string> arguments{"%e", "-x", "%e", "%e"};
    const auto substituted = binwalk::substitute_source_file(arguments, "carved.bin");

    ASSERT_EQ(substituted.size(), std::size_t{4});
    EXPECT_EQ(substituted[0], "carved.bin");
    EXPECT_EQ(substituted[1], "-x");
    EXPECT_EQ(substituted[2], "carved.bin");
    EXPECT_EQ(substituted[3], "carved.bin");
}

TEST(ExtractionFrameworkPlaceholder, ReturnsAnEmptyVectorForAnEmptyArgumentList) {
    EXPECT_TRUE(binwalk::substitute_source_file({}, "carved.bin").empty());
    EXPECT_TRUE(binwalk::substitute_source_file({}, "").empty());
}

TEST(ExtractionFrameworkPlaceholder, InsertsAReplacementContainingSpacesVerbatim) {
    const std::string replacement = R"(C:\some path\with spaces\carved file.bin)";
    const auto substituted = binwalk::substitute_source_file({"%e"}, replacement);

    ASSERT_EQ(substituted.size(), std::size_t{1});
    EXPECT_EQ(substituted[0], replacement);
    EXPECT_NE(substituted[0].find(' '), std::string::npos);
}

TEST(ExtractionFrameworkPlaceholder, SubstitutesAPlaceholderThatIsNotTheLastArgument) {
    const std::vector<std::string> dmg2img{"-i", "%e", "-o", "mbr.img"};
    const auto substituted = binwalk::substitute_source_file(dmg2img, R"(C:\tmp\dmg_0.dmg)");

    ASSERT_EQ(substituted.size(), std::size_t{4});
    EXPECT_EQ(substituted[0], "-i");
    EXPECT_EQ(substituted[1], R"(C:\tmp\dmg_0.dmg)");
    EXPECT_EQ(substituted[2], "-o");
    EXPECT_EQ(substituted[3], "mbr.img");
}

TEST(ExtractionFrameworkPlaceholder, PreservesUpstreamArgumentShapesByteForByte) {

    expect_only_placeholders_substituted({"%e"}, R"(C:\out\cab_0.cab)");

    expect_only_placeholders_substituted({"-i", "%e", "-o", "mbr.img"}, R"(C:\out\dmg_0.dmg)");

    expect_only_placeholders_substituted(
        {"x", "-y", "-o.", "-p''", "%e"}, R"(C:\out\7zip_2A.bin)"
    );

    expect_only_placeholders_substituted(
        {"-output", "s-record.bin", "-binary", "%e"}, R"(C:\out\srecord_0.hex)"
    );
}

TEST(ExtractionFrameworkProcess, MissingProgramIsNotFoundAndReturnsPromptly) {
    binwalk::process_request request;
    request.program = missing_program;
    request.arguments = {"--version"};

    const auto start = std::chrono::steady_clock::now();
    const auto result = binwalk::run_process(request);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start
    ).count();

    EXPECT_EQ(result.status, binwalk::process_status::not_found);
    EXPECT_TRUE(result.utility_missing());
    EXPECT_FALSE(result.completed());
    EXPECT_LT(elapsed, 5000) << "resolving a missing program must not block";
}

TEST(ExtractionFrameworkProcess, ExecutableAvailableRejectsGarbageAndEmptyNames) {
    EXPECT_FALSE(binwalk::executable_available(missing_program));
    EXPECT_NO_THROW({ EXPECT_FALSE(binwalk::executable_available("")); });
    EXPECT_NO_THROW({ EXPECT_FALSE(binwalk::executable_available(" ")); });
}

#if defined(_WIN32)
TEST(ExtractionFrameworkProcess, ExecutableAvailableResolvesBareNamesAndAbsolutePaths) {

    EXPECT_TRUE(binwalk::executable_available("cmd"));

    const std::filesystem::path absolute_shell = R"(C:\Windows\System32\cmd.exe)";
    if(path_exists(absolute_shell)) {
        EXPECT_TRUE(binwalk::executable_available(absolute_shell.string()));
    }

    const std::filesystem::path absolute_missing =
        R"(C:\Windows\System32\binwalk_no_such_program_zzz.exe)";
    EXPECT_FALSE(binwalk::executable_available(absolute_missing.string()));
}
#endif

TEST(ExtractionFrameworkProcess, RequestDefaultsAreSane) {
    const binwalk::process_request request;

    EXPECT_TRUE(request.program.empty());
    EXPECT_TRUE(request.arguments.empty());
    EXPECT_TRUE(request.working_directory.empty());
    EXPECT_EQ(request.timeout_ms, 0U) << "0 must mean wait forever";
    EXPECT_TRUE(request.discard_output);
}

TEST(ExtractionFrameworkProcess, ResultPredicatesAgreeWithStatus) {
    binwalk::process_result result;
    EXPECT_EQ(result.status, binwalk::process_status::spawn_failed);
    EXPECT_EQ(result.exit_code, -1);
    EXPECT_TRUE(result.error_message.empty());
    EXPECT_FALSE(result.completed());
    EXPECT_FALSE(result.utility_missing());

    result.status = binwalk::process_status::completed;
    EXPECT_TRUE(result.completed());
    EXPECT_FALSE(result.utility_missing());

    result.status = binwalk::process_status::not_found;
    EXPECT_FALSE(result.completed());
    EXPECT_TRUE(result.utility_missing());

    result.status = binwalk::process_status::timed_out;
    EXPECT_FALSE(result.completed());
    EXPECT_FALSE(result.utility_missing());
}

TEST(ExtractionFrameworkProcess, ExtractionResultDefaultsToAFailedResult) {
    const binwalk::extraction_result result;

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.size.has_value());
    EXPECT_TRUE(result.extractor.empty());
    EXPECT_TRUE(result.output_directory.empty());
    EXPECT_FALSE(result.do_not_recurse);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::none);
}

#if defined(_WIN32)

TEST(ExtractionFrameworkProcess, RealSpawnPropagatesAZeroExitCode) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "exit", "0"};
    request.timeout_ms = 15000;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_TRUE(result.completed());
    EXPECT_FALSE(result.utility_missing());
    EXPECT_EQ(result.exit_code, 0);
}

TEST(ExtractionFrameworkProcess, RealSpawnPropagatesANonZeroExitCode) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "exit", "3"};
    request.timeout_ms = 15000;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 3) << "the child's exit code must be reported exactly";
}

TEST(ExtractionFrameworkProcess, RealSpawnWithDiscardedOutputSurvivesAChattyChild) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "echo", "binwalk_stdout_probe", "1>&2"};
    request.timeout_ms = 15000;
    request.discard_output = true;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0);
}

TEST(ExtractionFrameworkProcess, RealSpawnWithInheritedOutputSurvivesAChattyChild) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "echo", "binwalk_stdout_probe"};
    request.timeout_ms = 15000;
    request.discard_output = false;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0);
}

TEST(ExtractionFrameworkProcess, TimeoutTerminatesAWedgedChild) {
    if(!binwalk::executable_available("ping")) {
        GTEST_SKIP() << "ping is not available on this machine";
    }

    binwalk::process_request request;
    request.program = "ping";
    request.arguments = {"-n", "30", "127.0.0.1"};
    request.timeout_ms = 750;
    request.discard_output = true;

    const auto start = std::chrono::steady_clock::now();
    const auto result = binwalk::run_process(request);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start
    ).count();

    EXPECT_EQ(result.status, binwalk::process_status::timed_out) << result.error_message;
    EXPECT_FALSE(result.completed());
    EXPECT_FALSE(result.utility_missing());
    EXPECT_LT(elapsed, 10000)
        << "run_process waited on the child instead of enforcing timeout_ms";
}

TEST_F(extraction_framework_test, RealSpawnHonorsTheRequestedWorkingDirectory) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const auto work = root_ / "work";
    std::error_code error;
    std::filesystem::create_directories(work, error);
    ASSERT_FALSE(static_cast<bool>(error)) << error.message();

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "mkdir", "spawn_marker"};
    request.working_directory = work.string();
    request.timeout_ms = 15000;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0);
    EXPECT_TRUE(path_exists(work / "spawn_marker"))
        << "the child's relative mkdir did not land in working_directory";

    const auto here = std::filesystem::current_path(error);
    if(!error) {
        EXPECT_FALSE(path_exists(here / "spawn_marker"))
            << "the child ran in the test's cwd, not in working_directory";
    }
}

TEST_F(extraction_framework_test, RealSpawnPassesAnArgumentWithSpacesAsOneArgument) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const auto work = root_ / "work";
    std::error_code error;
    std::filesystem::create_directories(work, error);
    ASSERT_FALSE(static_cast<bool>(error)) << error.message();

    binwalk::process_request request;
    request.program = "cmd";
    request.arguments = {"/c", "mkdir", "one argument with spaces"};
    request.working_directory = work.string();
    request.timeout_ms = 15000;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0);

    EXPECT_TRUE(path_exists(work / "one argument with spaces"));
    EXPECT_FALSE(path_exists(work / "one"));
    EXPECT_FALSE(path_exists(work / "argument"));
    EXPECT_FALSE(path_exists(work / "with"));
    EXPECT_FALSE(path_exists(work / "spaces"));
    EXPECT_EQ(count_entries(work), std::size_t{1})
        << "the argument was split into several arguments";
}

TEST_F(extraction_framework_test, RealSpawnDeliversShellHostileArgumentsUnmangled) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    write_batch_file(root_ / "check_args.bat", {
        "@echo off",
        R"(if not "%~1"=="-i" exit /b 11)",
        R"(if not "%~2"=="-o." exit /b 12)",
        R"(if not "%~3"=="-p''" exit /b 13)",
        R"(if not "%~4"=="-output" exit /b 14)",
        R"(if not "%~5"=="s-record.bin" exit /b 15)",
        "exit /b 0"
    });

    binwalk::process_request request;
    request.program = "cmd";

    request.arguments = {
        "/c", ".\\check_args.bat", "-i", "-o.", "-p''", "-output", "s-record.bin"
    };
    request.working_directory = root_.string();
    request.timeout_ms = 15000;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0)
        << "argument 1..5 mangled; the failing index is exit_code - 10";
}

TEST_F(extraction_framework_test, DiscardedOutputDoesNotDeadlockOnAVeryChattyChild) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    write_batch_file(root_ / "chatty.bat", {
        "@echo off",
        "for /l %%i in (1,1,2000) do echo line %%i padding padding padding padding padding",
        "exit /b 0"
    });

    binwalk::process_request request;
    request.program = "cmd";

    request.arguments = {"/c", ".\\chatty.bat"};
    request.working_directory = root_.string();
    request.timeout_ms = 20000;
    request.discard_output = true;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed)
        << "a chatty child deadlocked or timed out: " << result.error_message;
    EXPECT_EQ(result.exit_code, 0);
}

#if defined(_MSC_VER)

TEST(ExtractionFrameworkArgvOracle, ReceivesEveryAwkwardArgumentByteForByte) {
    if(!own_argv_contains(argv_oracle_flag)) {
        GTEST_SKIP() << "not running as the argv fidelity child process";
    }

    const auto values = argv_oracle_values();
    for(const auto& value : values) {
        EXPECT_TRUE(own_argv_contains(value.c_str()))
            << "the argument [" << value << "] did not survive the spawn";
    }

    EXPECT_EQ(__argc, static_cast<int>(values.size()) + 3)
        << "an argument was split or merged in transit";
}

TEST_F(extraction_framework_test, RealSpawnPreservesQuotesAndSpacesInArguments) {
    if(own_argv_contains(argv_oracle_flag)) {
        GTEST_SKIP() << "recursion guard: this process is already an oracle child";
    }
    const auto self = own_executable_path();
    if(!self.has_value()) {
        GTEST_SKIP() << "could not locate this test executable to re-spawn it";
    }
    if(!binwalk::executable_available(self->string())) {
        GTEST_SKIP() << "this test executable is not resolvable as a program";
    }

    binwalk::process_request request;
    request.program = self->string();
    request.arguments = {argv_oracle_filter, argv_oracle_flag};
    for(const auto& value : argv_oracle_values()) {
        request.arguments.push_back(value);
    }
    request.working_directory = root_.string();
    request.timeout_ms = 30000;
    request.discard_output = true;

    const auto result = binwalk::run_process(request);
    ASSERT_EQ(result.status, binwalk::process_status::completed) << result.error_message;
    EXPECT_EQ(result.exit_code, 0)
        << "the re-spawned child did not receive its arguments byte for byte; "
           "run it directly with --gtest_filter=ExtractionFrameworkArgvOracle.* to see which";
}

#endif
#endif

TEST_F(extraction_framework_test, DryRunOnANullInternalExtractorIsUnsupportedAndWritesNothing) {
    const auto data = minimal_png();
    const auto signature = whole_buffer_signature(data);
    const binwalk::internal_extractor function = nullptr;

    const auto result = binwalk::dry_run_extractor(function, binwalk::byte_view(data), signature);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);
    EXPECT_EQ(count_entries(root_), std::size_t{0});
}

TEST_F(extraction_framework_test, DryRunOnAnExternalDefinitionIsUnsupportedAndWritesNothing) {
    const auto data = minimal_png();
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "external_only";
    definition.command = "cmd";
    definition.extension = "bin";
    definition.arguments = {"%e"};

    const auto result = binwalk::dry_run_extractor(definition, binwalk::byte_view(data), signature);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);
    EXPECT_EQ(count_entries(root_), std::size_t{0});
}

TEST_F(extraction_framework_test, DryRunOnANoneDefinitionIsUnsupportedAndWritesNothing) {
    const auto data = minimal_png();
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    ASSERT_EQ(definition.type, binwalk::extractor_type::none);
    ASSERT_EQ(definition.internal, nullptr);

    const auto result = binwalk::dry_run_extractor(definition, binwalk::byte_view(data), signature);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);
    EXPECT_EQ(count_entries(root_), std::size_t{0});
}

TEST_F(extraction_framework_test, DryRunOnAnEmptyBufferDoesNotCrash) {
    const auto definition = internal_extractor_for("png");
    if(!definition.has_value()) {
        GTEST_SKIP() << "no internal png extractor in builtin_signatures()";
    }

    binwalk::signature_result signature;
    signature.offset = 0;
    signature.size = 44;
    signature.name = "png";
    signature.id = "png_empty_probe";

    const auto result = binwalk::dry_run_extractor(*definition, binwalk::byte_view{}, signature);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(count_entries(root_), std::size_t{0});
}

TEST_F(extraction_framework_test, MissingExternalUtilityReportsUtilityNotFoundAndCleansUp) {
    const std::vector<std::uint8_t> data(4096, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "no_such_utility";
    definition.command = missing_program;
    definition.extension = "bin";
    definition.arguments = {"-d", "%e"};

    EXPECT_FALSE(binwalk::external_utility_available(definition));

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition, output_root.string()
    );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_not_found);

    if(!result.output_directory.empty()) {
        EXPECT_FALSE(path_exists(result.output_directory))
            << "the failed extraction left its per-offset directory behind: "
            << result.output_directory;
    }

    const auto extracted_parent = find_entry_named_with(output_root, ".extracted");
    if(extracted_parent.has_value()) {
        EXPECT_EQ(count_entries(*extracted_parent), std::size_t{0})
            << "the .extracted tree is not empty after a failed extraction";
    }
    EXPECT_EQ(count_non_empty_files(output_root), std::size_t{0})
        << "the carved input file survived a failed extraction";
}

TEST_F(extraction_framework_test, ExternalExtractorLeavesTheExtractorFieldEmptyWhenTheUtilityNeverRan) {
    const std::vector<std::uint8_t> data(1024, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "absent_utility";
    definition.command = missing_program;
    definition.extension = "bin";
    definition.arguments = {"%e"};

    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition,
        (root_ / "out").string()
    );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_not_found);
    EXPECT_EQ(result.extractor, "")
        << "an empty extractor field is how a caller tells 'never launched' from "
           "'ran and was rejected'";
}

#if defined(_WIN32)

TEST_F(extraction_framework_test, ExternalExtractorNamesTheUtilityOnceItActuallyRan) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const std::vector<std::uint8_t> data(1024, 0x5a);
    const auto signature = whole_buffer_signature(data);

    const auto run_case = [&](const std::string& case_name,
                              const std::vector<std::string>& arguments) {
        binwalk::extractor definition;
        definition.type = binwalk::extractor_type::external;
        definition.name = "cmd_" + case_name;
        definition.command = "cmd";
        definition.extension = "bin";
        definition.arguments = arguments;
        definition.exit_codes = {0};
        return binwalk::execute_extractor(
            binwalk::byte_view(data), "fixture.bin", signature, definition,
            (root_ / case_name).string()
        );
    };

    const auto rejected = run_case("bad_exit", {"/c", "exit", "9"});
    EXPECT_FALSE(rejected.success);
    EXPECT_EQ(rejected.failure, binwalk::extraction_failure::utility_failed);
    EXPECT_EQ(rejected.extractor, "cmd");

    const auto silent = run_case("silent", {"/c", "exit", "0"});
    EXPECT_FALSE(silent.success);
    EXPECT_EQ(silent.failure, binwalk::extraction_failure::no_output);
    EXPECT_EQ(silent.extractor, "cmd")
        << "a utility that ran and produced nothing has still run, and is named";

    const auto produced = run_case(
        "produced", {"/c", "copy", binwalk::source_file_placeholder, "external_output.bin"}
    );
    EXPECT_TRUE(produced.success)
        << "failure code " << static_cast<int>(produced.failure);
    EXPECT_EQ(produced.failure, binwalk::extraction_failure::none);
    EXPECT_EQ(produced.extractor, "cmd");
}

#endif

TEST_F(extraction_framework_test, ExternalUtilityAvailableIsFalseForNonExternalDefinitions) {
    binwalk::extractor none_definition;
    none_definition.name = "none_with_command";
    none_definition.command = "cmd";
    EXPECT_FALSE(binwalk::external_utility_available(none_definition));

    const auto internal_definition = internal_extractor_for("png");
    if(internal_definition.has_value()) {
        binwalk::extractor probe = *internal_definition;
        probe.command = "cmd";
        EXPECT_EQ(probe.type, binwalk::extractor_type::internal);
        EXPECT_FALSE(binwalk::external_utility_available(probe));
    }

    binwalk::extractor external_missing;
    external_missing.type = binwalk::extractor_type::external;
    external_missing.name = "external_missing";
    external_missing.command = missing_program;
    EXPECT_FALSE(binwalk::external_utility_available(external_missing));
}

TEST_F(extraction_framework_test, PreferredExtractorOverridesAGoodDefinitionInExecuteExtractor) {
    const auto data = minimal_png();
    const auto internal_definition = internal_extractor_for("png");
    if(!internal_definition.has_value()) {
        GTEST_SKIP() << "no internal png extractor in builtin_signatures()";
    }
    auto signature = scan_for(data, "png");
    ASSERT_TRUE(signature.has_value()) << "the known-good png fixture is not recognised";

    binwalk::extractor preferred;
    preferred.type = binwalk::extractor_type::external;
    preferred.name = "preferred_missing_utility";
    preferred.command = missing_program;
    preferred.extension = "png";
    preferred.arguments = {"%e"};
    signature->preferred_extractor = preferred;

    const auto output_root = root_ / "out";

    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.png", *signature, *internal_definition,
        output_root.string()
    );

    EXPECT_FALSE(result.success)
        << "preferred_extractor did not override the definition argument";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_not_found);
    EXPECT_EQ(count_non_empty_files(output_root), std::size_t{0});
}

TEST_F(extraction_framework_test, PreferredExtractorOverridesAGoodDefinitionInDryRun) {
    const auto data = minimal_png();
    const auto internal_definition = internal_extractor_for("png");
    if(!internal_definition.has_value()) {
        GTEST_SKIP() << "no internal png extractor in builtin_signatures()";
    }
    auto signature = scan_for(data, "png");
    ASSERT_TRUE(signature.has_value()) << "the known-good png fixture is not recognised";

    binwalk::extractor preferred;
    preferred.type = binwalk::extractor_type::external;
    preferred.name = "preferred_external";
    preferred.command = "cmd";
    preferred.extension = "png";
    signature->preferred_extractor = preferred;

    const auto result = binwalk::dry_run_extractor(
        *internal_definition, binwalk::byte_view(data), *signature
    );

    EXPECT_FALSE(result.success)
        << "a dry run of an external preferred_extractor must be unsupported";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);
    EXPECT_EQ(count_entries(root_), std::size_t{0});
}

TEST_F(extraction_framework_test, PreferredExtractorAlsoOverridesAUselessDefinition) {
    const auto data = minimal_png();
    const auto internal_definition = internal_extractor_for("png");
    if(!internal_definition.has_value()) {
        GTEST_SKIP() << "no internal png extractor in builtin_signatures()";
    }
    auto signature = scan_for(data, "png");
    ASSERT_TRUE(signature.has_value()) << "the known-good png fixture is not recognised";
    signature->preferred_extractor = *internal_definition;

    const binwalk::extractor useless_definition;
    ASSERT_EQ(useless_definition.type, binwalk::extractor_type::none);

    const auto result = binwalk::dry_run_extractor(
        useless_definition, binwalk::byte_view(data), *signature
    );

    EXPECT_TRUE(result.success)
        << "preferred_extractor did not rescue an extractor_type::none definition ("
        << static_cast<int>(result.failure) << ")";
    ASSERT_TRUE(result.size.has_value());

    auto plain = *signature;
    plain.preferred_extractor.reset();
    const auto direct = binwalk::dry_run_extractor(
        *internal_definition, binwalk::byte_view(data), plain
    );
    ASSERT_TRUE(direct.size.has_value());
    EXPECT_EQ(*result.size, *direct.size);
    EXPECT_EQ(count_entries(root_), std::size_t{0}) << "the dry run wrote to disk";
}

#if defined(_WIN32)

TEST_F(extraction_framework_test, ExternalExtractorCarvesSubstitutesAndSpawnsTheUtility) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const std::vector<std::uint8_t> data(4096, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "cmd_copy";
    definition.command = "cmd";
    definition.extension = "bin";
    definition.arguments = {"/c", "copy", binwalk::source_file_placeholder, "external_output.bin"};
    definition.exit_codes = {0};

    EXPECT_TRUE(binwalk::external_utility_available(definition));

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition, output_root.string()
    );

    EXPECT_TRUE(result.success)
        << "external extraction failed with failure code " << static_cast<int>(result.failure);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::none);

    const auto copied = find_entry_named_with(output_root, "external_output.bin");
    ASSERT_TRUE(copied.has_value())
        << "the utility's output is not under " << output_root.string();
    std::error_code error;

    EXPECT_EQ(std::filesystem::file_size(*copied, error), data.size());
    EXPECT_FALSE(static_cast<bool>(error)) << error.message();
}

TEST_F(extraction_framework_test, ExternalExtractorAcceptsAnyListedExitCode) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const auto emitter = root_ / "emit2.bat";
    write_batch_file(emitter, {
        "@echo off",
        "echo produced-output>produced.txt",
        "exit /b 2"
    });

    const std::vector<std::uint8_t> data(1024, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "cmd_exit_two";
    definition.command = "cmd";
    definition.extension = "bin";

    definition.arguments = {"/c", "call", emitter.string()};
    definition.exit_codes = {0, 2};

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition, output_root.string()
    );

    EXPECT_TRUE(result.success)
        << "exit code 2 is listed in exit_codes but was treated as a failure ("
        << static_cast<int>(result.failure) << ")";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::none);
    EXPECT_TRUE(find_entry_named_with(output_root, "produced.txt").has_value())
        << "the child did not run with the output directory as its cwd";
}

TEST_F(extraction_framework_test, ExternalExtractorRejectsAnExitCodeOutsideExitCodes) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const auto emitter = root_ / "emit1.bat";
    write_batch_file(emitter, {
        "@echo off",
        "echo produced-output>produced.txt",
        "exit /b 1"
    });

    const std::vector<std::uint8_t> data(1024, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "cmd_exit_one";
    definition.command = "cmd";
    definition.extension = "bin";
    definition.arguments = {"/c", "call", emitter.string()};
    definition.exit_codes = {0, 2};

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition, output_root.string()
    );

    EXPECT_FALSE(result.success) << "exit code 1 is not in exit_codes {0, 2}";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_failed);
}

TEST_F(extraction_framework_test, EmptyExitCodesDefaultsToZeroOnly) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const std::vector<std::uint8_t> data(1024, 0x5a);
    const auto signature = whole_buffer_signature(data);

    const auto succeeding = root_ / "emit0.bat";
    write_batch_file(succeeding, {
        "@echo off",
        "echo produced-output>produced.txt",
        "exit /b 0"
    });
    const auto failing = root_ / "emit1.bat";
    write_batch_file(failing, {
        "@echo off",
        "echo produced-output>produced.txt",
        "exit /b 1"
    });

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "cmd_default_exit_codes";
    definition.command = "cmd";
    definition.extension = "bin";
    definition.exit_codes = {};

    definition.arguments = {"/c", "call", succeeding.string()};
    const auto accepted = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition,
        (root_ / "out_zero").string()
    );
    EXPECT_TRUE(accepted.success)
        << "exit code 0 must be accepted when exit_codes is empty ("
        << static_cast<int>(accepted.failure) << ")";

    definition.arguments = {"/c", "call", failing.string()};
    const auto rejected = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition,
        (root_ / "out_one").string()
    );
    EXPECT_FALSE(rejected.success) << "exit code 1 must be rejected when exit_codes is empty";
    EXPECT_EQ(rejected.failure, binwalk::extraction_failure::utility_failed);
}

TEST_F(extraction_framework_test, ExternalExtractorReportsNoOutputWhenTheUtilityWritesNothing) {
    if(!binwalk::executable_available("cmd")) {
        GTEST_SKIP() << "cmd is not available on this machine";
    }

    const std::vector<std::uint8_t> data(4096, 0x5a);
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor definition;
    definition.type = binwalk::extractor_type::external;
    definition.name = "cmd_silent";
    definition.command = "cmd";
    definition.extension = "bin";
    definition.arguments = {"/c", "exit", "0"};
    definition.exit_codes = {0};

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.bin", signature, definition, output_root.string()
    );

    EXPECT_FALSE(result.success)
        << "the carved input file must not be counted as extracted output";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::no_output);
    if(!result.output_directory.empty()) {
        EXPECT_FALSE(path_exists(result.output_directory))
            << "the per-offset directory survived a no-output failure";
    }
    EXPECT_EQ(count_non_empty_files(output_root), std::size_t{0})
        << "the carved input file was left on disk";
}

#endif

TEST_F(extraction_retry_test, RetryToEofRescuesAnUnderEstimatedSignature) {
    probe_a.can_succeed = true;
    probe_a.success_threshold = available_from(0);
    const auto signature = probe_signature_result("probe_a", 0, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    ASSERT_EQ(probe_a.calls, 2) << "the failed extraction was not retried";
    ASSERT_EQ(probe_a.observed_sizes.size(), std::size_t{2});
    EXPECT_EQ(probe_a.observed_sizes[0], std::uint64_t{100});
    EXPECT_EQ(probe_a.observed_sizes[1], available_from(0))
        << "the retry must widen size to everything from the offset to EOF";
    EXPECT_EQ(probe_a.observed_data_sizes[1], data_.size())
        << "the retry must still be handed the whole buffer";

    const auto found = extractions.find(signature.id);
    ASSERT_NE(found, extractions.end());
    EXPECT_TRUE(found->second.success) << "the retry succeeded but its result was discarded";
    ASSERT_TRUE(found->second.size.has_value());
    EXPECT_EQ(*found->second.size, available_from(0));
}

TEST_F(extraction_retry_test, RetriesExactlyOnceAndDoesNotLoop) {
    probe_a.can_succeed = false;
    const auto signature = probe_signature_result("probe_a", 0, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 2) << "exactly one retry: never zero, never a loop";

    const auto found = extractions.find(signature.id);
    ASSERT_NE(found, extractions.end());
    EXPECT_FALSE(found->second.success);
}

TEST_F(extraction_retry_test, TheRetryResultReplacesTheFirstIncludingItsFailureReason) {
    probe_a.can_succeed = false;
    probe_a.first_failure = binwalk::extraction_failure::invalid_data;
    probe_a.later_failure = binwalk::extraction_failure::write_error;
    const auto signature = probe_signature_result("probe_a", 0, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    ASSERT_EQ(probe_a.calls, 2);
    const auto found = extractions.find(signature.id);
    ASSERT_NE(found, extractions.end());
    EXPECT_FALSE(found->second.success);
    EXPECT_EQ(found->second.failure, binwalk::extraction_failure::write_error)
        << "the recorded failure must be the retry's, not the first attempt's";
}

TEST_F(extraction_retry_test, NoRetryWhenTheSignatureAlreadyReachesEof) {
    probe_a.can_succeed = false;
    const auto signature = probe_signature_result("probe_a", 0, available_from(0));

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 1) << "retrying an identical widening is wasted work";
    EXPECT_NE(extractions.find(signature.id), extractions.end());
}

TEST_F(extraction_retry_test, NoRetryWhenTheSignatureSizeExceedsTheAvailableData) {
    probe_a.can_succeed = false;

    const auto signature = probe_signature_result("probe_a", 0, available_from(0) * 2);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 1);
    EXPECT_NE(extractions.find(signature.id), extractions.end());
}

TEST_F(extraction_retry_test, DeclinedExtractionIsNeitherAttemptedNorRetried) {
    probe_a.can_succeed = false;
    auto signature = probe_signature_result("probe_a", 0, 100);
    signature.extraction_declined = true;

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 0) << "a declined extraction is a refusal, not a failure to retry";
    EXPECT_EQ(extractions.find(signature.id), extractions.end())
        << "a declined signature must not appear in the extraction map at all";
    EXPECT_EQ(count_non_empty_files(root_), std::size_t{0});
}

TEST_F(extraction_retry_test, NoRetryAfterASuccessfulFirstAttempt) {
    probe_a.can_succeed = true;
    probe_a.success_threshold = 0;
    const auto signature = probe_signature_result("probe_a", 0, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 1) << "a successful extraction must not be retried";
    const auto found = extractions.find(signature.id);
    ASSERT_NE(found, extractions.end());
    EXPECT_TRUE(found->second.success);
    ASSERT_TRUE(found->second.size.has_value());
    EXPECT_EQ(*found->second.size, std::uint64_t{100}) << "the first attempt's size must stand";
}

TEST_F(extraction_retry_test, TheRetryCarriesThePreferredExtractor) {
    probe_a.can_succeed = false;
    probe_b.can_succeed = false;

    auto signature = probe_signature_result("probe_shared", 0, 100);
    binwalk::extractor preferred;
    preferred.type = binwalk::extractor_type::internal;
    preferred.name = "probe_a_preferred";
    preferred.internal = &probe_a_extractor;
    signature.preferred_extractor = preferred;

    const auto extractions = extract_with(
        make_probe_signature("probe_shared", &probe_b_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 2) << "the override must be used on both the attempt and the retry";
    EXPECT_EQ(probe_b.calls, 0) << "the retry fell back to the registered extractor";
    EXPECT_NE(extractions.find(signature.id), extractions.end());
}

TEST_F(extraction_retry_test, PreferredExtractorNeedsNoMatchingRegistryEntry) {
    probe_a.can_succeed = true;
    probe_a.success_threshold = 0;
    probe_b.can_succeed = true;
    probe_b.success_threshold = 0;

    auto signature = probe_signature_result("probe_unregistered", 0, 100);
    binwalk::extractor preferred;
    preferred.type = binwalk::extractor_type::internal;
    preferred.name = "probe_a_preferred";
    preferred.internal = &probe_a_extractor;
    signature.preferred_extractor = preferred;

    const auto extractions = extract_with(
        make_probe_signature("probe_something_else", &probe_b_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 1) << "the override must run without a registry entry to back it";
    EXPECT_EQ(probe_b.calls, 0);
    const auto found = extractions.find(signature.id);
    ASSERT_NE(found, extractions.end()) << "preferred_extractor was inert for an unknown name";
    EXPECT_TRUE(found->second.success);
}

TEST_F(extraction_retry_test, AnUnknownSignatureNameWithoutAnOverrideIsSkipped) {
    probe_a.can_succeed = true;
    probe_a.success_threshold = 0;
    probe_b.can_succeed = true;
    probe_b.success_threshold = 0;
    const auto signature = probe_signature_result("probe_unregistered", 0, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_something_else", &probe_b_extractor), signature
    );

    EXPECT_EQ(probe_a.calls, 0);
    EXPECT_EQ(probe_b.calls, 0) << "an unmatched name must not fall through to another entry";
    EXPECT_EQ(extractions.find(signature.id), extractions.end());
}

TEST_F(extraction_retry_test, TheRetryWidensToEofFromTheSignatureOffsetNotFromZero) {
    probe_a.can_succeed = false;
    const std::uint64_t offset = 1000;
    const auto signature = probe_signature_result("probe_a", offset, 100);

    const auto extractions = extract_with(
        make_probe_signature("probe_a", &probe_a_extractor), signature
    );

    ASSERT_EQ(probe_a.calls, 2);
    ASSERT_EQ(probe_a.observed_sizes.size(), std::size_t{2});
    EXPECT_EQ(probe_a.observed_offsets[1], offset) << "the retry must keep the offset";
    EXPECT_EQ(probe_a.observed_sizes[1], available_from(offset))
        << "the retry must widen to data.size() - offset, not to data.size()";
    EXPECT_NE(probe_a.observed_sizes[1], static_cast<std::uint64_t>(data_.size()));
    EXPECT_NE(extractions.find(signature.id), extractions.end());
}

TEST_F(extraction_framework_test, UnsupportedAndUtilityNotFoundAreDifferentAnswers) {
    const auto data = minimal_png();
    const auto signature = whole_buffer_signature(data);

    binwalk::extractor external_definition;
    external_definition.type = binwalk::extractor_type::external;
    external_definition.name = "absent_utility";
    external_definition.command = missing_program;
    external_definition.extension = "bin";
    external_definition.arguments = {"%e"};

    const auto unsupported = binwalk::dry_run_extractor(
        external_definition, binwalk::byte_view(data), signature
    );
    EXPECT_FALSE(unsupported.success);
    EXPECT_EQ(unsupported.failure, binwalk::extraction_failure::unsupported);

    const auto absent = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.png", signature, external_definition,
        (root_ / "out").string()
    );
    EXPECT_FALSE(absent.success);
    EXPECT_EQ(absent.failure, binwalk::extraction_failure::utility_not_found);

    EXPECT_NE(unsupported.failure, absent.failure)
        << "'this build cannot' and 'that tool is not installed' must not collapse";

    EXPECT_NE(binwalk::extraction_failure::timed_out, binwalk::extraction_failure::utility_failed);
}

TEST_F(extraction_framework_test, MbrCarvesAZeroLengthPartitionAsAZeroByteFile) {
    const auto definition = internal_extractor_for("mbr");
    if(!definition.has_value()) {
        GTEST_SKIP() << "no internal mbr extractor in builtin_signatures()";
    }

    const auto data = mbr_with_a_zero_length_partition();
    const auto signature = scan_for(data, "mbr");
    ASSERT_TRUE(signature.has_value()) << "the mbr fixture is not recognised";
    EXPECT_EQ(signature->offset, std::uint64_t{0});
    EXPECT_EQ(signature->size, std::uint64_t{2048});
    EXPECT_FALSE(signature->extraction_declined);

    const auto dry = binwalk::dry_run_extractor(
        *definition, binwalk::byte_view(data), *signature
    );
    EXPECT_TRUE(dry.success) << "failure code " << static_cast<int>(dry.failure);
    ASSERT_TRUE(dry.size.has_value());
    EXPECT_EQ(*dry.size, std::uint64_t{2048});
    EXPECT_EQ(count_entries(root_), std::size_t{0}) << "the dry run wrote to disk";

    const auto output_root = root_ / "out";
    const auto real = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.mbr", *signature, *definition, output_root.string()
    );
    EXPECT_TRUE(real.success) << "failure code " << static_cast<int>(real.failure);
    ASSERT_TRUE(real.size.has_value());
    EXPECT_EQ(*real.size, std::uint64_t{2048});

    const auto first = find_entry_named_with(output_root, "Linux_partition.0");
    ASSERT_TRUE(first.has_value()) << "the non-empty partition was not carved";
    EXPECT_EQ(file_size_of(*first), std::uintmax_t{1024});

    const auto second = find_entry_named_with(output_root, "Linux_partition.1");
    ASSERT_TRUE(second.has_value())
        << "the zero-length partition must still produce a file; upstream emits it";
    EXPECT_EQ(file_size_of(*second), std::uintmax_t{0})
        << "the zero-length partition's file must be exactly zero bytes";
}

TEST_F(extraction_framework_test, RiffDeclinesExtractionWhenItSpansTheWholeFile) {
    const auto data = riff_wave();
    ASSERT_EQ(data.size(), std::size_t{44});

    const binwalk::scanner scanner;
    const auto output_root = root_ / "out";
    const auto analysis = scanner.analyze(
        binwalk::byte_view(data), "fixture.wav", true, output_root.string()
    );

    const auto* riff = find_in_file_map(analysis.file_map, "riff");
    ASSERT_NE(riff, nullptr) << "the riff fixture is not recognised";
    EXPECT_EQ(riff->offset, std::uint64_t{0});
    EXPECT_EQ(riff->size, std::uint64_t{44});
    EXPECT_TRUE(riff->extraction_declined)
        << "a whole-file riff must decline extraction, not attempt it";

    EXPECT_EQ(analysis.extractions.find(riff->id), analysis.extractions.end())
        << "a declined signature must record no extraction";
    EXPECT_TRUE(analysis.extractions.empty());
    EXPECT_EQ(count_entries(output_root), std::size_t{0})
        << "no output directory may be created for a declined extraction";
}

TEST_F(extraction_framework_test, RiffExtractsWhenTrailingDataFollowsTheSignature) {
    auto data = riff_wave();
    data.resize(64, 0);
    ASSERT_EQ(data.size(), std::size_t{64});

    const binwalk::scanner scanner;
    const auto output_root = root_ / "out";
    const auto analysis = scanner.analyze(
        binwalk::byte_view(data), "fixture.wav", true, output_root.string()
    );

    const auto* riff = find_in_file_map(analysis.file_map, "riff");
    ASSERT_NE(riff, nullptr) << "the riff fixture is not recognised";
    EXPECT_EQ(riff->offset, std::uint64_t{0});
    EXPECT_EQ(riff->size, std::uint64_t{44}) << "the signature covers 44 of the 64 bytes";
    EXPECT_FALSE(riff->extraction_declined)
        << "a riff that does not reach EOF must be extracted, not declined";

    const auto found = analysis.extractions.find(riff->id);
    ASSERT_NE(found, analysis.extractions.end()) << "no extraction was recorded";
    EXPECT_TRUE(found->second.success)
        << "failure code " << static_cast<int>(found->second.failure);
    ASSERT_TRUE(found->second.size.has_value());
    EXPECT_EQ(*found->second.size, std::uint64_t{44});

    const auto carved = find_entry_named_with(output_root, "video.wav");
    ASSERT_TRUE(carved.has_value()) << "expected the carved file to be named video.wav";
    EXPECT_EQ(file_size_of(*carved), std::uintmax_t{44})
        << "the carve must be the signature's 44 bytes, not the whole 64-byte buffer";
}

TEST(ScannerRegistryFilters, TheCountingRegistryIsShapedAsTheseTestsAssume) {
    const auto registry = counting_registry();
    ASSERT_EQ(registry.size(), std::size_t{3});
    EXPECT_EQ(total_magic_patterns(), std::size_t{6});

    std::size_t short_signatures = 0;
    for(const auto& value : registry) {
        EXPECT_GE(value.magic.size(), std::size_t{2}) << value.name;
        if(value.short_signature) {
            ++short_signatures;
        }
    }
    EXPECT_EQ(short_signatures, std::size_t{1})
        << "without a short signature the search_all invariance test proves nothing";
}

TEST(ScannerRegistryFilters, PatternCountDoesNotVaryWithSearchAll) {
    binwalk::scan_options plain;
    binwalk::scan_options everything;
    everything.search_all = true;

    const binwalk::scanner without(counting_registry(), plain);
    const binwalk::scanner with(counting_registry(), everything);

    EXPECT_EQ(without.pattern_count(), with.pattern_count())
        << "a short signature's magic patterns must count with and without -a";
    EXPECT_EQ(without.pattern_count(), total_magic_patterns());
    EXPECT_EQ(with.pattern_count(), total_magic_patterns());
    EXPECT_EQ(without.signature_count(), with.signature_count());
}

TEST(ScannerRegistryFilters, PatternCountIsTheSumOfMagicPatternsOverIncludedSignatures) {
    const binwalk::scanner all(counting_registry());
    EXPECT_EQ(all.pattern_count(), total_magic_patterns());

    binwalk::scan_options options;
    options.include = {"gzip", "PNG"};
    const binwalk::scanner two(counting_registry(), options);

    EXPECT_EQ(two.signature_count(), std::size_t{2});
    EXPECT_EQ(two.pattern_count(), magic_count_of("gzip") + magic_count_of("PNG"));
}

TEST(ScannerRegistryFilters, SignatureCountIsTheNumberOfIncludedSignatures) {
    const binwalk::scanner all(counting_registry());
    EXPECT_EQ(all.signature_count(), std::size_t{3});

    binwalk::scan_options everything;
    everything.search_all = true;
    EXPECT_EQ(binwalk::scanner(counting_registry(), everything).signature_count(), std::size_t{3});

    binwalk::scan_options included;
    included.include = {"gzip"};
    EXPECT_EQ(binwalk::scanner(counting_registry(), included).signature_count(), std::size_t{1});

    binwalk::scan_options excluded;
    excluded.exclude = {"gzip"};
    EXPECT_EQ(binwalk::scanner(counting_registry(), excluded).signature_count(), std::size_t{2});
}

TEST(ScannerRegistryFilters, IncludeSelectsBySignatureNameIgnoringCase) {
    for(const std::string token : {"gzip", "GZIP", "GzIp", "gZiP"}) {
        binwalk::scan_options options;
        options.include = {token};
        const binwalk::scanner scanner(counting_registry(), options);

        EXPECT_EQ(scanner.signature_count(), std::size_t{1}) << "include token: " << token;
        EXPECT_EQ(scanner.pattern_count(), magic_count_of("gzip")) << "include token: " << token;
    }
}

TEST(ScannerRegistryFilters, IncludeFoldsTheRegistryNameAsWellAsTheToken) {
    binwalk::scan_options options;
    options.include = {"png"};
    const binwalk::scanner scanner(counting_registry(), options);

    EXPECT_EQ(scanner.signature_count(), std::size_t{1})
        << "a lower-case token must match a registry entry named \"PNG\"";
    EXPECT_EQ(scanner.pattern_count(), magic_count_of("PNG"));
}

TEST(ScannerRegistryFilters, ExcludeDropsBySignatureNameIgnoringCase) {
    for(const std::string token : {"gzip", "GZIP", "GzIp"}) {
        binwalk::scan_options options;
        options.exclude = {token};
        const binwalk::scanner scanner(counting_registry(), options);

        EXPECT_EQ(scanner.signature_count(), std::size_t{2}) << "exclude token: " << token;
        EXPECT_EQ(scanner.pattern_count(), total_magic_patterns() - magic_count_of("gzip"))
            << "exclude token: " << token;
    }
}

TEST(ScannerRegistryFilters, UnmatchedFilterTokensBehaveSanely) {
    binwalk::scan_options include_nothing;
    include_nothing.include = {"binwalk_no_such_format_zzz"};
    const binwalk::scanner empty(counting_registry(), include_nothing);
    EXPECT_EQ(empty.signature_count(), std::size_t{0});
    EXPECT_EQ(empty.pattern_count(), std::size_t{0});

    binwalk::scan_options exclude_nothing;
    exclude_nothing.exclude = {"binwalk_no_such_format_zzz"};
    const binwalk::scanner untouched(counting_registry(), exclude_nothing);
    EXPECT_EQ(untouched.signature_count(), std::size_t{3});
    EXPECT_EQ(untouched.pattern_count(), total_magic_patterns());
}

TEST(ScannerRegistryFilters, AnIncludeListDecidesAloneSoIncludeOutranksExclude) {
    binwalk::scan_options options;
    options.include = {"GZIP"};
    options.exclude = {"gzip"};
    const binwalk::scanner scanner(counting_registry(), options);

    EXPECT_EQ(scanner.signature_count(), std::size_t{1})
        << "an include list decides alone; the exclude list is never consulted";
    EXPECT_EQ(scanner.pattern_count(), magic_count_of("gzip"));
}

#if defined(_WIN32)

TEST_F(extraction_framework_test, ExtractionSucceedsWhenTheOutputPathExceedsMaxPath) {
    const auto definition = internal_extractor_for("riff");
    if(!definition.has_value()) {
        GTEST_SKIP() << "no internal riff extractor in builtin_signatures()";
    }

    const auto long_root = make_long_root(233);
    if(!long_root.has_value()) {
        GTEST_SKIP() << "this machine's temp path leaves no room for a 233-character root "
                        "below the 248-character directory limit";
    }

    const long_path_guard guard;

    std::error_code error;
    std::filesystem::create_directories(*long_root, error);
    ASSERT_FALSE(static_cast<bool>(error))
        << "could not create the long root: " << error.message();
    ASSERT_EQ(long_root->string().size(), std::size_t{233});

    auto data = riff_wave();
    data.resize(64, 0);
    const auto signature = scan_for(data, "riff");
    ASSERT_TRUE(signature.has_value()) << "the riff fixture is not recognised";

    const auto real = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.wav", *signature, *definition, long_root->string()
    );

    EXPECT_TRUE(real.success) << "failure code " << static_cast<int>(real.failure);
    EXPECT_EQ(real.failure, binwalk::extraction_failure::none);
    ASSERT_FALSE(real.output_directory.empty())
        << "before the long-path fix this came back empty with failure=write_error";

    EXPECT_EQ(real.output_directory.find("\\\\?\\"), std::string::npos)
        << "output_directory must stay unprefixed: " << real.output_directory;

    const auto carved = std::filesystem::path(real.output_directory) / "video.wav";
    EXPECT_GT(carved.string().size(), std::size_t{260})
        << "this fixture is no longer exercising MAX_PATH at all: " << carved.string();

    EXPECT_TRUE(std::filesystem::exists(prefixed(carved), error))
        << "carved file missing (probed WITH the \\\\?\\ prefix): " << carved.string();
    EXPECT_EQ(std::filesystem::file_size(prefixed(carved), error), std::uintmax_t{44});
}

#endif

TEST_F(extraction_framework_test, GzipBlamesTheDataForACorruptDeflateStream) {
    if(!zlib_backend_enabled()) {
        GTEST_SKIP() << "the zlib backend is off in this build";
    }
    const auto definition = internal_extractor_for("gzip");
    if(!definition.has_value()) {
        GTEST_SKIP() << "no internal gzip extractor in builtin_signatures()";
    }

    auto data = minimal_gzip();
    for(std::size_t index = 10; index < data.size(); ++index) {
        data[index] = 0xff;
    }

    binwalk::signature_result signature;
    signature.name = "gzip";
    signature.id = "gzip_corrupt_probe";
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());
    signature.confidence = binwalk::confidence_medium;

    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.gz", signature, *definition,
        (root_ / "out").string()
    );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::invalid_data)
        << "a stream that cannot be decoded is the data's fault";
}

TEST_F(extraction_framework_test, GzipReportsWriteErrorNotInvalidDataWhenTheOutputCannotBeWritten) {
    if(!zlib_backend_enabled()) {
        GTEST_SKIP() << "the zlib backend is off in this build";
    }
    const auto definition = internal_extractor_for("gzip");
    if(!definition.has_value()) {
        GTEST_SKIP() << "no internal gzip extractor in builtin_signatures()";
    }

    const auto data = minimal_gzip();
    const auto signature = scan_for(data, "gzip");
    ASSERT_TRUE(signature.has_value()) << "the gzip fixture is not recognised";

    const auto blocker = root_ / "blocker";
    {
        std::ofstream stream(blocker, std::ios::binary);
        stream << "not a directory";
    }
    std::error_code error;
    ASSERT_TRUE(std::filesystem::is_regular_file(blocker, error)) << error.message();

    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data), "fixture.gz", *signature, *definition,
        (blocker / "out").string()
    );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::write_error);
    EXPECT_NE(result.failure, binwalk::extraction_failure::invalid_data)
        << "a filesystem problem must not be blamed on the firmware";
}

TEST(ScannerShortSignatures, NeedAtLeastOneByteBeyondTheirMagic) {

    const std::vector<std::uint8_t> full{0x1f, 0x9d, 0x90, 0x41, 0x42};
    const binwalk::scanner scanner;

    for(std::size_t length = 2; length <= 3; ++length) {
        const auto results = scanner.scan(binwalk::byte_view(full.data(), length));
        EXPECT_EQ(find_in_file_map(results, "compressd"), nullptr)
            << "buffer length " << length << " is not longer than the 3-byte magic, "
               "so it must not be detected";
    }

    for(std::size_t length = 4; length <= 5; ++length) {
        const auto results = scanner.scan(binwalk::byte_view(full.data(), length));
        const auto* found = find_in_file_map(results, "compressd");
        ASSERT_NE(found, nullptr) << "buffer length " << length
                                  << " has a byte past the magic and must be detected";
        EXPECT_EQ(found->offset, std::uint64_t{0}) << "buffer length " << length;
        EXPECT_EQ(found->size, static_cast<std::uint64_t>(length))
            << "buffer length " << length;
    }
}

TEST(ScannerShortSignatures, DropResultsThatRunPastTheEndOfTheBuffer) {
    const std::vector<std::uint8_t> data{0x5b, 0x5d, 0, 0, 0, 0, 0, 0};

    const binwalk::scanner rejecting(
        {make_short_probe_signature("past_eof_probe", &past_eof_parser)}
    );
    const auto dropped = rejecting.scan(binwalk::byte_view(data));
    EXPECT_EQ(find_in_file_map(dropped, "past_eof_probe"), nullptr)
        << "a short-signature result running past EOF must be dropped, exactly as "
           "the Aho-Corasick path already drops it";

    const binwalk::scanner accepting(
        {make_short_probe_signature("in_range_probe", &in_range_parser)}
    );
    const auto kept = accepting.scan(binwalk::byte_view(data));
    const auto* found = find_in_file_map(kept, "in_range_probe");
    ASSERT_NE(found, nullptr)
        << "an in-range short-signature result must still survive the guard";
    EXPECT_EQ(found->offset, std::uint64_t{0});
    EXPECT_EQ(found->size, static_cast<std::uint64_t>(data.size()));
}

TEST_P(extraction_parity_test, DryRunMatchesRealExtractionAndWritesNothing) {
    const auto& fixture = GetParam();
    if(fixture.needs_zlib && !zlib_backend_enabled()) {
        GTEST_SKIP() << fixture.format << " needs the zlib backend, which is off in this build";
    }

    binwalk::extractor definition;
    binwalk::signature_result signature;
    const auto state = resolve_fixture(fixture, definition, signature);
    if(state == fixture_state::no_internal_extractor) {
        GTEST_SKIP() << "builtin_signatures() exposes no internal extractor for "
                     << fixture.format;
    }
    if(state == fixture_state::not_recognised) {
        if(fixture.proven) {
            FAIL() << "the known-good in-memory fixture for " << fixture.format
                   << " is no longer recognised by the scanner";
        }
        GTEST_SKIP() << "could not build an in-memory fixture the scanner accepts as "
                     << fixture.format;
    }

    const auto dry_directory = root_ / "dry";
    std::error_code error;
    std::filesystem::create_directories(dry_directory, error);
    ASSERT_FALSE(static_cast<bool>(error)) << error.message();
    ASSERT_EQ(count_entries(root_), std::size_t{1});

    const auto dry = binwalk::dry_run_extractor(
        definition, binwalk::byte_view(fixture.data), signature
    );

    EXPECT_TRUE(dry.success) << "dry run of " << fixture.format
                             << " failed with failure code " << static_cast<int>(dry.failure);
    ASSERT_TRUE(dry.size.has_value()) << "a successful dry run must report the true total size";
    EXPECT_EQ(count_entries(dry_directory), std::size_t{0}) << "the dry run wrote to disk";
    EXPECT_EQ(count_entries(root_), std::size_t{1}) << "the dry run created something on disk";

    const auto output_root = root_ / "out";
    const auto real = binwalk::execute_extractor(
        binwalk::byte_view(fixture.data), "fixture.bin", signature, definition,
        output_root.string()
    );

    EXPECT_TRUE(real.success) << "real extraction of " << fixture.format
                              << " failed with failure code " << static_cast<int>(real.failure);
    EXPECT_EQ(real.failure, binwalk::extraction_failure::none);
    ASSERT_TRUE(real.size.has_value());
    EXPECT_EQ(*dry.size, *real.size) << "the dry run and the real extraction disagree on size";
    EXPECT_GT(count_entries(output_root), std::size_t{0})
        << "a successful real extraction wrote nothing";
    EXPECT_EQ(count_entries(dry_directory), std::size_t{0});
}

TEST_P(extraction_parity_test, DryRunRejectsTruncatedData) {
    const auto& fixture = GetParam();
    if(fixture.needs_zlib && !zlib_backend_enabled()) {
        GTEST_SKIP() << fixture.format << " needs the zlib backend, which is off in this build";
    }

    binwalk::extractor definition;
    binwalk::signature_result signature;
    const auto state = resolve_fixture(fixture, definition, signature);
    if(state == fixture_state::no_internal_extractor) {
        GTEST_SKIP() << "builtin_signatures() exposes no internal extractor for "
                     << fixture.format;
    }
    if(state == fixture_state::not_recognised) {
        if(fixture.proven) {
            FAIL() << "the known-good in-memory fixture for " << fixture.format
                   << " is no longer recognised by the scanner";
        }
        GTEST_SKIP() << "could not build an in-memory fixture the scanner accepts as "
                     << fixture.format;
    }

    const auto truncated = binwalk::byte_view(fixture.data).subview(0, 3);
    ASSERT_EQ(truncated.size(), std::size_t{3});

    const auto dry = binwalk::dry_run_extractor(definition, truncated, signature);

    EXPECT_FALSE(dry.success) << "the dry run of " << fixture.format
                              << " accepted a 3-byte truncation of a "
                              << signature.size << "-byte signature";
    EXPECT_EQ(count_entries(root_), std::size_t{0}) << "a failed dry run wrote to disk";
}

INSTANTIATE_TEST_SUITE_P(
    BuiltinInternalExtractors,
    extraction_parity_test,
    ::testing::ValuesIn(parity_fixtures()),
    [](const ::testing::TestParamInfo<parity_fixture>& information) {
        return std::string(information.param.format);
    }
);
