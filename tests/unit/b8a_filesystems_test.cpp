
#include "../../lib/src/formats/b8a_filesystems.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
namespace {

using binwalk::byte_view;
using binwalk::confidence_high;
using binwalk::confidence_medium;
using binwalk::signature;
using binwalk::signature_result;

using bytes = std::vector<std::uint8_t>;

const std::array<std::string, 4>& batch_names() {
    static const std::array<std::string, 4> names{
        "cramfs", "romfs", "android_sparse", "dtb"
    };
    return names;
}

const std::vector<signature>& batch_signatures() {
    static const std::vector<signature> value = binwalk::formats::b8a_filesystems_signatures();
    return value;
}

const signature* signature_named(const std::string& name) {
    for(const auto& value : batch_signatures()) {
        if(value.name == name) {
            return &value;
        }
    }
    return nullptr;
}

enum class tier { low, medium, high };

void expect_tier(std::uint8_t confidence, tier expected, const std::string& what) {
    switch(expected) {
    case tier::low:
        EXPECT_LT(confidence, confidence_medium) << what << ": oracle reports the LOW tier";
        break;
    case tier::medium:
        EXPECT_GE(confidence, confidence_medium)
            << what << ": oracle reports at least the MEDIUM tier";
        EXPECT_LT(confidence, confidence_high)
            << what << ": oracle reports MEDIUM, not HIGH -- the tier boundary is "
            << "what makes this a distinguishable result";
        break;
    case tier::high:
        EXPECT_GE(confidence, confidence_high) << what << ": oracle reports the HIGH tier";
        break;
    }
}

struct fixture_location {
    std::filesystem::path directory;
    std::string searched;
};

fixture_location locate_fixtures() {
    fixture_location location;
    std::filesystem::path directory = std::filesystem::current_path();
    for(int depth = 0; depth < 10; ++depth) {
        const auto candidate = directory / "tests" / "fixtures";
        location.searched += "  " + candidate.string() + "\n";
        std::error_code error;
        if(std::filesystem::is_directory(candidate, error)) {
            location.directory = candidate;
            return location;
        }
        const auto parent = directory.parent_path();
        if(parent.empty() || parent == directory) {
            break;
        }
        directory = parent;
    }
    return location;
}

const fixture_location& fixtures() {
    static const fixture_location location = locate_fixtures();
    return location;
}

bytes load_fixture(const std::string& name) {
    if(fixtures().directory.empty()) {
        return {};
    }
    std::ifstream stream(fixtures().directory / name, std::ios::binary);
    if(!stream) {
        return {};
    }
    return bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

#define BINWALK_LOAD_FIXTURE(variable, file)                                             \
    const bytes variable = load_fixture(file);                                           \
    ASSERT_FALSE((variable).empty())                                                     \
        << "could not read tests/fixtures/" << (file) << ". Directories searched:\n"      \
        << fixtures().searched

void put_u16le(bytes& target, std::uint16_t value) {
    target.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    target.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
}

void put_u32le(bytes& target, std::uint32_t value) {
    for(unsigned shift = 0; shift < 32U; shift += 8U) {
        target.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

void patch_u32le(bytes& target, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        target.at(offset + index) =
            static_cast<std::uint8_t>((value >> (static_cast<unsigned>(index) * 8U)) & 0xFFU);
    }
}

void patch_u32be(bytes& target, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        const unsigned shift = static_cast<unsigned>(3 - index) * 8U;
        target.at(offset + index) = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

bytes concat(const bytes& first, const bytes& second) {
    bytes joined = first;
    joined.insert(joined.end(), second.begin(), second.end());
    return joined;
}

bytes at_offset(const bytes& payload, std::size_t padding) {
    bytes data(padding, 0x00);
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

std::string as_text(const bytes& data) {
    return std::string(data.begin(), data.end());
}

bool contains_text(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

std::optional<signature_result> parse_at(
    const std::string& name,
    const bytes& data,
    std::size_t offset
) {
    const auto* value = signature_named(name);
    if(value == nullptr || value->parser == nullptr) {
        return std::nullopt;
    }
    return value->parser(byte_view(data), offset);
}

std::vector<signature_result> scan_batch(const bytes& data) {
    const binwalk::scanner scanner(batch_signatures());
    return scanner.scan(byte_view(data));
}

std::vector<signature_result> scan_only(const bytes& data, const std::string& name) {
    binwalk::scan_options options;
    options.include = {name};
    const binwalk::scanner scanner(batch_signatures(), options);
    return scanner.scan(byte_view(data));
}

void expect_no_result_named(
    const bytes& data,
    const std::string& name,
    const std::string& why
) {
    const auto started = std::chrono::steady_clock::now();
    const auto results = scan_batch(data);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    for(const auto& value : results) {
        EXPECT_NE(value.name, name)
            << "scan() reported a " << name << " result for " << why
            << ". A required REJECTION is as strict as a required detection "
            << "(policy).";
    }
    EXPECT_LT(elapsed, std::chrono::seconds(20))
        << "scan() over " << why << " did not return promptly";
}

void expect_rejected(
    const std::string& name,
    const bytes& data,
    std::size_t offset,
    const std::string& why
) {
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by this batch";
    ASSERT_NE(value->parser, nullptr) << name << " has no parser";
    const auto result = value->parser(byte_view(data), offset);
    EXPECT_FALSE(result.has_value())
        << name << " accepted " << why
        << ". A required REJECTION is as strict as a required detection "
        << "(policy).";
}

constexpr std::uint32_t sparse_magic = 0xED26FF3AU;
constexpr std::uint16_t chunk_raw = 0xCAC1U;
constexpr std::uint16_t chunk_fill = 0xCAC2U;
constexpr std::uint16_t chunk_dont_care = 0xCAC3U;
constexpr std::uint16_t chunk_crc = 0xCAC4U;

bytes sparse_header(
    std::uint32_t block_size,
    std::uint32_t block_count,
    std::uint32_t total_chunks
) {
    bytes header;
    put_u32le(header, sparse_magic);
    put_u16le(header, 1);
    put_u16le(header, 0);
    put_u16le(header, 28);
    put_u16le(header, 12);
    put_u32le(header, block_size);
    put_u32le(header, block_count);
    put_u32le(header, total_chunks);
    put_u32le(header, 0);
    return header;
}

bytes sparse_chunk(
    std::uint16_t type,
    std::uint32_t output_block_count,
    std::uint32_t total_size
) {
    bytes chunk;
    put_u16le(chunk, type);
    put_u16le(chunk, 0);
    put_u32le(chunk, output_block_count);
    put_u32le(chunk, total_size);
    return chunk;
}

void append(bytes& target, const bytes& more) {
    target.insert(target.end(), more.begin(), more.end());
}

std::vector<std::string> extracted_files_under(const std::filesystem::path& directory) {
    return binwalk::chroot::extracted_files(directory.string());
}

std::uint64_t bytes_written_under(const std::filesystem::path& directory) {
    std::uint64_t total = 0;
    for(const auto& path : extracted_files_under(directory)) {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if(!error) {
            total += static_cast<std::uint64_t>(size);
        }
    }
    return total;
}

bytes read_file(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    return bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

signature_result probe_signature(const std::string& name, std::uint64_t offset, std::uint64_t size) {
    signature_result value;
    value.offset = offset;
    value.size = size;
    value.name = name;
    value.confidence = confidence_high;
    return value;
}

class b8a_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b8a_";
        const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
        if(information != nullptr) {
            name += information->name();
        }
        root_ = base / name;
        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
        ASSERT_TRUE(extracted_files_under(root_).empty());
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    binwalk::extraction_result run_extractor(
        const std::string& name,
        const bytes& data,
        std::uint64_t offset,
        std::uint64_t size
    ) {
        const auto* value = signature_named(name);
        EXPECT_NE(value, nullptr);
        if(value == nullptr || !value->extractor_definition.has_value()) {
            return {};
        }
        const auto result = probe_signature(name, offset, size);
        return binwalk::execute_extractor(
            byte_view(data), name + "_input.bin", result, *value->extractor_definition,
            root_.string()
        );
    }

    void expect_rejected_writing_nothing(
        const std::string& name,
        const bytes& data,
        const std::string& why
    ) {
        SCOPED_TRACE(why);

        const binwalk::scanner scanner(batch_signatures());
        const auto started = std::chrono::steady_clock::now();
        const auto results = scanner.scan(byte_view(data));
        const auto scan_elapsed = std::chrono::steady_clock::now() - started;
        for(const auto& value : results) {
            EXPECT_NE(value.name, name)
                << "scan() reported a " << name << " result for " << why
                << " -- the required rejection did not happen";
        }

        EXPECT_LT(scan_elapsed, std::chrono::seconds(20))
            << "scan() over " << why << " took "
            << std::chrono::duration_cast<std::chrono::milliseconds>(scan_elapsed).count()
            << " ms -- an infinite loop or an unbounded allocation";

        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value());
        const auto probe = probe_signature(name, 0, data.size());
        const auto dry_started = std::chrono::steady_clock::now();
        const auto dry = binwalk::dry_run_extractor(
            *value->extractor_definition, byte_view(data), probe
        );
        const auto dry_elapsed = std::chrono::steady_clock::now() - dry_started;
        EXPECT_FALSE(dry.success) << "the dry run accepted " << why;
        EXPECT_LT(dry_elapsed, std::chrono::seconds(20))
            << "dry_run_extractor over " << why << " did not return promptly";
        EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
            << "a DRY RUN wrote bytes (policy rule 1)";

        const auto extraction = run_extractor(name, data, 0, data.size());
        EXPECT_FALSE(extraction.success) << "real extraction accepted " << why;
        EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
            << "the rejected extraction wrote "
            << bytes_written_under(root_) << " bytes for " << why;
        EXPECT_TRUE(extracted_files_under(root_).empty());
        if(!extraction.output_directory.empty()) {
            std::error_code error;
            const bool present = std::filesystem::exists(extraction.output_directory, error);
            if(present) {
                EXPECT_TRUE(extracted_files_under(extraction.output_directory).empty())
                    << "the failed extraction left output behind in "
                    << extraction.output_directory;
            }
        }
    }

    std::filesystem::path root_;
};

}

TEST(B8aRegistry, AllFourSignaturesArePresentExactlyOnce) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        std::size_t count = 0;
        for(const auto& value : registry) {
            if(value.name == name) {
                ++count;
            }
        }
        EXPECT_EQ(count, 1U)
            << "signature \"" << name << "\" must appear exactly once in the assembled "
            << "registry. A name absent from the frozen 111-entry table in "
            << "lib/src/builtin.cpp silently drops out of the registry and out of "
            << "--include/--exclude.";
    }
    EXPECT_EQ(batch_signatures().size(), batch_names().size())
        << "b8a_filesystems_signatures() must return exactly these four";
}

TEST(B8aRegistry, RegistrationFactsMatchUpstreamMagicRs) {

    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        EXPECT_FALSE(value->short_signature) << name << ": magic.rs says short = false";
        EXPECT_EQ(value->magic_offset, 0U) << name << ": magic.rs says magic_offset = 0";
        EXPECT_FALSE(value->always_display) << name << ": magic.rs says always_display = false";
        EXPECT_NE(value->parser, nullptr) << name << " has no parser";
        EXPECT_FALSE(value->magic.empty()) << name << " has no magic pattern";
    }
}

TEST(B8aRegistry, ExtractorKindsMatchTheContract) {
    struct expectation {
        const char* name;
        binwalk::extractor_type type;
        const char* command_or_name;
    };

    const std::array<expectation, 4> expected{{
        {"cramfs", binwalk::extractor_type::external, "7zz"},
        {"romfs", binwalk::extractor_type::internal, "romfs_built_in"},
        {"android_sparse", binwalk::extractor_type::internal, "android_sparse_built_in"},
        {"dtb", binwalk::extractor_type::internal, "dtb_built_in"}
    }};

    for(const auto& entry : expected) {
        const auto* value = signature_named(entry.name);
        ASSERT_NE(value, nullptr) << entry.name;
        ASSERT_TRUE(value->extractor_definition.has_value())
            << entry.name << " must carry an extractor definition";
        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, entry.type) << entry.name;
        if(entry.type == binwalk::extractor_type::internal) {
            EXPECT_NE(definition.internal, nullptr)
                << entry.name << " is internal but has a null function pointer";

            EXPECT_EQ(definition.name, entry.command_or_name) << entry.name;
        } else {
            EXPECT_EQ(definition.command, entry.command_or_name)
                << entry.name << ": upstream invokes the standalone 7-Zip CLI as `7zz`";
        }
    }
}

TEST(B8aRegistry, NoMagicPatternIsAPrefixOfAnother) {
    struct pattern {
        std::string owner;
        bytes magic;
    };
    std::vector<pattern> patterns;
    for(const auto& value : batch_signatures()) {
        for(const auto& magic : value.magic) {
            patterns.push_back({value.name, magic});
        }
    }
    ASSERT_EQ(patterns.size(), 4U)
        << "each of the four formats registers exactly one magic pattern";

    for(const auto& left : patterns) {
        for(const auto& right : patterns) {
            if(&left == &right) {
                continue;
            }
            const bool prefix =
                left.magic.size() <= right.magic.size()
                && std::equal(left.magic.begin(), left.magic.end(), right.magic.begin());
            EXPECT_FALSE(prefix)
                << "\"" << left.owner << "\"'s magic is now a PREFIX of \"" << right.owner
                << "\"'s. The two can therefore collide at one offset and the overlap "
                << "filter's equal-offset tie-break becomes reachable -- which this batch "
                << "has no test for, because until now it could not happen. Add one, or "
                << "revert the magic change.";
        }
    }
}

TEST(B8aFixtures, TheFixtureCorpusIsReachable) {
    ASSERT_FALSE(fixtures().directory.empty())
        << "tests/fixtures was not found. Every oracle-parity test in this file "
        << "depends on it, so this is a hard failure rather than a skip. "
        << "Directories searched:\n" << fixtures().searched;
    for(const char* name : {
            "cramfs.bin", "cramfs_be.bin", "cramfs_bad_crc.bin", "cramfs_file.bin",
            "romfs.bin", "romfs_tree.bin", "romfs_selfref.bin",
            "android_sparse.bin", "dtb.bin"}) {
        EXPECT_FALSE(load_fixture(name).empty()) << "missing tests/fixtures/" << name;
    }
}

TEST(B8aCramfs, LittleEndianFixtureReproducesTheGoldenFileMap) {
    BINWALK_LOAD_FIXTURE(data, "cramfs.bin");
    ASSERT_EQ(data.size(), 4096U);

    const auto result = parse_at("cramfs", data, 16);
    ASSERT_TRUE(result.has_value()) << "cramfs.bin must be detected";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 4096U) << "tests/golden/cramfs.json: size 4096";
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a CRC-valid cramfs image");

    EXPECT_TRUE(contains_text(result->description, "little endian"))
        << "description must report the endianness: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "2 files"))
        << "description must report the file count: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "4096"))
        << "description must report the total size: " << result->description;
}

TEST(B8aCramfs, AnImageContainingARealFileIsDetectedIdentically) {

    BINWALK_LOAD_FIXTURE(data, "cramfs_file.bin");
    ASSERT_EQ(data.size(), 4096U);
    const auto result = parse_at("cramfs", data, 16);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 4096U);
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a cramfs image containing a file");
    EXPECT_TRUE(contains_text(result->description, "little endian"));
    EXPECT_TRUE(contains_text(result->description, "2 files"));
}

TEST(B8aCramfs, BigEndianImageIsDetectedAndReportedAsBigEndian) {
    BINWALK_LOAD_FIXTURE(data, "cramfs_be.bin");
    const auto result = parse_at("cramfs", data, 16);
    ASSERT_TRUE(result.has_value()) << "a big-endian cramfs must be detected too";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 4096U);
    expect_tier(result->confidence, tier::high, "a CRC-valid big-endian cramfs image");
    EXPECT_TRUE(contains_text(result->description, "big endian"))
        << "the endianness is the whole point of this fixture: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "2 files"));
}

TEST(B8aCramfs, ChecksumErrorKeepsTheDetectionButDropsToTheMediumTier) {

    BINWALK_LOAD_FIXTURE(data, "cramfs_bad_crc.bin");
    const auto result = parse_at("cramfs", data, 16);
    ASSERT_TRUE(result.has_value())
        << "a CRC mismatch lowers confidence; it does not reject the image";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 4096U);
    expect_tier(result->confidence, tier::medium, "a cramfs image with a bad CRC");
    EXPECT_TRUE(contains_text(result->description, "checksum"))
        << "the description has to say the checksum failed: " << result->description;
}

TEST(B8aCramfs, TheParserRewindsSixteenBytesFromTheMagicMatch) {
    BINWALK_LOAD_FIXTURE(base, "cramfs.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{16}, std::size_t{1024}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(base, padding);
        const auto result = parse_at("cramfs", data, padding + 16);
        ASSERT_TRUE(result.has_value()) << "cramfs at offset " << padding;
        EXPECT_EQ(result->offset, padding)
            << "the reported offset is the HEADER, 16 bytes before the magic string";
        EXPECT_EQ(result->size, 4096U);
        expect_tier(result->confidence, tier::high, "a cramfs image at a non-zero offset");
    }
}

TEST(B8aCramfs, SignatureStringBeforeOffsetSixteenIsRejectedWithoutUnderflow) {

    const bytes magic{
        'C', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd', ' ',
        'R', 'O', 'M', 'F', 'S'
    };
    for(std::size_t match : {std::size_t{0}, std::size_t{8}, std::size_t{15}}) {
        SCOPED_TRACE(match);
        bytes data(match, 0x00);
        data.insert(data.end(), magic.begin(), magic.end());
        data.resize(match + 16 + 4096, 0x00);
        expect_rejected(
            "cramfs", data, match,
            "the cramfs signature string at offset " + std::to_string(match)
                + ", where the 16-byte rewind would underflow"
        );
    }
}

TEST(B8aCramfs, DeclaredSizeNotLargerThanTheHeaderIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "cramfs.bin");

    for(std::uint32_t size : {0U, 1U, 40U, 48U}) {
        SCOPED_TRACE(size);
        bytes data = base;
        patch_u32le(data, 4, size);
        expect_rejected(
            "cramfs", data, 16,
            "a cramfs header declaring size " + std::to_string(size)
                + ", which is not larger than the 48-byte header structure"
        );
    }
}

TEST(B8aCramfs, DeclaredSizeRunningPastTheEndOfDataIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "cramfs.bin");
    bytes data = base;
    patch_u32le(data, 4, 0x10000U);
    expect_rejected("cramfs", data, 16, "a cramfs image declaring 64 KiB inside a 4 KiB buffer");
}

TEST(B8aCramfs, TruncatedImageIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "cramfs.bin");
    for(std::size_t length : {std::size_t{16}, std::size_t{32}, std::size_t{47},
                              std::size_t{48}, std::size_t{2048}, std::size_t{4095}}) {
        SCOPED_TRACE(length);
        bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(length));
        expect_rejected(
            "cramfs", data, 16,
            "a cramfs image truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B8aCramfs, WrongMagicIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "cramfs.bin");
    for(std::uint32_t magic : {0U, 0x28CD3D44U, 0x453DCD29U, 0xFFFFFFFFU}) {
        SCOPED_TRACE(magic);
        bytes data = base;
        patch_u32le(data, 0, magic);
        expect_rejected(
            "cramfs", data, 16,
            "a cramfs signature string with a non-cramfs magic word"
        );
    }
}

TEST(B8aCramfs, EmptyAndShortBuffersAreRejectedWithoutReadingOutOfBounds) {
    for(std::size_t length = 0; length <= 64; ++length) {
        SCOPED_TRACE(length);
        const bytes data(length, 0x00);
        for(std::size_t offset : {std::size_t{0}, std::size_t{16}, length}) {
            const auto result = parse_at("cramfs", data, offset);
            EXPECT_FALSE(result.has_value());
        }
    }
}

TEST(B8aCramfsExternal, DryRunOfAnExternalExtractorIsUnsupported) {

    BINWALK_LOAD_FIXTURE(data, "cramfs.bin");
    const auto* value = signature_named("cramfs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("cramfs", 0, 4096)
    );
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);
}

TEST_F(b8a_extraction_test, CramfsExtractionRecoversTheFileWhenTheUtilityIsPresent) {
    BINWALK_LOAD_FIXTURE(data, "cramfs_file.bin");
    ASSERT_EQ(data.size(), 4096U);
    const auto* value = signature_named("cramfs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    if(!binwalk::external_utility_available(*value->extractor_definition)) {

        GTEST_SKIP() << "7zz is not installed; cramfs is an EXTERNAL extractor and "
                        "policy rule 5 requires the suite to pass on a "
                        "machine with no external utilities";
    }

    const auto result = run_extractor("cramfs", data, 0, 4096);
    EXPECT_NE(result.failure, binwalk::extraction_failure::utility_not_found)
        << "external_utility_available said 7zz is present";
    ASSERT_TRUE(result.success)
        << "7zz recovers hello.txt from this image at exit code 0. Upstream fails "
        << "only because of its whole-file symlink shortcut (D4); we carve, so we "
        << "must succeed. failure code = " << static_cast<int>(result.failure);

    const auto files = extracted_files_under(root_);
    ASSERT_EQ(files.size(), 1U) << "the image contains exactly one regular file";
    const auto content = read_file(files.front());
    EXPECT_EQ(content.size(), 72U);
    EXPECT_EQ(
        as_text(content),
        "cramfs fixture payload for binwalk-cpp, synthesised and never upstream.\n"
    );
}

TEST_F(b8a_extraction_test, CramfsExtractionOfAnEmptyImageIsNoOutputNotSuccess) {

    BINWALK_LOAD_FIXTURE(data, "cramfs.bin");
    const auto* value = signature_named("cramfs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    if(!binwalk::external_utility_available(*value->extractor_definition)) {

        GTEST_SKIP() << "7zz is not installed; policy rule 5 requires the "
                        "suite to pass on a machine with no external utilities";
    }

    const auto result = run_extractor("cramfs", data, 0, 4096);
    EXPECT_FALSE(result.success)
        << "7zz exits 0 on this image but writes no files, and policy "
        << "rule 4 requires BOTH a good exit code and non-empty output";
    EXPECT_EQ(result.failure, binwalk::extraction_failure::no_output)
        << "the utility ran and produced nothing: that is `no_output`, not "
        << "`utility_failed` (it did not reject the data) and not "
        << "`utility_not_found` (it is installed). failure code = "
        << static_cast<int>(result.failure);
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0});
}

TEST(B8aRomfs, FixtureReproducesTheGoldenFileMapAndSize) {
    BINWALK_LOAD_FIXTURE(data, "romfs.bin");
    ASSERT_EQ(data.size(), 240U);
    const auto result = parse_at("romfs", data, 0);
    ASSERT_TRUE(result.has_value()) << "romfs.bin must be detected";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 240U) << "tests/golden/romfs.json: size 240";
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a valid romfs image");
    EXPECT_TRUE(contains_text(result->description, "binwalkcpp"))
        << "the description must carry the volume name: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "240"))
        << "the description must carry the total size: " << result->description;
}

TEST(B8aRomfs, DetectedAtANonZeroOffset) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{16}, std::size_t{512}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(base, padding);
        const auto result = parse_at("romfs", data, padding);
        ASSERT_TRUE(result.has_value()) << "romfs at offset " << padding;
        EXPECT_EQ(result->offset, padding);
        EXPECT_EQ(result->size, 240U);
    }
}

TEST(B8aRomfs, HeaderChecksumMustBeValid) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    for(std::size_t index : {std::size_t{12}, std::size_t{13}, std::size_t{14}, std::size_t{15}}) {
        SCOPED_TRACE(index);
        bytes data = base;
        data.at(index) = static_cast<std::uint8_t>(data.at(index) ^ 0xFFU);
        expect_rejected("romfs", data, 0, "a romfs image whose header checksum does not sum to zero");
    }
}

TEST(B8aRomfs, DeclaredImageSizeNotLargerThanTheHeaderIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");

    for(std::uint32_t size : {0U, 8U, 16U}) {
        SCOPED_TRACE(size);
        bytes data = base;
        patch_u32be(data, 8, size);
        expect_rejected(
            "romfs", data, 0,
            "a romfs image declaring size " + std::to_string(size)
        );
    }
}

TEST(B8aRomfs, DeclaredImageSizeRunningPastTheEndOfDataIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    bytes data = base;
    patch_u32be(data, 8, 0x1000U);
    expect_rejected("romfs", data, 0, "a romfs image declaring 4 KiB inside a 240-byte buffer");
}

TEST(B8aRomfs, TruncatedImageIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    for(std::size_t length : {std::size_t{8}, std::size_t{15}, std::size_t{16},
                              std::size_t{32}, std::size_t{80}, std::size_t{239}}) {
        SCOPED_TRACE(length);
        bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(length));
        expect_rejected(
            "romfs", data, 0,
            "a romfs image truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B8aRomfs, WrongMagicIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    for(std::size_t index = 0; index < 8; ++index) {
        SCOPED_TRACE(index);
        bytes data = base;
        data.at(index) = static_cast<std::uint8_t>(data.at(index) ^ 0x01U);
        expect_rejected("romfs", data, 0, "a romfs image with a corrupted \"-rom1fs-\" magic");
    }
}

TEST(B8aRomfs, EmptyAndShortBuffersAreRejectedWithoutReadingOutOfBounds) {
    for(std::size_t length = 0; length <= 40; ++length) {
        SCOPED_TRACE(length);
        bytes data(length, 0x00);
        const bytes magic{'-', 'r', 'o', 'm', '1', 'f', 's', '-'};
        for(std::size_t index = 0; index < magic.size() && index < data.size(); ++index) {
            data[index] = magic[index];
        }
        const auto result = parse_at("romfs", data, 0);
        EXPECT_FALSE(result.has_value());
    }
}

TEST(B8aRomfs, SelfReferentialDirectoryIsRefusedPromptly) {
    BINWALK_LOAD_FIXTURE(data, "romfs_selfref.bin");
    const binwalk::scanner scanner(batch_signatures());
    const auto started = std::chrono::steady_clock::now();
    const auto results = scanner.scan(byte_view(data));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    for(const auto& value : results) {
        EXPECT_NE(value.name, "romfs")
            << "a romfs directory whose first-child offset points back at its own "
            << "header must be refused, not walked. Upstream's duplicate-offset "
            << "guard is per-call, so it recurses forever and the oracle dies with "
            << "a stack overflow (0xC00000FD) on this exact input.";
    }
    EXPECT_LT(elapsed, std::chrono::seconds(20))
        << "scan() over a self-referential romfs took "
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";

    const auto direct = parse_at("romfs", data, 0);
    EXPECT_FALSE(direct.has_value());
}

TEST(B8aRomfs, DryRunReportsSuccessAndTheTrueSize) {
    BINWALK_LOAD_FIXTURE(data, "romfs.bin");
    const auto* value = signature_named("romfs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("romfs", 0, 240)
    );
    EXPECT_TRUE(result.success) << "tests/golden/romfs.json records success:true";
    ASSERT_TRUE(result.size.has_value())
        << "policy rule 2: a successful dry run carries the true size";
    EXPECT_EQ(*result.size, 240U);
}

TEST_F(b8a_extraction_test, RomfsExtractsExactlyOneFileWithTheRightBytes) {
    BINWALK_LOAD_FIXTURE(data, "romfs.bin");
    const auto result = run_extractor("romfs", data, 0, 240);
    ASSERT_TRUE(result.success) << "tests/golden/romfs.json records success:true";
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 240U) << "tests/golden/romfs.json records size 240";
    EXPECT_EQ(result.extractor, "romfs_built_in");

    const auto files = extracted_files_under(root_);
    ASSERT_EQ(files.size(), 1U)
        << "exactly one non-empty regular file is expected from this image";
    const auto content = read_file(files.front());

    const bytes expected(data.begin() + 0x80, data.begin() + 0x80 + 104);
    EXPECT_EQ(content.size(), 104U) << "tests/golden/romfs.json: one 104-byte file";
    EXPECT_EQ(content, expected) << "the extracted bytes are not the file's bytes";
    EXPECT_TRUE(contains_text(as_text(content), "binwalk-cpp romfs fixture"));

    EXPECT_TRUE(contains_text(files.front(), "binwalkcpp"))
        << "extracted under: " << files.front();
}

TEST_F(b8a_extraction_test, RomfsWritesAnInertPlaceholderForAnEscapingSymlink) {

    BINWALK_LOAD_FIXTURE(data, "romfs_tree.bin");
    ASSERT_EQ(data.size(), 272U);

    const auto result = run_extractor("romfs", data, 0, 272);
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 272U);

    const auto files = extracted_files_under(root_);
    const std::string target = "../../../../etc/passwd";
    const std::string placeholder = "symlink " + target;

    bool found_placeholder = false;
    bool found_child = false;
    for(const auto& path : files) {
        const auto content = as_text(read_file(path));
        if(content == placeholder) {
            found_placeholder = true;
            std::error_code error;
            EXPECT_FALSE(std::filesystem::is_symlink(std::filesystem::symlink_status(path, error)))
                << "the symlink placeholder must be a REGULAR FILE, never a real link: "
                << path;
        }
        if(content == "child\n") {
            found_child = true;
        }
    }
    EXPECT_TRUE(found_placeholder)
        << "no extracted file had the exact content \"" << placeholder << "\". The "
        << "placeholder is 8 bytes of \"symlink \" (note the trailing space) followed "
        << "by the target verbatim, with no trailing newline.";
    EXPECT_TRUE(found_child)
        << "the regular file nested inside the RomFS sub-directory was not extracted";

    for(const auto& path : files) {
        EXPECT_TRUE(contains_text(path, root_.filename().string()))
            << "an extracted file landed outside the output root: " << path;
    }
}

TEST_F(b8a_extraction_test, RomfsSilentlySkipsDeviceNodesJustLikeUpstream) {

    BINWALK_LOAD_FIXTURE(data, "romfs_tree.bin");
    const auto result = run_extractor("romfs", data, 0, 272);
    ASSERT_TRUE(result.success);

    const auto files = extracted_files_under(root_);
    EXPECT_EQ(files.size(), 2U)
        << "expected exactly the symlink placeholder and the nested regular file. "
        << "A third file means the character-device entry was extracted, which "
        << "upstream's directory/symlink/regular filter makes impossible.";
    for(const auto& path : files) {
        const auto content = as_text(read_file(path));
        EXPECT_NE(content, "c 5 1")
            << "a device-node placeholder was written for a RomFS entry: " << path;
        EXPECT_NE(content, "fifo") << path;
        EXPECT_NE(content, "socket") << path;
    }
}

TEST_F(b8a_extraction_test, RomfsExtractionOfARejectedImageWritesNothing) {
    BINWALK_LOAD_FIXTURE(base, "romfs.bin");
    bytes data = base;
    patch_u32be(data, 8, 0x1000U);
    const auto result = run_extractor("romfs", data, 0, data.size());
    EXPECT_FALSE(result.success);
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0});
}

TEST_F(b8a_extraction_test, AndroidSparseFillChunkWithNoPayloadIsRejected) {

    bytes image = sparse_header(4096, 1, 1);
    append(image, sparse_chunk(chunk_fill, 1, 12));
    expect_rejected_writing_nothing(
        "android_sparse", image, "a FILL chunk with total_size == 12 (no fill value)"
    );
}

TEST(B8aAndroidSparse, FillChunkWithNoPayloadIsRejectedByTheParser) {
    bytes image = sparse_header(4096, 1, 1);
    append(image, sparse_chunk(chunk_fill, 1, 12));
    const auto started = std::chrono::steady_clock::now();
    const auto result = parse_at("android_sparse", image, 0);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_FALSE(result.has_value())
        << "a FILL chunk must carry exactly 4 bytes of fill value";
    EXPECT_LT(elapsed, std::chrono::seconds(20))
        << "the parser did not return -- this is the v3.1.1 infinite loop";
}

TEST_F(b8a_extraction_test, AndroidSparseFillChunkWithAWrongPayloadSizeIsRejected) {

    bytes image = sparse_header(4096, 1, 1);
    append(image, sparse_chunk(chunk_fill, 1, 20));
    image.resize(image.size() + 8, 0x00);
    expect_rejected_writing_nothing(
        "android_sparse", image, "a FILL chunk with total_size == 20 (8 bytes of fill)"
    );
}

TEST(B8aAndroidSparse, EveryFillPayloadSizeOtherThanFourIsRejected) {
    for(std::uint32_t payload : {0U, 1U, 2U, 3U, 5U, 8U, 16U, 4096U}) {
        SCOPED_TRACE(payload);
        bytes image = sparse_header(4096, 1, 1);
        append(image, sparse_chunk(chunk_fill, 1, 12 + payload));
        image.resize(image.size() + payload, 0xAB);
        expect_rejected(
            "android_sparse", image, 0,
            "a FILL chunk carrying " + std::to_string(payload) + " bytes of fill value"
        );
    }
}

TEST_F(b8a_extraction_test, AndroidSparseOverflowingTotalSizeIsRejectedHavingWrittenNothing) {

    constexpr std::uint32_t huge = 0xFFFFFFFCU;
    bytes image = sparse_header(huge, huge, 1);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    expect_rejected_writing_nothing(
        "android_sparse", image,
        "a header whose block_count * block_size overflows (u32::MAX - 3 squared)"
    );
}

TEST_F(b8a_extraction_test, AndroidSparseOversizedButNonOverflowingTotalIsRejected) {

    bytes image = sparse_header(65536, 0xFFFFFFFFU, 1);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    expect_rejected_writing_nothing(
        "android_sparse", image, "a 256 TB declared image (block_size 65536, block_count 2^32-1)"
    );
}

TEST_F(b8a_extraction_test, AndroidSparseChunkClaimingMoreBlocksThanTheHeaderIsRejected) {

    bytes image = sparse_header(4096, 1, 1);
    append(image, sparse_chunk(chunk_dont_care, 1000000000U, 12));
    expect_rejected_writing_nothing(
        "android_sparse", image, "a chunk claiming 1e9 blocks when the header declares 1"
    );
}

TEST_F(b8a_extraction_test, AndroidSparseRawChunkPayloadMustCoverExactlyItsBlocks) {

    bytes image = sparse_header(4, 16, 1);
    append(image, sparse_chunk(chunk_raw, 16, 12 + 4));
    image.resize(image.size() + 4, 0x00);
    expect_rejected_writing_nothing(
        "android_sparse", image, "a RAW chunk whose payload is not block_count * block_size"
    );
}

TEST(B8aAndroidSparse, CumulativeBlocksAcrossChunksMayNotExceedTheHeaderCount) {

    bytes image = sparse_header(4, 1, 2);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    expect_rejected(
        "android_sparse", image, 0,
        "two one-block chunks against a header declaring a single block"
    );
}

TEST_F(b8a_extraction_test, AndroidSparseChunkTotalSizeBelowTheHeaderSizeIsRejected) {

    for(std::uint32_t total_size : {0U, 1U, 11U}) {
        SCOPED_TRACE(total_size);
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, total_size));
        expect_rejected_writing_nothing(
            "android_sparse", image,
            "a chunk header with total_size == " + std::to_string(total_size)
                + " (below the 12-byte chunk header)"
        );
    }
}

TEST(B8aAndroidSparse, EveryChunkTotalSizeBelowTwelveIsRejectedPromptly) {
    for(std::uint32_t total_size = 0; total_size < 12; ++total_size) {
        SCOPED_TRACE(total_size);
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, total_size));
        const auto started = std::chrono::steady_clock::now();
        const auto result = parse_at("android_sparse", image, 0);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        EXPECT_FALSE(result.has_value())
            << "total_size " << total_size << " underflows total_size - 12";
        EXPECT_LT(elapsed, std::chrono::seconds(20));
    }
}

TEST(B8aAndroidSparse, FixtureIsDetectedWithTheOracleNumbers) {
    BINWALK_LOAD_FIXTURE(data, "android_sparse.bin");
    ASSERT_EQ(data.size(), 72U);
    const auto result = parse_at("android_sparse", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 72U);
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a valid android sparse image");
    EXPECT_TRUE(contains_text(result->description, "version 1.0")) << result->description;
    EXPECT_TRUE(contains_text(result->description, "28")) << result->description;
    EXPECT_TRUE(contains_text(result->description, "72")) << result->description;
}

TEST_F(b8a_extraction_test, AndroidSparseFixtureExtractsTheUnsparsedImage) {
    BINWALK_LOAD_FIXTURE(data, "android_sparse.bin");
    const auto result = run_extractor("android_sparse", data, 0, 72);
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 72U);
    EXPECT_EQ(result.extractor, "android_sparse_built_in");

    const auto files = extracted_files_under(root_);
    ASSERT_EQ(files.size(), 1U);

    const bytes expected{
        0x41, 0x42, 0x43, 0x44, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(read_file(files.front()), expected);

    EXPECT_TRUE(contains_text(files.front(), "unsparsed.img"))
        << "extracted as: " << files.front();
}

TEST_F(b8a_extraction_test, AndroidSparseMinimalImageExtractsOneZeroBlock) {

    bytes image = sparse_header(4, 1, 1);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    ASSERT_EQ(image.size(), 40U);

    const auto parsed = parse_at("android_sparse", image, 0);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->size, 40U);
    expect_tier(parsed->confidence, tier::high, "a minimal valid sparse image");

    const auto result = run_extractor("android_sparse", image, 0, 40);
    ASSERT_TRUE(result.success);
    const auto files = extracted_files_under(root_);
    ASSERT_EQ(files.size(), 1U);
    EXPECT_EQ(read_file(files.front()), bytes(4, 0x00));
}

TEST(B8aAndroidSparse, CrcChunksAreAcceptedAndContributeNoOutputBlocks) {

    bytes image = sparse_header(4, 1, 2);
    append(image, sparse_chunk(chunk_crc, 0, 16));
    image.resize(image.size() + 4, 0x00);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    ASSERT_EQ(image.size(), 56U);

    const auto result = parse_at("android_sparse", image, 0);
    ASSERT_TRUE(result.has_value()) << "a CRC chunk is a known chunk type";
    EXPECT_EQ(result->size, 56U);
}

TEST(B8aAndroidSparse, DetectedAtANonZeroOffset) {
    bytes image = sparse_header(4, 1, 1);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    for(std::size_t padding : {std::size_t{1}, std::size_t{32}, std::size_t{4096}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(image, padding);
        const auto result = parse_at("android_sparse", data, padding);
        ASSERT_TRUE(result.has_value()) << "a sparse image at offset " << padding;
        EXPECT_EQ(result->offset, padding);
        EXPECT_EQ(result->size, 40U) << "`size` is the image length, not the file length";
    }
}

TEST(B8aAndroidSparse, HeaderFieldsMustMatchTheSpec) {
    struct mutation {
        const char* what;
        std::size_t offset;
        std::uint32_t value;
        std::size_t width;
    };

    const std::array<mutation, 7> mutations{{
        {"major_version 2", 4, 2U, 2},
        {"major_version 0", 4, 0U, 2},
        {"minor_version 1", 6, 1U, 2},
        {"a file header size other than 28", 8, 32U, 2},
        {"a file header size of 0", 8, 0U, 2},
        {"a chunk header size other than 12", 10, 16U, 2},
        {"a block size that is not a multiple of 4", 12, 3U, 4}
    }};

    for(const auto& entry : mutations) {
        SCOPED_TRACE(entry.what);
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, 12));
        for(std::size_t index = 0; index < entry.width; ++index) {
            const unsigned shift = static_cast<unsigned>(index) * 8U;
            image.at(entry.offset + index) =
                static_cast<std::uint8_t>((entry.value >> shift) & 0xFFU);
        }
        expect_rejected("android_sparse", image, 0, std::string("a sparse image with ") + entry.what);
    }
}

TEST(B8aAndroidSparse, ACorruptedMagicProducesNoResultThroughTheScanner) {

    bytes image = sparse_header(4U, 1U, 1U);
    append(image, sparse_chunk(chunk_dont_care, 1U, 12U));
    for(std::uint32_t magic : {0U, 0xED26FF3BU, 0x3AFF26EDU, 0xFFFFFFFFU}) {
        SCOPED_TRACE(magic);
        bytes data = image;
        patch_u32le(data, 0, magic);
        expect_no_result_named(data, "android_sparse", "a sparse header with the wrong magic");
    }
}

TEST(B8aAndroidSparse, UnknownChunkTypesAreRejected) {
    for(std::uint16_t type : {std::uint16_t{0x0000}, std::uint16_t{0xCAC0},
                              std::uint16_t{0xCAC5}, std::uint16_t{0xDEAD}}) {
        SCOPED_TRACE(type);
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(type, 1, 12));
        expect_rejected("android_sparse", image, 0, "a chunk of an unknown type");
    }
}

TEST(B8aAndroidSparse, ANonZeroReservedFieldIsRejected) {
    bytes image = sparse_header(4, 1, 1);
    bytes chunk = sparse_chunk(chunk_dont_care, 1, 12);
    chunk.at(2) = 0x01;
    append(image, chunk);
    expect_rejected("android_sparse", image, 0, "a chunk header whose reserved field is non-zero");
}

TEST(B8aAndroidSparse, DontCareChunksMustCarryNoPayload) {
    for(std::uint32_t payload : {1U, 4U, 12U}) {
        SCOPED_TRACE(payload);
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, 12 + payload));
        image.resize(image.size() + payload, 0x00);
        expect_rejected(
            "android_sparse", image, 0,
            "a DONT_CARE chunk carrying " + std::to_string(payload) + " bytes of payload"
        );
    }
}

TEST(B8aAndroidSparse, CrcChunksMustCarryExactlyFourBytes) {
    for(std::uint32_t payload : {0U, 1U, 8U}) {
        SCOPED_TRACE(payload);
        bytes image = sparse_header(4, 1, 2);
        append(image, sparse_chunk(chunk_crc, 0, 12 + payload));
        image.resize(image.size() + payload, 0x00);
        append(image, sparse_chunk(chunk_dont_care, 1, 12));
        expect_rejected(
            "android_sparse", image, 0,
            "a CRC chunk carrying " + std::to_string(payload) + " bytes"
        );
    }
}

TEST(B8aAndroidSparse, TheProcessedChunkCountMustEqualTheDeclaredCount) {

    bytes image = sparse_header(4, 1, 2);
    append(image, sparse_chunk(chunk_dont_care, 1, 12));
    expect_rejected(
        "android_sparse", image, 0,
        "a sparse image declaring 2 chunks but carrying 1"
    );

    bytes zero_chunks = sparse_header(4, 1, 0);
    append(zero_chunks, sparse_chunk(chunk_dont_care, 1, 12));
    expect_rejected(
        "android_sparse", zero_chunks, 0,
        "a sparse image declaring 0 chunks but carrying 1"
    );
}

TEST(B8aAndroidSparse, RawChunkTruncatedPayloadProducesNoResult) {

    for(std::size_t present : {std::size_t{0}, std::size_t{1}, std::size_t{3}}) {
        SCOPED_TRACE(present);
        bytes image = sparse_header(4U, 1U, 1U);
        append(image, sparse_chunk(chunk_raw, 1U, 16U));
        image.resize(image.size() + present, 0x41);
        expect_no_result_named(
            image, "android_sparse", "a RAW chunk whose payload runs past the end of the file"
        );
    }

    bytes whole = sparse_header(4U, 1U, 1U);
    append(whole, sparse_chunk(chunk_raw, 1U, 16U));
    append(whole, bytes{'A', 'B', 'C', 'D'});
    const auto parsed = parse_at("android_sparse", whole, 0);
    ASSERT_TRUE(parsed.has_value()) << "a complete RAW chunk must still be accepted";
    EXPECT_EQ(parsed->size, 44U);
}

TEST(B8aAndroidSparse, HeaderOnlyAndShortBuffersAreRejected) {
    const bytes header = sparse_header(4, 1, 1);
    for(std::size_t length = 0; length <= header.size(); ++length) {
        SCOPED_TRACE(length);
        const bytes data(header.begin(), header.begin() + static_cast<std::ptrdiff_t>(length));
        const auto result = parse_at("android_sparse", data, 0);
        EXPECT_FALSE(result.has_value())
            << "a sparse file header with no chunk data at all must be rejected";
    }
}

TEST_F(b8a_extraction_test, AndroidSparseDryRunNeverWritesAnything) {

    BINWALK_LOAD_FIXTURE(data, "android_sparse.bin");
    const auto* value = signature_named("android_sparse");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("android_sparse", 0, 72)
    );
    EXPECT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 72U);
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
        << "the dry run wrote to disk";
}

TEST(B8aDtb, FixtureIsDetectedInTheMediumTier) {
    BINWALK_LOAD_FIXTURE(data, "dtb.bin");
    ASSERT_EQ(data.size(), 104U);
    const auto result = parse_at("dtb", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 104U);
    EXPECT_FALSE(result->extraction_declined);

    expect_tier(result->confidence, tier::medium, "a valid device tree blob");
    EXPECT_TRUE(contains_text(result->description, "version: 17")) << result->description;
    EXPECT_TRUE(contains_text(result->description, "CPU ID: 0")) << result->description;
    EXPECT_TRUE(contains_text(result->description, "104")) << result->description;
}

TEST(B8aDtb, DetectedAtANonZeroOffset) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{8}, std::size_t{256}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(base, padding);
        const auto result = parse_at("dtb", data, padding);
        ASSERT_TRUE(result.has_value()) << "a dtb at offset " << padding;
        EXPECT_EQ(result->offset, padding);
        EXPECT_EQ(result->size, 104U);
    }
}

TEST(B8aDtb, VersionMustBeSeventeenAndCompatibleVersionSixteen) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    for(std::uint32_t version : {0U, 16U, 18U, 0xFFFFFFFFU}) {
        SCOPED_TRACE(version);
        bytes data = base;
        patch_u32be(data, 20, version);
        expect_rejected("dtb", data, 0, "a dtb declaring version " + std::to_string(version));
    }
    for(std::uint32_t compatible : {0U, 15U, 17U}) {
        SCOPED_TRACE(compatible);
        bytes data = base;
        patch_u32be(data, 24, compatible);
        expect_rejected(
            "dtb", data, 0,
            "a dtb declaring min_compatible_version " + std::to_string(compatible)
        );
    }
}

TEST(B8aDtb, EveryDeclaredOffsetMustStartAfterTheFortyByteHeader) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    struct field {
        const char* what;
        std::size_t offset;
    };
    const std::array<field, 3> fields{{
        {"dt_struct_offset", 8},
        {"dt_strings_offset", 12},
        {"mem_reservation_block_offset", 16}
    }};
    for(const auto& entry : fields) {
        for(std::uint32_t value : {0U, 8U, 32U}) {
            SCOPED_TRACE(std::string(entry.what) + " = " + std::to_string(value));
            bytes data = base;
            patch_u32be(data, entry.offset, value);
            expect_rejected(
                "dtb", data, 0,
                std::string(entry.what) + " pointing inside the 40-byte header"
            );
        }
    }
}

TEST(B8aDtb, TheMemoryReservationBlockMustBeEightByteAligned) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    for(std::uint32_t offset : {41U, 42U, 44U, 47U}) {
        SCOPED_TRACE(offset);
        bytes data = base;
        patch_u32be(data, 16, offset);
        expect_rejected(
            "dtb", data, 0,
            "a mem_reservation_block_offset of " + std::to_string(offset)
                + ", which is not 8-byte aligned"
        );
    }
}

TEST(B8aDtb, BlocksRunningPastTheEndOfDataAreRejected) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    {
        bytes data = base;
        patch_u32be(data, 32, 0x1000U);
        expect_rejected("dtb", data, 0, "a dtb whose strings block runs past EOF");
    }
    {
        bytes data = base;
        patch_u32be(data, 36, 0x1000U);
        expect_rejected("dtb", data, 0, "a dtb whose struct block runs past EOF");
    }
    {
        bytes data = base;
        patch_u32be(data, 12, 0xFFFFFF00U);
        expect_rejected("dtb", data, 0, "a dtb whose strings offset is absurd");
    }
}

TEST(B8aDtb, TruncatedImageIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    for(std::size_t length : {std::size_t{4}, std::size_t{16}, std::size_t{39},
                              std::size_t{40}, std::size_t{64}, std::size_t{91}}) {
        SCOPED_TRACE(length);
        const bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(length));
        expect_rejected(
            "dtb", data, 0,
            "a dtb truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B8aDtb, ACorruptedMagicProducesNoResultThroughTheScanner) {

    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    for(std::uint32_t magic : {0U, 0xD00DFEECU, 0xD00DFEEEU, 0xEDFE0DD0U}) {
        SCOPED_TRACE(magic);
        bytes data = base;
        patch_u32be(data, 0, magic);
        expect_no_result_named(data, "dtb", "a dtb header with the wrong magic word");
    }
}

TEST(B8aDtb, EmptyAndShortBuffersAreRejectedWithoutReadingOutOfBounds) {
    for(std::size_t length = 0; length <= 48; ++length) {
        SCOPED_TRACE(length);
        bytes data(length, 0x00);
        const bytes magic{0xD0, 0x0D, 0xFE, 0xED};
        for(std::size_t index = 0; index < magic.size() && index < data.size(); ++index) {
            data[index] = magic[index];
        }
        const auto result = parse_at("dtb", data, 0);
        EXPECT_FALSE(result.has_value());
    }
}

TEST(B8aDtb, ATotalSizeOfZeroIsReportedVerbatimByTheParser) {
    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    bytes data = base;
    patch_u32be(data, 4, 0);
    const auto result = parse_at("dtb", data, 0);
    ASSERT_TRUE(result.has_value())
        << "total_size is not range-checked by dtb_parser; only the block bounds are";
    EXPECT_EQ(result->size, 0U)
        << "the PARSER reports 0. Extending it to a real span is the scanner's "
        << "zero-size fill, which a parser-level test cannot see (policy).";
    expect_tier(result->confidence, tier::medium, "a dtb declaring total_size 0");
}

TEST_F(b8a_extraction_test, DtbExtractsEachPropertyAsAFile) {
    BINWALK_LOAD_FIXTURE(data, "dtb.bin");
    const auto result = run_extractor("dtb", data, 0, 104);
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 104U);
    EXPECT_EQ(result.extractor, "dtb_built_in");

    const auto files = extracted_files_under(root_);
    ASSERT_EQ(files.size(), 1U) << "the blob carries exactly one property";

    const bytes expected{'t', 'e', 's', 't', 0x00};
    EXPECT_EQ(read_file(files.front()), expected);
    EXPECT_TRUE(contains_text(files.front(), "compatible"))
        << "extracted as: " << files.front();
}

TEST(B8aDtb, DryRunReportsSuccessAndTheStructureSize) {
    BINWALK_LOAD_FIXTURE(data, "dtb.bin");
    const auto* value = signature_named("dtb");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("dtb", 0, 104)
    );
    EXPECT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, 104U);
}

TEST_F(b8a_extraction_test, DtbWithoutAnEndTokenStillDetectsButFailsToExtract) {

    BINWALK_LOAD_FIXTURE(base, "dtb.bin");
    bytes data = base;
    ASSERT_EQ(data.at(91), 0x09U) << "byte 91 is the low byte of the FDT_END token";
    data.at(91) = 0x04U;

    const auto parsed = parse_at("dtb", data, 0);
    ASSERT_TRUE(parsed.has_value())
        << "dtb detection does NOT depend on a successful extraction";
    EXPECT_EQ(parsed->offset, 0U);
    EXPECT_EQ(parsed->size, 104U);
    expect_tier(parsed->confidence, tier::medium, "a dtb with no FDT_END token");

    const auto result = run_extractor("dtb", data, 0, 104);
    EXPECT_FALSE(result.success) << "the struct block never reaches FDT_END";
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
        << "a failed dtb extraction must not leave partial output behind";
}

namespace {

bytes combined_image() {
    const bytes pad(64, 0x00);
    bytes data = pad;
    data = concat(data, load_fixture("android_sparse.bin"));
    data = concat(data, pad);
    data = concat(data, load_fixture("dtb.bin"));
    data = concat(data, pad);
    data = concat(data, load_fixture("romfs.bin"));
    data = concat(data, pad);
    data = concat(data, load_fixture("cramfs.bin"));
    data = concat(data, pad);
    return data;
}

}

TEST(B8aScanner, TheScannerStampsTheNameOnEveryResult) {

    const bytes data = combined_image();
    ASSERT_FALSE(data.empty());
    const auto results = scan_batch(data);

    struct expectation {
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::array<expectation, 4> expected{{
        {"android_sparse", 64, 72},
        {"dtb", 200, 104},
        {"romfs", 368, 240},
        {"cramfs", 672, 4096}
    }};

    ASSERT_EQ(results.size(), expected.size())
        << "expected exactly one result per fixture in the combined image";
    for(std::size_t index = 0; index < expected.size(); ++index) {
        SCOPED_TRACE(expected[index].name);
        EXPECT_EQ(results[index].name, expected[index].name)
            << "scanner::populate() must stamp the registry name onto the result";
        EXPECT_EQ(results[index].offset, expected[index].offset);
        EXPECT_EQ(results[index].size, expected[index].size);
        EXPECT_FALSE(results[index].extraction_declined);
    }
}

TEST(B8aScanner, EveryResultGetsANonEmptyUniqueId) {
    const bytes data = combined_image();
    ASSERT_FALSE(data.empty());
    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 4U);

    std::vector<std::string> ids;
    for(const auto& value : results) {
        EXPECT_FALSE(value.id.empty())
            << "`id` is stamped by scanner::populate(); a parser leaves it empty";
        ids.push_back(value.id);
    }
    std::sort(ids.begin(), ids.end());
    EXPECT_EQ(std::adjacent_find(ids.begin(), ids.end()), ids.end())
        << "the extractions map is keyed by id, so two results may not share one";
}

TEST(B8aScanner, AlwaysDisplayIsFalseForAllFour) {

    const bytes data = combined_image();
    ASSERT_FALSE(data.empty());
    for(const auto& value : scan_batch(data)) {
        EXPECT_FALSE(value.always_display) << value.name;
    }
}

TEST(B8aScanner, IncludeAndExcludeFilterOnTheRegisteredName) {
    const bytes data = combined_image();
    ASSERT_FALSE(data.empty());

    for(const auto& name : batch_names()) {
        SCOPED_TRACE(name);
        const auto included = scan_only(data, name);
        ASSERT_EQ(included.size(), 1U) << "--include=" << name << " must select exactly one";
        EXPECT_EQ(included.front().name, name);

        binwalk::scan_options options;
        options.exclude = {name};
        const binwalk::scanner scanner(batch_signatures(), options);
        const auto excluded = scanner.scan(byte_view(data));
        EXPECT_EQ(excluded.size(), 3U);
        for(const auto& value : excluded) {
            EXPECT_NE(value.name, name) << "--exclude=" << name << " did not drop it";
        }
    }
}

TEST(B8aScanner, AZeroSizeResultIsExtendedToTheNextResult) {

    bytes dtb = load_fixture("dtb.bin");
    ASSERT_EQ(dtb.size(), 104U);
    patch_u32be(dtb, 4, 0U);
    const auto parsed = parse_at("dtb", dtb, 0);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size, 0U)
        << "the parser must report 0 for this input, or the fill is not what is "
        << "under test";

    {
        const auto results = scan_batch(dtb);
        ASSERT_EQ(results.size(), 1U);
        EXPECT_EQ(results.front().name, "dtb");
        EXPECT_EQ(results.front().size, 104U)
            << "with nothing after it, a zero-size result is filled to EOF";
    }
    {
        const bytes romfs = load_fixture("romfs.bin");
        ASSERT_EQ(romfs.size(), 240U);
        bytes data = concat(dtb, bytes(24, 0x00));
        data = concat(data, romfs);
        const auto results = scan_batch(data);
        ASSERT_EQ(results.size(), 2U);
        EXPECT_EQ(results[0].name, "dtb");
        EXPECT_EQ(results[0].size, 128U)
            << "the zero-size dtb must be filled up to the romfs result at 128";
        EXPECT_EQ(results[1].name, "romfs");
        EXPECT_EQ(results[1].offset, 128U);
        EXPECT_EQ(results[1].size, 240U);
    }
}

TEST(B8aScanner, RejectedImagesProduceNoResultThroughTheScanner) {

    struct hostile {
        const char* what;
        bytes data;
    };
    std::vector<hostile> cases;
    {
        bytes image = sparse_header(4096, 1, 1);
        append(image, sparse_chunk(chunk_fill, 1, 12));
        cases.push_back({"FILL chunk with no payload", image});
    }
    {
        bytes image = sparse_header(0xFFFFFFFCU, 0xFFFFFFFCU, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, 12));
        cases.push_back({"overflowing block_count * block_size", image});
    }
    {
        bytes image = sparse_header(65536, 0xFFFFFFFFU, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, 12));
        cases.push_back({"a 256 TB declared image", image});
    }
    {
        bytes image = sparse_header(4, 1, 1);
        append(image, sparse_chunk(chunk_dont_care, 1, 0));
        cases.push_back({"a chunk header with total_size 0", image});
    }
    {
        bytes selfref = load_fixture("romfs_selfref.bin");
        if(!selfref.empty()) {
            cases.push_back({"a self-referential romfs directory", selfref});
        }
    }

    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.what);
        const auto started = std::chrono::steady_clock::now();
        const auto results = scan_batch(entry.data);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        EXPECT_TRUE(results.empty())
            << "scan() reported " << results.size() << " result(s) for " << entry.what;
        EXPECT_LT(elapsed, std::chrono::seconds(20));
    }
}
