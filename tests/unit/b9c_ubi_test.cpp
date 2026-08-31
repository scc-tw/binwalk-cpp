
#include "../../lib/src/formats/b9c_ubi.hpp"

#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

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
#include <utility>
#include <vector>
namespace {

using binwalk::byte_view;
using binwalk::confidence_high;
using binwalk::confidence_medium;
using binwalk::extraction_failure;
using binwalk::signature;
using binwalk::signature_result;

using bytes = std::vector<std::uint8_t>;

const std::array<std::string, 3>& batch_names() {
    static const std::array<std::string, 3> names{"qnx_ifs", "ubi", "ubifs"};
    return names;
}

const std::vector<signature>& batch_signatures() {
    static const std::vector<signature> value = binwalk::formats::b9c_ubi_signatures();
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

enum class tier { low, high };

void expect_tier(std::uint8_t confidence, tier expected, const std::string& what) {
    if(expected == tier::low) {
        EXPECT_LT(confidence, confidence_medium)
            << what << ": the oracle reports the LOW tier, which is what keeps this "
            << "result from suppressing whatever else the scanner finds inside its span";
    } else {
        EXPECT_GE(confidence, confidence_high) << what << ": the oracle reports the HIGH tier";
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

#define BINWALK_LOAD_FIXTURE(variable, file)                                          \
    const bytes variable = load_fixture(file);                                        \
    ASSERT_FALSE((variable).empty())                                                  \
        << "could not read tests/fixtures/" << (file) << ". Directories searched:\n"   \
        << fixtures().searched

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

std::vector<signature_result> scan_batch(const bytes& data) {
    const binwalk::scanner scanner(batch_signatures());
    return scanner.scan(byte_view(data));
}

std::vector<signature_result> results_named(
    const std::vector<signature_result>& results,
    const std::string& name
) {
    std::vector<signature_result> matching;
    for(const auto& value : results) {
        if(value.name == name) {
            matching.push_back(value);
        }
    }
    return matching;
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

bool contains_text(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

bytes prefix_of(const bytes& data, std::size_t length) {
    const auto count = length < data.size() ? length : data.size();
    return bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(count));
}

bytes with_byte_set(const bytes& data, std::size_t offset, std::uint8_t value) {
    bytes copy = data;
    copy.at(offset) = value;
    return copy;
}

void expect_parser_survives(const std::string& name, const bytes& data, std::size_t offset) {
    const auto started = std::chrono::steady_clock::now();
    const auto result = parse_at(name, data, offset);
    (void)result;
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, std::chrono::seconds(10))
        << name << " did not return promptly at offset " << offset
        << " over " << data.size() << " bytes";
}

std::vector<std::filesystem::path> files_under(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> found;
    std::error_code error;
    if(!std::filesystem::exists(directory, error)) {
        return found;
    }
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        iterator != end;
        iterator.increment(error)) {
        if(error) {
            break;
        }
        std::error_code entry_error;
        if(std::filesystem::is_regular_file(iterator->path(), entry_error)) {
            found.push_back(iterator->path());
        }
    }
    return found;
}

std::uint64_t bytes_written_under(const std::filesystem::path& directory) {
    std::uint64_t total = 0;
    for(const auto& path : files_under(directory)) {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if(!error) {
            total += static_cast<std::uint64_t>(size);
        }
    }
    return total;
}

signature_result probe_signature(
    const std::string& name,
    std::uint64_t offset,
    std::uint64_t size,
    std::uint8_t confidence
) {
    signature_result value;
    value.offset = offset;
    value.size = size;
    value.name = name;
    value.confidence = confidence;
    return value;
}

class b9c_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b9c_";
        const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
        if(information != nullptr) {
            name += information->name();
        }
        root_ = base / name;
        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
        ASSERT_TRUE(files_under(root_).empty());
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    binwalk::extraction_result run_extractor(
        const std::string& name,
        const bytes& data,
        std::uint64_t offset,
        std::uint64_t size,
        std::uint8_t confidence
    ) {
        const auto* value = signature_named(name);
        EXPECT_NE(value, nullptr);
        if(value == nullptr || !value->extractor_definition.has_value()) {
            return {};
        }
        const auto result = probe_signature(name, offset, size, confidence);
        return binwalk::execute_extractor(
            byte_view(data), name + "_input.bin", result, *value->extractor_definition,
            root_.string()
        );
    }

    void expect_documented_capability_gap(const std::string& name, const bytes& data) {
        SCOPED_TRACE(name);
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name << " is not registered by this batch";
        ASSERT_TRUE(value->extractor_definition.has_value())
            << name << " must still DECLARE an extractor -- the gap is in what it can do";

        const auto probe = probe_signature(name, 0, data.size(), confidence_high);
        const auto dry = binwalk::dry_run_extractor(
            *value->extractor_definition, byte_view(data), probe
        );
        EXPECT_FALSE(dry.success) << name << " dry run claimed success";
        EXPECT_EQ(dry.failure, extraction_failure::unsupported)
            << name << ": upstream extracts this with a PYTHON tool "
            << "(ubireader_extract_images / ubireader_extract_files) and contract "
            << "section 7 forbids Python even as a subprocess, so section 7b pins the "
            << "observable result to `unsupported`. Any OTHER failure code would "
            << "misreport a missing capability as a runtime error.";
        EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
            << "a DRY RUN wrote bytes (policy rule 1)";

        const auto extraction = run_extractor(name, data, 0, data.size(), confidence_high);
        EXPECT_FALSE(extraction.success) << name << " real extraction claimed success";
        EXPECT_EQ(extraction.failure, extraction_failure::unsupported)
            << name << ": the real path must report the same documented gap as the dry run";
        EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
            << "an unsupported extraction wrote " << bytes_written_under(root_) << " bytes";
        EXPECT_TRUE(files_under(root_).empty());
    }

    std::filesystem::path root_;
};

}

TEST(B9cRegistry, BatchRegistersExactlyItsThreeSignatures) {
    ASSERT_EQ(batch_signatures().size(), batch_names().size());
    for(const auto& name : batch_names()) {
        EXPECT_NE(signature_named(name), nullptr)
            << name << " is missing from b9c_ubi_signatures()";
    }
}

TEST(B9cRegistry, EveryBatchSignatureHasAParser) {
    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        EXPECT_NE(value->parser, nullptr) << name << " has no parser";
    }
}

TEST(B9cRegistry, MagicPatternsAreTheDocumentedBytes) {
    const auto* qnx = signature_named("qnx_ifs");
    ASSERT_NE(qnx, nullptr);
    ASSERT_EQ(qnx->magic.size(), 1U);
    EXPECT_EQ(qnx->magic[0], bytes({0xEB, 0x7E, 0xFF, 0x00, 0x01, 0x00}));

    const auto* ubi = signature_named("ubi");
    ASSERT_NE(ubi, nullptr);
    ASSERT_EQ(ubi->magic.size(), 1U);
    EXPECT_EQ(ubi->magic[0], bytes({'U', 'B', 'I', '#', 0x01}));

    const auto* ubifs = signature_named("ubifs");
    ASSERT_NE(ubifs, nullptr);
    ASSERT_EQ(ubifs->magic.size(), 1U);
    EXPECT_EQ(ubifs->magic[0], bytes({0x31, 0x18, 0x10, 0x06}));
}

TEST(B9cRegistry, AllThreeAreLongSignaturesAtMagicOffsetZero) {
    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        EXPECT_FALSE(value->short_signature) << name << " is not a short signature upstream";
        EXPECT_EQ(value->magic_offset, 0U) << name;
        EXPECT_FALSE(value->always_display) << name;
    }
}

TEST(B9cExtractorDeclaration, QnxIfsDeclaresTheExternalDumpifsUtility) {

    const auto* value = signature_named("qnx_ifs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.command, "dumpifs");
    EXPECT_EQ(definition.extension, "ifs");
    EXPECT_EQ(definition.arguments, std::vector<std::string>({"-x", "%e"}));
    EXPECT_EQ(definition.exit_codes, std::vector<std::int32_t>({0}));
    EXPECT_FALSE(definition.do_not_recurse);
    EXPECT_EQ(definition.internal, nullptr) << "an external extractor has no internal entry point";
}

TEST(B9cExtractorDeclaration, TheQnxIfsPlaceholderIsItsOwnWholeArgument) {

    const auto* value = signature_named("qnx_ifs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    std::size_t placeholders = 0;
    for(const auto& argument : value->extractor_definition->arguments) {
        if(argument.find('%') == std::string::npos) {
            continue;
        }
        EXPECT_EQ(argument, "%e")
            << "argument \"" << argument << "\" splices a placeholder into a longer string";
        ++placeholders;
    }
    EXPECT_EQ(placeholders, 1U);
}

TEST(B9cExtractorDeclaration, UbiAndUbifsStillDeclareAnInternalExtractor) {

    for(const auto& name : {std::string("ubi"), std::string("ubifs")}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        ASSERT_TRUE(value->extractor_definition.has_value()) << name;
        EXPECT_EQ(value->extractor_definition->type, binwalk::extractor_type::internal) << name;
        EXPECT_NE(value->extractor_definition->internal, nullptr) << name;
    }
}

TEST_F(b9c_extraction_test, UbiExtractionReportsUnsupportedAndWritesNothing) {

    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    expect_documented_capability_gap("ubi", data);
}

TEST_F(b9c_extraction_test, UbifsExtractionReportsUnsupportedAndWritesNothing) {

    BINWALK_LOAD_FIXTURE(data, "ubifs.bin");
    expect_documented_capability_gap("ubifs", data);
}

TEST_F(b9c_extraction_test, TheUnsupportedStubsIgnoreTheirInputEntirely) {

    BINWALK_LOAD_FIXTURE(broken, "ubifs_bad_crc.bin");
    expect_documented_capability_gap("ubifs", broken);
}

TEST_F(b9c_extraction_test, ADryRunOfTheExternalQnxIfsExtractorIsUnsupported) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs.bin");
    const auto* value = signature_named("qnx_ifs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto probe = probe_signature("qnx_ifs", 0, data.size(), binwalk::confidence_low);
    const auto dry = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe
    );
    EXPECT_FALSE(dry.success);
    EXPECT_EQ(dry.failure, extraction_failure::unsupported);
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0});
}

TEST_F(b9c_extraction_test, QnxIfsExtractionWithoutDumpifsIsUtilityNotFound) {

    const auto* value = signature_named("qnx_ifs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    if(binwalk::external_utility_available(*value->extractor_definition)) {

        GTEST_SKIP() << "dumpifs is installed on this machine; the absent-utility "
                     << "branch is unobservable";
    }
    BINWALK_LOAD_FIXTURE(data, "qnx_ifs.bin");
    const auto extraction = run_extractor("qnx_ifs", data, 0, data.size(), binwalk::confidence_low);
    EXPECT_FALSE(extraction.success);
    EXPECT_EQ(extraction.failure, extraction_failure::utility_not_found)
        << "a missing utility must be distinguishable from a utility that ran and "
        << "rejected the data (policy rule 5)";
    EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0});
}

TEST(B9cQnxIfs, ImageIsDetectedAtOffsetZero) {
    BINWALK_LOAD_FIXTURE(data, "qnx_ifs.bin");
    const auto result = parse_at("qnx_ifs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 256U);
    expect_tier(result->confidence, tier::low, "qnx_ifs");
    EXPECT_TRUE(contains_text(result->description, "256"))
        << "the description must carry the total size: " << result->description;
}

TEST(B9cQnxIfs, ImageIsDetectedAtANonZeroOffset) {
    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_at_offset.bin");
    const auto result = parse_at("qnx_ifs", data, 1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1000U);
    EXPECT_EQ(result->size, 256U) << "`size` is the stored size, not the file length";
}

TEST(B9cQnxIfs, StoredSizeIsReportedRatherThanTheFileLength) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_distinct.bin");
    const auto result = parse_at("qnx_ifs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 200U);
}

TEST(B9cQnxIfs, AnImageDeclaringMoreThanRemainsIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_oversize.bin");
    expect_rejected("qnx_ifs", data, 0, "an image declaring more data than the file holds");
}

TEST(B9cQnxIfs, AnImageFillingItsFileExactlyIsDetected) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_exact.bin");
    ASSERT_EQ(data.size(), 128U);
    const auto result = parse_at("qnx_ifs", data, 0);
    ASSERT_TRUE(result.has_value()) << "an image exactly as long as its file is valid";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 128U);
}

TEST(B9cQnxIfs, AnImageFillingTheRemainderAfterAnOffsetExactlyIsDetected) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_offset_exact.bin");
    ASSERT_EQ(data.size(), 1256U);
    const auto result = parse_at("qnx_ifs", data, 1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1000U);
    EXPECT_EQ(result->size, 256U);
}

TEST(B9cQnxIfs, AStoredSizeOfZeroIsLeftAtZeroByTheParser) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_stored_zero.bin");
    const auto result = parse_at("qnx_ifs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 0U);
}

TEST(B9cQnxIfs, ATruncatedHeaderIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_truncated.bin");
    expect_rejected("qnx_ifs", data, 0, "a header cut short of its 64 bytes");
}

TEST(B9cQnxIfs, AnImageAtAnOffsetDeclaringMoreThanRemainsIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_offset_oversize.bin");
    expect_rejected("qnx_ifs", data, 1000, "an image at offset 1000 overrunning the file");
}

TEST(B9cQnxIfs, ANonZeroFlagsFieldIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "qnx_ifs_flags2_set.bin");
    expect_rejected("qnx_ifs", data, 0, "a header whose flags2 byte is not zero");
}

TEST(B9cQnxIfs, EveryReservedZeroFieldIsRejectedWhenSet) {
    const std::array<const char*, 4> reserved{
        "qnx_ifs_zero0_set.bin",
        "qnx_ifs_zero1_set.bin",
        "qnx_ifs_zero2_set.bin",
        "qnx_ifs_zero3_set.bin"
    };
    for(const auto* file : reserved) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        expect_rejected("qnx_ifs", data, 0, "a header with a reserved field set");
    }
}

TEST(B9cQnxIfs, EveryPrefixShorterThanTheHeaderIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs.bin");
    for(std::size_t length = 0; length < 64; ++length) {
        SCOPED_TRACE(length);
        const auto truncated = prefix_of(data, length);
        expect_parser_survives("qnx_ifs", truncated, 0);
        EXPECT_FALSE(parse_at("qnx_ifs", truncated, 0).has_value())
            << "a " << length << "-byte buffer cannot hold a 64-byte startup header";
    }
}

TEST(B9cQnxIfs, TheMagicAndVersionAreRechecked) {

    BINWALK_LOAD_FIXTURE(data, "qnx_ifs.bin");
    ASSERT_TRUE(parse_at("qnx_ifs", data, 0).has_value());
    expect_rejected("qnx_ifs", with_byte_set(data, 0, 0x00), 0, "a corrupted magic byte");
    expect_rejected("qnx_ifs", with_byte_set(data, 4, 0x02), 0, "a version other than 1");
}

TEST(B9cQnxIfs, EveryAcceptedImageIsReportedAtTheLowTier) {

    const std::array<const char*, 4> accepted{
        "qnx_ifs.bin", "qnx_ifs_exact.bin", "qnx_ifs_distinct.bin", "qnx_ifs_stored_zero.bin"
    };
    for(const auto* file : accepted) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        const auto result = parse_at("qnx_ifs", data, 0);
        ASSERT_TRUE(result.has_value());
        expect_tier(result->confidence, tier::low, file);
    }
}

TEST(B9cUbi, TwoEraseBlockImageIsDetected) {
    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    const auto result = parse_at("ubi", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 512U);
    expect_tier(result->confidence, tier::high, "ubi");
    EXPECT_TRUE(contains_text(result->description, "version: 1"))
        << "the description must carry the EC header version: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "512"))
        << "the description must carry the image size: " << result->description;
}

TEST(B9cUbi, ThreeEraseBlockImageIsDetected) {

    BINWALK_LOAD_FIXTURE(data, "ubi_3peb.bin");
    const auto result = parse_at("ubi", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 768U) << "3 erase blocks of 256 bytes";
}

TEST(B9cUbi, ImageIsDetectedAtANonZeroOffset) {

    BINWALK_LOAD_FIXTURE(data, "ubi_at_offset.bin");
    ASSERT_EQ(data.size(), 1512U);
    const auto result = parse_at("ubi", data, 1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1000U);
    EXPECT_EQ(result->size, 512U);
}

TEST(B9cUbi, ImageSizeIsBlockCountTimesEraseBlockSize) {

    BINWALK_LOAD_FIXTURE(data, "ubi_distinct.bin");
    const auto result = parse_at("ubi", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 1536U);
}

TEST(B9cUbi, EraseCountHeaderPaddingIsNotValidated) {

    BINWALK_LOAD_FIXTURE(data, "ubi_ec_padding_set.bin");
    const auto result = parse_at("ubi", data, 0);
    ASSERT_TRUE(result.has_value())
        << "the EC header's padding fields are parsed and ignored upstream";
    EXPECT_EQ(result->size, 1536U);
}

TEST(B9cUbi, AnEmbeddedUbifsSuperblockDoesNotChangeTheUbiSize) {

    BINWALK_LOAD_FIXTURE(data, "ubi_with_ubifs.bin");
    const auto result = parse_at("ubi", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 16384U);
}

TEST(B9cUbi, TiedEraseBlockSizesResolveToTheFirstSeenDeterministically) {

    BINWALK_LOAD_FIXTURE(data, "ubi_gap_tie.bin");
    ASSERT_EQ(data.size(), 1024U);
    for(int repeat = 0; repeat < 8; ++repeat) {
        SCOPED_TRACE(repeat);
        const auto result = parse_at("ubi", data, 0);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->size, 768U) << "3 blocks of the first-seen 256-byte gap";
    }
}

TEST(B9cUbi, ABadEraseCountHeaderCrcIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "ubi_bad_ec_crc.bin");
    expect_rejected("ubi", data, 0, "an erase-count header whose CRC does not match");
}

TEST(B9cUbi, OffsetsPointingBackIntoTheHeaderAreRejected) {

    BINWALK_LOAD_FIXTURE(vid, "ubi_vid_offset_too_small.bin");
    expect_rejected("ubi", vid, 0, "a volume-id header offset inside the EC header");
    BINWALK_LOAD_FIXTURE(payload, "ubi_data_offset_too_small.bin");
    expect_rejected("ubi", payload, 0, "a data offset inside the EC header");
}

TEST(B9cUbi, AnImageWithoutTwoValidVolumeHeadersIsRejected) {

    const std::array<const char*, 3> insufficient{
        "ubi_one_vid_header.bin", "ubi_single_peb.bin", "ubi_ec_only.bin"
    };
    for(const auto* file : insufficient) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        expect_rejected("ubi", data, 0, "an image with no measurable erase-block size");
    }
}

TEST(B9cUbi, ARejectedVolumeHeaderWidensTheGeometryPastTheEndOfTheFile) {

    const std::array<const char*, 4> padded{
        "ubi_vid_padding1.bin", "ubi_vid_padding2.bin",
        "ubi_vid_padding3.bin", "ubi_vid_padding4.bin"
    };
    for(const auto* file : padded) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        ASSERT_EQ(data.size(), 1536U);
        const auto result = parse_at("ubi", data, 0);
        ASSERT_TRUE(result.has_value())
            << "the parser does not clamp, so it still reports a size here";
        EXPECT_EQ(result->size, 2048U) << "2 surviving blocks of 1024 bytes";
        EXPECT_GT(result->size, static_cast<std::uint64_t>(data.size()))
            << "this is the case the scanner must drop";
    }
}

TEST(B9cUbi, EveryPrefixShorterThanTheEraseCountHeaderIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    for(std::size_t length = 0; length < 64; ++length) {
        SCOPED_TRACE(length);
        const auto truncated = prefix_of(data, length);
        expect_parser_survives("ubi", truncated, 0);
        EXPECT_FALSE(parse_at("ubi", truncated, 0).has_value())
            << "a " << length << "-byte buffer cannot hold a 64-byte erase-count header";
    }
}

TEST(B9cUbi, TheEraseBlockWalkSurvivesEveryPrefixOfAValidImage) {

    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    for(std::size_t length = 0; length <= data.size(); ++length) {
        expect_parser_survives("ubi", prefix_of(data, length), 0);
    }
}

TEST(B9cUbi, TheMagicIsRecheckedByTheParser) {

    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    ASSERT_TRUE(parse_at("ubi", data, 0).has_value());
    expect_rejected("ubi", with_byte_set(data, 0, 0x00), 0, "a corrupted EC header magic");
}

TEST(B9cUbi, EveryAcceptedImageIsReportedAtTheHighTier) {
    const std::array<const char*, 4> accepted{
        "ubi.bin", "ubi_3peb.bin", "ubi_distinct.bin", "ubi_with_ubifs.bin"
    };
    for(const auto* file : accepted) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        const auto result = parse_at("ubi", data, 0);
        ASSERT_TRUE(result.has_value());
        expect_tier(result->confidence, tier::high, file);
    }
}

TEST(B9cUbifs, SuperblockIsDetectedAtOffsetZero) {
    BINWALK_LOAD_FIXTURE(data, "ubifs.bin");
    const auto result = parse_at("ubifs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 4096U);
    expect_tier(result->confidence, tier::high, "ubifs");
    EXPECT_TRUE(contains_text(result->description, "4096"))
        << "the description must carry the total size: " << result->description;
}

TEST(B9cUbifs, SuperblockIsDetectedAtANonZeroOffset) {
    BINWALK_LOAD_FIXTURE(data, "ubifs_at_offset.bin");
    ASSERT_EQ(data.size(), 5096U);
    const auto result = parse_at("ubifs", data, 1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1000U);
    EXPECT_EQ(result->size, 4096U);
}

TEST(B9cUbifs, TotalSizeIsLebSizeTimesLebCount) {

    BINWALK_LOAD_FIXTURE(fits, "ubifs_fits.bin");
    const auto four_blocks = parse_at("ubifs", fits, 0);
    ASSERT_TRUE(four_blocks.has_value());
    EXPECT_EQ(four_blocks->size, 16384U);

    BINWALK_LOAD_FIXTURE(distinct, "ubifs_distinct.bin");
    const auto seven_blocks = parse_at("ubifs", distinct, 0);
    ASSERT_TRUE(seven_blocks.has_value());
    EXPECT_EQ(seven_blocks->size, 10752U);
    EXPECT_TRUE(contains_text(seven_blocks->description, "10752"))
        << "the description must carry the total size: " << seven_blocks->description;
}

TEST(B9cUbifs, ALebCountOfZeroLeavesTheSizeAtZero) {

    BINWALK_LOAD_FIXTURE(data, "ubifs_leb_zero.bin");
    const auto result = parse_at("ubifs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 0U);
}

TEST(B9cUbifs, ASizeLargerThanTheRemainingDataIsNotClampedByTheParser) {

    const std::array<std::pair<const char*, std::uint64_t>, 3> overruns{{
        std::pair<const char*, std::uint64_t>{"ubifs_oversize.bin", 16384U},
        std::pair<const char*, std::uint64_t>{"ubifs_one_short.bin", 16384U},
        std::pair<const char*, std::uint64_t>{"ubifs_distinct_short.bin", 10752U}
    }};
    for(const auto& entry : overruns) {
        SCOPED_TRACE(entry.first);
        BINWALK_LOAD_FIXTURE(data, entry.first);
        const auto result = parse_at("ubifs", data, 0);
        ASSERT_TRUE(result.has_value()) << "the parser does not clamp";
        EXPECT_EQ(result->size, entry.second);
        EXPECT_GT(result->size, static_cast<std::uint64_t>(data.size()))
            << "this is the case the scanner must drop";
    }
}

TEST(B9cUbifs, ANonSuperblockNodeTypeIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "ubifs_wrong_node_type.bin");
    expect_rejected("ubifs", data, 0, "a UBIFS node that is not a superblock");
}

TEST(B9cUbifs, ABadHeaderCrcIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "ubifs_bad_crc.bin");
    expect_rejected("ubifs", data, 0, "a superblock whose header CRC does not match");
}

TEST(B9cUbifs, AGroupTypeOutOfRangeIsRejected) {
    BINWALK_LOAD_FIXTURE(data, "ubifs_bad_group_type.bin");
    expect_rejected("ubifs", data, 0, "a superblock with an out-of-range group type");
}

TEST(B9cUbifs, NonZeroPaddingIsRejected) {
    const std::array<const char*, 2> padded{
        "ubifs_nonzero_padding1.bin", "ubifs_nonzero_padding2.bin"
    };
    for(const auto* file : padded) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        expect_rejected("ubifs", data, 0, "a superblock with non-zero padding");
    }
}

TEST(B9cUbifs, ASuperblockCutShortOfItsCrcWindowIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "ubifs_truncated.bin");
    ASSERT_EQ(data.size(), 4095U);
    expect_rejected("ubifs", data, 0, "a superblock one byte short of its CRC window");
}

TEST(B9cUbifs, AMutationInsideTheUnparsedTailIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "ubifs_tail_mutated.bin");
    expect_rejected("ubifs", data, 0, "a superblock whose unparsed tail was mutated");
}

TEST(B9cUbifs, EveryPrefixShorterThanTheCrcWindowIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "ubifs.bin");
    ASSERT_EQ(data.size(), 4096U);
    for(std::size_t length = 0; length < data.size(); ++length) {
        const auto truncated = prefix_of(data, length);
        EXPECT_FALSE(parse_at("ubifs", truncated, 0).has_value())
            << "a " << length << "-byte buffer cannot hold a 4096-byte superblock node";
    }
    EXPECT_TRUE(parse_at("ubifs", data, 0).has_value())
        << "the full 4096 bytes must still be accepted";
}

TEST(B9cUbifs, TheMagicIsRecheckedByTheParser) {

    BINWALK_LOAD_FIXTURE(data, "ubifs.bin");
    ASSERT_TRUE(parse_at("ubifs", data, 0).has_value());
    expect_rejected("ubifs", with_byte_set(data, 0, 0x00), 0, "a corrupted node magic");
}

TEST(B9cUbifs, EveryAcceptedSuperblockIsReportedAtTheHighTier) {
    const std::array<const char*, 4> accepted{
        "ubifs.bin", "ubifs_fits.bin", "ubifs_distinct.bin", "ubifs_leb_zero.bin"
    };
    for(const auto* file : accepted) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        const auto result = parse_at("ubifs", data, 0);
        ASSERT_TRUE(result.has_value());
        expect_tier(result->confidence, tier::high, file);
    }
}

TEST(B9cSafety, EveryParserRejectsAnEmptyView) {
    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        ASSERT_NE(value->parser, nullptr) << name;
        EXPECT_FALSE(value->parser(byte_view(), 0).has_value()) << name << " accepted an empty view";
    }
}

TEST(B9cSafety, EveryParserRejectsASingleByte) {
    const bytes one_byte{0x31};
    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        ASSERT_NE(value->parser, nullptr) << name;
        EXPECT_FALSE(value->parser(byte_view(one_byte), 0).has_value())
            << name << " accepted a one-byte input";
    }
}

TEST(B9cSafety, EveryParserSurvivesAnOffsetPastTheEndOfTheData) {
    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    for(const auto& name : batch_names()) {
        for(const std::size_t offset : {data.size(), data.size() + 1, data.size() + 4096}) {
            expect_parser_survives(name, data, offset);
            EXPECT_FALSE(parse_at(name, data, offset).has_value())
                << name << " reported a result starting past the end of the data";
        }
    }
}

TEST(B9cSafety, EveryParserSurvivesEveryOffsetIntoAValidImage) {

    const std::array<const char*, 2> corpus{"ubi.bin", "qnx_ifs.bin"};
    for(const auto* file : corpus) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        for(const auto& name : batch_names()) {
            for(std::size_t offset = 0; offset <= data.size(); ++offset) {
                expect_parser_survives(name, data, offset);
            }
        }
    }
}

TEST(B9cSafety, EveryParserSurvivesEveryPrefixOfEveryOtherFormatsImage) {

    const std::array<const char*, 3> corpus{"ubi.bin", "ubifs.bin", "qnx_ifs.bin"};
    for(const auto* file : corpus) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        for(std::size_t length = 0; length <= data.size(); length += 7) {
            const auto truncated = prefix_of(data, length);
            for(const auto& name : batch_names()) {
                expect_parser_survives(name, truncated, 0);
            }
        }
    }
}

TEST(B9cScanner, ScanStampsNameIdAndAlwaysDisplayOntoEveryResult) {

    BINWALK_LOAD_FIXTURE(data, "ubi.bin");
    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "ubi");
    EXPECT_FALSE(results[0].id.empty()) << "scan() assigns every result an id";
    EXPECT_FALSE(results[0].always_display) << "upstream registers all three with always_display false";
    EXPECT_FALSE(results[0].extraction_declined);
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, 512U);

    const auto direct = parse_at("ubi", data, 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_TRUE(direct->name.empty())
        << "a parser does not know its own name -- that is what makes this a "
        << "scanner-only assertion";
}

TEST(B9cScanner, EveryOracleDetectionIsReportedWithItsOffsetSizeAndName) {

    struct row {
        const char* file;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::array<row, 16> table{{
        {"ubi.bin", "ubi", 0U, 512U},
        {"ubi_3peb.bin", "ubi", 0U, 768U},
        {"ubi_at_offset.bin", "ubi", 1000U, 512U},
        {"ubi_distinct.bin", "ubi", 0U, 1536U},
        {"ubi_ec_padding_set.bin", "ubi", 0U, 1536U},
        {"ubi_with_ubifs.bin", "ubi", 0U, 16384U},
        {"ubifs.bin", "ubifs", 0U, 4096U},
        {"ubifs_at_offset.bin", "ubifs", 1000U, 4096U},
        {"ubifs_fits.bin", "ubifs", 0U, 16384U},
        {"ubifs_distinct.bin", "ubifs", 0U, 10752U},
        {"ubifs_leb_zero.bin", "ubifs", 0U, 4096U},
        {"qnx_ifs.bin", "qnx_ifs", 0U, 256U},
        {"qnx_ifs_at_offset.bin", "qnx_ifs", 1000U, 256U},
        {"qnx_ifs_exact.bin", "qnx_ifs", 0U, 128U},
        {"qnx_ifs_distinct.bin", "qnx_ifs", 0U, 200U},
        {"qnx_ifs_offset_exact.bin", "qnx_ifs", 1000U, 256U}
    }};
    for(const auto& entry : table) {
        SCOPED_TRACE(entry.file);
        BINWALK_LOAD_FIXTURE(data, entry.file);
        const auto results = scan_batch(data);
        ASSERT_EQ(results.size(), 1U) << "the oracle's file_map for this fixture has one entry";
        EXPECT_EQ(results[0].name, entry.name);
        EXPECT_EQ(results[0].offset, entry.offset);
        EXPECT_EQ(results[0].size, entry.size);
    }
}

TEST(B9cScanner, EveryOracleRejectionProducesAnEmptyFileMap) {

    const std::array<const char*, 28> rejected{
        "ubi_bad_ec_crc.bin", "ubi_vid_offset_too_small.bin", "ubi_data_offset_too_small.bin",
        "ubi_one_vid_header.bin", "ubi_single_peb.bin", "ubi_ec_only.bin",
        "ubi_vid_padding1.bin", "ubi_vid_padding2.bin", "ubi_vid_padding3.bin",
        "ubi_vid_padding4.bin",
        "ubifs_bad_crc.bin", "ubifs_wrong_node_type.bin", "ubifs_bad_group_type.bin",
        "ubifs_nonzero_padding1.bin", "ubifs_nonzero_padding2.bin", "ubifs_truncated.bin",
        "ubifs_tail_mutated.bin", "ubifs_oversize.bin", "ubifs_one_short.bin",
        "ubifs_distinct_short.bin",
        "qnx_ifs_flags2_set.bin", "qnx_ifs_zero0_set.bin", "qnx_ifs_zero1_set.bin",
        "qnx_ifs_zero2_set.bin", "qnx_ifs_zero3_set.bin", "qnx_ifs_truncated.bin",
        "qnx_ifs_oversize.bin", "qnx_ifs_offset_oversize.bin"
    };
    for(const auto* file : rejected) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        const auto results = scan_batch(data);
        EXPECT_TRUE(results.empty())
            << "the oracle reports an empty file_map for this fixture, but scan() "
            << "returned " << results.size() << " result(s), the first named \""
            << (results.empty() ? std::string() : results[0].name) << "\"";
    }
}

TEST(B9cScanner, AResultLongerThanTheDataRemainingIsDropped) {

    const std::array<const char*, 7> dropped{
        "ubifs_oversize.bin", "ubifs_one_short.bin", "ubifs_distinct_short.bin",
        "ubi_vid_padding1.bin", "ubi_vid_padding2.bin",
        "ubi_vid_padding3.bin", "ubi_vid_padding4.bin"
    };
    for(const auto* file : dropped) {
        SCOPED_TRACE(file);
        BINWALK_LOAD_FIXTURE(data, file);
        const auto results = scan_batch(data);
        EXPECT_TRUE(results.empty()) << "an over-long result must not survive the scan";
    }

    BINWALK_LOAD_FIXTURE(fits, "ubifs_fits.bin");
    const auto surviving = results_named(scan_batch(fits), "ubifs");
    ASSERT_EQ(surviving.size(), 1U) << "16384 bytes declared in a 16384-byte file is fine";
    EXPECT_EQ(surviving[0].size, 16384U);
}

TEST(B9cScanner, AHighConfidenceResultSuppressesWhatIsFoundInsideIt) {

    BINWALK_LOAD_FIXTURE(data, "ubi_with_ubifs.bin");
    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "ubi");
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, 16384U);
    EXPECT_TRUE(results_named(results, "ubifs").empty())
        << "the inner superblock must be suppressed by the enclosing UBI image";
}

TEST(B9cScanner, TwoNonOverlappingFormatsAreBothReported) {

    BINWALK_LOAD_FIXTURE(data, "ubifs_then_ubi.bin");
    ASSERT_EQ(data.size(), 4608U);
    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 2U);
    EXPECT_EQ(results[0].name, "ubifs");
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, 4096U);
    EXPECT_EQ(results[1].name, "ubi");
    EXPECT_EQ(results[1].offset, 4096U);
    EXPECT_EQ(results[1].size, 512U);
    EXPECT_NE(results[0].id, results[1].id) << "every result gets its own id";
}

TEST(B9cScanner, AZeroSizeResultIsFilledInByTheScanner) {

    BINWALK_LOAD_FIXTURE(ubifs, "ubifs_leb_zero.bin");
    const auto ubifs_direct = parse_at("ubifs", ubifs, 0);
    ASSERT_TRUE(ubifs_direct.has_value());
    ASSERT_EQ(ubifs_direct->size, 0U) << "the fill only exists because the parser returns 0";
    const auto ubifs_results = scan_batch(ubifs);
    ASSERT_EQ(ubifs_results.size(), 1U);
    EXPECT_EQ(ubifs_results[0].size, 4096U) << "extended to the end of the 4096-byte file";

    BINWALK_LOAD_FIXTURE(qnx, "qnx_ifs_stored_zero.bin");
    const auto qnx_direct = parse_at("qnx_ifs", qnx, 0);
    ASSERT_TRUE(qnx_direct.has_value());
    ASSERT_EQ(qnx_direct->size, 0U) << "the fill only exists because the parser returns 0";
    const auto qnx_results = scan_batch(qnx);
    ASSERT_EQ(qnx_results.size(), 1U);
    EXPECT_EQ(qnx_results[0].size, 256U) << "extended to the end of the 256-byte file";
}

TEST(B9cScanner, TiedEraseBlockSizesAreDeterministicThroughTheScanner) {

    BINWALK_LOAD_FIXTURE(data, "ubi_gap_tie.bin");
    for(int repeat = 0; repeat < 8; ++repeat) {
        SCOPED_TRACE(repeat);
        const auto results = scan_batch(data);
        ASSERT_EQ(results.size(), 1U);
        EXPECT_EQ(results[0].name, "ubi");
        EXPECT_EQ(results[0].offset, 0U);
        EXPECT_EQ(results[0].size, 768U);
    }
}

TEST(B9cScanner, ScanningAnEmptyOrTinyInputIsSafeAndEmpty) {
    for(const bytes& data : {bytes{}, bytes{0x31}, bytes{'U', 'B', 'I', '#', 0x01}}) {
        const auto results = scan_batch(data);
        EXPECT_TRUE(results.empty());
    }
    expect_no_result_named(bytes(4096, 0x00), "ubi", "4096 zero bytes");
}
