
#include "../../lib/src/formats/b9a_squashfs.hpp"

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
using binwalk::extractor;
using binwalk::extractor_type;
using binwalk::signature;
using binwalk::signature_result;

using bytes = std::vector<std::uint8_t>;

constexpr const char* squashfs_name = "squashfs";

const std::vector<signature>& batch_signatures() {
    static const std::vector<signature> value = binwalk::formats::b9a_squashfs_signatures();
    return value;
}

const signature* squashfs_signature() {
    for(const auto& value : batch_signatures()) {
        if(value.name == squashfs_name) {
            return &value;
        }
    }
    return nullptr;
}

void expect_high_tier(std::uint8_t confidence, const std::string& what) {
    EXPECT_GE(confidence, confidence_high)
        << what << ": the oracle reports confidence 250, the HIGH tier";
    EXPECT_GE(confidence, confidence_medium)
        << what << ": HIGH implies at least MEDIUM, which is what the overlap "
        << "filter and skip_contents branch on";
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

void poke_le(bytes& target, std::size_t offset, std::uint64_t value, std::size_t width) {
    for(std::size_t index = 0; index < width; ++index) {
        const std::size_t shift = index * 8U;
        target.at(offset + index) = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

void poke_be(bytes& target, std::size_t offset, std::uint64_t value, std::size_t width) {
    for(std::size_t index = 0; index < width; ++index) {
        const std::size_t shift = (width - 1U - index) * 8U;
        target.at(offset + index) = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

void poke(bytes& target, bool big_endian, std::size_t offset, std::uint64_t value, std::size_t width) {
    if(big_endian) {
        poke_be(target, offset, value, width);
    } else {
        poke_le(target, offset, value, width);
    }
}

constexpr std::uint32_t mtime_v4 = 0x672699BFU;
constexpr std::uint32_t mtime_v2 = 0x4993E763U;

struct v4_params {
    std::array<char, 4> magic{{'h', 's', 'q', 's'}};
    bool big_endian = false;
    std::size_t total = 4096;
    std::uint32_t inode_count = 2;
    std::uint32_t modification_time = mtime_v4;
    std::uint32_t block_size = 131072;
    std::uint32_t fragment_count = 0;
    std::uint16_t compression_id = 1;
    std::uint16_t block_log = 17;
    std::uint16_t flags = 0;
    std::uint16_t id_count = 0;
    std::uint16_t major_version = 4;
    std::uint16_t minor_version = 0;
    std::uint64_t root_inode_ref = 0;
    std::uint64_t image_size = 315;
    std::uint64_t uid_start = 307;
    std::uint64_t uid_entry = 301;
    bool write_uid_entry = true;
};

bytes build_v4(const v4_params& parameters) {
    bytes image(parameters.total, 0x00);
    const bool be = parameters.big_endian;
    for(std::size_t index = 0; index < 4; ++index) {
        image.at(index) = static_cast<std::uint8_t>(parameters.magic.at(index));
    }
    poke(image, be, 4, parameters.inode_count, 4);
    poke(image, be, 8, parameters.modification_time, 4);
    poke(image, be, 12, parameters.block_size, 4);
    poke(image, be, 16, parameters.fragment_count, 4);
    poke(image, be, 20, parameters.compression_id, 2);
    poke(image, be, 22, parameters.block_log, 2);
    poke(image, be, 24, parameters.flags, 2);
    poke(image, be, 26, parameters.id_count, 2);
    poke(image, be, 28, parameters.major_version, 2);
    poke(image, be, 30, parameters.minor_version, 2);
    poke(image, be, 32, parameters.root_inode_ref, 8);
    poke(image, be, 40, parameters.image_size, 8);
    poke(image, be, 48, parameters.uid_start, 8);
    if(parameters.write_uid_entry && parameters.uid_start + 8U <= parameters.total) {
        poke(image, be, static_cast<std::size_t>(parameters.uid_start), parameters.uid_entry, 8);
    }
    return image;
}

struct v123_params {
    std::array<char, 4> magic{{'s', 'q', 's', 'h'}};
    bool big_endian = true;
    std::size_t total = 4096;
    std::uint32_t inode_count = 431;
    std::uint32_t bytes_used_2 = 1024;
    std::uint32_t uid_start_2 = 900;
    std::uint32_t guid_start_2 = 0;
    std::uint32_t inode_table_start_2 = 0;
    std::uint32_t directory_table_start_2 = 0;
    std::uint16_t major_version = 2;
    std::uint16_t minor_version = 0;
    std::uint16_t block_size_1 = 0;
    std::uint16_t block_log = 16;
    std::uint8_t flags = 0;
    std::uint8_t uid_count = 0;
    std::uint8_t guid_count = 0;
    std::uint32_t modification_time = mtime_v2;
    std::uint64_t root_inode_ref = 0;
    std::uint32_t block_size = 65536;
    std::uint32_t fragment_entry_count = 0;
    std::uint32_t fragment_table_start_2 = 0;
    std::uint64_t image_size = 0;
    std::uint64_t uid_start = 0;
    std::uint64_t guid_start = 0;
    std::uint64_t inode_table_start = 0;
    std::uint64_t directory_table_start = 0;
    std::uint64_t fragment_table_start = 0;
    std::uint64_t lookup_table_start = 0;
    std::uint32_t uid_entry = 500;

    std::optional<std::uint64_t> uid_entry_at;
};

bytes build_v123(const v123_params& parameters) {
    bytes image(parameters.total, 0x00);
    const bool be = parameters.big_endian;
    for(std::size_t index = 0; index < 4; ++index) {
        image.at(index) = static_cast<std::uint8_t>(parameters.magic.at(index));
    }
    poke(image, be, 4, parameters.inode_count, 4);
    poke(image, be, 8, parameters.bytes_used_2, 4);
    poke(image, be, 12, parameters.uid_start_2, 4);
    poke(image, be, 16, parameters.guid_start_2, 4);
    poke(image, be, 20, parameters.inode_table_start_2, 4);
    poke(image, be, 24, parameters.directory_table_start_2, 4);
    poke(image, be, 28, parameters.major_version, 2);
    poke(image, be, 30, parameters.minor_version, 2);
    poke(image, be, 32, parameters.block_size_1, 2);
    poke(image, be, 34, parameters.block_log, 2);
    poke(image, be, 36, parameters.flags, 1);
    poke(image, be, 37, parameters.uid_count, 1);
    poke(image, be, 38, parameters.guid_count, 1);
    poke(image, be, 39, parameters.modification_time, 4);
    poke(image, be, 43, parameters.root_inode_ref, 8);
    poke(image, be, 51, parameters.block_size, 4);
    poke(image, be, 55, parameters.fragment_entry_count, 4);
    poke(image, be, 59, parameters.fragment_table_start_2, 4);
    poke(image, be, 63, parameters.image_size, 8);
    poke(image, be, 71, parameters.uid_start, 8);
    poke(image, be, 79, parameters.guid_start, 8);
    poke(image, be, 87, parameters.inode_table_start, 8);
    poke(image, be, 95, parameters.directory_table_start, 8);
    poke(image, be, 103, parameters.fragment_table_start, 8);
    poke(image, be, 111, parameters.lookup_table_start, 8);

    const std::uint64_t entry_at = parameters.uid_entry_at.has_value()
        ? *parameters.uid_entry_at
        : (parameters.major_version < 3
               ? static_cast<std::uint64_t>(parameters.uid_start_2)
               : parameters.uid_start);

    if(entry_at + 4U <= parameters.total) {
        poke(image, be, static_cast<std::size_t>(entry_at), parameters.uid_entry, 4);
    }
    return image;
}

bytes offset_padding(std::size_t length) {
    bytes padding(length, 0x00);
    for(std::size_t index = 0; index < padding.size(); ++index) {
        padding.at(index) = static_cast<std::uint8_t>((index * 7U + 0x5AU) & 0xFFU);
    }
    return padding;
}

bytes with_padding(const bytes& image, std::size_t length = 2048) {
    bytes data = offset_padding(length);
    data.insert(data.end(), image.begin(), image.end());
    return data;
}

std::optional<signature_result> parse_at(const bytes& data, std::size_t offset) {
    const auto* value = squashfs_signature();
    if(value == nullptr || value->parser == nullptr) {
        return std::nullopt;
    }
    return value->parser(byte_view(data), offset);
}

std::optional<signature_result> parse(const bytes& data) {
    return parse_at(data, 0);
}

void expect_rejected(const bytes& data, std::size_t offset, const std::string& why) {
    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr) << "squashfs is not registered by this batch";
    ASSERT_NE(value->parser, nullptr) << "squashfs has no parser";
    const auto result = value->parser(byte_view(data), offset);
    EXPECT_FALSE(result.has_value())
        << "squashfs accepted " << why
        << ". A required REJECTION is as strict as a required detection "
        << "(policy).";
}

bool contains_text(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

void expect_shared_extractor_shape(const extractor& definition, const std::string& what) {
    EXPECT_EQ(definition.type, extractor_type::external)
        << what << ": sasquatch is an external utility";
    EXPECT_EQ(definition.extension, "sqsh") << what;
    ASSERT_EQ(definition.exit_codes.size(), 2U) << what;
    EXPECT_EQ(definition.exit_codes.at(0), 0) << what;
    EXPECT_EQ(definition.exit_codes.at(1), 2)
        << what << ": exit code 2 is sasquatch's \"not running as root\" and "
        << "still counts as SUCCESS. Dropping it turns every non-root "
        << "extraction into a false failure.";
    EXPECT_FALSE(definition.do_not_recurse)
        << what << ": a squashfs image's contents are themselves scanned";
    EXPECT_TRUE(definition.name.empty()) << what << ": external definitions carry no name";
    EXPECT_EQ(definition.internal, nullptr) << what << ": external, so no internal entry point";
}

void expect_command(
    const extractor& definition,
    const std::string& command,
    const std::vector<std::string>& arguments,
    const std::string& what
) {
    EXPECT_EQ(definition.command, command) << what;
    EXPECT_EQ(definition.arguments, arguments) << what;
}

}

TEST(SquashfsSignature, TheBatchRegistersExactlyOneSignatureNamedSquashfs) {
    ASSERT_EQ(batch_signatures().size(), 1U)
        << "b9a_squashfs_signatures() owns exactly one signature";
    EXPECT_EQ(batch_signatures().front().name, squashfs_name);
    EXPECT_NE(batch_signatures().front().parser, nullptr);
}

TEST(SquashfsSignature, SevenFourByteMagicsAtOffsetZero) {
    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(value->magic_offset, 0U);
    ASSERT_EQ(value->magic.size(), 7U)
        << "upstream src/signatures/squashfs.rs lists seven spellings";
    const std::array<std::string, 7> expected{
        {"sqsh", "hsqs", "sqlz", "qshs", "tqsh", "hsqt", "shsq"}
    };
    for(const auto& pattern : value->magic) {
        ASSERT_EQ(pattern.size(), 4U) << "every squashfs magic is exactly 4 bytes";
        const std::string text(pattern.begin(), pattern.end());
        bool found = false;
        for(const auto& candidate : expected) {
            found = found || candidate == text;
        }
        EXPECT_TRUE(found) << "unexpected magic pattern: " << text;
    }
}

TEST(SquashfsFixtureAnchor, BuilderReproducesTheCommittedV4Image) {
    BINWALK_LOAD_FIXTURE(fixture, "squashfs.bin");
    EXPECT_EQ(build_v4(v4_params{}), fixture)
        << "build_v4's defaults must equal tests/fixtures/squashfs.bin, which "
        << "the oracle validated. Every mutant in this file inherits that "
        << "validation through this equality.";
}

TEST(SquashfsFixtureAnchor, BuilderReproducesTheCommittedV2Image) {
    BINWALK_LOAD_FIXTURE(fixture, "squashfs_v2.bin");
    EXPECT_EQ(build_v123(v123_params{}), fixture)
        << "build_v123's defaults must equal tests/fixtures/squashfs_v2.bin";
}

TEST(SquashfsV4LittleEndian, GoldenEquivalentImage) {
    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value()) << "tests/golden/squashfs.json detects at offset 0";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 315U) << "golden size, STRICT under policy";
    expect_high_tier(result->confidence, "squashfs.bin");
    EXPECT_EQ(
        result->description,
        "SquashFS file system, little endian, version: 4.0, compression: gzip, "
        "inode count: 2, block size: 131072, image size: 315 bytes, "
        "created: 2024-11-02 21:29:35"
    ) << "description wording is FREE under section 5; ours copies upstream, so "
      << "this full compare is free coverage of every reported fact at once. If "
      << "the wording was intentionally changed, weaken this to substring probes "
      << "-- do NOT change the numbers.";
}

TEST(SquashfsV4LittleEndian, TheBuiltImageMatchesTheFixtureResult) {
    const auto result = parse(build_v4(v4_params{}));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 315U);
    expect_high_tier(result->confidence, "built v4 default");
}

TEST(SquashfsV4LittleEndian, SizeIsTheDeclaredImageSizeNotTheFileLength) {

    v4_params parameters;
    parameters.image_size = 4096;
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 4096U);
}

TEST(SquashfsV4LittleEndian, DescriptionCarriesTheSubstantiveFacts) {
    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(contains_text(result->description, "little endian"));
    EXPECT_TRUE(contains_text(result->description, "4.0"));
    EXPECT_TRUE(contains_text(result->description, "gzip"));
    EXPECT_TRUE(contains_text(result->description, "131072"));
    EXPECT_TRUE(contains_text(result->description, "315"));
    EXPECT_TRUE(contains_text(result->description, "2024-11-02 21:29:35"))
        << "modification_time 0x672699BF is a Unix epoch rendered in UTC";
}

TEST(SquashfsV4LittleEndian, TheTimestampIsRenderedInUtcNotLocalTime) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(contains_text(result->description, "2024-11-02 21:29:35"))
        << "epoch 0x672699BF is 2024-11-02 21:29:35 UTC. Got: " << result->description;
    EXPECT_FALSE(contains_text(result->description, "2024-11-03"))
        << "a local-time rendering on a UTC+8 machine would land on the next day";
}

TEST(SquashfsV4LittleEndian, ExtractionIsNotDeclined) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->extraction_declined)
        << "a squashfs image is always offered to the extractor";
}

TEST(SquashfsEndianness, BigEndianV4Image) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_be.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 400U);
    expect_high_tier(result->confidence, "squashfs_be.bin");
    EXPECT_TRUE(contains_text(result->description, "big endian"));
    EXPECT_TRUE(contains_text(result->description, "4.0"));
    EXPECT_TRUE(contains_text(result->description, "xz"));
    EXPECT_TRUE(contains_text(result->description, "400"));
}

TEST(SquashfsEndianness, TheMagicSpellingDoesNotDecideEndianness) {

    v4_params parameters;
    parameters.magic = {{'s', 'q', 's', 'h'}};
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 315U);
    EXPECT_TRUE(contains_text(result->description, "little endian"))
        << "the magic must not be allowed to override the version field";
}

TEST(SquashfsEndianness, ALittleEndianReadAboveFourReReadsTheVersionBigEndian) {

    v4_params parameters;
    parameters.big_endian = true;
    parameters.image_size = 400;
    parameters.uid_start = 300;
    parameters.uid_entry = 200;
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(contains_text(result->description, "big endian"));
    EXPECT_TRUE(contains_text(result->description, "4.0"));
}

TEST(SquashfsLegacyVersions, BigEndianV2ImageIsGoldenStructural) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v2.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U) << "golden offset";
    EXPECT_EQ(result->size, 1024U) << "this fixture's own self-consistent size";
    expect_high_tier(result->confidence, "squashfs_v2.bin");
    EXPECT_TRUE(contains_text(result->description, "big endian")) << "golden fact";
    EXPECT_TRUE(contains_text(result->description, "2.0")) << "golden fact";
    EXPECT_TRUE(contains_text(result->description, "unknown")) << "golden fact";
    EXPECT_TRUE(contains_text(result->description, "431")) << "golden fact";
    EXPECT_TRUE(contains_text(result->description, "65536")) << "golden fact";
    EXPECT_TRUE(contains_text(result->description, "2009-02-12 09:09:55")) << "golden fact";
}

TEST(SquashfsLegacyVersions, VersionsBelowFourAlwaysReportCompressionUnknown) {

    v123_params parameters;
    parameters.inode_table_start_2 = 4;
    const auto result = parse(build_v123(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(contains_text(result->description, "unknown"))
        << "v1-v3 have no compression field, so the report is always `unknown`";
    EXPECT_FALSE(contains_text(result->description, "xz"));
}

TEST(SquashfsLegacyVersions, BigEndianV1Image) {

    v123_params parameters;
    parameters.major_version = 1;
    const auto result = parse(build_v123(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 1024U);
    EXPECT_TRUE(contains_text(result->description, "1.0"));
    EXPECT_TRUE(contains_text(result->description, "big endian"));
}

TEST(SquashfsLegacyVersions, LittleEndianV2Image) {

    v123_params parameters;
    parameters.magic = {{'h', 's', 'q', 's'}};
    parameters.big_endian = false;
    const auto result = parse(build_v123(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 1024U);
    EXPECT_TRUE(contains_text(result->description, "little endian"));
    EXPECT_TRUE(contains_text(result->description, "2.0"));
}

TEST(SquashfsLegacyVersions, VersionThreeUsesTheU64FieldsAtSixtyThreeAndSeventyOne) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v3.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value())
        << "detection proves uid_start was read from the u64 at @71, not from "
        << "uid_start_2 @12 (which is 8 and would fail the structure-size gate)";
    EXPECT_EQ(result->size, 1024U)
        << "image_size must come from the u64 at @63, not bytes_used_2 @8 (777)";
    EXPECT_TRUE(contains_text(result->description, "3.0"));
}

TEST(SquashfsLegacyVersions, VersionsBelowThreeUseTheUnderscoreTwoFields) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v2_override.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value())
        << "detection proves uid_start was overridden by uid_start_2 @12 for "
        << "version < 3; the u64 at @71 is 50 and would fail the gate";
    EXPECT_EQ(result->size, 1024U)
        << "for version < 3, image_size is overridden by bytes_used_2 @8; the "
        << "u64 at @63 is 3000";
}

TEST(SquashfsLegacyVersions, TheLegacyStructureSizeIsOneHundredNineteen) {

    v123_params rejected;
    rejected.uid_entry = 119;
    expect_rejected(build_v123(rejected), 0, "a UID entry of 119, which is not > 119");

    v123_params accepted;
    accepted.uid_entry = 120;
    const auto result = parse(build_v123(accepted));
    ASSERT_TRUE(result.has_value()) << "120 clears the 119-byte structure size";
    EXPECT_EQ(result->size, 1024U);
}

TEST(SquashfsLegacyVersions, MinimalSelfConsistentLegacyImageIsOneHundredTwentyFourBytes) {

    v123_params parameters;
    parameters.total = 124;
    parameters.bytes_used_2 = 124;
    parameters.uid_start_2 = 120;
    parameters.uid_entry = 0;
    parameters.uid_entry_at = 120;
    parameters.block_size = 4096;
    parameters.block_log = 12;
    const bytes image = build_v123(parameters);
    const auto result = parse(image);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 124U);

    const bytes truncated(image.begin(), image.begin() + 123);
    expect_rejected(truncated, 0, "a 124-byte image declared inside 123 bytes");
}

TEST(SquashfsMagic, EverySpellingParsesTheSameSuperblock) {

    const std::array<std::array<char, 4>, 7> spellings{{
        {{'s', 'q', 's', 'h'}},
        {{'h', 's', 'q', 's'}},
        {{'s', 'q', 'l', 'z'}},
        {{'q', 's', 'h', 's'}},
        {{'t', 'q', 's', 'h'}},
        {{'h', 's', 'q', 't'}},
        {{'s', 'h', 's', 'q'}},
    }};
    for(const auto& spelling : spellings) {
        const std::string text(spelling.begin(), spelling.end());
        v4_params parameters;
        parameters.magic = spelling;
        const auto result = parse(build_v4(parameters));
        ASSERT_TRUE(result.has_value()) << "magic `" << text << "` did not parse";
        EXPECT_EQ(result->offset, 0U) << text;
        EXPECT_EQ(result->size, 315U) << text;
        expect_high_tier(result->confidence, text);
        EXPECT_TRUE(contains_text(result->description, "little endian")) << text;
    }
}

TEST(SquashfsCompression, TheSevenKnownIdsAreNamed) {

    const std::array<std::pair<std::uint16_t, const char*>, 7> table{{
        {std::uint16_t{0}, "unknown"},
        {std::uint16_t{1}, "gzip"},
        {std::uint16_t{2}, "lzma"},
        {std::uint16_t{3}, "lzo"},
        {std::uint16_t{4}, "xz"},
        {std::uint16_t{5}, "lz4"},
        {std::uint16_t{6}, "zstd"},
    }};
    for(const auto& entry : table) {
        v4_params parameters;
        parameters.compression_id = entry.first;
        const auto result = parse(build_v4(parameters));
        ASSERT_TRUE(result.has_value())
            << "compression id " << entry.first << " is known and must be accepted";
        EXPECT_EQ(result->size, 315U) << "compression id " << entry.first;
        EXPECT_TRUE(contains_text(result->description, entry.second))
            << "compression id " << entry.first << " should be reported as `"
            << entry.second << "`, got: " << result->description;
    }
}

TEST(SquashfsCompression, ZstdIsAccepted) {

    v4_params parameters;
    parameters.compression_id = 6;
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 315U);
    EXPECT_TRUE(contains_text(result->description, "zstd"));
}

TEST(SquashfsCompression, IdSevenAndAboveIsRejected) {

    for(const std::uint16_t id : {std::uint16_t{7}, std::uint16_t{8},
                                  std::uint16_t{255}, std::uint16_t{0xFFFF}}) {
        v4_params parameters;
        parameters.compression_id = id;
        expect_rejected(
            build_v4(parameters), 0,
            "compression id " + std::to_string(id) + ", which is not in 0..=6"
        );
    }
}

TEST(SquashfsOffset, DetectionAtANonZeroOffset) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_at_offset.bin");
    const auto result = parse_at(data, 2048);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 2048U) << "the match offset is reported, not 0";
    EXPECT_EQ(result->size, 315U) << "size stays the declared image_size";
    expect_high_tier(result->confidence, "squashfs_at_offset.bin");
    EXPECT_TRUE(contains_text(result->description, "little endian"));
}

TEST(SquashfsOffset, TheUidGateComparesAnAbsoluteFileOffset) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_abs_uid.bin");
    const auto result = parse_at(data, 2048);
    ASSERT_TRUE(result.has_value())
        << "uid_start 30 is <= the v4 structure size 56, but the ABSOLUTE offset "
        << "2078 clears the gate -- this is the behaviour to preserve";
    EXPECT_EQ(result->offset, 2048U);
    EXPECT_EQ(result->size, 315U);

    v4_params at_zero;
    at_zero.uid_start = 30;
    at_zero.write_uid_entry = false;
    expect_rejected(
        build_v4(at_zero), 0,
        "uid_start 30 at offset 0, whose absolute uid offset 30 is not > 56"
    );
}

TEST(SquashfsOffset, DetectionAtAnOddUnalignedOffset) {

    const auto result = parse_at(with_padding(build_v4(v4_params{}), 1023), 1023);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1023U) << "the raw match offset, not a rounded one";
    EXPECT_EQ(result->size, 315U);
    expect_high_tier(result->confidence, "odd offset 1023");
}

TEST(SquashfsOffset, TheImageSizeClampIsMeasuredFromTheMatchOffset) {

    v4_params fits;
    fits.image_size = 4096;
    const auto accepted = parse_at(with_padding(build_v4(fits)), 2048);
    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->offset, 2048U);
    EXPECT_EQ(accepted->size, 4096U);

    v4_params overruns;
    overruns.image_size = 4097;
    expect_rejected(
        with_padding(build_v4(overruns)), 2048,
        "an image_size of 4097 with only 4096 bytes left after the match offset"
    );
}

TEST(SquashfsOffset, AZeroUidStartAtANonZeroOffsetStillFailsOnTheEntryValue) {

    v4_params parameters;
    parameters.uid_start = 0;
    parameters.write_uid_entry = false;
    expect_rejected(
        with_padding(build_v4(parameters)), 2048,
        "a UID entry read from the superblock's own magic, which exceeds image_size"
    );
}

TEST(SquashfsRejects, ExactlyOneHundredTwentyBytesAvailable) {

    v4_params parameters;
    parameters.total = 120;
    parameters.image_size = 121;
    parameters.uid_start = 64;
    parameters.uid_entry = 0;
    parameters.block_size = 4096;
    parameters.block_log = 12;
    expect_rejected(build_v4(parameters), 0, "exactly 120 bytes of available data");

    parameters.total = 121;
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value()) << "121 bytes is one more than the floor";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 121U);
    expect_high_tier(result->confidence, "121-byte v4 image");
}

TEST(SquashfsRejects, ShortBuffersOfEveryLengthBelowTheFloor) {

    const bytes full = build_v4(v4_params{});
    for(std::size_t length = 0; length <= 120; ++length) {
        const bytes truncated(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(length));
        expect_rejected(truncated, 0, "a buffer of only " + std::to_string(length) + " bytes");
    }
}

TEST(SquashfsRejects, ATruncatedSixtyFourByteFile) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_truncated.bin");
    ASSERT_EQ(data.size(), 64U);
    EXPECT_EQ(data.at(0), std::uint8_t{'h'});
    expect_rejected(data, 0, "a 64-byte file that merely begins with `hsqs`");
}

TEST(SquashfsRejects, VersionsOutsideOneThroughFour) {

    for(const std::uint16_t version : {std::uint16_t{0}, std::uint16_t{5},
                                       std::uint16_t{6}, std::uint16_t{0xFFFF}}) {
        v4_params parameters;
        parameters.major_version = version;
        expect_rejected(
            build_v4(parameters), 0,
            "major_version " + std::to_string(version) + ", outside 1..=4"
        );
    }
}

TEST(SquashfsRejects, ImageSizeOfOneHundredTwentyOrLess) {

    for(const std::uint64_t size : {std::uint64_t{0}, std::uint64_t{1},
                                    std::uint64_t{56}, std::uint64_t{119},
                                    std::uint64_t{120}}) {
        v4_params parameters;
        parameters.image_size = size;
        expect_rejected(
            build_v4(parameters), 0,
            "an image_size of " + std::to_string(size) + ", which is not > 120"
        );
    }
}

TEST(SquashfsRejects, ImageSizeLargerThanTheBytesAvailable) {

    v4_params parameters;
    parameters.image_size = 8192;
    expect_rejected(build_v4(parameters), 0, "an image_size of 8192 in a 4096-byte file");

    parameters.image_size = 4097;
    expect_rejected(build_v4(parameters), 0, "an image_size one byte past the file end");
}

TEST(SquashfsRejects, ZeroBlockSize) {

    v4_params parameters;
    parameters.block_size = 0;
    parameters.block_log = 0;
    expect_rejected(build_v4(parameters), 0, "a block_size of 0");
}

TEST(SquashfsRejects, BlockLogThatDoesNotMatchBlockSize) {

    for(const std::uint16_t log : {std::uint16_t{0}, std::uint16_t{16},
                                   std::uint16_t{18}, std::uint16_t{32}}) {
        v4_params parameters;
        parameters.block_log = log;
        expect_rejected(
            build_v4(parameters), 0,
            "block_log " + std::to_string(log) + " against block_size 131072 (2^17)"
        );
    }
}

TEST(SquashfsRejects, BlockLogIsFloorLogTwoNotAnExactPowerOfTwoCheck) {

    v4_params odd;
    odd.block_size = 131073;
    const auto accepted = parse(build_v4(odd));
    ASSERT_TRUE(accepted.has_value())
        << "floor(log2(131073)) == 17 == block_log, so this must be accepted";
    EXPECT_EQ(accepted->size, 315U);

    v4_params tiny;
    tiny.block_size = 1;
    tiny.block_log = 0;
    const auto smallest = parse(build_v4(tiny));
    ASSERT_TRUE(smallest.has_value()) << "floor(log2(1)) == 0";
    EXPECT_EQ(smallest->size, 315U);
}

TEST(SquashfsUidProbe, AZeroEntryIsAccepted) {

    v4_params parameters;
    parameters.uid_entry = 0;
    const auto result = parse(build_v4(parameters));
    ASSERT_TRUE(result.has_value()) << "a UID entry of 0 is explicitly allowed";
    EXPECT_EQ(result->size, 315U);
    expect_high_tier(result->confidence, "uid_entry == 0");
}

TEST(SquashfsUidProbe, TheV4StructureSizeIsFiftySix) {

    v4_params rejected;
    rejected.uid_entry = 56;
    expect_rejected(build_v4(rejected), 0, "a non-zero UID entry of 56, which is not > 56");

    v4_params accepted;
    accepted.uid_entry = 57;
    const auto result = parse(build_v4(accepted));
    ASSERT_TRUE(result.has_value()) << "57 clears the 56-byte v4 structure size";
    EXPECT_EQ(result->size, 315U);
}

TEST(SquashfsUidProbe, TheEntryMayEqualImageSizeButNotExceedIt) {

    v4_params accepted;
    accepted.uid_entry = 315;
    const auto result = parse(build_v4(accepted));
    ASSERT_TRUE(result.has_value()) << "the bound is <= image_size, inclusive";
    EXPECT_EQ(result->size, 315U);

    v4_params rejected;
    rejected.uid_entry = 316;
    expect_rejected(build_v4(rejected), 0, "a UID entry of 316 against image_size 315");
}

TEST(SquashfsUidProbe, AUidStartOfZeroOnAV4ImageAtOffsetZeroIsRejected) {

    v4_params parameters;
    parameters.uid_start = 0;
    parameters.write_uid_entry = false;
    const auto start = std::chrono::steady_clock::now();
    expect_rejected(build_v4(parameters), 0, "uid_start 0, whose absolute offset is not > 56");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 2)
        << "the uid_start == 0 rejection must be O(1)";
}

TEST(SquashfsUidProbe, AUidStartPastEndOfFileIsRejectedWithoutCrashing) {

    v4_params parameters;
    parameters.uid_start = std::uint64_t{1} << 40;
    parameters.write_uid_entry = false;
    expect_rejected(build_v4(parameters), 0, "a uid_start of 2^40 in a 4096-byte file");

    parameters.uid_start = 0xFFFFFFFFFFFFFFFFULL;
    expect_rejected(build_v4(parameters), 0, "a uid_start of UINT64_MAX (overflow bait)");

    parameters.uid_start = 0xFFFFFFFFFFFFFFF8ULL;
    expect_rejected(build_v4(parameters), 0, "a uid_start where uid_abs + 8 would wrap");
}

TEST(SquashfsUidProbe, TheEntryReadMustFitEntirelyInsideTheBuffer) {

    v4_params fits;
    fits.uid_start = 4088;
    fits.uid_entry = 0;
    const auto result = parse(build_v4(fits));
    ASSERT_TRUE(result.has_value()) << "a u64 read ending exactly at EOF is in bounds";
    EXPECT_EQ(result->size, 315U);

    v4_params overruns;
    overruns.uid_start = 4092;
    overruns.write_uid_entry = false;
    expect_rejected(build_v4(overruns), 0, "a u64 UID read that runs four bytes past EOF");
}

TEST(SquashfsUidProbe, VersionFourReadsTheEntryAsAU64) {

    v4_params parameters;
    parameters.uid_entry = 0x0000000100000135ULL;
    expect_rejected(
        build_v4(parameters), 0,
        "a v4 UID entry of 0x100000135, which only passes if read as a u32"
    );
}

TEST(SquashfsUidProbe, VersionsBelowFourReadTheEntryAsAU32) {

    bytes image = build_v123(v123_params{});
    for(std::size_t index = 904; index < 908; ++index) {
        image.at(index) = 0xFF;
    }
    const auto result = parse(image);
    ASSERT_TRUE(result.has_value())
        << "v1-v3 read a u32 UID entry; the 0xFFFFFFFF that follows must not be "
        << "pulled into the value";
    EXPECT_EQ(result->size, 1024U);
}

TEST(SquashfsFieldDiscrimination, EveryV4FieldIsReadFromItsOwnOffset) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v4_fields.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 2000U)
        << "image_size is the u64 at @40. 1700 would mean @32, 1500 would mean @48.";
    expect_high_tier(result->confidence, "squashfs_v4_fields.bin");
    EXPECT_TRUE(contains_text(result->description, "little endian"));
    EXPECT_TRUE(contains_text(result->description, "4.7"))
        << "major @28 and minor @30, distinct on purpose";
    EXPECT_TRUE(contains_text(result->description, "lzo"))
        << "compression_id is the u16 at @20";
    EXPECT_TRUE(contains_text(result->description, "165"))
        << "inode_count is the u32 at @4";
    EXPECT_TRUE(contains_text(result->description, "262144"))
        << "block_size is the u32 at @12";
    EXPECT_TRUE(contains_text(result->description, "2000"));
    EXPECT_TRUE(contains_text(result->description, "2020-09-13 12:26:40"))
        << "modification_time is the u32 at @8";
}

TEST(SquashfsFieldDiscrimination, EveryV3FieldIsReadFromItsOwnUnalignedOffset) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v3_fields.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value())
        << "detection requires uid_start from the u64 at @71 (1500); the `_2` "
        << "slot points at poison";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 2000U)
        << "image_size is the u64 at @63. A size of 1234 means the version-<3 "
        << "`_2` override was applied to a version-3 image.";
    expect_high_tier(result->confidence, "squashfs_v3_fields.bin");
    EXPECT_TRUE(contains_text(result->description, "big endian"));
    EXPECT_TRUE(contains_text(result->description, "3.5"));
    EXPECT_TRUE(contains_text(result->description, "unknown"))
        << "the legacy layout has no compression field at all";
    EXPECT_TRUE(contains_text(result->description, "193"))
        << "inode_count is the u32 at @4";
    EXPECT_TRUE(contains_text(result->description, "4096"))
        << "block_size is the u32 at @51, not block_size_1 (513) at @32";
    EXPECT_TRUE(contains_text(result->description, "2020-09-13 12:26:40"))
        << "modification_time is the UNALIGNED u32 at @39";
}

TEST(SquashfsFieldDiscrimination, VersionTwoIgnoresPoisonedU64FieldsEntirely) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v2_fields.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value())
        << "for version < 3 the u64s at @63/@71 must be ignored; both are "
        << "UINT64_MAX here and either one would reject";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 2000U) << "image_size comes from bytes_used_2 @8";
    expect_high_tier(result->confidence, "squashfs_v2_fields.bin");
    EXPECT_TRUE(contains_text(result->description, "big endian"));
    EXPECT_TRUE(contains_text(result->description, "2.9"));
    EXPECT_TRUE(contains_text(result->description, "unknown"));
    EXPECT_TRUE(contains_text(result->description, "193"));
    EXPECT_TRUE(contains_text(result->description, "4096"));
    EXPECT_TRUE(contains_text(result->description, "2020-09-13 12:26:40"));
}

TEST(SquashfsPreferredExtractor, LittleEndianV4TakesTheLittleEndianBranch) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value())
        << "the parser knows the endianness, so it sets the per-result override";
    const auto& definition = *result->preferred_extractor;
    expect_command(definition, "sasquatch", {"-le", "%e"}, "little-endian v4");
    EXPECT_NE(definition.command, "sasquatch-v4be")
        << "a little-endian v4 image must NOT take the v4-big-endian branch: "
        << "endianness is tested BEFORE the version";
    expect_shared_extractor_shape(definition, "little-endian v4");
}

TEST(SquashfsPreferredExtractor, BigEndianV4TakesTheV4BigEndianBranch) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_be.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    expect_command(*result->preferred_extractor, "sasquatch-v4be", {"%e"}, "big-endian v4");
    expect_shared_extractor_shape(*result->preferred_extractor, "big-endian v4");
}

TEST(SquashfsPreferredExtractor, BigEndianVersionTwoTakesTheBigEndianBranch) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v2.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    expect_command(*result->preferred_extractor, "sasquatch", {"-be", "%e"}, "big-endian v2");
    expect_shared_extractor_shape(*result->preferred_extractor, "big-endian v2");
}

TEST(SquashfsPreferredExtractor, BigEndianVersionThreeTakesTheBigEndianBranch) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_v3.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    expect_command(*result->preferred_extractor, "sasquatch", {"-be", "%e"}, "big-endian v3");
}

TEST(SquashfsPreferredExtractor, BigEndianVersionOneTakesTheBigEndianBranch) {

    v123_params parameters;
    parameters.major_version = 1;
    const auto result = parse(build_v123(parameters));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    expect_command(*result->preferred_extractor, "sasquatch", {"-be", "%e"}, "big-endian v1");
}

TEST(SquashfsPreferredExtractor, LittleEndianVersionTwoTakesTheLittleEndianBranch) {

    v123_params parameters;
    parameters.magic = {{'h', 's', 'q', 's'}};
    parameters.big_endian = false;
    const auto result = parse(build_v123(parameters));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    expect_command(*result->preferred_extractor, "sasquatch", {"-le", "%e"}, "little-endian v2");
    expect_shared_extractor_shape(*result->preferred_extractor, "little-endian v2");
}

TEST(SquashfsPreferredExtractor, ThePreferredExtractorIsSetOnEveryAcceptedImage) {

    const std::array<const char*, 8> every_fixture{{
        "squashfs.bin", "squashfs_be.bin", "squashfs_v2.bin",
        "squashfs_v2_override.bin", "squashfs_v3.bin", "squashfs_v4_fields.bin",
        "squashfs_v3_fields.bin", "squashfs_v2_fields.bin"
    }};
    for(const char* name : every_fixture) {
        const bytes data = load_fixture(name);
        ASSERT_FALSE(data.empty()) << "could not read tests/fixtures/" << name;
        const auto result = parse(data);
        ASSERT_TRUE(result.has_value()) << name;
        ASSERT_TRUE(result->preferred_extractor.has_value()) << name;
        expect_shared_extractor_shape(*result->preferred_extractor, name);
        const auto& command = result->preferred_extractor->command;
        EXPECT_TRUE(command == "sasquatch" || command == "sasquatch-v4be")
            << name << ": unexpected command `" << command << "`";
    }
}

TEST(SquashfsPreferredExtractor, TheRegistryDefaultDefinitionIsSasquatchWithNoEndianFlag) {

    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "squashfs must carry a default external extractor";
    expect_command(*value->extractor_definition, "sasquatch", {"%e"}, "registry default");
    expect_shared_extractor_shape(*value->extractor_definition, "registry default");
}

TEST(SquashfsRobustness, AUidStartPointingAtTheSuperblockItselfTerminatesImmediately) {

    v4_params parameters;
    parameters.uid_start = 64;
    parameters.uid_entry = 64;
    const auto start = std::chrono::steady_clock::now();
    const auto result = parse(build_v4(parameters));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    ASSERT_TRUE(result.has_value()) << "the oracle accepts this image";
    EXPECT_EQ(result->size, 315U);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 2)
        << "a self-referential UID pointer must not start a traversal";
}

TEST(SquashfsRobustness, AUidStartPointingAtItsOwnPointerFieldTerminatesImmediately) {

    v4_params parameters;
    parameters.uid_start = 48;
    parameters.write_uid_entry = false;
    const auto start = std::chrono::steady_clock::now();
    expect_rejected(build_v4(parameters), 0, "a uid_start that points at the uid_start field");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 2)
        << "the pointer must be read once, never followed";
}

TEST(SquashfsRobustness, AMaximalImageSizeAllocatesNothingAndReturnsAtOnce) {

    for(const std::uint64_t size : {std::uint64_t{0xFFFFFFFFFFFFFFFFULL},
                                    std::uint64_t{0x8000000000000000ULL},
                                    std::uint64_t{0x0000FFFFFFFFFFFFULL}}) {
        v4_params parameters;
        parameters.image_size = size;
        const auto start = std::chrono::steady_clock::now();
        expect_rejected(build_v4(parameters), 0, "a colossal declared image_size");
        const auto elapsed = std::chrono::steady_clock::now() - start;
        EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 2)
            << "the size bound must be checked before anything is allocated";
    }
}

TEST(SquashfsRobustness, EveryOffsetInABufferOfRepeatedMagicsIsCheapToReject) {

    bytes storm(65536, 0x00);
    for(std::size_t index = 0; index + 4 <= storm.size(); index += 4) {
        storm.at(index + 0) = static_cast<std::uint8_t>('h');
        storm.at(index + 1) = static_cast<std::uint8_t>('s');
        storm.at(index + 2) = static_cast<std::uint8_t>('q');
        storm.at(index + 3) = static_cast<std::uint8_t>('s');
    }
    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    ASSERT_NE(value->parser, nullptr);

    const auto start = std::chrono::steady_clock::now();
    std::size_t accepted = 0;
    for(std::size_t offset = 0; offset + 4 <= storm.size(); offset += 4) {
        if(value->parser(byte_view(storm), offset).has_value()) {
            ++accepted;
        }
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_EQ(accepted, 0U)
        << "a wall of magics with no superblock behind them must all be rejected";
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 20)
        << "16384 parser calls over 64 KB must be linear, not quadratic";
}

TEST(SquashfsRobustness, ScanningARepeatedMagicBufferCompletesQuickly) {

    bytes storm(65536, 0x00);
    for(std::size_t index = 0; index + 4 <= storm.size(); index += 4) {
        storm.at(index + 0) = static_cast<std::uint8_t>('h');
        storm.at(index + 1) = static_cast<std::uint8_t>('s');
        storm.at(index + 2) = static_cast<std::uint8_t>('q');
        storm.at(index + 3) = static_cast<std::uint8_t>('s');
    }
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    const auto start = std::chrono::steady_clock::now();
    const auto results = scanner.scan(byte_view(storm));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(results.empty()) << "the oracle reports an empty file_map for this input";
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 20)
        << "no quadratic blowup on a dense magic field";
}

TEST(SquashfsRobustness, ParsingPastTheEndOfTheBufferIsNotAnAccess) {

    const bytes data = build_v4(v4_params{});
    expect_rejected(data, data.size(), "an offset exactly at the end of the buffer");
    expect_rejected(data, data.size() + 1, "an offset one past the end of the buffer");
    expect_rejected(data, data.size() * 2, "an offset far past the end of the buffer");
    expect_rejected(bytes{}, 0, "an empty buffer");
}

TEST(SquashfsRobustness, EveryByteOfTheSuperblockCanBeCorruptedWithoutCrashing) {

    const bytes base = build_v4(v4_params{});
    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    ASSERT_NE(value->parser, nullptr);
    for(std::size_t index = 0; index < 56; ++index) {
        for(const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xFF}}) {
            bytes mutated = base;
            mutated.at(index) = fill;
            const auto result = value->parser(byte_view(mutated), 0);
            if(result.has_value()) {

                EXPECT_GT(result->size, 120U)
                    << "byte " << index << " set to " << static_cast<int>(fill);
                EXPECT_LE(result->size, mutated.size())
                    << "byte " << index << " set to " << static_cast<int>(fill);
            }
        }
    }
}

TEST(SquashfsScanner, ScanStampsTheNameAndAlwaysDisplayAndAnId) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results.front().name, "squashfs") << "golden name";
    EXPECT_FALSE(results.front().always_display) << "golden always_display";
    EXPECT_FALSE(results.front().extraction_declined) << "golden extraction_declined";
    EXPECT_FALSE(results.front().id.empty())
        << "the id is random by construction and FREE under section 5, but it "
        << "must be populated";
}

TEST(SquashfsScanner, ScanReproducesTheGoldenFileMap) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U) << "the golden file_map has exactly one entry";
    EXPECT_EQ(results.front().offset, 0U);
    EXPECT_EQ(results.front().size, 315U);
    EXPECT_EQ(results.front().name, "squashfs");
    expect_high_tier(results.front().confidence, "scanned squashfs.bin");
}

TEST(SquashfsScanner, TheScannerDoesNotDropThePreferredExtractor) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    ASSERT_TRUE(results.front().preferred_extractor.has_value())
        << "the override must survive scanner::populate()";
    expect_command(
        *results.front().preferred_extractor, "sasquatch", {"-le", "%e"},
        "scanned little-endian v4"
    );
}

TEST(SquashfsScanner, ScanFindsTheImageAtANonZeroOffset) {

    BINWALK_LOAD_FIXTURE(data, "squashfs_at_offset.bin");
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results.front().offset, 2048U);
    EXPECT_EQ(results.front().size, 315U);
    EXPECT_EQ(results.front().name, "squashfs");
}

TEST(SquashfsScanner, ExcludeRemovesTheSignature) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    binwalk::scan_options options;
    options.exclude = {"squashfs"};
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures(), options);
    EXPECT_TRUE(scanner.scan(byte_view(data)).empty())
        << "--exclude=squashfs must silence this signature entirely";
}

TEST(SquashfsScanner, IncludeKeepsTheSignature) {
    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    binwalk::scan_options options;
    options.include = {"squashfs"};
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures(), options);
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U) << "--include=squashfs must keep it";
    EXPECT_EQ(results.front().name, "squashfs");
    EXPECT_EQ(results.front().size, 315U);
}

TEST(SquashfsScanner, ARejectedSuperblockProducesNoResultAtAll) {

    v4_params parameters;
    parameters.compression_id = 7;
    const bytes data = build_v4(parameters);
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    EXPECT_TRUE(scanner.scan(byte_view(data)).empty())
        << "an unknown compression id yields an EMPTY file_map, not a size-0 entry";
}

TEST(SquashfsScanner, TheScannerRegistersOneSignatureAndSevenPatterns) {
    const binwalk::scanner scanner(binwalk::formats::b9a_squashfs_signatures());
    EXPECT_EQ(scanner.signature_count(), 1U);
    EXPECT_EQ(scanner.pattern_count(), 7U)
        << "seven magic spellings, all four bytes, all at magic_offset 0";
}

TEST(SquashfsExternalExtraction, ADryRunOfAnExternalDefinitionIsUnsupported) {

    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());

    const auto dry = binwalk::dry_run_extractor(
        *result->preferred_extractor, byte_view(data), *result
    );
    EXPECT_FALSE(dry.success);
    EXPECT_EQ(dry.failure, binwalk::extraction_failure::unsupported)
        << "a dry run of an external extractor is `unsupported`, never a "
        << "silent failure";

    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto default_dry = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), *result
    );
    EXPECT_FALSE(default_dry.success);
    EXPECT_EQ(default_dry.failure, binwalk::extraction_failure::unsupported);
}

TEST(SquashfsExternalExtraction, AvailabilityIsQueryableWithoutRunningAnything) {

    const auto* value = squashfs_signature();
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const bool available = binwalk::external_utility_available(*value->extractor_definition);
    SUCCEED() << "sasquatch " << (available ? "is" : "is not")
              << " installed on this machine; both are legitimate";
}

TEST(SquashfsExternalExtraction, LittleEndianDefinitionRunsWhenPresent) {
    BINWALK_LOAD_FIXTURE(data, "squashfs.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    const auto& definition = *result->preferred_extractor;

    if(!binwalk::external_utility_available(definition)) {
        GTEST_SKIP() << "sasquatch is not installed on this machine, which is "
                        "expected; the little-endian extraction path cannot be "
                        "executed here";
    }

    const auto root = std::filesystem::temp_directory_path()
        / ("binwalk_squashfs_le_" + std::to_string(
               static_cast<unsigned long long>(
                   std::chrono::steady_clock::now().time_since_epoch().count())));
    std::error_code error;
    std::filesystem::create_directories(root, error);
    ASSERT_FALSE(error) << "could not create " << root.string();

    const auto extraction = binwalk::execute_extractor(
        byte_view(data), (fixtures().directory / "squashfs.bin").string(),
        *result, definition, root.string()
    );
    EXPECT_NE(extraction.failure, binwalk::extraction_failure::utility_not_found)
        << "the utility was reported available, so it must not come back missing";
    std::filesystem::remove_all(root, error);
}

TEST(SquashfsExternalExtraction, BigEndianV4DefinitionRunsWhenPresent) {
    BINWALK_LOAD_FIXTURE(data, "squashfs_be.bin");
    const auto result = parse(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->preferred_extractor.has_value());
    const auto& definition = *result->preferred_extractor;
    ASSERT_EQ(definition.command, "sasquatch-v4be");

    if(!binwalk::external_utility_available(definition)) {
        GTEST_SKIP() << "sasquatch-v4be is not installed on this machine, which "
                        "is expected; the big-endian v4 extraction path cannot "
                        "be executed here";
    }

    const auto root = std::filesystem::temp_directory_path()
        / ("binwalk_squashfs_be_" + std::to_string(
               static_cast<unsigned long long>(
                   std::chrono::steady_clock::now().time_since_epoch().count())));
    std::error_code error;
    std::filesystem::create_directories(root, error);
    ASSERT_FALSE(error) << "could not create " << root.string();

    const auto extraction = binwalk::execute_extractor(
        byte_view(data), (fixtures().directory / "squashfs_be.bin").string(),
        *result, definition, root.string()
    );
    EXPECT_NE(extraction.failure, binwalk::extraction_failure::utility_not_found);
    std::filesystem::remove_all(root, error);
}
