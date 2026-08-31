
#include "../../lib/src/formats/b9b_jffs2_yaffs.hpp"

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

const std::array<std::string, 2>& batch_names() {
    static const std::array<std::string, 2> names{"jffs2", "yaffs"};
    return names;
}

const std::vector<signature>& batch_signatures() {
    static const std::vector<signature> value = binwalk::formats::b9b_jffs2_yaffs_signatures();
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
        << "could not read tests/fixtures/" << (file) << ". Directories searched:\n"     \
        << fixtures().searched

void put_u16(bytes& target, std::uint16_t value, bool big_endian) {
    const auto high = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
    const auto low = static_cast<std::uint8_t>(value & 0xFFU);
    if(big_endian) {
        target.push_back(high);
        target.push_back(low);
    } else {
        target.push_back(low);
        target.push_back(high);
    }
}

void put_u32(bytes& target, std::uint32_t value, bool big_endian) {
    for(unsigned index = 0; index < 4U; ++index) {
        const unsigned shift = big_endian ? (3U - index) * 8U : index * 8U;
        target.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

void patch_u32le(bytes& target, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        target.at(offset + index) =
            static_cast<std::uint8_t>((value >> (static_cast<unsigned>(index) * 8U)) & 0xFFU);
    }
}

bytes concat(const bytes& first, const bytes& second) {
    bytes joined = first;
    joined.insert(joined.end(), second.begin(), second.end());
    return joined;
}

void append(bytes& target, const bytes& more) {
    target.insert(target.end(), more.begin(), more.end());
}

bytes at_offset(const bytes& payload, std::size_t padding) {
    bytes data(padding, 0x00);
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

bool contains_text(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

constexpr std::uint16_t jffs2_type_dirent = 0xE001;
constexpr std::uint16_t jffs2_type_inode = 0xE002;
constexpr std::uint16_t jffs2_type_cleanmarker = 0x2003;

std::uint32_t reflected_crc32(
    const std::uint8_t* data,
    std::size_t length,
    std::uint32_t seed,
    std::uint32_t final_xor
) {
    std::uint32_t crc = seed;
    for(std::size_t index = 0; index < length; ++index) {
        crc ^= data[index];
        for(int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = (crc & 1U) != 0U ? 0xEDB88320U : 0U;
            crc = (crc >> 1) ^ mask;
        }
    }
    return crc ^ final_xor;
}

std::uint32_t raw_crc32(const std::uint8_t* data, std::size_t length) {
    return reflected_crc32(data, length, 0U, 0U);
}

std::uint32_t standard_crc32(const std::uint8_t* data, std::size_t length) {
    return reflected_crc32(data, length, 0xFFFFFFFFU, 0xFFFFFFFFU);
}

std::size_t roundup4(std::size_t value) {
    return (value + 3U) & ~static_cast<std::size_t>(3U);
}

bytes jffs2_header(
    bool big_endian,
    std::uint16_t type,
    std::uint32_t size,
    std::optional<std::uint32_t> crc_override = std::nullopt
) {
    bytes header;
    put_u16(header, 0x1985U, big_endian);
    put_u16(header, type, big_endian);
    put_u32(header, size, big_endian);
    const std::uint32_t crc =
        crc_override.has_value() ? *crc_override : raw_crc32(header.data(), header.size());
    put_u32(header, crc, big_endian);
    return header;
}

bytes jffs2_node(bool big_endian, std::uint16_t type, std::uint32_t size) {
    bytes node = jffs2_header(big_endian, type, size);
    const std::size_t occupied = std::max<std::size_t>(roundup4(size), node.size());
    node.resize(occupied, 0x00);
    return node;
}

struct jffs2_spec {
    std::uint16_t type;
    std::uint32_t size;
};

bytes jffs2_image(bool big_endian, const std::vector<jffs2_spec>& nodes) {
    bytes image;
    for(const auto& node : nodes) {
        append(image, jffs2_node(big_endian, node.type, node.size));
    }
    return image;
}

const std::vector<jffs2_spec>& fixture_node_list() {
    static const std::vector<jffs2_spec> nodes{
        {jffs2_type_dirent, 20},
        {jffs2_type_inode, 33},
        {jffs2_type_cleanmarker, 16},
        {jffs2_type_inode, 64}
    };
    return nodes;
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

std::vector<signature_result> scan_only(const bytes& data, const std::string& name) {
    binwalk::scan_options options;
    options.include = {name};
    const binwalk::scanner scanner(batch_signatures(), options);
    return scanner.scan(byte_view(data));
}

constexpr std::chrono::seconds hang_bound{5};

struct bounded_outcome {
    std::optional<signature_result> parsed;
    std::vector<signature_result> results;
};

bounded_outcome expect_bounded_scan(
    const std::string& name,
    const bytes& data,
    std::size_t offset,
    const std::string& why
) {
    bounded_outcome outcome;
    const auto* value = signature_named(name);
    EXPECT_NE(value, nullptr) << name << " is not registered by this batch";
    if(value == nullptr || value->parser == nullptr) {
        return outcome;
    }

    const auto started = std::chrono::steady_clock::now();
    outcome.parsed = value->parser(byte_view(data), offset);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, hang_bound)
        << name << " took "
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
        << " ms on " << why << " -- an unbounded walk or allocation "
        << "(policy)";

    const auto scan_started = std::chrono::steady_clock::now();
    outcome.results = scan_batch(data);
    const auto scan_elapsed = std::chrono::steady_clock::now() - scan_started;
    EXPECT_LT(scan_elapsed, hang_bound)
        << "scan() over " << why << " took "
        << std::chrono::duration_cast<std::chrono::milliseconds>(scan_elapsed).count()
        << " ms";

    for(const auto& result : outcome.results) {
        EXPECT_LE(result.offset + result.size, static_cast<std::uint64_t>(data.size()))
            << result.name << " reported a span running past the end of " << why;
    }
    return outcome;
}

void expect_prompt_rejection(
    const std::string& name,
    const bytes& data,
    std::size_t offset,
    const std::string& why
) {
    SCOPED_TRACE(why);
    const auto outcome = expect_bounded_scan(name, data, offset, why);
    EXPECT_FALSE(outcome.parsed.has_value()) << name << " accepted " << why;
    for(const auto& result : outcome.results) {
        EXPECT_NE(result.name, name)
            << "scan() reported a " << name << " result at offset " << result.offset
            << " for " << why;
    }
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

signature_result probe_signature(const std::string& name, std::uint64_t offset, std::uint64_t size) {
    signature_result value;
    value.offset = offset;
    value.size = size;
    value.name = name;
    value.confidence = confidence_high;
    return value;
}

class b9b_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b9b_";
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

    void expect_nothing_written(const binwalk::extraction_result& result) {
        EXPECT_EQ(bytes_written_under(root_), std::uint64_t{0})
            << "the extraction wrote " << bytes_written_under(root_) << " bytes";
        EXPECT_TRUE(extracted_files_under(root_).empty());
        if(!result.output_directory.empty()) {
            std::error_code error;
            if(std::filesystem::exists(result.output_directory, error)) {
                EXPECT_TRUE(extracted_files_under(result.output_directory).empty())
                    << "output left behind in " << result.output_directory;
            }
        }
    }

    std::filesystem::path root_;
};

}

TEST(B9bRegistry, BothSignaturesArePresentExactlyOnce) {
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
        << "b9b_jffs2_yaffs_signatures() must return exactly these two";
}

TEST(B9bRegistry, RegistrationFactsMatchUpstreamMagicRs) {

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

TEST(B9bRegistry, Jffs2RegistersTheSixNodeHeaderMagics) {

    const auto* value = signature_named("jffs2");
    ASSERT_NE(value, nullptr);
    const std::array<bytes, 6> expected{{
        bytes{0x19, 0x85, 0xE0, 0x01},
        bytes{0x19, 0x85, 0xE0, 0x02},
        bytes{0x19, 0x85, 0x20, 0x03},
        bytes{0x85, 0x19, 0x01, 0xE0},
        bytes{0x85, 0x19, 0x02, 0xE0},
        bytes{0x85, 0x19, 0x03, 0x20}
    }};
    EXPECT_EQ(value->magic.size(), expected.size());
    for(const auto& pattern : expected) {
        const bool present =
            std::find(value->magic.begin(), value->magic.end(), pattern) != value->magic.end();
        EXPECT_TRUE(present) << "jffs2 is missing a registered node-header magic";
    }
}

TEST(B9bRegistry, YaffsRegistersTheFourObjectHeaderMagics) {

    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    const std::array<bytes, 4> expected{{
        bytes{0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF},
        bytes{0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF},
        bytes{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF},
        bytes{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF}
    }};
    EXPECT_EQ(value->magic.size(), expected.size());
    for(const auto& pattern : expected) {
        const bool present =
            std::find(value->magic.begin(), value->magic.end(), pattern) != value->magic.end();
        EXPECT_TRUE(present) << "yaffs is missing a registered object-header magic";
    }
}

TEST(B9bRegistry, NoMagicPatternIsAPrefixOfAnother) {

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
    ASSERT_EQ(patterns.size(), 10U) << "6 jffs2 patterns + 4 yaffs patterns";

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
                << "\"'s, so the two can collide at one offset and the overlap filter's "
                << "equal-offset tie-break becomes reachable -- which this batch has no "
                << "test for, because until now it could not happen. Add one, or revert "
                << "the magic change.";
        }
    }
}

TEST(B9bFixtures, TheFixtureCorpusIsReachable) {
    ASSERT_FALSE(fixtures().directory.empty())
        << "tests/fixtures was not found. Every oracle-parity test in this file "
        << "depends on it, so this is a hard failure rather than a skip. "
        << "Directories searched:\n" << fixtures().searched;
    struct expectation {
        const char* name;
        std::size_t size;
    };
    const std::array<expectation, 10> expected{{
        {"jffs2.bin", 136}, {"jffs2_le.bin", 136}, {"jffs2_at_offset.bin", 1160},
        {"jffs2_two_nodes.bin", 56}, {"jffs2_bad_crc.bin", 136},
        {"yaffs.bin", 135168}, {"yaffs_be.bin", 35904},
        {"yaffs_alt_geometry.bin", 34560}, {"yaffs_truncated.bin", 33792},
        {"yaffs_no_spare.bin", 33793}
    }};
    for(const auto& entry : expected) {
        const auto data = load_fixture(entry.name);
        EXPECT_FALSE(data.empty()) << "missing tests/fixtures/" << entry.name;
        EXPECT_EQ(data.size(), entry.size)
            << entry.name << " is not the length the oracle was run against; every "
            << "size expectation in this file is keyed to it";
    }
}

TEST(B9bJffs2Builder, ReproducesTheBigEndianFixtureByteForByte) {
    BINWALK_LOAD_FIXTURE(fixture, "jffs2.bin");
    const bytes built = jffs2_image(true, fixture_node_list());
    EXPECT_EQ(built.size(), 136U)
        << "20 + roundup4(33) + 16 + 64 == 136; if this is 132 the round-up is missing";
    EXPECT_EQ(built, fixture)
        << "the spec-derived builder must reproduce tests/fixtures/jffs2.bin exactly";
}

TEST(B9bJffs2Builder, ReproducesTheLittleEndianFixtureByteForByte) {
    BINWALK_LOAD_FIXTURE(fixture, "jffs2_le.bin");
    const bytes built = jffs2_image(false, fixture_node_list());
    EXPECT_EQ(built.size(), 136U);
    EXPECT_EQ(built, fixture)
        << "the little-endian image is the same structure with every field byte "
        << "swapped, INCLUDING the CRC -- which is computed over the swapped header "
        << "bytes, not swapped after the fact";
}

TEST(B9bJffs2, BigEndianFixtureIsDetectedWithTheOracleNumbers) {
    BINWALK_LOAD_FIXTURE(data, "jffs2.bin");
    const auto result = parse_at("jffs2", data, 0);
    ASSERT_TRUE(result.has_value()) << "jffs2.bin must be detected";
    EXPECT_EQ(result->offset, 0U);

    EXPECT_EQ(result->size, 136U);
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a valid four-node jffs2 image");
    EXPECT_TRUE(contains_text(result->description, "big endian"))
        << "description must report the endianness: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "4"))
        << "description must report the node count: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "136"))
        << "description must report the total size: " << result->description;
}

TEST(B9bJffs2, LittleEndianFixtureIsDetectedWithTheOracleNumbers) {
    BINWALK_LOAD_FIXTURE(data, "jffs2_le.bin");
    const auto result = parse_at("jffs2", data, 0);
    ASSERT_TRUE(result.has_value()) << "jffs2_le.bin must be detected";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 136U);
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::high, "a valid little-endian jffs2 image");
    EXPECT_TRUE(contains_text(result->description, "little endian"))
        << "the endianness is the whole point of this fixture: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "136"));
}

TEST(B9bJffs2, DetectedAtOffsetOneThousandTwentyFour) {
    BINWALK_LOAD_FIXTURE(data, "jffs2_at_offset.bin");
    const auto result = parse_at("jffs2", data, 1024);
    ASSERT_TRUE(result.has_value()) << "jffs2_at_offset.bin must be detected at 1024";
    EXPECT_EQ(result->offset, 1024U) << "the reported offset is the first node's, not 0";
    EXPECT_EQ(result->size, 136U)
        << "size is the span of the node chain, not the distance to EOF";
    expect_tier(result->confidence, tier::high, "a jffs2 image at offset 1024");
    EXPECT_TRUE(contains_text(result->description, "big endian"));
}

TEST(B9bJffs2, TwoNodesIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "jffs2_two_nodes.bin");
    expect_rejected("jffs2", data, 0, "a jffs2 chain of exactly two valid nodes");
}

TEST(B9bJffs2, BadCrcIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "jffs2_bad_crc.bin");
    ASSERT_EQ(data.size(), 136U);
    expect_rejected("jffs2", data, 0, "a jffs2 image with every node header CRC corrupted");
    EXPECT_TRUE(scan_batch(data).empty()) << "and nothing survives at any inner node either";
}

TEST(B9bJffs2, CorruptingOnlyTheFirstCrcMovesTheDetectionRatherThanRemovingIt) {

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    bytes data = base;
    data.at(8) = static_cast<std::uint8_t>(data.at(8) ^ 0xFFU);

    const auto direct = parse_at("jffs2", data, 0);
    EXPECT_FALSE(direct.has_value()) << "node 0 itself is still refused";

    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results.front().name, "jffs2");
    EXPECT_EQ(results.front().offset, 20U)
        << "the scanner probes node 1's magic independently of node 0";
    EXPECT_EQ(results.front().size, 116U) << "36 + 16 + 64 == 116";
    expect_tier(results.front().confidence, tier::high, "a chain starting at node 1");
    EXPECT_TRUE(contains_text(results.front().description, "3"))
        << "three nodes remain: " << results.front().description;

    bytes two = data;
    two.at(28) = static_cast<std::uint8_t>(two.at(28) ^ 0xFFU);
    EXPECT_TRUE(scan_batch(two).empty())
        << "with nodes 0 and 1 both refused, neither surviving start point can reach "
        << "three nodes before EOF";
}

TEST(B9bJffs2, ABadCrcMidChainIsSkippedButOnTheLastNodeItShortensTheSpan) {

    struct expectation {
        const char* what;
        std::size_t crc_byte;
        std::uint64_t size;
    };
    const std::array<expectation, 3> cases{{
        {"node 1 (header at 20)", 28, 136},
        {"node 2 (header at 56)", 64, 136},
        {"node 3 (header at 72), the last one", 80, 72}
    }};

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.what);
        bytes data = base;
        data.at(entry.crc_byte) = static_cast<std::uint8_t>(data.at(entry.crc_byte) ^ 0xFFU);

        const auto result = parse_at("jffs2", data, 0);
        ASSERT_TRUE(result.has_value())
            << "node 0 is untouched, so the chain still starts at offset 0";
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, entry.size)
            << "a walk that STOPPED at the bad CRC instead of skipping it would "
            << "report the offset of that node here";
        expect_tier(result->confidence, tier::high, "a chain with one bad node CRC");
        EXPECT_TRUE(contains_text(result->description, "3"))
            << "three nodes survive in every row: " << result->description;
    }
}

TEST(B9bJffs2, TheNodeCountBarIsExactlyMoreThanTwo) {

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    ASSERT_EQ(base.size(), 136U);

    for(std::size_t prefix : {std::size_t{20}, std::size_t{56}}) {
        SCOPED_TRACE(prefix);
        bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(prefix));
        expect_rejected(
            "jffs2", data, 0,
            "a jffs2 chain truncated to " + std::to_string(prefix)
                + " bytes, which is fewer than three nodes"
        );
    }

    {
        bytes data(base.begin(), base.begin() + 72);
        const auto result = parse_at("jffs2", data, 0);
        ASSERT_TRUE(result.has_value()) << "three nodes is exactly enough";
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, 72U)
            << "20 + roundup4(33) + 16 == 72; 68 would mean the round-up was skipped";
        expect_tier(result->confidence, tier::high, "a three-node jffs2 chain");
        EXPECT_TRUE(contains_text(result->description, "3"))
            << "the node count must be reported: " << result->description;
        EXPECT_TRUE(contains_text(result->description, "72")) << result->description;
    }
}

TEST(B9bJffs2, RoundingEachNodeUpToFourBytesIsLoadBearing) {

    const bytes data = jffs2_image(true, {
        {jffs2_type_dirent, 13}, {jffs2_type_inode, 13}, {jffs2_type_inode, 13}
    });
    ASSERT_EQ(data.size(), 48U);
    const auto result = parse_at("jffs2", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 48U)
        << "45 here means the node size is used raw instead of rounded up to 4";
    expect_tier(result->confidence, tier::high, "three 13-byte jffs2 nodes");
}

TEST(B9bJffs2, EveryPartialRoundUpResidueIsHandled) {

    const bytes data = jffs2_image(true, {
        {jffs2_type_dirent, 12}, {jffs2_type_inode, 13},
        {jffs2_type_inode, 14}, {jffs2_type_cleanmarker, 15}
    });
    ASSERT_EQ(data.size(), 60U);
    const auto result = parse_at("jffs2", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, 60U)
        << "64 here means an already-aligned size is rounded up a whole word";
    EXPECT_TRUE(contains_text(result->description, "4")) << result->description;
}

TEST(B9bJffs2, TheSizeFieldIsReadFromDisplacementFour) {

    struct expectation {
        std::vector<jffs2_spec> nodes;
        std::uint64_t total;
    };
    const std::vector<expectation> cases{
        {{{jffs2_type_dirent, 12}, {jffs2_type_inode, 100}, {jffs2_type_inode, 40}}, 152},
        {{{jffs2_type_dirent, 64}, {jffs2_type_inode, 12}, {jffs2_type_inode, 12}}, 88},
        {{{jffs2_type_cleanmarker, 16}, {jffs2_type_cleanmarker, 16},
          {jffs2_type_cleanmarker, 16}, {jffs2_type_cleanmarker, 16}}, 64},
        {{{jffs2_type_dirent, 12}, {jffs2_type_inode, 12}, {jffs2_type_inode, 12},
          {jffs2_type_inode, 12}, {jffs2_type_inode, 12}}, 60}
    };
    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.total);
        const bytes data = jffs2_image(true, entry.nodes);
        ASSERT_EQ(data.size(), entry.total);
        const auto result = parse_at("jffs2", data, 0);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->size, entry.total);
    }
}

TEST(B9bJffs2, TheForwardScanUsesTheFirstNodesByteOrder) {

    const bytes leading = jffs2_node(true, jffs2_type_dirent, 20);
    bytes data = leading;
    for(int index = 0; index < 3; ++index) {
        append(data, jffs2_node(false, jffs2_type_inode, 20));
    }
    ASSERT_EQ(data.size(), 80U);

    const bytes big_magic{0x19, 0x85};
    ASSERT_EQ(
        std::search(
            data.begin() + static_cast<std::ptrdiff_t>(leading.size()), data.end(),
            big_magic.begin(), big_magic.end()
        ),
        data.end()
    ) << "the constructed image must contain no stray big-endian magic after node 1";

    expect_rejected(
        "jffs2", data, 0,
        "a big-endian first node followed by three little-endian nodes"
    );

    const bytes leading_le = jffs2_node(false, jffs2_type_dirent, 20);
    bytes mirrored = leading_le;
    for(int index = 0; index < 3; ++index) {
        append(mirrored, jffs2_node(true, jffs2_type_inode, 20));
    }
    const bytes little_magic{0x85, 0x19};
    ASSERT_EQ(
        std::search(
            mirrored.begin() + static_cast<std::ptrdiff_t>(leading_le.size()), mirrored.end(),
            little_magic.begin(), little_magic.end()
        ),
        mirrored.end()
    );
    expect_rejected(
        "jffs2", mirrored, 0,
        "a little-endian first node followed by three big-endian nodes"
    );

    for(bool big_endian : {true, false}) {
        SCOPED_TRACE(big_endian);
        const bytes consistent = jffs2_image(big_endian, {
            {jffs2_type_dirent, 20}, {jffs2_type_inode, 20},
            {jffs2_type_inode, 20}, {jffs2_type_inode, 20}
        });
        const auto result = parse_at("jffs2", consistent, 0);
        ASSERT_TRUE(result.has_value()) << "a consistent four-node chain must be accepted";
        EXPECT_EQ(result->size, 80U);
    }
}

TEST(B9bJffs2, AllThreeNodeTypesWorkAsTheFirstNode) {

    for(std::uint16_t type : {jffs2_type_dirent, jffs2_type_inode, jffs2_type_cleanmarker}) {
        for(bool big_endian : {true, false}) {
            SCOPED_TRACE(static_cast<int>(type) * 2 + (big_endian ? 1 : 0));
            const bytes data = jffs2_image(big_endian, {
                {type, 16}, {jffs2_type_inode, 20}, {jffs2_type_inode, 24}
            });
            ASSERT_EQ(data.size(), 60U);
            const auto result = parse_at("jffs2", data, 0);
            ASSERT_TRUE(result.has_value())
                << "node type 0x" << std::hex << type << " must be a usable chain head";
            EXPECT_EQ(result->size, 60U);
        }
    }
}

TEST(B9bJffs2, TheFirstNodeHeaderCrcMustBeTheRawKernelVariant) {

    const bytes tail = concat(
        jffs2_node(true, jffs2_type_inode, 20), jffs2_node(true, jffs2_type_inode, 20)
    );
    const bytes header = jffs2_header(true, jffs2_type_dirent, 20);
    ASSERT_EQ(header.size(), 12U);

    {
        bytes data = jffs2_node(true, jffs2_type_dirent, 20);
        append(data, tail);
        const auto result = parse_at("jffs2", data, 0);
        ASSERT_TRUE(result.has_value()) << "the raw-CRC control must be accepted";
        EXPECT_EQ(result->size, 60U);
    }

    const std::uint32_t over_eight = raw_crc32(header.data(), 8);
    struct wrong {
        const char* what;
        std::uint32_t crc;
    };
    const std::array<wrong, 5> wrongs{{
        {"the ordinary zlib CRC-32 of the same 8 bytes", standard_crc32(header.data(), 8)},
        {"the raw CRC of only the first 4 header bytes", raw_crc32(header.data(), 4)},
        {"the raw CRC of only the first 6 header bytes", raw_crc32(header.data(), 6)},
        {"the correct CRC, bit-inverted", over_eight ^ 0xFFFFFFFFU},
        {"the correct CRC plus one", over_eight + 1U}
    }};
    for(const auto& entry : wrongs) {
        SCOPED_TRACE(entry.what);
        ASSERT_NE(entry.crc, over_eight) << "this case is not actually wrong";
        bytes node = jffs2_header(true, jffs2_type_dirent, 20, entry.crc);
        node.resize(20, 0x00);
        bytes data = node;
        append(data, tail);
        ASSERT_EQ(data.size(), 60U);
        expect_rejected("jffs2", data, 0, std::string("a first node carrying ") + entry.what);
    }
}

TEST(B9bJffs2, TrailingDataDoesNotExtendTheReportedSize) {

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{64}, std::size_t{4096}}) {
        SCOPED_TRACE(padding);
        const bytes data = concat(base, bytes(padding, 0x00));
        const auto result = parse_at("jffs2", data, 0);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, 136U);
    }
}

TEST(B9bJffs2, TwoChainsMergeUntilTheGapBetweenThemExceedsMaxPageSize) {

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    ASSERT_EQ(base.size(), 136U);

    struct expectation {
        std::size_t gap;
        std::size_t results;
        std::uint64_t size;
        const char* nodes;
        bool oracle_measured;
    };
    const std::array<expectation, 7> cases{{
        {0, 1, 272, "8", true},
        {4, 1, 276, "8", true},
        {64, 1, 336, "8", true},

        {131071, 1, 131343, "8", false},
        {131072, 1, 131344, "8", true},
        {131073, 2, 136, "4", true},
        {131074, 2, 136, "4", false}
    }};

    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.gap);
        bytes data = base;
        append(data, bytes(entry.gap, 0x2E));
        append(data, base);
        ASSERT_EQ(data.size(), 272U + entry.gap);

        const auto provenance =
            entry.oracle_measured ? "oracle-measured" : "ours-measured, brackets the boundary";
        const auto results = scan_batch(data);
        ASSERT_EQ(results.size(), entry.results)
            << "a gap of " << entry.gap << " bytes must produce " << entry.results
            << " result(s); the MAX_PAGE_SIZE break is at exactly 131072 ("
            << provenance << ")";
        EXPECT_EQ(results.front().name, "jffs2");
        EXPECT_EQ(results.front().offset, 0U);
        EXPECT_EQ(results.front().size, entry.size);
        EXPECT_TRUE(contains_text(results.front().description, entry.nodes))
            << "expected " << entry.nodes << " nodes: " << results.front().description;

        if(entry.results == 2) {

            EXPECT_EQ(results[1].offset, 136U + entry.gap)
                << "the second chain is reported at its absolute file offset";
            EXPECT_EQ(results[1].size, 136U);
            EXPECT_TRUE(contains_text(results[1].description, "4"))
                << results[1].description;
            EXPECT_NE(results[0].id, results[1].id);
        }
    }
}

TEST(B9bJffs2, DetectedAtSyntheticNonZeroOffsets) {

    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{3}, std::size_t{16},
                               std::size_t{1024}, std::size_t{65536}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(base, padding);
        const auto result = parse_at("jffs2", data, padding);
        ASSERT_TRUE(result.has_value()) << "jffs2 at offset " << padding;
        EXPECT_EQ(result->offset, padding);
        EXPECT_EQ(result->size, 136U);
        expect_tier(result->confidence, tier::high, "a jffs2 image at a non-zero offset");
    }
}

TEST(B9bJffs2, TheParserIsRelativeToTheGivenOffsetNotTheChainStart) {

    const bytes data = jffs2_image(true, {
        {jffs2_type_dirent, 16}, {jffs2_type_inode, 16}, {jffs2_type_inode, 16},
        {jffs2_type_inode, 16}, {jffs2_type_inode, 16}, {jffs2_type_inode, 16}
    });
    ASSERT_EQ(data.size(), 96U);
    const auto result = parse_at("jffs2", data, 32);
    ASSERT_TRUE(result.has_value())
        << "four nodes remain from offset 32, which is more than the bar of two";
    EXPECT_EQ(result->offset, 32U);
    EXPECT_EQ(result->size, 64U) << "the span is measured from the match, not from 0";
}

TEST(B9bJffs2, AFirstNodeThatReachesOrPassesTheEndOfDataIsRejected) {

    for(std::uint32_t declared : {136U, 137U, 1024U, 0x10000U, 0x7FFFFFFFU, 0xFFFFFF00U}) {
        SCOPED_TRACE(declared);
        bytes data = jffs2_header(true, jffs2_type_dirent, declared);
        data.resize(136, 0x00);
        expect_rejected(
            "jffs2", data, 0,
            "a first jffs2 node declaring " + std::to_string(declared)
                + " bytes inside a 136-byte buffer"
        );
    }
}

TEST(B9bJffs2, AWrongMagicWordIsRejected) {
    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");

    for(std::size_t index : {std::size_t{0}, std::size_t{1}}) {
        SCOPED_TRACE(index);
        bytes data = base;
        data.at(index) = static_cast<std::uint8_t>(data.at(index) ^ 0x01U);
        expect_rejected("jffs2", data, 0, "a jffs2 node with a corrupted 0x1985 magic");
    }
}

TEST(B9bJffs2, EmptyAndShortBuffersAreRejectedWithoutReadingOutOfBounds) {
    BINWALK_LOAD_FIXTURE(base, "jffs2.bin");
    for(std::size_t length = 0; length <= 24; ++length) {
        SCOPED_TRACE(length);
        const bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(length));
        for(std::size_t offset : {std::size_t{0}, length}) {
            const auto result = parse_at("jffs2", data, offset);
            EXPECT_FALSE(result.has_value());
        }
    }

    for(std::size_t offset : {std::size_t{136}, std::size_t{137}, std::size_t{100000}}) {
        SCOPED_TRACE(offset);
        const auto result = parse_at("jffs2", base, offset);
        EXPECT_FALSE(result.has_value());
    }
}

TEST(B9bJffs2Hardening, AFirstNodeDeclaringZeroBytesTerminates) {

    bytes data = jffs2_header(true, jffs2_type_dirent, 0);
    data.resize(4096, 0x00);
    expect_prompt_rejection("jffs2", data, 0, "a jffs2 first node declaring size 0");
}

TEST(B9bJffs2Hardening, AChainOfZeroSizedNodesIsWalkedOnceAndDetected) {

    for(bool big_endian : {true, false}) {
        SCOPED_TRACE(big_endian);
        bytes data;
        for(int index = 0; index < 64; ++index) {
            append(data, jffs2_header(big_endian, jffs2_type_dirent, 0));
        }
        ASSERT_EQ(data.size(), 768U);

        const auto outcome = expect_bounded_scan(
            "jffs2", data, 0, "64 back-to-back zero-sized jffs2 nodes"
        );
        ASSERT_TRUE(outcome.parsed.has_value())
            << "upstream detects this degenerate chain; we must not detect less";
        EXPECT_EQ(outcome.parsed->offset, 0U);
        EXPECT_EQ(outcome.parsed->size, 756U);
        expect_tier(outcome.parsed->confidence, tier::high, "a zero-sized node chain");
        EXPECT_TRUE(contains_text(outcome.parsed->description, "65"))
            << "65 nodes, not 64: " << outcome.parsed->description;
        EXPECT_TRUE(contains_text(
            outcome.parsed->description, big_endian ? "big endian" : "little endian"
        )) << outcome.parsed->description;

        ASSERT_EQ(outcome.results.size(), 1U);
        EXPECT_EQ(outcome.results.front().offset, 0U);
        EXPECT_EQ(outcome.results.front().size, 756U);
    }
}

TEST(B9bJffs2Hardening, AFirstNodeDeclaringTheWholeAddressSpaceTerminates) {

    for(std::uint32_t declared : {0xFFFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFDU, 0x80000000U}) {
        SCOPED_TRACE(declared);
        bytes data = jffs2_header(true, jffs2_type_dirent, declared);
        data.resize(8192, 0x00);
        expect_prompt_rejection(
            "jffs2", data, 0,
            "a jffs2 first node declaring " + std::to_string(declared) + " bytes"
        );
    }
}

TEST(B9bJffs2Hardening, ADenseFieldOfMagicBytesTerminates) {

    struct pattern {
        const char* what;
        bytes unit;
    };
    const std::array<pattern, 4> patterns{{
        {"repeated bare 19 85", bytes{0x19, 0x85}},
        {"repeated 19 85 E0 01", bytes{0x19, 0x85, 0xE0, 0x01}},
        {"repeated 85 19 01 E0", bytes{0x85, 0x19, 0x01, 0xE0}},
        {"repeated 19 85 20 03", bytes{0x19, 0x85, 0x20, 0x03}}
    }};
    for(const auto& entry : patterns) {
        bytes data;
        data.reserve(256U * 1024U);
        while(data.size() < 256U * 1024U) {
            append(data, entry.unit);
        }
        expect_prompt_rejection("jffs2", data, 0, entry.what);
    }
}

TEST(B9bJffs2Hardening, AMillionNodeChainIsWalkedInBoundedTime) {

    bytes data;
    data.reserve(1024U * 1024U);
    while(data.size() < 1024U * 1024U) {
        append(data, jffs2_header(true, jffs2_type_cleanmarker, 12));
    }
    const auto started = std::chrono::steady_clock::now();
    const auto result = parse_at("jffs2", data, 0);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, hang_bound)
        << "walking a 1 MiB chain of 12-byte nodes took "
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
    if(result.has_value()) {
        EXPECT_LE(result->size, static_cast<std::uint64_t>(data.size()))
            << "a reported span may never exceed the data it was measured over";
        EXPECT_EQ(result->offset, 0U);
    }
}

TEST(B9bJffs2Extraction, TheDefinitionIsAnInternalStub) {
    const auto* value = signature_named("jffs2");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "jffs2 must still CARRY a definition so the CLI can report the gap; an "
        << "absent definition is indistinguishable from a format nobody thought about";
    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::internal)
        << "the gap is in OUR native extractor, not in a missing external tool. An "
        << "external definition here would mean spawning something, and the only "
        << "thing upstream spawns is Python (policy).";
    EXPECT_NE(definition.internal, nullptr)
        << "an internal definition with a null function pointer cannot report "
        << "`unsupported`; it reports nothing";
}

TEST(B9bJffs2Extraction, DryRunIsUnsupported) {
    BINWALK_LOAD_FIXTURE(data, "jffs2.bin");
    const auto* value = signature_named("jffs2");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("jffs2", 0, 136)
    );
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported)
        << "policy: the jffs2 gap is reported as `unsupported`, which is "
        << "what lets a caller tell \"not built\" from \"the data was bad\". "
        << "failure code = " << static_cast<int>(result.failure);
}

TEST_F(b9b_extraction_test, Jffs2RealExtractionIsUnsupportedAndWritesNothing) {
    BINWALK_LOAD_FIXTURE(data, "jffs2.bin");
    const auto result = run_extractor("jffs2", data, 0, 136);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported)
        << "failure code = " << static_cast<int>(result.failure);

    expect_nothing_written(result);
}

TEST(B9bYaffs, LittleEndianFixtureReproducesTheGoldenFileMap) {
    BINWALK_LOAD_FIXTURE(data, "yaffs.bin");
    ASSERT_EQ(data.size(), 135168U);
    const auto result = parse_at("yaffs", data, 0);
    ASSERT_TRUE(result.has_value()) << "yaffs.bin must be detected";
    EXPECT_EQ(result->offset, 0U) << "tests/golden/yaffs.json: offset 0";
    EXPECT_EQ(result->size, 126720U)
        << "tests/golden/yaffs.json: size 126720. Note this is NOT the file length "
        << "(135168) -- the trailing 8448 bytes are 0xFF flash filler that ends the "
        << "object-header walk, so a parser that reports the file length is wrong "
        << "in a way no all-image fixture could catch.";
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::medium, "a valid YAFFSv2 image");
    EXPECT_TRUE(contains_text(result->description, "little endian"))
        << result->description;
    EXPECT_TRUE(contains_text(result->description, "2048"))
        << "description must report the page size: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "64"))
        << "description must report the spare size: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "126720"))
        << "description must report the image size: " << result->description;
}

TEST(B9bYaffs, BigEndianFixtureIsDetectedAsBigEndian) {
    BINWALK_LOAD_FIXTURE(data, "yaffs_be.bin");
    ASSERT_EQ(data.size(), 35904U);
    const auto result = parse_at("yaffs", data, 0);
    ASSERT_TRUE(result.has_value()) << "yaffs_be.bin must be detected";
    EXPECT_EQ(result->offset, 0U);
    EXPECT_EQ(result->size, 33792U);
    expect_tier(result->confidence, tier::medium, "a big-endian YAFFSv2 image");
    EXPECT_TRUE(contains_text(result->description, "big endian"))
        << "endianness is `big` exactly when the byte at the match offset is 0: "
        << result->description;
    EXPECT_TRUE(contains_text(result->description, "2048"));
    EXPECT_TRUE(contains_text(result->description, "33792"));
}

TEST(B9bYaffs, TruncatedImageIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "yaffs_truncated.bin");
    ASSERT_EQ(data.size(), 33792U);
    ASSERT_EQ(data.at(2048), 0xFFU);
    ASSERT_EQ(data.at(31680), 0x03U) << "block 15's object header is present and valid";
    expect_rejected("yaffs", data, 0, "a yaffs image of exactly 33792 bytes");
}

TEST(B9bYaffs, ImageWithNoSpareAreaMagicIsRejected) {

    BINWALK_LOAD_FIXTURE(data, "yaffs_no_spare.bin");
    ASSERT_EQ(data.size(), 33793U);
    ASSERT_EQ(data.at(2048), 0x00U)
        << "the spare region exists; it is zeroed, not absent";
    expect_rejected("yaffs", data, 0, "a yaffs object header with no spare-area magic anywhere");
}

TEST(B9bYaffs, AlternateGeometryFixtureIsProbedNotAssumed) {
    BINWALK_LOAD_FIXTURE(data, "yaffs_alt_geometry.bin");
    ASSERT_EQ(data.size(), 34560U);
    const auto result = parse_at("yaffs", data, 0);
    ASSERT_TRUE(result.has_value()) << "yaffs_alt_geometry.bin must be detected";
    EXPECT_EQ(result->offset, 0U);

    EXPECT_EQ(result->size, 33920U);
    expect_tier(result->confidence, tier::medium, "a 512/128 YAFFSv2 image");
    EXPECT_TRUE(contains_text(result->description, "512"))
        << "page size 512, not 2048: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "128"))
        << "spare size 128, not 64: " << result->description;
    EXPECT_TRUE(contains_text(result->description, "33920")) << result->description;
    EXPECT_TRUE(contains_text(result->description, "little endian")) << result->description;
}

TEST(B9bYaffs, TheTwoGeometriesDisagreeOnBothAxesAtOnce) {

    BINWALK_LOAD_FIXTURE(standard, "yaffs.bin");
    BINWALK_LOAD_FIXTURE(alternate, "yaffs_alt_geometry.bin");
    const auto first = parse_at("yaffs", standard, 0);
    const auto second = parse_at("yaffs", alternate, 0);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->size, 126720U);
    EXPECT_EQ(second->size, 33920U);
    EXPECT_NE(first->description, second->description)
        << "the two images have different geometries; the descriptions must differ";
    EXPECT_TRUE(contains_text(first->description, "2048"));
    EXPECT_TRUE(contains_text(second->description, "512"));
}

TEST(B9bYaffs, TheAvailabilityGateIsStrictAndOneAppendedByteFlipsIt) {

    BINWALK_LOAD_FIXTURE(base, "yaffs_truncated.bin");
    ASSERT_EQ(base.size(), 33792U);
    expect_rejected("yaffs", base, 0, "a yaffs image of exactly 33792 bytes");

    for(std::size_t extra : {std::size_t{1}, std::size_t{2}, std::size_t{3}}) {
        SCOPED_TRACE(extra);
        const bytes data = concat(base, bytes(extra, 0x00));
        const auto result = parse_at("yaffs", data, 0);
        ASSERT_TRUE(result.has_value())
            << "33792 + " << extra << " bytes is past the gate and must be detected";
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, 33792U)
            << "the appended padding is not part of the image";
        expect_tier(result->confidence, tier::medium, "a just-large-enough yaffs image");
        EXPECT_TRUE(contains_text(result->description, "2048")) << result->description;
        EXPECT_TRUE(contains_text(result->description, "64")) << result->description;
        EXPECT_TRUE(contains_text(result->description, "33792")) << result->description;
    }
}

TEST(B9bYaffs, TheGateIsMeasuredFromTheMatchOffsetNotTheFileStart) {

    BINWALK_LOAD_FIXTURE(base, "yaffs_truncated.bin");
    const bytes exactly = at_offset(base, 1024);
    expect_rejected(
        "yaffs", exactly, 1024,
        "a 33792-byte yaffs image at offset 1024, with only padding before it"
    );

    const bytes one_more = at_offset(concat(base, bytes(1, 0x00)), 1024);
    const auto result = parse_at("yaffs", one_more, 1024);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 1024U);
    EXPECT_EQ(result->size, 33792U);
}

TEST(B9bYaffs, ASpareAreaMagicMustFollowThePage) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    bytes data = base;
    for(std::size_t index = 2048; index < 2054; ++index) {
        data.at(index) = 0xFF;
    }
    expect_rejected("yaffs", data, 0, "a yaffs image whose spare-area magic has been erased");

    const auto control = parse_at("yaffs", base, 0);
    ASSERT_TRUE(control.has_value());
    EXPECT_EQ(control->size, 126720U);
}

TEST(B9bYaffs, TheSpareSizeIsFoundByValidatingAHeaderAtTwoBlocks) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    ASSERT_EQ(base.at(4224), 0x03U) << "block 2's header is a directory object";
    bytes data = base;
    patch_u32le(data, 4224, 7U);
    expect_rejected(
        "yaffs", data, 0,
        "a yaffs image whose object header at (page + spare) * 2 is not parseable"
    );
}

TEST(B9bYaffs, DetectedAtSyntheticNonZeroOffsets) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    for(std::size_t padding : {std::size_t{1}, std::size_t{3}, std::size_t{512},
                               std::size_t{4096}}) {
        SCOPED_TRACE(padding);
        const bytes data = at_offset(base, padding);
        const auto result = parse_at("yaffs", data, padding);
        ASSERT_TRUE(result.has_value()) << "yaffs at offset " << padding;
        EXPECT_EQ(result->offset, padding);
        EXPECT_EQ(result->size, 126720U);
        expect_tier(result->confidence, tier::medium, "a yaffs image at a non-zero offset");
        EXPECT_TRUE(contains_text(result->description, "2048")) << result->description;
    }
}

TEST(B9bYaffs, TrailingDataDoesNotExtendTheImage) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    for(std::uint8_t filler : {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x5A}}) {
        SCOPED_TRACE(static_cast<int>(filler));
        const bytes data = concat(base, bytes(8192, filler));
        const auto result = parse_at("yaffs", data, 0);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->size, 126720U)
            << "the image size is where the object-header walk stopped, not EOF";
    }
}

TEST(B9bYaffs, AFileObjectContributesCeilingOfFileSizeOverPageBlocks) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    ASSERT_EQ(base.at(0), 0x03U) << "object 0 starts life as a directory";

    struct expectation {
        const char* what;
        std::uint32_t file_size;
        std::uint64_t image_size;
    };
    const std::array<expectation, 4> cases{{

        {"exactly 62 pages", 126976U, 133056U},

        {"61 pages plus one byte", 124929U, 133056U},

        {"exactly 60 pages", 122880U, 128832U},

        {"an empty file", 0U, 126720U}
    }};

    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.what);
        bytes data = base;
        patch_u32le(data, 0, 1U);
        patch_u32le(data, 292, entry.file_size);
        const auto result = parse_at("yaffs", data, 0);
        ASSERT_TRUE(result.has_value()) << "a file object is still a valid image head";
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, entry.image_size)
            << "126720 here means file_size was read as zero -- the usual cause is "
            << "reading it from the wrong displacement, since displacement 292 is the "
            << "only place these bytes were written";
    }
}

TEST(B9bYaffsHardening, AnOverDeclaredFileObjectIsRefusedAtThatOffsetAndFoundAtTheNext) {

    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    const std::array<std::uint32_t, 4> declared{
        {0xFFFFFFFFU, 0xFFFFF800U, 0x80000000U, 131072U}
    };
    for(std::uint32_t file_size : declared) {
        SCOPED_TRACE(file_size);
        bytes data = base;
        patch_u32le(data, 0, 1U);
        patch_u32le(data, 292, file_size);

        const auto outcome = expect_bounded_scan(
            "yaffs", data, 0,
            "a yaffs file object declaring " + std::to_string(file_size)
                + " bytes inside a 135168-byte file"
        );
        EXPECT_FALSE(outcome.parsed.has_value())
            << "the image size implied by " << file_size
            << " bytes of file data runs past EOF and must be refused AT OFFSET 0";
        ASSERT_EQ(outcome.results.size(), 1U);
        EXPECT_EQ(outcome.results.front().name, "yaffs");
        EXPECT_EQ(outcome.results.front().offset, 2112U)
            << "the surviving image starts at the next object header, one block in";
        EXPECT_EQ(outcome.results.front().size, 124608U)
            << "59 remaining objects at 2112 bytes each";
        expect_tier(outcome.results.front().confidence, tier::medium, "the surviving image");
    }
}

TEST(B9bYaffsHardening, ADenseFieldOfObjectHeaderMagicsTerminates) {

    const bytes unit{0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF};
    bytes data;
    data.reserve(256U * 1024U);
    while(data.size() < 256U * 1024U) {
        append(data, unit);
    }
    expect_prompt_rejection("yaffs", data, 0, "256 KiB of back-to-back yaffs magics");
}

TEST(B9bYaffs, EmptyAndShortBuffersAreRejectedWithoutReadingOutOfBounds) {
    BINWALK_LOAD_FIXTURE(base, "yaffs.bin");
    for(std::size_t length = 0; length <= 64; ++length) {
        SCOPED_TRACE(length);
        const bytes data(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(length));
        for(std::size_t offset : {std::size_t{0}, length}) {
            const auto result = parse_at("yaffs", data, offset);
            EXPECT_FALSE(result.has_value());
        }
    }

    for(std::size_t offset : {std::size_t{135168}, std::size_t{135169}, std::size_t{1U << 24}}) {
        SCOPED_TRACE(offset);
        const auto result = parse_at("yaffs", base, offset);
        EXPECT_FALSE(result.has_value());
    }

    ASSERT_EQ(base.at(101376), 0x03U) << "101376 == 48 * 2112 is a block boundary";
    const auto late = parse_at("yaffs", base, 101376U);
    EXPECT_FALSE(late.has_value())
        << "an object header with exactly 33792 following bytes must be refused";
}

TEST(B9bYaffsExternal, TheDefinitionMatchesUpstreamYaffs2Rs) {
    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;

    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.command, "unyaffs");
    EXPECT_EQ(definition.extension, "img")
        << "the carved file is named <name>_<HEX>.img and is what unyaffs reads";

    const std::vector<std::string> expected_arguments{"%e", "yaffs-root"};
    EXPECT_EQ(definition.arguments, expected_arguments);
    const std::vector<std::int32_t> expected_exit_codes{0};
    EXPECT_EQ(definition.exit_codes, expected_exit_codes);
    EXPECT_FALSE(definition.do_not_recurse)
        << "a yaffs image can contain further extractable artifacts";
}

TEST(B9bYaffsExternal, ThePlaceholderIsAWholeArgumentNotASubstring) {

    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    std::size_t whole = 0;
    for(const auto& argument : value->extractor_definition->arguments) {
        if(argument == "%e") {
            ++whole;
        } else {
            EXPECT_EQ(argument.find("%e"), std::string::npos)
                << "argument \"" << argument << "\" embeds the placeholder, which is "
                << "never substituted";
        }
    }
    EXPECT_EQ(whole, 1U) << "exactly one argument is the bare placeholder";
}

TEST(B9bYaffsExternal, DryRunOfAnExternalExtractorIsUnsupported) {

    BINWALK_LOAD_FIXTURE(data, "yaffs.bin");
    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, byte_view(data), probe_signature("yaffs", 0, 126720)
    );
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported)
        << "failure code = " << static_cast<int>(result.failure);
}

TEST_F(b9b_extraction_test, YaffsExtractionWithoutTheUtilityReportsUtilityNotFound) {
    BINWALK_LOAD_FIXTURE(data, "yaffs.bin");
    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    if(binwalk::external_utility_available(*value->extractor_definition)) {

        GTEST_SKIP() << "unyaffs IS installed here, so the absent branch cannot be "
                        "observed; the present branch is covered separately";
    }

    const auto result = run_extractor("yaffs", data, 0, 126720);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_not_found)
        << "policy rule 5: a missing utility is neither a build error "
        << "nor a crash, and the reason must be DISTINGUISHABLE from `utility_failed` "
        << "so the CLI can say the tool is absent rather than that the data was bad. "
        << "failure code = " << static_cast<int>(result.failure);
    expect_nothing_written(result);
}

TEST_F(b9b_extraction_test, YaffsExtractionRecoversContentWhenTheUtilityIsPresent) {
    BINWALK_LOAD_FIXTURE(data, "yaffs.bin");
    const auto* value = signature_named("yaffs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    if(!binwalk::external_utility_available(*value->extractor_definition)) {

        GTEST_SKIP() << "unyaffs is not installed; yaffs uses an EXTERNAL extractor and "
                        "policy rule 5 requires the suite to pass on a "
                        "machine with no external utilities";
    }

    const auto result = run_extractor("yaffs", data, 0, 126720);
    EXPECT_NE(result.failure, binwalk::extraction_failure::utility_not_found)
        << "external_utility_available said unyaffs is present, so the spawn must at "
        << "least have happened; failure code = " << static_cast<int>(result.failure);
    if(result.success) {
        EXPECT_FALSE(extracted_files_under(root_).empty())
            << "policy rule 4: success requires BOTH an accepted exit code "
            << "AND non-empty output";
    }
}

TEST(B9bScanner, TheScannerStampsTheNameOnEveryResult) {

    BINWALK_LOAD_FIXTURE(jffs2, "jffs2.bin");
    BINWALK_LOAD_FIXTURE(yaffs, "yaffs.bin");

    const bytes data = concat(yaffs, jffs2);
    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 2U) << "one result per image";

    EXPECT_EQ(results[0].name, "yaffs")
        << "scanner::populate() must stamp the registry name onto the result";
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, 126720U);
    EXPECT_EQ(results[1].name, "jffs2");
    EXPECT_EQ(results[1].offset, 135168U);
    EXPECT_EQ(results[1].size, 136U);
    for(const auto& value : results) {
        EXPECT_FALSE(value.extraction_declined) << value.name;
        EXPECT_FALSE(value.always_display)
            << value.name << ": upstream magic.rs says always_display = false, and "
            << "that flag is stamped after the parser returns";
        EXPECT_FALSE(value.id.empty())
            << "`id` is stamped by scanner::populate(); a parser leaves it empty";
    }
    EXPECT_NE(results[0].id, results[1].id)
        << "the extractions map is keyed by id, so two results may not share one";
}

TEST(B9bScanner, IncludeAndExcludeFilterOnTheRegisteredName) {
    BINWALK_LOAD_FIXTURE(jffs2, "jffs2.bin");
    BINWALK_LOAD_FIXTURE(yaffs, "yaffs.bin");
    const bytes data = concat(yaffs, jffs2);

    for(const auto& name : batch_names()) {
        SCOPED_TRACE(name);
        const auto included = scan_only(data, name);
        ASSERT_EQ(included.size(), 1U) << "--include=" << name << " must select exactly one";
        EXPECT_EQ(included.front().name, name);

        binwalk::scan_options options;
        options.exclude = {name};
        const binwalk::scanner scanner(batch_signatures(), options);
        const auto excluded = scanner.scan(byte_view(data));
        ASSERT_EQ(excluded.size(), 1U);
        EXPECT_NE(excluded.front().name, name) << "--exclude=" << name << " did not drop it";
    }
}

TEST(B9bScanner, OneImageProducesOneResultNotOnePerInternalMatch) {

    struct expectation {
        const char* fixture;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::array<expectation, 5> expected{{
        {"jffs2.bin", "jffs2", 0, 136},
        {"jffs2_le.bin", "jffs2", 0, 136},
        {"jffs2_at_offset.bin", "jffs2", 1024, 136},
        {"yaffs.bin", "yaffs", 0, 126720},
        {"yaffs_be.bin", "yaffs", 0, 33792}
    }};
    for(const auto& entry : expected) {
        SCOPED_TRACE(entry.fixture);
        const bytes data = load_fixture(entry.fixture);
        ASSERT_FALSE(data.empty()) << "missing tests/fixtures/" << entry.fixture;
        const auto results = scan_batch(data);
        ASSERT_EQ(results.size(), 1U)
            << "the oracle reports exactly one result for this file over the FULL "
            << "registry, so anything else is a scanner-level divergence";
        EXPECT_EQ(results.front().name, entry.name);
        EXPECT_EQ(results.front().offset, entry.offset);
        EXPECT_EQ(results.front().size, entry.size);
        EXPECT_FALSE(results.front().always_display);
        EXPECT_FALSE(results.front().extraction_declined);
        EXPECT_FALSE(results.front().id.empty());
    }
}

TEST(B9bScanner, RejectedFixturesProduceNothingThroughTheWholePipeline) {

    for(const char* fixture : {"jffs2_two_nodes.bin", "jffs2_bad_crc.bin",
                               "yaffs_truncated.bin", "yaffs_no_spare.bin"}) {
        SCOPED_TRACE(fixture);
        const bytes data = load_fixture(fixture);
        ASSERT_FALSE(data.empty()) << "missing tests/fixtures/" << fixture;
        const auto results = scan_batch(data);
        EXPECT_TRUE(results.empty())
            << "scan() reported " << results.size() << " result(s) for a file the "
            << "oracle rejects entirely";
    }
}

TEST(B9bScanner, TheZeroSizeFillIsUnreachableFromThisBatch) {

    for(const char* fixture : {"jffs2.bin", "jffs2_le.bin", "jffs2_at_offset.bin",
                               "yaffs.bin", "yaffs_be.bin", "yaffs_alt_geometry.bin"}) {
        SCOPED_TRACE(fixture);
        const bytes data = load_fixture(fixture);
        ASSERT_FALSE(data.empty()) << "missing tests/fixtures/" << fixture;
        for(const auto& result : scan_batch(data)) {
            EXPECT_GT(result.size, 0U)
                << result.name << " produced a zero-size result, which the scanner "
                << "would then extend by filling -- a path this batch does not test";
        }

        for(std::size_t offset = 0; offset + 16 <= data.size(); ++offset) {
            const auto jffs2 = parse_at("jffs2", data, offset);
            if(jffs2.has_value()) {
                ASSERT_GT(jffs2->size, 0U) << "zero-size jffs2 result at " << offset;
            }
        }
    }
}

TEST(B9bScanner, BothFormatsSurviveInOneBufferWithTheirOwnSpans) {

    BINWALK_LOAD_FIXTURE(yaffs, "yaffs.bin");
    BINWALK_LOAD_FIXTURE(jffs2, "jffs2.bin");
    bytes data = yaffs;
    append(data, bytes(777, 0x00));
    const std::uint64_t jffs2_offset = data.size();
    append(data, jffs2);

    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), 2U);
    EXPECT_EQ(results[0].name, "yaffs");
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, 126720U);
    EXPECT_EQ(results[1].name, "jffs2");
    EXPECT_EQ(results[1].offset, jffs2_offset);
    EXPECT_EQ(results[1].size, 136U);
    expect_tier(results[0].confidence, tier::medium, "yaffs in a combined buffer");
    expect_tier(results[1].confidence, tier::high, "jffs2 in a combined buffer");
}
