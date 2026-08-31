#include <binwalk/builtin.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
namespace {

std::string normalized(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    for(const char character : text) {
        const auto value = static_cast<unsigned char>(character);
        if(std::isalnum(value) != 0) {
            result.push_back(static_cast<char>(std::tolower(value)));
        }
    }
    return result;
}

bool mentions(const std::string& description, const std::string& fact) {
    return normalized(description).find(fact) != std::string::npos;
}

enum class confidence_tier { low, medium };

void expect_confidence_tier(std::uint8_t confidence, confidence_tier expected) {
    if(expected == confidence_tier::low) {
        EXPECT_LT(confidence, binwalk::confidence_medium)
            << "the oracle reports this result in the LOW confidence tier; a "
            << "higher tier changes which overlapping results survive";
    } else {
        EXPECT_GE(confidence, binwalk::confidence_medium)
            << "the oracle reports this result in the MEDIUM confidence tier";
        EXPECT_LT(confidence, binwalk::confidence_high)
            << "the oracle reports MEDIUM, not HIGH; a high-tier result wins "
            << "overlap ties that a medium-tier one loses";
    }
}

struct fixture_location {
    std::filesystem::path directory;
    std::string searched;
};

fixture_location locate_fixtures() {
    fixture_location location;
    std::vector<std::filesystem::path> starting_points;

    const std::filesystem::path source_file(__FILE__);
    if(source_file.is_absolute()) {
        starting_points.push_back(source_file.parent_path());
    }

    std::error_code error;
    const auto working_directory = std::filesystem::current_path(error);
    if(!error) {
        starting_points.push_back(working_directory);
    }

    for(const auto& starting_point : starting_points) {
        std::filesystem::path directory = starting_point;
        for(int level = 0; level < 12; ++level) {
            for(const char* relative : {"fixtures", "tests/fixtures"}) {
                const auto candidate = directory / relative;
                location.searched += candidate.string();
                location.searched += "\n";
                if(std::filesystem::exists(candidate / "crc32.bin", error)) {
                    location.directory = candidate;
                    return location;
                }
            }
            const auto parent = directory.parent_path();
            if(parent.empty() || parent == directory) {
                break;
            }
            directory = parent;
        }
    }
    return location;
}

const fixture_location& fixtures() {
    static const fixture_location location = locate_fixtures();
    return location;
}

std::vector<std::uint8_t> read_fixture(const std::string& name) {
    if(fixtures().directory.empty()) {
        return {};
    }
    const auto path = fixtures().directory / name;

    std::error_code error;
    const auto file_size = std::filesystem::file_size(path, error);
    if(error) {
        return {};
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    if(!buffer.empty()) {
        stream.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size())
        );
        if(!stream) {
            return {};
        }
    }
    return buffer;
}

std::vector<binwalk::signature_result> scan_for(
    const std::string& signature_name, const std::vector<std::uint8_t>& data
) {
    binwalk::scan_options options;
    options.include = {signature_name};
    const binwalk::scanner scanner(options);
    return scanner.scan(binwalk::byte_view(data));
}

using poke = std::pair<std::size_t, std::uint8_t>;

constexpr poke at(std::size_t offset, int value) noexcept {
    return poke(offset, static_cast<std::uint8_t>(value));
}

constexpr std::uint8_t filler_byte = 0x5A;

std::vector<std::uint8_t> build_input(
    const std::vector<std::uint8_t>& fixture,
    const std::vector<poke>& pokes,
    std::size_t truncate_to,
    std::size_t prefix
) {
    std::vector<std::uint8_t> data = fixture;
    for(const auto& entry : pokes) {
        if(entry.first < data.size()) {
            data[entry.first] = entry.second;
        }
    }
    if(truncate_to != 0 && truncate_to < data.size()) {
        data.resize(truncate_to);
    }
    if(prefix != 0) {
        std::vector<std::uint8_t> prefixed(prefix, filler_byte);
        prefixed.insert(prefixed.end(), data.begin(), data.end());
        return prefixed;
    }
    return data;
}

void expect_in_bounds(
    const std::vector<binwalk::signature_result>& results, std::size_t data_size
) {
    const auto limit = static_cast<std::uint64_t>(data_size);
    for(const auto& result : results) {
        EXPECT_LE(result.offset, limit) << "result offset is past the end of the buffer";
        if(result.offset <= limit) {
            EXPECT_LE(result.size, limit - result.offset)
                << "reported size runs past the end of the buffer; carving this "
                << "result would read out of bounds";
        }
    }
}

struct batch_entry {
    const char* name;
    bool always_display;
    bool short_signature;
    std::size_t magic_count;
};

const std::vector<batch_entry>& batch_entries() {
    static const std::vector<batch_entry> entries{
        {"crc32", false, false, 2},
        {"sha256", false, false, 2},
        {"rsa", true, false, 5},
        {"aes_sbox", false, false, 2},
        {"aes_forward_table", false, false, 1},
        {"aes_reverse_table", false, false, 1},
        {"aes_rcon", false, false, 2},
        {"aes_acceleration_table", false, false, 8},
        {"luks", false, false, 1},
        {"pkcs_der_hash", false, false, 5},
        {"dpapi", true, true, 1},
        {"md5", false, false, 2},
    };
    return entries;
}

const std::vector<binwalk::signature>& registry() {
    static const std::vector<binwalk::signature> signatures = binwalk::builtin_signatures();
    return signatures;
}

const binwalk::signature* find_signature(const std::string& name) {
    const auto found = std::find_if(
        registry().begin(),
        registry().end(),
        [&name](const binwalk::signature& value) { return value.name == name; }
    );
    return found == registry().end() ? nullptr : &*found;
}

}

TEST(B3ConstantsFixtureCorpus, IsReachableFromTheTestBinary) {
    ASSERT_FALSE(fixtures().directory.empty())
        << "could not find tests/fixtures. Every oracle-parity test in this "
        << "file needs it. Directories tried:\n"
        << fixtures().searched;
    EXPECT_FALSE(read_fixture("crc32.bin").empty());
}

TEST(B3ConstantsRegistry, EveryBatchSignatureIsRegisteredExactlyOnce) {
    for(const auto& entry : batch_entries()) {
        const auto count = std::count_if(
            registry().begin(),
            registry().end(),
            [&entry](const binwalk::signature& value) { return value.name == entry.name; }
        );
        EXPECT_EQ(count, 1)
            << "signature \"" << entry.name << "\" is registered " << count
            << " times, expected exactly once. The name is STRICT under "
            << "contract §5 and must match the frozen magic.rs order table in "
            << "lib/src/builtin.cpp character-for-character; a typo silently "
            << "removes the format from --include/--exclude.";
    }
}

TEST(B3ConstantsRegistry, BatchSignaturesFollowUpstreamRegistrationOrder) {

    std::size_t previous_index = 0;
    std::string previous_name;
    for(const auto& registered : registry()) {
        const auto found = std::find_if(
            batch_entries().begin(),
            batch_entries().end(),
            [&registered](const batch_entry& entry) { return registered.name == entry.name; }
        );
        if(found == batch_entries().end()) {
            continue;
        }
        const auto index =
            static_cast<std::size_t>(std::distance(batch_entries().begin(), found));
        EXPECT_GE(index, previous_index)
            << "\"" << registered.name << "\" is registered after \"" << previous_name
            << "\", which inverts upstream magic.rs order and would change "
            << "overlap resolution.";
        previous_index = index;
        previous_name = registered.name;
    }
}

TEST(B3ConstantsRegistry, AlwaysDisplayMatchesUpstreamMagicTable) {
    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        EXPECT_EQ(registered->always_display, entry.always_display)
            << "always_display for \"" << entry.name << "\" disagrees with "
            << "upstream magic.rs (rsa and dpapi are true, the other ten false)";
    }
}

TEST(B3ConstantsRegistry, ShortSignatureFlagMatchesUpstreamMagicTable) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        EXPECT_EQ(registered->short_signature, entry.short_signature)
            << "short_signature for \"" << entry.name << "\" disagrees with upstream magic.rs";
    }
}

TEST(B3ConstantsRegistry, MagicOffsetIsZeroForEveryBatchSignature) {
    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        EXPECT_EQ(registered->magic_offset, 0U)
            << "upstream magic.rs gives \"" << entry.name << "\" magic_offset 0";
    }
}

TEST(B3ConstantsRegistry, MagicPatternCountsMatchUpstream) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        EXPECT_EQ(registered->magic.size(), entry.magic_count)
            << "\"" << entry.name << "\" declares " << registered->magic.size()
            << " magic patterns, upstream declares " << entry.magic_count;
        for(const auto& pattern : registered->magic) {
            EXPECT_FALSE(pattern.empty())
                << "\"" << entry.name << "\" declares an empty magic pattern, which "
                << "would match at every offset in every file";
        }
    }
}

TEST(B3ConstantsRegistry, HashMagicListsAreBigEndianFirst) {

    const std::vector<std::pair<std::string, std::vector<std::uint8_t>>> big_endian_first{
        {"crc32",
         {0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96,
          0xEE, 0x0E, 0x61, 0x2C, 0x99, 0x09, 0x51, 0xBA}},
        {"sha256",
         {0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
          0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5}},
        {"md5",
         {0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
          0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee}},
    };

    for(const auto& expected : big_endian_first) {
        const auto* registered = find_signature(expected.first);
        ASSERT_NE(registered, nullptr) << "signature \"" << expected.first << "\" is not registered";
        ASSERT_GE(registered->magic.size(), 2U);
        EXPECT_EQ(registered->magic[0], expected.second)
            << "\"" << expected.first << "\" must list the BIG endian constant table "
            << "first; the endianness reported in the description is derived from "
            << "which entry matched.";
    }
}

TEST(B3ConstantsRegistry, NoBatchSignatureDeclaresAnExtractor) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        EXPECT_FALSE(registered->extractor_definition.has_value())
            << "\"" << entry.name << "\" declares an extractor; upstream magic.rs "
            << "declares extractor: None for every signature in this batch";
    }
}

namespace {

struct oracle_row {
    const char* label;
    const char* signature;
    const char* fixture;
    std::vector<poke> pokes;
    std::size_t truncate_to;
    std::size_t prefix;
    std::uint64_t offset;
    std::uint64_t size;
    confidence_tier confidence;
    bool always_display;
    std::vector<std::string> facts;
    std::vector<std::string> absent_facts;
};

const std::vector<oracle_row>& pinned_fixture_rows() {
    static const std::vector<oracle_row> rows{

        {"crc32_big_endian", "crc32", "crc32.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"big"}, {"little"}},
        {"crc32_little_endian", "crc32", "crc32_le.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"little"}, {"big"}},
        {"sha256_big_endian", "sha256", "sha256.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"big"}, {"little"}},
        {"sha256_little_endian", "sha256", "sha256_le.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"little"}, {"big"}},
        {"md5_big_endian", "md5", "md5.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"big"}, {"little"}},
        {"md5_little_endian", "md5", "md5_le.bin", {}, 0, 0,
         0, 16, confidence_tier::low, false, {"little"}, {"big"}},

        {"aes_sbox_forward", "aes_sbox", "aes_sbox.bin", {}, 0, 0,
         0, 64, confidence_tier::low, false, {"aessbox"}, {}},
        {"aes_sbox_reverse", "aes_sbox", "aes_sbox_rev.bin", {}, 0, 0,
         0, 32, confidence_tier::low, false, {"aessbox"}, {}},
        {"aes_forward_table", "aes_forward_table", "aes_forward_table.bin", {}, 0, 0,
         0, 32, confidence_tier::low, false, {"aesforwardtable"}, {}},
        {"aes_reverse_table", "aes_reverse_table", "aes_reverse_table.bin", {}, 0, 0,
         0, 32, confidence_tier::low, false, {"aesreversetable"}, {}},
        {"aes_rcon_bytes", "aes_rcon", "aes_rcon.bin", {}, 0, 0,
         0, 26, confidence_tier::low, false, {"aesrcon"}, {}},
        {"aes_rcon_u32", "aes_rcon", "aes_rcon_u32.bin", {}, 0, 0,
         0, 40, confidence_tier::low, false, {"aesrcon"}, {}},
        {"aes_acceleration_table", "aes_acceleration_table", "aes_acceleration_table.bin",
         {}, 0, 0, 0, 32, confidence_tier::low, false, {"aesaccelerationtable"}, {}},

        {"pkcs_der_sha256", "pkcs_der_hash", "pkcs_der_hash.bin", {}, 0, 0,
         0, 19, confidence_tier::medium, false, {"sha256"}, {"sha1"}},
        {"pkcs_der_sha1", "pkcs_der_hash", "pkcs_der_hash_sha1.bin", {}, 0, 0,
         0, 15, confidence_tier::medium, false, {"sha1"}, {"sha256"}},

        {"rsa_2048", "rsa", "rsa.bin", {}, 0, 0,
         0, 272, confidence_tier::medium, true,
         {"2048", "cansigntrue", "canencrypttrue", "0123456789abcdef"}, {}},
        {"rsa_1024", "rsa", "rsa_1024.bin", {}, 0, 0,
         0, 143, confidence_tier::medium, true,
         {"1024", "cansignfalse", "canencrypttrue", "fedcba9876543210"}, {}},

        {"luks_v1", "luks", "luks.bin", {}, 0, 0,
         0, 592, confidence_tier::medium, false,
         {"version1", "aes", "xtsplain64", "sha256"}, {}},
        {"luks_v2", "luks", "luks_v2.bin", {}, 0, 0,
         0, 20480, confidence_tier::medium, false,
         {"version2", "16384", "sha256"}, {}},
    };
    return rows;
}

const std::vector<oracle_row>& synthesised_positive_rows() {
    static const std::vector<oracle_row> rows{

        {"rsa_2048_length_low_end", "rsa", "rsa.bin",
         {at(13, 0x07), at(14, 0xF9)}, 0, 0,
         0, 272, confidence_tier::medium, true,
         {"2048", "cansigntrue", "canencrypttrue", "0123456789abcdef"}, {}},

        {"at_offset_crc32", "crc32", "crc32.bin", {}, 0, 7,
         7, 16, confidence_tier::low, false, {"big"}, {"little"}},
        {"at_offset_md5_little_endian", "md5", "md5_le.bin", {}, 0, 3,
         3, 16, confidence_tier::low, false, {"little"}, {"big"}},
        {"at_offset_aes_sbox", "aes_sbox", "aes_sbox.bin", {}, 0, 11,
         11, 64, confidence_tier::low, false, {"aessbox"}, {}},
        {"at_offset_aes_rcon_u32", "aes_rcon", "aes_rcon_u32.bin", {}, 0, 5,
         5, 40, confidence_tier::low, false, {"aesrcon"}, {}},
        {"at_offset_pkcs_der_sha256", "pkcs_der_hash", "pkcs_der_hash.bin", {}, 0, 5,
         5, 19, confidence_tier::medium, false, {"sha256"}, {"sha1"}},
        {"at_offset_rsa_2048", "rsa", "rsa.bin", {}, 0, 3,
         3, 272, confidence_tier::medium, true,
         {"2048", "cansigntrue", "canencrypttrue", "0123456789abcdef"}, {}},
        {"at_offset_rsa_1024", "rsa", "rsa_1024.bin", {}, 0, 9,
         9, 143, confidence_tier::medium, true,
         {"1024", "cansignfalse", "canencrypttrue", "fedcba9876543210"}, {}},
        {"at_offset_luks_v1", "luks", "luks.bin", {}, 0, 16,
         16, 592, confidence_tier::medium, false,
         {"version1", "aes", "xtsplain64", "sha256"}, {}},
        {"at_offset_luks_v2", "luks", "luks_v2.bin", {}, 0, 13,
         13, 20480, confidence_tier::medium, false,
         {"version2", "16384", "sha256"}, {}},
    };
    return rows;
}

struct oracle_row_name {
    template<typename ParamType>
    std::string operator()(const testing::TestParamInfo<ParamType>& info) const {
        return info.param.label;
    }
};

class B3ConstantsOracleParity : public testing::TestWithParam<oracle_row> {};

}

TEST_P(B3ConstantsOracleParity, MatchesTheOracle) {
    const auto& row = GetParam();
    const auto fixture = read_fixture(row.fixture);
    ASSERT_FALSE(fixture.empty()) << "fixture " << row.fixture << " could not be read";

    const auto data = build_input(fixture, row.pokes, row.truncate_to, row.prefix);
    const auto results = scan_for(row.signature, data);

    ASSERT_EQ(results.size(), 1U)
        << "the oracle reports exactly one " << row.signature << " result for this input";
    const auto& result = results.front();

    EXPECT_EQ(result.name, row.signature);
    EXPECT_EQ(result.offset, row.offset);
    EXPECT_EQ(result.size, row.size);
    expect_confidence_tier(result.confidence, row.confidence);
    EXPECT_EQ(result.always_display, row.always_display);

    EXPECT_FALSE(result.extraction_declined);
    EXPECT_FALSE(result.id.empty());
    EXPECT_FALSE(result.description.empty());
    expect_in_bounds(results, data.size());

    for(const auto& fact : row.facts) {
        EXPECT_TRUE(mentions(result.description, fact))
            << "description \"" << result.description << "\" does not carry the "
            << "substantive fact \"" << fact << "\" that the oracle reports";
    }
    for(const auto& fact : row.absent_facts) {
        EXPECT_FALSE(mentions(result.description, fact))
            << "description \"" << result.description << "\" carries \"" << fact
            << "\", which the oracle does not report for this input";
    }
}

INSTANTIATE_TEST_SUITE_P(
    PinnedFixtures,
    B3ConstantsOracleParity,
    testing::ValuesIn(pinned_fixture_rows()),
    oracle_row_name()
);

INSTANTIATE_TEST_SUITE_P(
    SynthesisedPositives,
    B3ConstantsOracleParity,
    testing::ValuesIn(synthesised_positive_rows()),
    oracle_row_name()
);

TEST(B3ConstantsEndianness, BigAndLittleVariantsReportOppositeEndianness) {
    const std::vector<std::array<std::string, 3>> pairs{
        {"crc32", "crc32.bin", "crc32_le.bin"},
        {"sha256", "sha256.bin", "sha256_le.bin"},
        {"md5", "md5.bin", "md5_le.bin"},
    };

    for(const auto& pair : pairs) {
        const auto big_data = read_fixture(pair[1]);
        const auto little_data = read_fixture(pair[2]);
        ASSERT_FALSE(big_data.empty()) << "fixture " << pair[1] << " could not be read";
        ASSERT_FALSE(little_data.empty()) << "fixture " << pair[2] << " could not be read";

        const auto big_results = scan_for(pair[0], big_data);
        const auto little_results = scan_for(pair[0], little_data);
        ASSERT_EQ(big_results.size(), 1U) << pair[1];
        ASSERT_EQ(little_results.size(), 1U) << pair[2];

        EXPECT_TRUE(mentions(big_results.front().description, "big"))
            << pair[1] << " holds the big endian constant table but is described as \""
            << big_results.front().description << "\". The two magic patterns are "
            << "probably registered in the wrong order.";
        EXPECT_FALSE(mentions(big_results.front().description, "little")) << pair[1];
        EXPECT_TRUE(mentions(little_results.front().description, "little"))
            << pair[2] << " holds the little endian constant table but is described as \""
            << little_results.front().description << "\".";
        EXPECT_FALSE(mentions(little_results.front().description, "big")) << pair[2];

        EXPECT_NE(big_results.front().description, little_results.front().description)
            << pair[0] << " reports the same description for both endiannesses, so the "
            << "endianness detection is not looking at the matched bytes at all";
    }
}

namespace {

struct magic_row {
    const char* label;
    const char* signature;
    std::vector<std::uint8_t> bytes;
    bool detected;
    std::uint64_t size;
    confidence_tier confidence;
    bool always_display;
    std::vector<std::string> facts;
};

const std::vector<magic_row>& magic_rows() {
    static const std::vector<magic_row> rows{
        {"crc32_big_endian", "crc32",
         {0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96,
          0xEE, 0x0E, 0x61, 0x2C, 0x99, 0x09, 0x51, 0xBA},
         true, 16, confidence_tier::low, false, {"big"}},
        {"crc32_little_endian", "crc32",
         {0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
          0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99},
         true, 16, confidence_tier::low, false, {"little"}},
        {"sha256_big_endian", "sha256",
         {0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
          0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5},
         true, 16, confidence_tier::low, false, {"big"}},
        {"sha256_little_endian", "sha256",
         {0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71,
          0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9},
         true, 16, confidence_tier::low, false, {"little"}},
        {"md5_big_endian", "md5",
         {0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
          0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee},
         true, 16, confidence_tier::low, false, {"big"}},
        {"md5_little_endian", "md5",
         {0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8,
          0xdb, 0x70, 0x20, 0x24, 0xee, 0xce, 0xbd, 0xc1},
         true, 16, confidence_tier::low, false, {"little"}},

        {"aes_sbox_forward", "aes_sbox",
         {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5},
         true, 8, confidence_tier::low, false, {"aessbox"}},
        {"aes_sbox_reverse", "aes_sbox",
         {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38},
         true, 8, confidence_tier::low, false, {"aessbox"}},
        {"aes_forward_table", "aes_forward_table",
         {0xC6, 0x63, 0x63, 0xA5, 0xF8, 0x7C, 0x7C, 0x84,
          0xEE, 0x77, 0x77, 0x99, 0xF6, 0x7B, 0x7B, 0x8D},
         true, 16, confidence_tier::low, false, {"aesforwardtable"}},
        {"aes_reverse_table", "aes_reverse_table",
         {0x51, 0xF4, 0xA7, 0x50, 0x7E, 0x41, 0x65, 0x53,
          0x1A, 0x17, 0xA4, 0xC3, 0x3A, 0x27, 0x5E, 0x96},
         true, 16, confidence_tier::low, false, {"aesreversetable"}},
        {"aes_rcon_bytes", "aes_rcon",
         {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36},
         true, 10, confidence_tier::low, false, {"aesrcon"}},
        {"aes_rcon_u32", "aes_rcon",
         {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
          0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
          0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
          0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
          0x1B, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00},
         true, 40, confidence_tier::low, false, {"aesrcon"}},

        {"aes_acceleration_sbox_x2", "aes_acceleration_table",
         {0xA5, 0x84, 0x99, 0x8D, 0x0D, 0xBD, 0xB1, 0x54,
          0x50, 0x03, 0xA9, 0x7D, 0x19, 0x62, 0xE6, 0x9A},
         true, 16, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_sbox_x3", "aes_acceleration_table",
         {0xC6, 0xF8, 0xEE, 0xF6, 0xFF, 0xD6, 0xDE, 0x91,
          0x60, 0x02, 0xCE, 0x56, 0xE7, 0xB5, 0x4D, 0xEC},
         true, 16, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_2", "aes_acceleration_table",
         {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
          0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
          0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_3", "aes_acceleration_table",
         {0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
          0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
          0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_9", "aes_acceleration_table",
         {0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f,
          0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
          0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_11", "aes_acceleration_table",
         {0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31,
          0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
          0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_13", "aes_acceleration_table",
         {0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23,
          0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
          0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},
        {"aes_acceleration_galois_14", "aes_acceleration_table",
         {0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a,
          0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
          0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca},
         true, 24, confidence_tier::low, false, {"aesaccelerationtable"}},

        {"pkcs_der_md5", "pkcs_der_hash",
         {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
          0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
         true, 18, confidence_tier::medium, false, {"md5"}},
        {"pkcs_der_sha1", "pkcs_der_hash",
         {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
          0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
         true, 15, confidence_tier::medium, false, {"sha1"}},
        {"pkcs_der_sha256", "pkcs_der_hash",
         {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
          0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
         true, 19, confidence_tier::medium, false, {"sha256"}},
        {"pkcs_der_sha384", "pkcs_der_hash",
         {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
          0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
         true, 19, confidence_tier::medium, false, {"sha384"}},
        {"pkcs_der_sha512", "pkcs_der_hash",
         {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
          0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04},
         true, 18, confidence_tier::medium, false, {"sha512"}},

        {"rsa_1024_magic_only", "rsa", {0x84, 0x8C, 0x03},
         false, 0, confidence_tier::medium, true, {}},
        {"rsa_2048_magic_only", "rsa", {0x85, 0x01, 0x0c, 0x03},
         false, 0, confidence_tier::medium, true, {}},
        {"rsa_3072_magic_only", "rsa", {0x85, 0x01, 0x8c, 0x03},
         false, 0, confidence_tier::medium, true, {}},
        {"rsa_4096_magic_only", "rsa", {0x85, 0x02, 0x0c, 0x03},
         false, 0, confidence_tier::medium, true, {}},
        {"rsa_8192_magic_only", "rsa", {0x85, 0x04, 0x0c, 0x03},
         false, 0, confidence_tier::medium, true, {}},
        {"luks_magic_only", "luks", {0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE},
         false, 0, confidence_tier::medium, false, {}},

        {"dpapi_magic_only", "dpapi",
         {0x01, 0x00, 0x00, 0x00, 0xD0, 0x8c, 0x9d, 0xdf, 0x01, 0x15,
          0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb},
         false, 0, confidence_tier::medium, true, {}},
    };
    return rows;
}

struct magic_row_name {
    template<typename ParamType>
    std::string operator()(const testing::TestParamInfo<ParamType>& info) const {
        return info.param.label;
    }
};

class B3ConstantsMagicOnly : public testing::TestWithParam<magic_row> {};

}

TEST_P(B3ConstantsMagicOnly, MatchesTheOracle) {
    const auto& row = GetParam();
    const auto results = scan_for(row.signature, row.bytes);
    expect_in_bounds(results, row.bytes.size());

    if(!row.detected) {
        EXPECT_TRUE(results.empty())
            << "the oracle reports no " << row.signature << " detection for these "
            << row.bytes.size() << " bytes; contract §5 makes absence as strict as presence";
        return;
    }

    ASSERT_EQ(results.size(), 1U)
        << "the oracle reports exactly one " << row.signature << " result here";
    const auto& result = results.front();
    EXPECT_EQ(result.name, row.signature);
    EXPECT_EQ(result.offset, 0U);
    EXPECT_EQ(result.size, row.size);
    expect_confidence_tier(result.confidence, row.confidence);
    EXPECT_EQ(result.always_display, row.always_display);
    EXPECT_FALSE(result.extraction_declined);
    for(const auto& fact : row.facts) {
        EXPECT_TRUE(mentions(result.description, fact))
            << "description \"" << result.description << "\" is missing \"" << fact << "\"";
    }
}

INSTANTIATE_TEST_SUITE_P(
    EveryRegisteredMagic,
    B3ConstantsMagicOnly,
    testing::ValuesIn(magic_rows()),
    magic_row_name()
);

namespace {

struct rejection_row {
    const char* label;
    const char* signature;
    const char* fixture;
    std::vector<poke> pokes;
    std::size_t truncate_to;
};

const std::vector<rejection_row>& rejection_rows() {
    static const std::vector<rejection_row> rows{

        {"luks_truncated_to_20_bytes", "luks", "luks.bin", {}, 20},

        {"luks_version_3", "luks", "luks.bin", {at(6, 0x00), at(7, 0x03)}, 0},
        {"luks_version_0", "luks", "luks.bin", {at(6, 0x00), at(7, 0x00)}, 0},

        {"luks_v1_empty_hash_fn", "luks", "luks.bin", {at(72, 0x00)}, 0},
        {"luks_v2_empty_hash_fn", "luks", "luks_v2.bin", {at(72, 0x00)}, 0},

        {"luks_v1_empty_cipher_algorithm", "luks", "luks.bin", {at(8, 0x00)}, 0},
        {"luks_v1_empty_cipher_mode", "luks", "luks.bin", {at(40, 0x00)}, 0},

        {"luks_v2_header_size_equals_minimum", "luks", "luks_v2.bin",
         {at(8, 0x00), at(9, 0x00), at(10, 0x00), at(11, 0x00),
          at(12, 0x00), at(13, 0x00), at(14, 0x0F), at(15, 0xC0)}, 0},
        {"luks_v2_header_size_below_minimum", "luks", "luks_v2.bin",
         {at(8, 0x00), at(9, 0x00), at(10, 0x00), at(11, 0x00),
          at(12, 0x00), at(13, 0x00), at(14, 0x04), at(15, 0x00)}, 0},
        {"luks_v2_header_size_equals_data_length", "luks", "luks_v2.bin",
         {at(8, 0x00), at(9, 0x00), at(10, 0x00), at(11, 0x00),
          at(12, 0x00), at(13, 0x00), at(14, 0x50), at(15, 0x00)}, 0},
        {"luks_v2_header_size_far_beyond_data", "luks", "luks_v2.bin",
         {at(8, 0x00), at(9, 0x00), at(10, 0x00), at(11, 0x00),
          at(12, 0xFF), at(13, 0xFF), at(14, 0xFF), at(15, 0xFF)}, 0},

        {"rsa_2048_terminator_not_d2", "rsa", "rsa.bin", {at(271, 0x00)}, 0},

        {"rsa_2048_usage_zero", "rsa", "rsa.bin", {at(12, 0x00)}, 0},
        {"rsa_2048_usage_three", "rsa", "rsa.bin", {at(12, 0x03)}, 0},

        {"rsa_2048_length_outside_accepted_set", "rsa", "rsa.bin",
         {at(13, 0x07), at(14, 0xF0)}, 0},

        {"rsa_2048_truncated_before_terminator", "rsa", "rsa.bin", {}, 271},

        {"rsa_1024_terminator_not_d2", "rsa", "rsa_1024.bin", {at(142, 0x00)}, 0},
        {"rsa_1024_usage_zero", "rsa", "rsa_1024.bin", {at(11, 0x00)}, 0},
        {"rsa_1024_length_outside_accepted_set", "rsa", "rsa_1024.bin",
         {at(12, 0x03), at(13, 0xF0)}, 0},
        {"rsa_1024_truncated_before_terminator", "rsa", "rsa_1024.bin", {}, 142},

        {"dpapi_description_len_odd", "dpapi", "dpapi.bin", {at(44, 0x09)}, 0},

        {"dpapi_truncated_mid_blob", "dpapi", "dpapi.bin", {}, 100},

        {"dpapi_salt_len_max", "dpapi", "dpapi.bin",
         {at(64, 0xFF), at(65, 0xFF), at(66, 0xFF), at(67, 0xFF)}, 0},
        {"dpapi_hmac_key_len_max", "dpapi", "dpapi.bin",
         {at(84, 0xFF), at(85, 0xFF), at(86, 0xFF), at(87, 0xFF)}, 0},
        {"dpapi_data_len_max", "dpapi", "dpapi.bin",
         {at(116, 0xFF), at(117, 0xFF), at(118, 0xFF), at(119, 0xFF)}, 0},
        {"dpapi_sign_len_max", "dpapi", "dpapi.bin",
         {at(152, 0xFF), at(153, 0xFF), at(154, 0xFF), at(155, 0xFF)}, 0},
    };
    return rows;
}

struct rejection_row_name {
    template<typename ParamType>
    std::string operator()(const testing::TestParamInfo<ParamType>& info) const {
        return info.param.label;
    }
};

class B3ConstantsRejection : public testing::TestWithParam<rejection_row> {};

}

TEST_P(B3ConstantsRejection, IsRejectedJustAsTheOracleRejectsIt) {
    const auto& row = GetParam();
    const auto fixture = read_fixture(row.fixture);
    ASSERT_FALSE(fixture.empty()) << "fixture " << row.fixture << " could not be read";

    const auto data = build_input(fixture, row.pokes, row.truncate_to, 0);
    const auto results = scan_for(row.signature, data);

    EXPECT_TRUE(results.empty())
        << "the oracle reports no " << row.signature << " detection for this input, so "
        << "neither may we (contract §5: absence is as strict as presence). Got "
        << results.size() << " result(s), first at offset "
        << (results.empty() ? std::uint64_t{0} : results.front().offset)
        << " described as \"" << (results.empty() ? std::string{} : results.front().description)
        << "\".";
    expect_in_bounds(results, data.size());
}

INSTANTIATE_TEST_SUITE_P(
    MalformedHeaders,
    B3ConstantsRejection,
    testing::ValuesIn(rejection_rows()),
    rejection_row_name()
);

TEST(B3ConstantsDpapi, DetectsAWellFormedBlobWhereUpstreamCannot) {
    const auto data = read_fixture("dpapi.bin");
    ASSERT_FALSE(data.empty()) << "fixture dpapi.bin could not be read";

    const auto results = scan_for("dpapi", data);

    ASSERT_EQ(results.size(), 1U)
        << "dpapi.bin is a well-formed DPAPI blob (48-byte header, an 8-byte "
        << "UTF-16 description, and a length-walk that lands exactly on EOF at "
        << "188 bytes). We detect it on purpose; the oracle cannot, because of "
        << "the two upstream defects described above.";

    const auto& result = results.front();
    EXPECT_EQ(result.name, "dpapi");
    EXPECT_EQ(result.offset, 0U);
    EXPECT_GE(result.confidence, binwalk::confidence_medium)
        << "upstream builds the result with CONFIDENCE_MEDIUM";
    EXPECT_TRUE(result.always_display)
        << "upstream magic.rs marks dpapi always_display: true";
    EXPECT_FALSE(result.extraction_declined);
    EXPECT_FALSE(result.description.empty());
    expect_in_bounds(results, data.size());

}

namespace {

struct fixture_entry {
    const char* fixture;
    const char* signature;
};

const std::vector<fixture_entry>& every_fixture() {
    static const std::vector<fixture_entry> entries{
        {"crc32.bin", "crc32"},
        {"crc32_le.bin", "crc32"},
        {"sha256.bin", "sha256"},
        {"sha256_le.bin", "sha256"},
        {"md5.bin", "md5"},
        {"md5_le.bin", "md5"},
        {"aes_sbox.bin", "aes_sbox"},
        {"aes_sbox_rev.bin", "aes_sbox"},
        {"aes_forward_table.bin", "aes_forward_table"},
        {"aes_reverse_table.bin", "aes_reverse_table"},
        {"aes_rcon.bin", "aes_rcon"},
        {"aes_rcon_u32.bin", "aes_rcon"},
        {"aes_acceleration_table.bin", "aes_acceleration_table"},
        {"pkcs_der_hash.bin", "pkcs_der_hash"},
        {"pkcs_der_hash_sha1.bin", "pkcs_der_hash"},
        {"rsa.bin", "rsa"},
        {"rsa_1024.bin", "rsa"},
        {"luks.bin", "luks"},
        {"luks_v2.bin", "luks"},
        {"dpapi.bin", "dpapi"},
    };
    return entries;
}

struct fixture_entry_name {
    template<typename ParamType>
    std::string operator()(const testing::TestParamInfo<ParamType>& info) const {
        std::string name = info.param.fixture;
        const auto dot = name.rfind('.');
        if(dot != std::string::npos) {
            name.erase(dot);
        }
        return name;
    }
};

class B3ConstantsTruncation : public testing::TestWithParam<fixture_entry> {};

}

TEST_P(B3ConstantsTruncation, EveryPrefixScansCleanlyAndInBounds) {
    const auto& entry = GetParam();
    const auto fixture = read_fixture(entry.fixture);
    ASSERT_FALSE(fixture.empty()) << "fixture " << entry.fixture << " could not be read";

    const std::size_t walk_limit = std::min<std::size_t>(fixture.size(), 96);
    for(std::size_t length = 0; length <= walk_limit; ++length) {
        const std::vector<std::uint8_t> prefix(fixture.begin(),
                                               fixture.begin() + static_cast<std::ptrdiff_t>(length));
        const auto results = scan_for(entry.signature, prefix);
        expect_in_bounds(results, prefix.size());
    }

    std::vector<std::size_t> extra{
        fixture.size() / 4, fixture.size() / 2, fixture.size() - 1, fixture.size()
    };
    for(const std::size_t boundary : {std::size_t{104}, std::size_t{143},
                                      std::size_t{188}, std::size_t{272},
                                      std::size_t{592}, std::size_t{4032},
                                      std::size_t{4033}, std::size_t{16384}}) {
        if(boundary <= fixture.size()) {
            extra.push_back(boundary - 1);
            extra.push_back(boundary);
        }
    }
    for(const std::size_t length : extra) {
        if(length > fixture.size()) {
            continue;
        }
        const std::vector<std::uint8_t> prefix(fixture.begin(),
                                               fixture.begin() + static_cast<std::ptrdiff_t>(length));
        const auto results = scan_for(entry.signature, prefix);
        expect_in_bounds(results, prefix.size());
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllFixtures,
    B3ConstantsTruncation,
    testing::ValuesIn(every_fixture()),
    fixture_entry_name()
);

TEST(B3ConstantsSafety, DegenerateBuffersScanCleanly) {

    const std::vector<std::size_t> lengths{0, 1, 2, 3, 7, 15, 16, 17, 63, 64, 1024};
    for(const auto& entry : batch_entries()) {
        for(const std::size_t length : lengths) {
            for(const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xFF}}) {
                const std::vector<std::uint8_t> data(length, fill);
                const auto results = scan_for(entry.name, data);
                expect_in_bounds(results, data.size());
            }
        }
    }
}

TEST(B3ConstantsSafety, ARepeatedMagicYieldsOneResultPerCopy) {

    constexpr std::size_t copies = 512;
    const std::vector<std::uint8_t> unit{
        0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96,
        0xEE, 0x0E, 0x61, 0x2C, 0x99, 0x09, 0x51, 0xBA
    };
    std::vector<std::uint8_t> data;
    data.reserve(unit.size() * copies);
    for(std::size_t repeat = 0; repeat < copies; ++repeat) {
        data.insert(data.end(), unit.begin(), unit.end());
    }

    const auto results = scan_for("crc32", data);
    expect_in_bounds(results, data.size());
    ASSERT_EQ(results.size(), copies)
        << "the oracle reports one crc32 result per copy of the table";

    std::vector<std::uint64_t> offsets;
    offsets.reserve(results.size());
    for(const auto& result : results) {
        EXPECT_EQ(result.size, static_cast<std::uint64_t>(unit.size()));
        offsets.push_back(result.offset);
    }
    std::sort(offsets.begin(), offsets.end());
    for(std::size_t index = 0; index < offsets.size(); ++index) {
        EXPECT_EQ(offsets[index], static_cast<std::uint64_t>(index * unit.size()));
    }
}

TEST(B3ConstantsSafety, TrailingMagicPrefixesNeverReadPastTheEnd) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = find_signature(entry.name);
        ASSERT_NE(registered, nullptr) << "signature \"" << entry.name << "\" is not registered";
        for(const auto& pattern : registered->magic) {
            for(std::size_t kept = 1; kept <= pattern.size(); ++kept) {
                std::vector<std::uint8_t> data(8, filler_byte);
                data.insert(data.end(), pattern.begin(),
                            pattern.begin() + static_cast<std::ptrdiff_t>(kept));
                const auto results = scan_for(entry.name, data);
                expect_in_bounds(results, data.size());
            }
        }
    }
}
