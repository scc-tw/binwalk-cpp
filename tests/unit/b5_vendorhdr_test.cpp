
#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <array>
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
using binwalk::confidence_medium;
using binwalk::signature;
using binwalk::signature_result;

const std::array<std::string, 12>& batch_signature_names() {
    static const std::array<std::string, 12> names{
        "dlob", "packimg", "chk", "cfe", "seama", "rtk", "binhdr", "tplink",
        "tplink_rtos", "uboot", "logfs", "android_bootimg"
    };
    return names;
}

const signature* find_signature(const std::vector<signature>& signatures, const std::string& name) {
    for(const auto& value : signatures) {
        if(value.name == name) {
            return &value;
        }
    }
    return nullptr;
}

bool is_low_tier(std::uint8_t confidence) {
    return confidence < confidence_medium;
}

bool is_at_least_medium_tier(std::uint8_t confidence) {
    return confidence >= confidence_medium;
}

std::optional<std::filesystem::path> find_fixtures_dir() {
    std::filesystem::path dir = std::filesystem::current_path();
    for(int depth = 0; depth < 10; ++depth) {
        std::error_code error;
        const auto candidate = dir / "tests" / "fixtures";
        if(std::filesystem::is_directory(candidate, error)) {
            return candidate;
        }
        const auto parent = dir.parent_path();
        if(parent.empty() || parent == dir) {
            break;
        }
        dir = parent;
    }
    return std::nullopt;
}

std::vector<std::uint8_t> read_fixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    return std::vector<std::uint8_t>(
        (std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>()
    );
}

void write_u32_be(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        data.at(offset + index) = static_cast<std::uint8_t>(value >> ((3 - index) * 8U));
    }
}

void write_u32_le(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    for(std::size_t index = 0; index < 4; ++index) {
        data.at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void write_u64_be(std::vector<std::uint8_t>& data, std::size_t offset, std::uint64_t value) {
    for(std::size_t index = 0; index < 8; ++index) {
        data.at(offset + index) = static_cast<std::uint8_t>(value >> ((7 - index) * 8U));
    }
}

std::vector<std::uint8_t> ascii_bytes(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void append(std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& more) {
    data.insert(data.end(), more.begin(), more.end());
}

std::vector<signature_result> scan_include(byte_view data, const std::string& name) {
    binwalk::scan_options options;
    options.include = {name};
    const binwalk::scanner scanner(options);
    return scanner.scan(data);
}

}

#define BINWALK_REQUIRE_FIXTURES_DIR(var)                                                 \
    const auto var = find_fixtures_dir();                                                 \
    if(!(var).has_value()) {                                                              \
        GTEST_SKIP() << "tests/fixtures directory not found upward from the test "        \
                        "binary's working directory";                                     \
    }

TEST(B5VendorHdr, AllTwelveSignaturesArePresentExactlyOnce) {
    const auto signatures = binwalk::builtin_signatures();
    for(const auto& name : batch_signature_names()) {
        std::size_t count = 0;
        for(const auto& value : signatures) {
            if(value.name == name) {
                ++count;
            }
        }
        EXPECT_EQ(count, 1U)
            << "signature \"" << name << "\" must be registered exactly once by the "
            << "b5_vendorhdr batch; found " << count << " registration(s)";
    }
}

TEST(B5VendorHdr, FullRegistryScanEachFixtureYieldsExactlyOneExpectedResult) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    struct expectation {
        const char* file;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::array<expectation, 16> table{{
        {"android_bootimg.bin", "android_bootimg", 0, 64},
        {"binhdr.bin", "binhdr", 0, 64},
        {"binhdr_at_offset.bin", "binhdr", 16, 48},
        {"cfe.bin", "cfe", 0, 68},
        {"cfe_at_offset.bin", "cfe", 16, 68},
        {"chk.bin", "chk", 0, 48},
        {"dlob.bin", "dlob", 0, 40},
        {"logfs.bin", "logfs", 0, 112},
        {"logfs_at_offset.bin", "logfs", 32, 112},
        {"packimg.bin", "packimg", 0, 32},
        {"rtk.bin", "rtk", 0, 32},
        {"seama.bin", "seama", 0, 32},
        {"seama_le.bin", "seama", 0, 28},
        {"tplink.bin", "tplink", 0, 512},
        {"tplink_rtos.bin", "tplink_rtos", 0, 160},
        {"uboot.bin", "uboot", 0, 36},
    }};

    const binwalk::scanner scanner;
    for(const auto& entry : table) {
        SCOPED_TRACE(entry.file);
        const auto data = read_fixture(*fixtures_dir / entry.file);
        ASSERT_FALSE(data.empty()) << "fixture failed to load: " << entry.file;
        const auto results = scanner.scan(byte_view(data));
        ASSERT_EQ(results.size(), 1U)
            << "expected exactly one match against the full registry";
        EXPECT_EQ(results[0].name, entry.name);
        EXPECT_EQ(results[0].offset, entry.offset);
        EXPECT_EQ(results[0].size, entry.size);
        EXPECT_FALSE(results[0].extraction_declined);
    }
}

TEST(B5VendorHdr, FullRegistryScanDlobBeatsSeamaAtSharedOffsetByConfidenceTier) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "dlob.bin");
    ASSERT_FALSE(data.empty());

    const binwalk::scanner scanner;
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "dlob");
    EXPECT_EQ(results[0].offset, std::uint64_t{0});
}

TEST(B5VendorHdr, FullRegistryScanSeamaBeatsDlobAtSharedOffsetBecauseDlobRejectsIt) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "seama.bin");
    ASSERT_FALSE(data.empty());

    const binwalk::scanner scanner;
    const auto results = scanner.scan(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "seama");
    EXPECT_EQ(results[0].offset, std::uint64_t{0});
}

TEST(B5VendorHdr, DlobDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "dlob.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dlob");
    ASSERT_NE(def, nullptr);
    ASSERT_NE(def->parser, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{40});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "dlob");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].name, "dlob");
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{40});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, DlobRejectsTruncatedFirstHalfOnlyHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "dlob.bin");
    ASSERT_FALSE(data.empty());
    data.resize(12);

    EXPECT_TRUE(scan_include(byte_view(data), "dlob").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dlob");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, DlobRejectsWhenSecondHalfDataSizeNotGreaterThanHeaderTotal) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "dlob.bin");
    ASSERT_FALSE(data.empty());
    write_u32_be(data, 20, 40);

    EXPECT_TRUE(scan_include(byte_view(data), "dlob").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dlob");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, PackimgDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "packimg.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "packimg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{32});
    EXPECT_TRUE(is_low_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "packimg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{32});
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, PackimgRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "packimg.bin");
    ASSERT_FALSE(data.empty());
    data.resize(16);

    EXPECT_TRUE(scan_include(byte_view(data), "packimg").empty());
}

TEST(B5VendorHdr, ChkDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "chk.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "chk");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{48});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "chk");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{48});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, ChkRejectsHeaderSizeEqualToStructSize) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "chk.bin");
    ASSERT_FALSE(data.empty());
    write_u32_be(data, 4, 40);

    EXPECT_TRUE(scan_include(byte_view(data), "chk").empty());
}

TEST(B5VendorHdr, ChkRejectsHeaderSizeAboveHundredByteCeiling) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "chk.bin");
    ASSERT_FALSE(data.empty());
    write_u32_be(data, 4, 101);

    EXPECT_TRUE(scan_include(byte_view(data), "chk").empty());
}

TEST(B5VendorHdr, ChkRejectsEmptyBoardId) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "chk.bin");
    ASSERT_FALSE(data.empty());
    data[40] = 0x00;

    EXPECT_TRUE(scan_include(byte_view(data), "chk").empty());
}

TEST(B5VendorHdr, ChkRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "chk.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "chk").empty());
}

TEST(B5VendorHdr, CfeAtFileStartDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "cfe.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "cfe");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 28);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0}) << "cfe's parser never sets size; "
                                                  "the scanner widens it";
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence))
        << "offset 0 => medium confidence";

    const auto scanned = scan_include(byte_view(data), "cfe");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{68}) << "widened to EOF - offset";
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_TRUE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, CfeAtNonZeroOffsetDirectParserAndScannerPinTheRewind) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "cfe_at_offset.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.size(), std::size_t{84});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "cfe");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 44);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{0});
    EXPECT_TRUE(is_low_tier(direct->confidence)) << "nonzero rewound offset => low confidence";

    const auto scanned = scan_include(byte_view(data), "cfe");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{68});
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_TRUE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, CfeUnderflowGuardRejectsOffsetSmallerThanRewindAtBothLevels) {
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "cfe");
    ASSERT_NE(def, nullptr);

    const std::vector<std::uint8_t> filler(40, 0);
    for(std::size_t offset = 0; offset < 28; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(def->parser(byte_view(filler), offset).has_value());
    }

    for(std::size_t magic_offset : {std::size_t{0}, std::size_t{4}, std::size_t{20}, std::size_t{27}}) {
        SCOPED_TRACE(magic_offset);
        std::vector<std::uint8_t> data(magic_offset + 256, 0);
        const auto magic = ascii_bytes("CFE1CFE1");
        for(std::size_t index = 0; index < magic.size(); ++index) {
            data[magic_offset + index] = magic[index];
        }
        EXPECT_TRUE(scan_include(byte_view(data), "cfe").empty());
    }
}

TEST(B5VendorHdr, CfeRewindPositionSweep) {
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "cfe");
    ASSERT_NE(def, nullptr);

    for(std::size_t prefix : {std::size_t{0}, std::size_t{1}, std::size_t{16}, std::size_t{100}}) {
        SCOPED_TRACE(prefix);

        std::vector<std::uint8_t> data(prefix + 28, 0);
        append(data, ascii_bytes("CFE1CFE1"));
        data.resize(prefix + 68, 0);

        const auto direct = def->parser(byte_view(data), prefix + 28);
        ASSERT_TRUE(direct.has_value());
        EXPECT_EQ(direct->offset, static_cast<std::uint64_t>(prefix));
        if(prefix == 0) {
            EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));
        } else {
            EXPECT_TRUE(is_low_tier(direct->confidence));
        }
    }
}

TEST(B5VendorHdr, CfeAcceptsMagicEvenWithNoTrailingData) {
    std::vector<std::uint8_t> data(28, 0);
    append(data, ascii_bytes("CFE1CFE1"));
    ASSERT_EQ(data.size(), std::size_t{36});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "cfe");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(data), 28);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "cfe");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{36});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
}

TEST(B5VendorHdr, SeamaBigEndianMagicDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "seama.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "seama");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{32});
    EXPECT_TRUE(is_low_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "seama");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{32});
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_TRUE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, SeamaLittleEndianMagicDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "seama_le.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "seama");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{28});
    EXPECT_TRUE(is_low_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "seama");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{28});
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_TRUE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, SeamaRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "seama.bin");
    ASSERT_FALSE(data.empty());
    data.resize(8);

    EXPECT_TRUE(scan_include(byte_view(data), "seama").empty());
}

TEST(B5VendorHdr, RtkDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "rtk.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "rtk");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{32});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "rtk");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{32});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, RtkRejectsImageSizeMismatch) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "rtk.bin");
    ASSERT_FALSE(data.empty());
    write_u32_le(data, 4, 63);

    EXPECT_TRUE(scan_include(byte_view(data), "rtk").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "rtk");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, RtkRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "rtk.bin");
    ASSERT_FALSE(data.empty());
    data.resize(16);

    EXPECT_TRUE(scan_include(byte_view(data), "rtk").empty());
}

TEST(B5VendorHdr, RtkScannerRejectsMagicAwayFromFixedOffsetZero) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto valid = read_fixture(*fixtures_dir / "rtk.bin");
    ASSERT_FALSE(valid.empty());

    std::vector<std::uint8_t> data(8, 0);
    append(data, valid);

    EXPECT_TRUE(scan_include(byte_view(data), "rtk").empty());
}

TEST(B5VendorHdr, BinhdrAtFileStartDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "binhdr");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 14);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0}) << "binhdr's parser never sets size; "
                                                  "the scanner widens it";
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "binhdr");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{64});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, BinhdrAtNonZeroOffsetDirectParserAndScannerPinTheRewind) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "binhdr_at_offset.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "binhdr");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 30);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{0});

    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "binhdr");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{48});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, BinhdrUnderflowGuardRejectsOffsetSmallerThanRewindAtBothLevels) {
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "binhdr");
    ASSERT_NE(def, nullptr);

    const std::vector<std::uint8_t> filler(40, 0);
    for(std::size_t offset = 0; offset < 14; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(def->parser(byte_view(filler), offset).has_value());
    }

    for(std::size_t magic_offset : {std::size_t{0}, std::size_t{4}, std::size_t{10}, std::size_t{13}}) {
        SCOPED_TRACE(magic_offset);
        std::vector<std::uint8_t> data(magic_offset + 256, 0);
        data[magic_offset + 0] = 'U';
        data[magic_offset + 1] = '2';
        data[magic_offset + 2] = 'N';
        data[magic_offset + 3] = 'D';
        EXPECT_TRUE(scan_include(byte_view(data), "binhdr").empty());
    }
}

TEST(B5VendorHdr, BinhdrRewindPositionSweep) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto header = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(header.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "binhdr");
    ASSERT_NE(def, nullptr);

    for(std::size_t prefix : {std::size_t{0}, std::size_t{1}, std::size_t{16}, std::size_t{100}}) {
        SCOPED_TRACE(prefix);
        std::vector<std::uint8_t> data(prefix, 0);
        append(data, header);

        const auto direct = def->parser(byte_view(data), prefix + 14);
        ASSERT_TRUE(direct.has_value());
        EXPECT_EQ(direct->offset, static_cast<std::uint64_t>(prefix));
    }
}

TEST(B5VendorHdr, BinhdrRejectsNonZeroReservedField) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(data.empty());
    write_u32_le(data, 4, 1);

    EXPECT_TRUE(scan_include(byte_view(data), "binhdr").empty());
}

TEST(B5VendorHdr, BinhdrRejectsUnknownHardwareId) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(data.empty());
    data[18] = 0xFF;

    EXPECT_TRUE(scan_include(byte_view(data), "binhdr").empty());
}

TEST(B5VendorHdr, BinhdrRejectsNulInsideBoardId) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(data.empty());
    data[1] = 0x00;

    EXPECT_TRUE(scan_include(byte_view(data), "binhdr").empty());
}

TEST(B5VendorHdr, BinhdrRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "binhdr.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "binhdr").empty());
}

TEST(B5VendorHdr, TplinkDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "tplink.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "tplink");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{512});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "tplink");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{512});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, TplinkRejectsNonZeroReservedFieldsAtEachKnownOffset) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto base = read_fixture(*fixtures_dir / "tplink.bin");
    ASSERT_FALSE(base.empty());

    for(std::size_t offset : {std::size_t{72}, std::size_t{92}, std::size_t{112}, std::size_t{158}}) {
        SCOPED_TRACE(offset);
        auto data = base;
        data[offset] = 1;
        EXPECT_TRUE(scan_include(byte_view(data), "tplink").empty());
    }
}

TEST(B5VendorHdr, TplinkAcceptsNonZeroChecksumByteAtOffsetNinetySix) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "tplink.bin");
    ASSERT_FALSE(data.empty());
    data[96] = 1;

    const auto scanned = scan_include(byte_view(data), "tplink");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].name, "tplink");
}

TEST(B5VendorHdr, TplinkRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "tplink.bin");
    ASSERT_FALSE(data.empty());
    data.resize(400);

    EXPECT_TRUE(scan_include(byte_view(data), "tplink").empty());
}

TEST(B5VendorHdr, TplinkRtosDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "tplink_rtos.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "tplink_rtos");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0}) << "tplink_rtos's parser never sets "
                                                  "size; the scanner widens it";
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "tplink_rtos");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{160});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, TplinkRtosRejectsWrongSecondMagic) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "tplink_rtos.bin");
    ASSERT_FALSE(data.empty());
    write_u32_be(data, 20, 0x494D4731U);

    EXPECT_TRUE(scan_include(byte_view(data), "tplink_rtos").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "tplink_rtos");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, TplinkRtosRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "tplink_rtos.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "tplink_rtos").empty());
}

TEST(B5VendorHdr, UbootDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "uboot.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "uboot");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{36});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "uboot");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{36});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_TRUE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, UbootRejectsNonDigitAfterMagic) {
    const auto data = ascii_bytes("U-Boot X-not-a-version");

    EXPECT_TRUE(scan_include(byte_view(data), "uboot").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "uboot");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, UbootRejectsWhenMagicEndsExactlyAtEOF) {
    const auto data = ascii_bytes("U-Boot ");
    ASSERT_EQ(data.size(), std::size_t{7});

    EXPECT_TRUE(scan_include(byte_view(data), "uboot").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "uboot");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B5VendorHdr, UbootAcceptsVersionStringRunningToEOFWithoutNulTerminator) {
    auto data = ascii_bytes("U-Boot ");
    append(data, ascii_bytes("2019.04-rc4-no-terminator"));

    const auto scanned = scan_include(byte_view(data), "uboot");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{25});
}

TEST(B5VendorHdr, UbootSizeIsUncappedEvenForAVeryLongVersionString) {
    auto data = ascii_bytes("U-Boot ");
    const std::vector<std::uint8_t> version(201, static_cast<std::uint8_t>('9'));
    append(data, version);
    data.push_back(0x00);

    const auto scanned = scan_include(byte_view(data), "uboot");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{201});
}

TEST(B5VendorHdr, LogfsAtFileStartDirectParserAndScannerPinTheRewind) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "logfs");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 24);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{112}) << "logfs reports the declared "
                                                    "filesystem_size directly, "
                                                    "not a widened value";
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "logfs");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{112});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, LogfsAtNonZeroOffsetDirectParserAndScannerPinTheRewind) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "logfs_at_offset.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "logfs");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 56);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{32});
    EXPECT_EQ(direct->size, std::uint64_t{112});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "logfs");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{32});
    EXPECT_EQ(scanned[0].size, std::uint64_t{112});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, LogfsUnderflowGuardRejectsOffsetSmallerThanRewindAtBothLevels) {
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "logfs");
    ASSERT_NE(def, nullptr);

    const std::vector<std::uint8_t> filler(100, 0);
    for(std::size_t offset = 0; offset < 24; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(def->parser(byte_view(filler), offset).has_value());
    }

    for(std::size_t magic_offset : {std::size_t{0}, std::size_t{8}, std::size_t{23}}) {
        SCOPED_TRACE(magic_offset);
        std::vector<std::uint8_t> data(magic_offset + 256, 0);
        const std::vector<std::uint8_t> magic{0x7A, 0x3A, 0x8E, 0x5C, 0xB9, 0xD5, 0xBF, 0x67};
        for(std::size_t index = 0; index < magic.size(); ++index) {
            data[magic_offset + index] = magic[index];
        }
        EXPECT_TRUE(scan_include(byte_view(data), "logfs").empty());
    }
}

TEST(B5VendorHdr, LogfsRewindPositionSweep) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto header = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(header.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "logfs");
    ASSERT_NE(def, nullptr);

    for(std::size_t prefix : {std::size_t{0}, std::size_t{1}, std::size_t{16}, std::size_t{100}}) {
        SCOPED_TRACE(prefix);
        std::vector<std::uint8_t> data(prefix, 0);
        append(data, header);

        const auto direct = def->parser(byte_view(data), prefix + 24);
        ASSERT_TRUE(direct.has_value());
        EXPECT_EQ(direct->offset, static_cast<std::uint64_t>(prefix));
        EXPECT_EQ(direct->size, std::uint64_t{112});
    }
}

TEST(B5VendorHdr, LogfsRejectsNonZeroPad0) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(data.empty());
    data[42] = 0x01;

    EXPECT_TRUE(scan_include(byte_view(data), "logfs").empty());
}

TEST(B5VendorHdr, LogfsRejectsNonZeroPad1) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(data.empty());
    data[46] = 0x01;

    EXPECT_TRUE(scan_include(byte_view(data), "logfs").empty());
}

TEST(B5VendorHdr, LogfsRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(data.empty());
    data.resize(60);

    EXPECT_TRUE(scan_include(byte_view(data), "logfs").empty());
}

TEST(B5VendorHdr, LogfsOversizedDeclaredSizeIsUnclampedAtParserLevelButRejectedByScanner) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "logfs.bin");
    ASSERT_FALSE(data.empty());
    write_u64_be(data, 48, std::uint64_t{0x10000000});

    EXPECT_TRUE(scan_include(byte_view(data), "logfs").empty())
        << "scanner must drop a result whose offset+size exceeds the file";

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "logfs");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(data), 24);
    ASSERT_TRUE(direct.has_value())
        << "the parser itself does not bound-check the declared size against "
           "available data -- upstream does not either";
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0x10000000});
}

TEST(B5VendorHdr, AndroidBootimgAtFileStartDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "android_bootimg.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "android_bootimg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0}) << "android_bootimg's parser never "
                                                  "sets size; the scanner widens it";
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence)) << "offset 0 => medium";

    const auto scanned = scan_include(byte_view(data), "android_bootimg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{64});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, AndroidBootimgAtNonZeroOffsetDirectParserAndScannerAreLowConfidence) {
    std::vector<std::uint8_t> data(16, 0x99);
    append(data, ascii_bytes("ANDROID!"));
    data.resize(80, 0);
    write_u32_le(data, 24, 4096);
    write_u32_le(data, 28, 0x10008000);
    write_u32_le(data, 32, 2048);
    write_u32_le(data, 36, 0x11000000);
    ASSERT_EQ(data.size(), std::size_t{80});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "android_bootimg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 16);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{0});
    EXPECT_TRUE(is_low_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "android_bootimg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{64});
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B5VendorHdr, AndroidBootimgRejectsTruncatedHeader) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "android_bootimg.bin");
    ASSERT_FALSE(data.empty());
    data.resize(12);

    EXPECT_TRUE(scan_include(byte_view(data), "android_bootimg").empty());
}

TEST(B5VendorHdr, AllTwelveParsersRejectEmptyAndOneByteInputWithoutCrashing) {
    const auto signatures = binwalk::builtin_signatures();
    const std::vector<std::uint8_t> empty_data;
    const std::vector<std::uint8_t> one_byte{0xFF};

    for(const auto& name : batch_signature_names()) {
        SCOPED_TRACE(name);
        const auto* def = find_signature(signatures, name);
        ASSERT_NE(def, nullptr) << "signature not registered: " << name;
        ASSERT_NE(def->parser, nullptr) << "no parser bound for: " << name;

        EXPECT_FALSE(def->parser(byte_view(empty_data), 0).has_value())
            << name << " must reject empty input without crashing";
        EXPECT_FALSE(def->parser(byte_view(one_byte), 0).has_value())
            << name << " must reject 1-byte input without crashing";
    }
}
