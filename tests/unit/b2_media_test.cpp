
#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
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
using binwalk::confidence_high;
using binwalk::confidence_medium;
using binwalk::signature;
using binwalk::signature_result;

const std::array<std::string, 12>& batch_signature_names() {
    static const std::array<std::string, 12> names{
        "bmp", "pdf", "png", "jpeg", "riff", "gif", "svg", "dxbc",
        "pem_certificate", "pem_public_key", "pem_private_key", "pcapng"
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

bool is_high_tier(std::uint8_t confidence) {
    return confidence >= confidence_high;
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

std::optional<std::vector<std::uint8_t>> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return std::nullopt;
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

std::vector<signature_result> scan_batch(byte_view data) {
    binwalk::scan_options options;
    options.include.assign(batch_signature_names().begin(), batch_signature_names().end());
    const binwalk::scanner scanner(options);
    return scanner.scan(data);
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

std::vector<std::filesystem::path> all_regular_files(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> files;
    std::error_code error;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        std::error_code is_file_error;
        if(iterator->is_regular_file(is_file_error) && !is_file_error) {
            files.push_back(iterator->path());
        }
    }
    return files;
}

class b2_media_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b2_media_";
        const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
        if(information != nullptr) {
            name += information->name();
        }
        root_ = base / name;

        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
        ASSERT_EQ(count_entries(root_), std::size_t{0});
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    std::filesystem::path root_;
};

}

#define BINWALK_REQUIRE_FIXTURES_DIR(var)                                                 \
    const auto var = find_fixtures_dir();                                                 \
    if(!(var).has_value()) {                                                              \
        GTEST_SKIP() << "tests/fixtures directory not found upward from the test "        \
                        "binary's working directory";                                     \
    }

TEST(B2Media, AllTwelveSignaturesArePresentExactlyOnce) {
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
            << "b2_media batch; found " << count << " registration(s)";
    }
}

TEST(B2MediaScanner, EachFixtureYieldsExactlyOneResultWithCorrectNameIdAlwaysDisplay) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    struct expectation {
        const char* file;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
        bool always_display;
        bool extraction_declined;
    };

    const std::array<expectation, 10> table{{
        {"gif.bin", "gif", 0, 29, false, true},
        {"svg.bin", "svg", 0, 99, false, true},
        {"dxbc.bin", "dxbc", 0, 40, false, false},
        {"pem_certificate.bin", "pem_certificate", 0, 184, false, true},
        {"pem_public_key.bin", "pem_public_key", 0, 142, true, true},
        {"pem_private_key.bin", "pem_private_key", 0, 229, true, true},
        {"pem_rsa_private_key.bin", "pem_private_key", 0, 172, true, true},
        {"pcapng.bin", "pcapng", 0, 48, false, true},
        {"png_iend_nonzero.bin", "png", 0, 49, false, true},
        {"riff_utf8_tag.bin", "riff", 0, 12, false, true},
    }};

    for(const auto& entry : table) {
        SCOPED_TRACE(entry.file);
        const auto data = read_fixture(*fixtures_dir / entry.file);
        ASSERT_FALSE(data.empty()) << "fixture failed to load: " << entry.file;
        const auto results = scan_batch(byte_view(data));
        ASSERT_EQ(results.size(), 1U) << "expected exactly one match scanning this batch's "
                                          "12 signatures only";
        EXPECT_EQ(results[0].name, entry.name);
        EXPECT_FALSE(results[0].id.empty()) << "scanner::populate() must stamp an id";
        EXPECT_EQ(results[0].offset, entry.offset);
        EXPECT_EQ(results[0].size, entry.size);
        EXPECT_EQ(results[0].always_display, entry.always_display);
        EXPECT_EQ(results[0].extraction_declined, entry.extraction_declined);
    }
}

TEST(B2MediaScanner, PemRsaPrivateKeyMagicReportsUnderThePemPrivateKeySignatureName) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_rsa_private_key.bin");
    ASSERT_FALSE(data.empty());

    const auto results = scan_batch(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "pem_private_key");
    EXPECT_TRUE(results[0].always_display);
}

TEST(B2MediaScanner, AtOffsetFixturesYieldExactlyOneResultEachAtTheExpectedOffset) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    struct expectation {
        const char* file;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::array<expectation, 3> table{{
        {"gif_at_offset.bin", "gif", 16, 29},
        {"svg_at_offset.bin", "svg", 16, 99},
        {"pcapng_at_offset.bin", "pcapng", 16, 48},
    }};
    for(const auto& entry : table) {
        SCOPED_TRACE(entry.file);
        const auto data = read_fixture(*fixtures_dir / entry.file);
        ASSERT_FALSE(data.empty());
        const auto results = scan_batch(byte_view(data));
        ASSERT_EQ(results.size(), 1U);
        EXPECT_EQ(results[0].name, entry.name);
        EXPECT_EQ(results[0].offset, entry.offset);
        EXPECT_EQ(results[0].size, entry.size);
        EXPECT_FALSE(results[0].extraction_declined);
    }
}

TEST(B2MediaScanner, PemCertificateEmbeddedYieldsPemCertificateAtOffsetSixteen) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_certificate_embedded.bin");
    ASSERT_FALSE(data.empty());
    const auto results = scan_batch(byte_view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "pem_certificate");
    EXPECT_EQ(results[0].offset, std::uint64_t{16});
    EXPECT_EQ(results[0].size, std::uint64_t{184});
    EXPECT_FALSE(results[0].always_display);
    EXPECT_FALSE(results[0].extraction_declined);
}

TEST(B2MediaGif, DirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    ASSERT_NE(def->parser, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{29});
    EXPECT_TRUE(is_high_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "gif");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{29});
    EXPECT_TRUE(is_high_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);

    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaGif, AtNonZeroOffsetDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "gif_at_offset.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 16);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{29});
    EXPECT_TRUE(is_high_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "gif");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{29});
    EXPECT_FALSE(scanned[0].extraction_declined)
        << "extraction_declined is offset==0 only -- a GIF embedded further in "
           "a larger file must NOT decline";
}

TEST(B2MediaGif, Gif87aMagicIsAcceptedIdenticallyToGif89a) {

    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto reference = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(reference.empty());
    ASSERT_EQ(reference.size(), std::size_t{29});
    ASSERT_EQ(reference.at(4), static_cast<std::uint8_t>('9'));
    std::vector<std::uint8_t> gif87 = reference;
    gif87.at(4) = static_cast<std::uint8_t>('7');

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(gif87), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->size, std::uint64_t{29});
    EXPECT_TRUE(is_high_tier(direct->confidence));
}

TEST(B2MediaGif, RejectsTruncatedBeforeFixedHeaderCompletes) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(data.empty());
    data.resize(12);

    EXPECT_TRUE(scan_include(byte_view(data), "gif").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaGif, RejectsTruncatedMidSubBlockChain) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "gif").empty());
}

TEST(B2MediaGif, RejectsNonTerminatingSubBlockChain) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.size(), std::size_t{29});
    data.at(27) = 0x01;

    EXPECT_TRUE(scan_include(byte_view(data), "gif").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaGif, RejectsWhenWidthOrHeightFieldIsTruncated) {
    auto data = ascii_bytes("GIF89a");
    data.push_back(0x10);
    EXPECT_TRUE(scan_include(byte_view(data), "gif").empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaSvg, DirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "svg.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "svg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{99});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "svg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{99});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaSvg, AtNonZeroOffsetDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "svg_at_offset.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "svg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 16);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{99});

    const auto scanned = scan_include(byte_view(data), "svg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{99});
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaSvg, RejectsWhenNoClosingTagBeforeEof) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "svg.bin");
    ASSERT_FALSE(data.empty());
    data.resize(50);

    EXPECT_TRUE(scan_include(byte_view(data), "svg").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "svg");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaSvg, TwoAdjacentHeadTagsRejectAtOffsetZeroButScannerFindsTheInnerMatch) {
    std::string text = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\">";
    ASSERT_EQ(text.size(), std::size_t{50});
    text += "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\">";
    text += "</svg>";
    const auto data = ascii_bytes(text);

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "svg");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());

    const auto direct_inner = def->parser(byte_view(data), 50);
    ASSERT_TRUE(direct_inner.has_value());
    EXPECT_EQ(direct_inner->offset, std::uint64_t{50});
    EXPECT_EQ(direct_inner->size, std::uint64_t{56});

    const auto scanned = scan_include(byte_view(data), "svg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{50});
    EXPECT_EQ(scanned[0].size, std::uint64_t{56});
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaSvg, RejectsWhenOffsetIsAtOrPastEndOfBuffer) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "svg.bin");
    ASSERT_FALSE(data.empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "svg");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), data.size()).has_value());
    EXPECT_FALSE(def->parser(byte_view(data), data.size() + 100).has_value());
}

std::vector<std::uint8_t> dxbc_header(
    std::uint32_t one,
    std::uint32_t total_size,
    std::uint32_t chunk_count
) {
    std::vector<std::uint8_t> data = ascii_bytes("DXBC");
    data.resize(4 + 16, 0);
    data.resize(4 + 16 + 4, 0);
    write_u32_le(data, 20, one);
    data.resize(4 + 16 + 4 + 4, 0);
    write_u32_le(data, 24, total_size);
    data.resize(4 + 16 + 4 + 4 + 4, 0);
    write_u32_le(data, 28, chunk_count);
    return data;
}

TEST(B2MediaDxbc, DirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "dxbc.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{40});
    EXPECT_TRUE(is_high_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "dxbc");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{40});
    EXPECT_TRUE(is_high_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);

    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaDxbc, RejectsWhenOneFieldIsNotOne) {
    auto data = dxbc_header(2, 40, 0);
    EXPECT_TRUE(scan_include(byte_view(data), "dxbc").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaDxbc, RejectsChunkCountAboveThirtyTwo) {
    auto data = dxbc_header(1, 40, 33);
    ASSERT_EQ(data.size(), std::size_t{32});

    EXPECT_TRUE(scan_include(byte_view(data), "dxbc").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaDxbc, AcceptsChunkCountAtThirtyTwoBoundaryWhenEveryOffsetIsValid) {
    auto data = dxbc_header(1, 999, 32);

    const std::size_t table_at = data.size();
    const std::size_t tag_at = table_at + (32 * 4);
    for(std::uint32_t index = 0; index < 32; ++index) {
        data.resize(data.size() + 4, 0);
        write_u32_le(data, table_at + (index * 4), static_cast<std::uint32_t>(tag_at));
    }
    append(data, ascii_bytes("SHDR"));
    ASSERT_EQ(data.size(), tag_at + 4);

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->size, std::uint64_t{999}) << "size comes from the header's total_size "
                                                    "field, not the buffer length";
}

TEST(B2MediaDxbc, RejectsChunkOffsetPointingOutsideBuffer) {
    auto data = dxbc_header(1, 40, 1);
    data.resize(data.size() + 4, 0);
    write_u32_le(data, 32, 0xFFFFFFU);

    EXPECT_TRUE(scan_include(byte_view(data), "dxbc").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaDxbc, RejectsTruncatedBeforeFixedHeaderCompletes) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "dxbc.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "dxbc").empty());
}

TEST(B2MediaDxbc, AcceptsShaderModelFiveShexChunkTag) {
    auto data = dxbc_header(1, 48, 1);
    const std::size_t table_at = data.size();
    const std::size_t tag_at = table_at + 4;
    data.resize(tag_at, 0);
    write_u32_le(data, table_at, static_cast<std::uint32_t>(tag_at));
    append(data, ascii_bytes("SHEX"));

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->size, std::uint64_t{48});
}

TEST(B2MediaPem, CertificateDirectParserMatchesOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_certificate.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_certificate");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{184});
    EXPECT_TRUE(is_high_tier(direct->confidence));
}

TEST(B2MediaPem, CertificateEmbeddedAtNonZeroOffsetDirectParserMatchesOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_certificate_embedded.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_certificate");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 16);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{184});
}

TEST(B2MediaPem, PublicKeyDirectParserMatchesOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_public_key.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_public_key");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{142});
    EXPECT_TRUE(is_high_tier(direct->confidence));
}

TEST(B2MediaPem, PrivateKeyDirectParserMatchesOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_private_key.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_private_key");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{229});
    EXPECT_TRUE(is_high_tier(direct->confidence));
}

TEST(B2MediaPem, RsaPrivateKeyDirectParserMatchesOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pem_rsa_private_key.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_private_key");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{172});
}

TEST(B2MediaPem, RejectsWhenNoEndMarkerPresent) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pem_certificate.bin");
    ASSERT_FALSE(data.empty());
    data.resize(100);

    EXPECT_TRUE(scan_include(byte_view(data), "pem_certificate").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_certificate");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPem, RejectsBelowMinimumPemLength) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pem_certificate.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "pem_certificate").empty());
}

TEST(B2MediaPem, RejectsWhenBase64BodyDoesNotDecode) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pem_certificate.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.at(30), static_cast<std::uint8_t>('o'));
    data.at(30) = static_cast<std::uint8_t>('!');

    EXPECT_TRUE(scan_include(byte_view(data), "pem_certificate").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pem_certificate");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPem, RejectsWhenBase64BodyLengthIsNotAMultipleOfFour) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pem_certificate.bin");
    ASSERT_FALSE(data.empty());

    data.insert(data.begin() + 30, static_cast<std::uint8_t>('A'));

    EXPECT_TRUE(scan_include(byte_view(data), "pem_certificate").empty());
}

TEST(B2MediaPem, RejectsUnrelatedBytesAtOffsetZero) {
    const auto data = ascii_bytes("not a pem file at all, just filler text.......");
    EXPECT_TRUE(scan_include(byte_view(data), "pem_certificate").empty());
    EXPECT_TRUE(scan_include(byte_view(data), "pem_public_key").empty());
    EXPECT_TRUE(scan_include(byte_view(data), "pem_private_key").empty());
}

TEST(B2MediaPcapng, DirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pcapng");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{48});
    EXPECT_TRUE(is_high_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "pcapng");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{48});
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaPcapng, AtNonZeroOffsetSixteenDirectParserAndScannerMatchOracle) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "pcapng_at_offset.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pcapng");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 16);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{16});
    EXPECT_EQ(direct->size, std::uint64_t{48});

    const auto scanned = scan_include(byte_view(data), "pcapng");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{16});
    EXPECT_EQ(scanned[0].size, std::uint64_t{48});
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaPcapng, DetectsAtPrefixesWhereTheOracleDivergesAndRejects) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto capture = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(capture.empty());
    ASSERT_EQ(capture.size(), std::size_t{48});

    for(const std::size_t prefix : {std::size_t{32}, std::size_t{64}, std::size_t{128}}) {
        SCOPED_TRACE(prefix);
        std::vector<std::uint8_t> data(prefix, 0);
        append(data, capture);

        const auto signatures = binwalk::builtin_signatures();
        const auto* def = find_signature(signatures, "pcapng");
        ASSERT_NE(def, nullptr);
        const auto direct = def->parser(byte_view(data), prefix);
        ASSERT_TRUE(direct.has_value())
            << "prefix " << prefix << ": this port detects a valid capture at any absolute "
            << "offset, unlike the oracle's relative-vs-absolute bug (see comment above)";
        EXPECT_EQ(direct->offset, static_cast<std::uint64_t>(prefix));
        EXPECT_EQ(direct->size, std::uint64_t{48});

        const auto scanned = scan_include(byte_view(data), "pcapng");
        ASSERT_EQ(scanned.size(), 1U);
        EXPECT_EQ(scanned[0].offset, static_cast<std::uint64_t>(prefix));
        EXPECT_EQ(scanned[0].size, std::uint64_t{48});
        EXPECT_FALSE(scanned[0].extraction_declined);
    }
}

TEST(B2MediaPcapng, RejectsSingleSectionHeaderBlockBelowTheTwoBlockMinimum) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_GE(data.size(), std::size_t{28});
    data.resize(28);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pcapng");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPcapng, RejectsTruncatedBeforeSectionStructureCompletes) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());
    data.resize(19);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
}

TEST(B2MediaPcapng, RejectsBadByteOrderMagic) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());
    write_u32_le(data, 8, 0xDEADBEEFU);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
}

TEST(B2MediaPcapng, RejectsBlockSizeBelowFooterSizeWithoutUnderflow) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());
    write_u32_le(data, 4, 2);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pcapng");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPcapng, RejectsWhenFooterDisagreesWithHeaderBlockSize) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());

    write_u32_le(data, 24, 999);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
}

TEST(B2MediaPcapng, RejectsReservedTopBitSetInBlockType) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "pcapng.bin");
    ASSERT_FALSE(data.empty());

    write_u32_le(data, 28, 0x80000001U);

    EXPECT_TRUE(scan_include(byte_view(data), "pcapng").empty());
}

std::vector<std::uint8_t> valid_bmp_bytes(std::uint32_t file_size, std::uint32_t pixel_bytes) {
    std::vector<std::uint8_t> data = ascii_bytes("BM");
    data.resize(2 + 4, 0);
    write_u32_le(data, 2, file_size);
    data.resize(2 + 4 + 4, 0);
    data.resize(2 + 4 + 4 + 4, 0);
    write_u32_le(data, 10, 54);
    data.resize(2 + 4 + 4 + 4 + 4, 0);
    write_u32_le(data, 14, 40);
    data.resize(54, 0);
    data.resize(54 + pixel_bytes, 0);
    return data;
}

TEST(B2MediaBmp, DirectParserAndScannerMatchOracle) {
    const auto data = valid_bmp_bytes(58, 4);
    ASSERT_EQ(data.size(), std::size_t{58});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "bmp");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{58});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "bmp");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{58});
    EXPECT_FALSE(scanned[0].always_display);
}

TEST(B2MediaBmp, TwoBmpsInOneBufferAreBothDetectedAtTheirOwnOffsets) {
    auto data = valid_bmp_bytes(58, 4);
    data.resize(data.size() + 1000, 0);
    const auto second = valid_bmp_bytes(70, 16);
    const auto second_offset = data.size();
    append(data, second);

    const auto scanned = scan_include(byte_view(data), "bmp");
    ASSERT_EQ(scanned.size(), 2U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{58});
    EXPECT_FALSE(scanned[0].extraction_declined);
    EXPECT_EQ(scanned[1].offset, static_cast<std::uint64_t>(second_offset));
    EXPECT_EQ(scanned[1].size, std::uint64_t{70});
    EXPECT_FALSE(scanned[1].extraction_declined);
}

TEST(B2MediaBmp, RejectsWhenFileSizeIsZero) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 2, 0);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsWhenPixelOffsetIsZero) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 10, 0);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsUnknownDibHeaderSize) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 14, 999);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsWhenPixelOffsetIsBeforeEndOfDibHeader) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 10, 53);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsWhenFileSizeExceedsAvailableData) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 2, 10000);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsWhenPixelOffsetExceedsAvailableData) {
    auto data = valid_bmp_bytes(58, 4);
    write_u32_le(data, 10, 10000);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

TEST(B2MediaBmp, RejectsTruncatedBelowMinimumHeaderSize) {
    auto data = valid_bmp_bytes(58, 4);
    data.resize(17);
    EXPECT_TRUE(scan_include(byte_view(data), "bmp").empty());
}

std::vector<std::uint8_t> valid_jpeg_bytes() {
    return {0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00, 0xFF, 0xD9};
}

TEST(B2MediaJpeg, DirectParserAndScannerMatchOracle) {
    const auto data = valid_jpeg_bytes();
    ASSERT_EQ(data.size(), std::size_t{10});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "jpeg");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{10});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "jpeg");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{10});
    EXPECT_FALSE(scanned[0].always_display);

    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaJpeg, TwoAdjacentJpegsAreBothDetectedAtAdjacentOffsets) {
    auto data = valid_jpeg_bytes();
    append(data, valid_jpeg_bytes());
    ASSERT_EQ(data.size(), std::size_t{20});

    const auto scanned = scan_include(byte_view(data), "jpeg");
    ASSERT_EQ(scanned.size(), 2U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{10});
    EXPECT_FALSE(scanned[0].extraction_declined) << "no longer the whole file";
    EXPECT_EQ(scanned[1].offset, std::uint64_t{10});
    EXPECT_EQ(scanned[1].size, std::uint64_t{10});
    EXPECT_FALSE(scanned[1].extraction_declined);
}

TEST(B2MediaJpeg, RejectsWhenMarkerPrefixIsNotFF) {
    auto data = valid_jpeg_bytes();
    data.at(2) = 0x00;
    EXPECT_TRUE(scan_include(byte_view(data), "jpeg").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "jpeg");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaJpeg, RejectsWhenMarkerLengthRunsPastEof) {
    auto data = valid_jpeg_bytes();
    data.at(4) = 0xFF;
    data.at(5) = 0xFF;
    EXPECT_TRUE(scan_include(byte_view(data), "jpeg").empty());
}

TEST(B2MediaJpeg, RejectsStartOfScanWithNoFollowingMarker) {
    std::vector<std::uint8_t> data{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02};
    append(data, std::vector<std::uint8_t>(10, 0x00));
    EXPECT_TRUE(scan_include(byte_view(data), "jpeg").empty());
}

TEST(B2MediaJpeg, RejectsTruncatedBeforeMarkerPairCompletes) {
    std::vector<std::uint8_t> data{0xFF};
    EXPECT_TRUE(scan_include(byte_view(data), "jpeg").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "jpeg");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPdf, DirectParserAndScannerMatchOracle) {
    const std::string text = "%PDF-1.4\n%" + std::string(53, 'X');
    const auto data = ascii_bytes(text);
    ASSERT_EQ(data.size(), std::size_t{63});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pdf");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{0}) << "pdf's parser never sets size; the "
                                                  "scanner widens it";
    EXPECT_TRUE(is_low_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "pdf");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{63}) << "widened to EOF";
    EXPECT_TRUE(is_low_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaPdf, DeclaresNoExtractor) {
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pdf");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->extractor_definition.has_value());
}

TEST(B2MediaPdf, RejectsWhenMinorVersionByteIsNotADigit) {
    const std::string text = "%PDF-1.X\n%more filler here.....";
    const auto data = ascii_bytes(text);
    EXPECT_TRUE(scan_include(byte_view(data), "pdf").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "pdf");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPdf, RejectsWhenNoPercentFoundBeforeOtherBytes) {
    const std::string text = "%PDF-1.4XXXXXXXX";
    const auto data = ascii_bytes(text);
    ASSERT_EQ(data.size(), std::size_t{16});
    EXPECT_TRUE(scan_include(byte_view(data), "pdf").empty());
}

TEST(B2MediaPdf, RejectsTruncatedBelowMinimumSixteenBytes) {
    const std::string text = "%PDF-1.4\n%";
    const auto data = ascii_bytes(text);
    ASSERT_LT(data.size(), std::size_t{16});
    EXPECT_TRUE(scan_include(byte_view(data), "pdf").empty());
}

TEST(B2MediaPng, IendWithNonzeroLengthIsAcceptedX8) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "png_iend_nonzero.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.size(), std::size_t{49});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "png");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{49});
    EXPECT_TRUE(is_high_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "png");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{49});
    EXPECT_TRUE(is_high_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaPng, IendLengthRunningPastEofIsRejectedX8) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "png_iend_nonzero.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.at(36), std::uint8_t{0x04});
    data.at(36) = 0xFF;

    EXPECT_TRUE(scan_include(byte_view(data), "png").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "png");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPng, RejectsWhenFirstChunkIsNotIhdr) {
    std::vector<std::uint8_t> data{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    data.resize(8 + 4, 0);
    write_u32_be(data, 8, 0);
    append(data, ascii_bytes("bad!"));
    data.resize(data.size() + 20, 0);

    EXPECT_TRUE(scan_include(byte_view(data), "png").empty());
}

TEST(B2MediaPng, RejectsIhdrWithWrongPayloadSize) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "png_iend_nonzero.bin");
    ASSERT_FALSE(data.empty());

    ASSERT_EQ(data.at(11), std::uint8_t{0x0D});
    data.at(11) = 0x0E;

    EXPECT_TRUE(scan_include(byte_view(data), "png").empty());
}

TEST(B2MediaPng, RejectsTruncatedBeforeSignatureCompletes) {
    std::vector<std::uint8_t> data{0x89, 'P', 'N', 'G'};
    EXPECT_TRUE(scan_include(byte_view(data), "png").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "png");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaPng, RejectsWhenAnyChunkLengthRunsPastEof) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto data = read_fixture(*fixtures_dir / "png_iend_nonzero.bin");
    ASSERT_FALSE(data.empty());
    data.resize(20);

    EXPECT_TRUE(scan_include(byte_view(data), "png").empty());
}

TEST(B2MediaRiff, ValidUtf8ChunkTagIsAcceptedX13) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "riff_utf8_tag.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.size(), std::size_t{12});

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "riff");
    ASSERT_NE(def, nullptr);

    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{12});
    EXPECT_TRUE(is_at_least_medium_tier(direct->confidence));

    const auto scanned = scan_include(byte_view(data), "riff");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{12});
    EXPECT_TRUE(is_at_least_medium_tier(scanned[0].confidence));
    EXPECT_FALSE(scanned[0].always_display);
    EXPECT_TRUE(scanned[0].extraction_declined);
}

TEST(B2MediaRiff, InvalidUtf8ChunkTagIsRejectedX13) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "riff_invalid_utf8_tag.bin");
    ASSERT_FALSE(data.empty());
    ASSERT_EQ(data.size(), std::size_t{12});

    EXPECT_TRUE(scan_include(byte_view(data), "riff").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "riff");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaRiff, NormalChunkWithTrailingDataDoesNotDeclineExtraction) {
    std::vector<std::uint8_t> data = ascii_bytes("RIFF");
    data.resize(8, 0);
    write_u32_le(data, 4, 20);
    append(data, ascii_bytes("WAVE"));
    data.resize(28, 0);
    data.resize(36, 0);

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "riff");
    ASSERT_NE(def, nullptr);
    const auto direct = def->parser(byte_view(data), 0);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(direct->offset, std::uint64_t{0});
    EXPECT_EQ(direct->size, std::uint64_t{28});

    const auto scanned = scan_include(byte_view(data), "riff");
    ASSERT_EQ(scanned.size(), 1U);
    EXPECT_EQ(scanned[0].offset, std::uint64_t{0});
    EXPECT_EQ(scanned[0].size, std::uint64_t{28});
    EXPECT_FALSE(scanned[0].extraction_declined);
}

TEST(B2MediaRiff, RejectsWhenDeclaredSizeExceedsAvailableData) {
    std::vector<std::uint8_t> data = ascii_bytes("RIFF");
    data.resize(8, 0);
    write_u32_le(data, 4, 0xFFFFFFFFU);
    append(data, ascii_bytes("WAVE"));

    EXPECT_TRUE(scan_include(byte_view(data), "riff").empty());
}

TEST(B2MediaRiff, RejectsTruncatedBelowTwelveBytes) {
    std::vector<std::uint8_t> data = ascii_bytes("RIFF");
    data.resize(11, 0);
    EXPECT_TRUE(scan_include(byte_view(data), "riff").empty());
    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "riff");
    ASSERT_NE(def, nullptr);
    EXPECT_FALSE(def->parser(byte_view(data), 0).has_value());
}

TEST(B2MediaExtractors, AllSevenNewFormatsDeclareInternalDoNotRecurseExtractor) {
    const std::array<const char*, 7> new_format_names{
        "gif", "svg", "dxbc", "pem_certificate", "pem_public_key", "pem_private_key", "pcapng"
    };
    const auto signatures = binwalk::builtin_signatures();
    for(const auto* name : new_format_names) {
        SCOPED_TRACE(name);
        const auto* def = find_signature(signatures, name);
        ASSERT_NE(def, nullptr);
        ASSERT_TRUE(def->extractor_definition.has_value())
            << name << " must declare an internal extractor";
        const auto& definition = *def->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
        EXPECT_NE(definition.internal, nullptr)
            << "an internal extractor with a null function pointer can only ever report "
               "extraction_failure::unsupported";
        EXPECT_TRUE(definition.command.empty())
            << "an internal extractor spawns nothing, so it must name no command";
        EXPECT_TRUE(definition.extension.empty());
        EXPECT_TRUE(definition.arguments.empty());
        EXPECT_TRUE(definition.exit_codes.empty());
        EXPECT_TRUE(definition.do_not_recurse)
            << name << " must set do_not_recurse -- these formats are not containers";
    }
}

TEST(B2MediaExtractors, DryRunOfEachOfTheSevenNewFormatsSucceedsWithCorrectSizeAndWritesNothing) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    struct expectation {
        const char* name;
        const char* file;
        std::uint64_t size;
    };
    const std::array<expectation, 7> table{{
        {"gif", "gif.bin", 29},
        {"svg", "svg.bin", 99},
        {"dxbc", "dxbc.bin", 40},
        {"pem_certificate", "pem_certificate.bin", 184},
        {"pem_public_key", "pem_public_key.bin", 142},
        {"pem_private_key", "pem_private_key.bin", 229},
        {"pcapng", "pcapng.bin", 48},
    }};

    const auto signatures = binwalk::builtin_signatures();
    for(const auto& entry : table) {
        SCOPED_TRACE(entry.name);
        const auto data = read_fixture(*fixtures_dir / entry.file);
        ASSERT_FALSE(data.empty());

        const auto* def = find_signature(signatures, entry.name);
        ASSERT_NE(def, nullptr);
        ASSERT_TRUE(def->extractor_definition.has_value());

        signature_result probe;
        probe.offset = 0;
        probe.name = entry.name;

        const auto result = binwalk::dry_run_extractor(*def->extractor_definition, byte_view(data), probe);
        EXPECT_TRUE(result.success)
            << "dry run failed with extraction_failure " << static_cast<int>(result.failure);
        ASSERT_TRUE(result.size.has_value())
            << "callers take `size` from a dry run (contract §1 rule 2)";
        EXPECT_EQ(*result.size, entry.size);
    }

    EXPECT_FALSE(std::filesystem::exists("image.gif"));
    EXPECT_FALSE(std::filesystem::exists("image.svg"));
    EXPECT_FALSE(std::filesystem::exists("shader.dxbc"));
    EXPECT_FALSE(std::filesystem::exists("pem.crt"));
    EXPECT_FALSE(std::filesystem::exists("pem.key"));
    EXPECT_FALSE(std::filesystem::exists("capture.pcapng"));
}

TEST(B2MediaExtractors, DryRunOfMalformedInputFailsAndWritesNothing) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    auto gif_data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(gif_data.empty());
    gif_data.at(27) = 0x01;

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    ASSERT_TRUE(def->extractor_definition.has_value());

    signature_result probe;
    probe.offset = 0;
    const auto result =
        binwalk::dry_run_extractor(*def->extractor_definition, byte_view(gif_data), probe);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(std::filesystem::exists("image.gif"));
}

TEST_F(b2_media_extraction_test, RealExtractionOfGifWritesTheCarvedBytes) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "gif.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "gif");
    ASSERT_NE(def, nullptr);
    ASSERT_TRUE(def->extractor_definition.has_value());

    signature_result signature;
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());
    signature.name = "gif";
    signature.id = "gif_extraction_probe";
    signature.confidence = confidence_high;

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        byte_view(data), "gif.bin", signature, *def->extractor_definition, output_root.string()
    );
    ASSERT_TRUE(result.success)
        << "extraction failed with extraction_failure " << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{29});

    const auto written = all_regular_files(output_root);
    ASSERT_EQ(written.size(), 1U) << "exactly one file should have been carved";
    const auto contents = read_file_bytes(written.front());
    ASSERT_TRUE(contents.has_value());
    EXPECT_EQ(*contents, data)
        << "extracted content is STRICT under contract §5: the written bytes must equal the "
           "carved range (here, the whole 29-byte fixture)";
}

TEST_F(b2_media_extraction_test, RealExtractionOfDxbcWritesTheCarvedBytes) {
    BINWALK_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto data = read_fixture(*fixtures_dir / "dxbc.bin");
    ASSERT_FALSE(data.empty());

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "dxbc");
    ASSERT_NE(def, nullptr);
    ASSERT_TRUE(def->extractor_definition.has_value());

    signature_result signature;
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());
    signature.name = "dxbc";
    signature.id = "dxbc_extraction_probe";
    signature.confidence = confidence_high;

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        byte_view(data), "dxbc.bin", signature, *def->extractor_definition, output_root.string()
    );
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{40});

    const auto written = all_regular_files(output_root);
    ASSERT_EQ(written.size(), 1U);
    const auto contents = read_file_bytes(written.front());
    ASSERT_TRUE(contents.has_value());
    EXPECT_EQ(*contents, data);
}

TEST_F(b2_media_extraction_test, RealExtractionOfRiffWritesTheCarvedBytes) {
    std::vector<std::uint8_t> data = ascii_bytes("RIFF");
    data.resize(8, 0);
    write_u32_le(data, 4, 20);
    append(data, ascii_bytes("WAVE"));
    data.resize(28, 0);
    data.resize(36, 0);

    const auto signatures = binwalk::builtin_signatures();
    const auto* def = find_signature(signatures, "riff");
    ASSERT_NE(def, nullptr);
    const auto parsed = def->parser(byte_view(data), 0);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(def->extractor_definition.has_value());

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        byte_view(data), "riff.bin", *parsed, *def->extractor_definition, output_root.string()
    );
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{28});

    const auto written = all_regular_files(output_root);
    ASSERT_EQ(written.size(), 1U);
    const auto contents = read_file_bytes(written.front());
    ASSERT_TRUE(contents.has_value());
    ASSERT_EQ(contents->size(), std::size_t{28});
    const std::vector<std::uint8_t> expected(data.begin(), data.begin() + 28);
    EXPECT_EQ(*contents, expected)
        << "extracted content must be exactly the carved 28-byte RIFF chunk, not the whole "
           "36-byte buffer including trailing filler";
}

TEST(B2MediaRobustness, EmptyAndOneByteInputsAreRejectedByEveryParserWithoutCrashing) {
    const auto signatures = binwalk::builtin_signatures();
    const std::vector<std::uint8_t> empty_data;
    const std::vector<std::uint8_t> one_byte_data{0x00};
    const std::vector<std::uint8_t> one_byte_nonzero{0xFF};

    for(const auto& name : batch_signature_names()) {
        SCOPED_TRACE(name);
        const auto* def = find_signature(signatures, name);
        ASSERT_NE(def, nullptr);
        ASSERT_NE(def->parser, nullptr);

        EXPECT_FALSE(def->parser(byte_view(empty_data), 0).has_value())
            << name << " must reject an empty buffer";
        EXPECT_FALSE(def->parser(byte_view(one_byte_data), 0).has_value())
            << name << " must reject a 1-byte buffer";
        EXPECT_FALSE(def->parser(byte_view(one_byte_nonzero), 0).has_value())
            << name << " must reject a 1-byte buffer (nonzero content)";

        EXPECT_TRUE(scan_include(byte_view(empty_data), name).empty());
        EXPECT_TRUE(scan_include(byte_view(one_byte_data), name).empty());
    }
}

TEST(B2MediaRobustness, OffsetPastEndOfBufferIsRejectedByEveryParserWithoutCrashing) {
    const auto signatures = binwalk::builtin_signatures();
    const std::vector<std::uint8_t> data(16, 0x41);

    for(const auto& name : batch_signature_names()) {
        SCOPED_TRACE(name);
        const auto* def = find_signature(signatures, name);
        ASSERT_NE(def, nullptr);
        EXPECT_FALSE(def->parser(byte_view(data), data.size()).has_value());
        EXPECT_FALSE(def->parser(byte_view(data), data.size() + 1000).has_value());
    }
}
