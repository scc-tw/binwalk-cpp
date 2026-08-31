#include <binwalk/scanner.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace {

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

} // namespace

TEST(Scanner, FindsAndValidatesPng) {
    const auto data = minimal_png();
    const binwalk::scanner scanner;
    const auto results = scanner.scan(binwalk::byte_view(data));

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "png");
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, data.size());
    EXPECT_EQ(results[0].confidence, binwalk::confidence_high);
    EXPECT_TRUE(results[0].extraction_declined);
    EXPECT_FALSE(results[0].id.empty());
}

TEST(Scanner, RejectsTruncatedPng) {
    auto data = minimal_png();
    data.resize(20);
    const binwalk::scanner scanner;

    EXPECT_TRUE(scanner.scan(binwalk::byte_view(data)).empty());
}

TEST(Scanner, RejectsBmpWhosePixelDataOverlapsItsDibHeader) {
    std::vector<std::uint8_t> data(64, 0);
    data[0] = 'B';
    data[1] = 'M';
    data[2] = 64;
    data[10] = 20;
    data[14] = 40;

    const binwalk::scanner scanner;
    EXPECT_TRUE(scanner.scan(binwalk::byte_view(data)).empty());
}

TEST(Scanner, FindsPdfAndInfersItsSize) {
    const std::vector<std::uint8_t> data{
        '%', 'P', 'D', 'F', '-', '1', '.', '7', '\n', '%', 0, 0, 0, 0, 0, 0
    };
    const binwalk::scanner scanner;
    const auto results = scanner.scan(binwalk::byte_view(data));

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "pdf");
    EXPECT_EQ(results[0].size, data.size());
    EXPECT_EQ(results[0].description, "PDF document, version 1.7");
}

TEST(Scanner, WalksJpegMarkersToTheEndOfImage) {
    const std::vector<std::uint8_t> data{
        0xff, 0xd8, 0xff, 0xdb, 0x00, 0x04, 0x00, 0x00, 0xff, 0xd9
    };
    const binwalk::scanner scanner;
    const auto results = scanner.scan(binwalk::byte_view(data));

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "jpeg");
    EXPECT_EQ(results[0].size, data.size());
    EXPECT_TRUE(results[0].extraction_declined);
}

TEST(Scanner, ValidatesAndExtractsGzipWithTheNativeZlibBackend) {
    const std::vector<std::uint8_t> data{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00,
        0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00
    };
    const auto output_root = std::filesystem::temp_directory_path()
        / "binwalk_cpp_gzip_test";
    std::error_code error;
    std::filesystem::remove_all(output_root, error);

    const binwalk::scanner scanner;
    const auto analysis = scanner.analyze(
        binwalk::byte_view(data), "fixture.gz", true, output_root.string()
    );

    ASSERT_EQ(analysis.file_map.size(), 1U);
    EXPECT_EQ(analysis.file_map[0].name, "gzip");
    EXPECT_EQ(analysis.file_map[0].size, data.size());
    EXPECT_EQ(analysis.file_map[0].confidence, binwalk::confidence_high);
    ASSERT_EQ(analysis.extractions.size(), 1U);
    const auto& extraction = analysis.extractions.begin()->second;
    EXPECT_TRUE(extraction.success);
    EXPECT_EQ(extraction.size, 7U);

    const auto decompressed = std::filesystem::path(extraction.output_directory)
        / "decompressed.bin";
    ASSERT_EQ(std::filesystem::file_size(decompressed), 5U);
    std::filesystem::remove_all(output_root, error);
}

TEST(Scanner, ParsesRiffChunkTypeAndSize) {
    const std::vector<std::uint8_t> data{
        'R', 'I', 'F', 'F', 0x04, 0x00, 0x00, 0x00, 'W', 'A', 'V', 'E'
    };
    const binwalk::scanner scanner;
    const auto results = scanner.scan(binwalk::byte_view(data));

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "riff");
    EXPECT_EQ(results[0].size, data.size());
    EXPECT_TRUE(results[0].extraction_declined);
}

TEST(Scanner, ParsesMbrAtItsFixedMagicOffset) {
    std::vector<std::uint8_t> data(2048, 0);
    data[446 + 4] = 0x83;
    data[446 + 8] = 1;
    data[446 + 12] = 3;
    data[510] = 0x55;
    data[511] = 0xaa;

    const binwalk::scanner scanner;
    const auto results = scanner.scan(binwalk::byte_view(data));

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].name, "mbr");
    EXPECT_EQ(results[0].offset, 0U);
    EXPECT_EQ(results[0].size, data.size());
    EXPECT_NE(results[0].description.find("partition: Linux"), std::string::npos);
}

TEST(Scanner, AnalyzeRunsTheRegisteredInternalExtractor) {
    auto image = minimal_png();
    std::vector<std::uint8_t> data{0xaa, 0xbb};
    data.insert(data.end(), image.begin(), image.end());

    const auto output_root = std::filesystem::temp_directory_path()
        / "binwalk_cpp_extraction_test";
    std::error_code error;
    std::filesystem::remove_all(output_root, error);

    const binwalk::scanner scanner;
    const auto analysis = scanner.analyze(
        binwalk::byte_view(data), "fixture.bin", true, output_root.string()
    );

    ASSERT_EQ(analysis.file_map.size(), 1U);
    ASSERT_EQ(analysis.extractions.size(), 1U);
    const auto& extraction = analysis.extractions.begin()->second;
    EXPECT_TRUE(extraction.success);
    EXPECT_EQ(extraction.extractor, "png_built_in");
    EXPECT_TRUE(extraction.do_not_recurse);
    EXPECT_EQ(
        std::filesystem::file_size(
            std::filesystem::path(extraction.output_directory) / "image.png"
        ),
        image.size()
    );

    std::filesystem::remove_all(output_root, error);
}

TEST(Scanner, HonorsIncludeAndExcludeFilters) {
    const auto data = minimal_png();
    binwalk::scan_options include_options;
    include_options.include = {"bmp"};
    const binwalk::scanner include_scanner(include_options);
    EXPECT_TRUE(include_scanner.scan(binwalk::byte_view(data)).empty());

    binwalk::scan_options exclude_options;
    exclude_options.exclude = {"png"};
    const binwalk::scanner exclude_scanner(exclude_options);
    EXPECT_TRUE(exclude_scanner.scan(binwalk::byte_view(data)).empty());
}
