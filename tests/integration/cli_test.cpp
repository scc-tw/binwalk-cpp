#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace {

std::vector<std::uint8_t> inner_gzip() {
    return {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00,
        0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00
    };
}

std::vector<std::uint8_t> nested_gzip() {
    const auto inner = inner_gzip();
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
    outer.insert(outer.end(), 8, 0);
    return outer;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(output);
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size())
    );
    ASSERT_TRUE(output);
}

std::string quote(const std::filesystem::path& path) {
    return "\"" + path.string() + "\"";
}

} // namespace

TEST(Cli, RecursivelyExtractsWithABoundedWorkerPool) {
    const auto root = std::filesystem::temp_directory_path()
        / "binwalk_cpp_cli_recursive_test";
    const auto input = root / "nested.gz";
    const auto output = root / "output";
    const auto log = root / "results.json";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    write_bytes(input, nested_gzip());

    const std::filesystem::path cli(BINWALK_CLI_PATH);
    auto command = quote(cli)
        + " --extract --matryoshka --threads 2 --quiet --include gzip --directory "
        + quote(output) + " --log " + quote(log) + " " + quote(input);
#if defined(_WIN32)
    command = "\"" + command + "\"";
#endif
    ASSERT_EQ(std::system(command.c_str()), 0) << command;

    nlohmann::json report;
    std::ifstream input_log(log, std::ios::binary);
    ASSERT_TRUE(input_log);
    input_log >> report;
    ASSERT_TRUE(report.is_array());
    ASSERT_EQ(report.size(), 3U);
    ASSERT_EQ(report[0]["Analysis"]["file_map"].size(), 1U);
    ASSERT_EQ(report[1]["Analysis"]["file_map"].size(), 1U);
    EXPECT_EQ(report[0]["Analysis"]["file_map"][0]["name"], "gzip");
    EXPECT_EQ(report[1]["Analysis"]["file_map"][0]["name"], "gzip");
    EXPECT_TRUE(report[2]["Analysis"]["file_map"].empty());

    const auto first_output = output / "nested.gz.extracted" / "0" / "decompressed.bin";
    const auto second_output = std::filesystem::path(first_output.string() + ".extracted")
        / "0" / "decompressed.bin";
    ASSERT_EQ(std::filesystem::file_size(first_output), inner_gzip().size());
    ASSERT_EQ(std::filesystem::file_size(second_output), 5U);

    std::ifstream final_output(second_output, std::ios::binary);
    const std::string contents{
        std::istreambuf_iterator<char>(final_output), std::istreambuf_iterator<char>()
    };
    EXPECT_EQ(contents, "hello");

    std::filesystem::remove_all(root, error);
}
