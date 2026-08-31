
#include <binwalk/byte_view.hpp>
#include <binwalk/codec.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>
namespace {

using binwalk::byte_view;
using binwalk::codec_id;
using binwalk::codec_options;
using binwalk::codec_result;
using binwalk::codec_status;

static_assert(static_cast<int>(codec_id::deflate) == 0, "codec_id reordered");
static_assert(static_cast<int>(codec_id::zlib_stream) == 1, "codec_id reordered");
static_assert(static_cast<int>(codec_id::gzip) == 2, "codec_id reordered");
static_assert(static_cast<int>(codec_id::bzip2) == 3, "codec_id reordered");
static_assert(static_cast<int>(codec_id::xz) == 4, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lzma_alone) == 5, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lz4_frame) == 6, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lz4_legacy) == 7, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lz4_block) == 8, "codec_id reordered");
static_assert(static_cast<int>(codec_id::zstd) == 9, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lzfse) == 10, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lzvn) == 11, "codec_id reordered");
static_assert(static_cast<int>(codec_id::lzo1x) == 12, "codec_id reordered");

bool codec_id_is_covered_by_this_file(codec_id id) noexcept {
    switch(id) {
        case codec_id::deflate:
        case codec_id::zlib_stream:
        case codec_id::gzip:
        case codec_id::bzip2:
        case codec_id::xz:
        case codec_id::lzma_alone:
        case codec_id::lz4_frame:
        case codec_id::lz4_legacy:
        case codec_id::lz4_block:
        case codec_id::zstd:
        case codec_id::lzfse:
        case codec_id::lzvn:
        case codec_id::lzo1x:
            return true;
    }
    return false;
}

const char* status_name(codec_status status) noexcept {
    switch(status) {
        case codec_status::ok:
            return "ok";
        case codec_status::unsupported:
            return "unsupported";
        case codec_status::invalid_data:
            return "invalid_data";
        case codec_status::truncated_data:
            return "truncated_data";
        case codec_status::output_limit_exceeded:
            return "output_limit_exceeded";
        case codec_status::write_error:
            return "write_error";
        case codec_status::internal_error:
            return "internal_error";
    }
    return "<unknown codec_status>";
}

std::string describe(codec_id id, const codec_result& result) {
    return binwalk::codec_name(id) + " -> status=" + status_name(result.status)
        + " input_consumed=" + std::to_string(result.input_consumed)
        + " output_size=" + std::to_string(result.output_size);
}

void append_le16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0x00FFU));
}

void append_be16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0x00FFU));
    out.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
}

void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
}

void append_be32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_bytes(
    std::vector<std::uint8_t>& out,
    const std::vector<std::uint8_t>& payload,
    std::size_t offset,
    std::size_t length
) {
    const auto begin = payload.begin() + static_cast<std::ptrdiff_t>(offset);
    out.insert(out.end(), begin, begin + static_cast<std::ptrdiff_t>(length));
}

std::vector<std::uint8_t> prefix_of(const std::vector<std::uint8_t>& bytes, std::size_t length) {
    return std::vector<std::uint8_t>(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)
    );
}

std::uint32_t adler32(const std::uint8_t* data, std::size_t size) {
    std::uint32_t a = 1U;
    std::uint32_t b = 0U;
    for(std::size_t i = 0; i < size; ++i) {
        a = (a + static_cast<std::uint32_t>(data[i])) % 65521U;
        b = (b + a) % 65521U;
    }
    return (b << 16) | a;
}

std::uint32_t crc32(const std::uint8_t* data, std::size_t size) {
    std::uint32_t crc = 0xFFFFFFFFU;
    for(std::size_t i = 0; i < size; ++i) {
        crc ^= static_cast<std::uint32_t>(data[i]);
        for(int bit = 0; bit < 8; ++bit) {
            crc = ((crc & 1U) != 0U) ? ((crc >> 1) ^ 0xEDB88320U) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFU;
}

std::uint32_t crc32(const std::vector<std::uint8_t>& data) {
    return crc32(data.data(), data.size());
}

std::vector<std::uint8_t> build_deflate_stored(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out;
    std::size_t offset = 0;
    do {
        const std::size_t chunk = std::min<std::size_t>(payload.size() - offset, 65535U);
        const bool final_block = (offset + chunk) >= payload.size();
        out.push_back(static_cast<std::uint8_t>(final_block ? 0x01U : 0x00U));
        const auto len = static_cast<std::uint16_t>(chunk);
        append_le16(out, len);
        append_le16(out, static_cast<std::uint16_t>(~len));
        append_bytes(out, payload, offset, chunk);
        offset += chunk;
    } while(offset < payload.size());
    return out;
}

std::vector<std::uint8_t> build_zlib(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out{0x78U, 0x01U};
    const auto deflate_data = build_deflate_stored(payload);
    out.insert(out.end(), deflate_data.begin(), deflate_data.end());
    append_be32(out, adler32(payload.data(), payload.size()));
    return out;
}

std::vector<std::uint8_t> build_gzip(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out{
        0x1FU, 0x8BU, 0x08U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU
    };
    const auto deflate_data = build_deflate_stored(payload);
    out.insert(out.end(), deflate_data.begin(), deflate_data.end());
    append_le32(out, crc32(payload));
    append_le32(out, static_cast<std::uint32_t>(payload.size() & 0xFFFFFFFFU));
    return out;
}

void append_xz_varint(std::vector<std::uint8_t>& out, std::uint64_t value) {
    while(value >= 0x80U) {
        out.push_back(static_cast<std::uint8_t>((value & 0x7FU) | 0x80U));
        value >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> build_xz(const std::vector<std::uint8_t>& payload) {
    const std::uint8_t stream_flags[2] = {0x00U, 0x01U};

    std::vector<std::uint8_t> out{0xFDU, 0x37U, 0x7AU, 0x58U, 0x5AU, 0x00U};
    out.push_back(stream_flags[0]);
    out.push_back(stream_flags[1]);
    append_le32(out, crc32(stream_flags, 2));

    std::vector<std::uint8_t> block_header{
        0x02U, 0x00U, 0x21U, 0x01U, 0x08U, 0x00U, 0x00U, 0x00U
    };
    append_le32(block_header, crc32(block_header));
    out.insert(out.end(), block_header.begin(), block_header.end());

    std::vector<std::uint8_t> lzma2;
    std::size_t offset = 0;
    while(offset < payload.size()) {
        const std::size_t chunk = std::min<std::size_t>(payload.size() - offset, 65536U);
        lzma2.push_back(static_cast<std::uint8_t>(offset == 0 ? 0x01U : 0x02U));
        append_be16(lzma2, static_cast<std::uint16_t>(chunk - 1U));
        append_bytes(lzma2, payload, offset, chunk);
        offset += chunk;
    }
    lzma2.push_back(0x00U);
    out.insert(out.end(), lzma2.begin(), lzma2.end());

    const std::size_t block_padding = (4U - (lzma2.size() % 4U)) % 4U;
    out.insert(out.end(), block_padding, 0x00U);
    append_le32(out, crc32(payload));

    std::vector<std::uint8_t> index{0x00U, 0x01U};
    append_xz_varint(
        index,
        static_cast<std::uint64_t>(block_header.size() + lzma2.size() + 4U)
    );
    append_xz_varint(index, static_cast<std::uint64_t>(payload.size()));
    const std::size_t index_padding = (4U - (index.size() % 4U)) % 4U;
    index.insert(index.end(), index_padding, 0x00U);
    append_le32(index, crc32(index));
    out.insert(out.end(), index.begin(), index.end());

    std::vector<std::uint8_t> footer_fields;
    append_le32(footer_fields, static_cast<std::uint32_t>((index.size() / 4U) - 1U));
    footer_fields.push_back(stream_flags[0]);
    footer_fields.push_back(stream_flags[1]);
    append_le32(out, crc32(footer_fields));
    out.insert(out.end(), footer_fields.begin(), footer_fields.end());
    out.push_back(0x59U);
    out.push_back(0x5AU);
    return out;
}

std::vector<std::uint8_t> build_zstd(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out{0x28U, 0xB5U, 0x2FU, 0xFDU, 0xA0U};
    append_le32(out, static_cast<std::uint32_t>(payload.size()));
    const std::uint32_t block_header =
        (static_cast<std::uint32_t>(payload.size()) << 3) | 0x1U;
    out.push_back(static_cast<std::uint8_t>(block_header & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((block_header >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((block_header >> 16) & 0xFFU));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> build_lz4_block(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out;
    const std::size_t literals = payload.size();
    if(literals < 15U) {
        out.push_back(static_cast<std::uint8_t>(literals << 4));
    } else {
        out.push_back(0xF0U);
        std::size_t remaining = literals - 15U;
        while(remaining >= 255U) {
            out.push_back(0xFFU);
            remaining -= 255U;
        }
        out.push_back(static_cast<std::uint8_t>(remaining));
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> build_lz4_legacy(const std::vector<std::uint8_t>& payload) {
    const auto block = build_lz4_block(payload);
    std::vector<std::uint8_t> out{0x02U, 0x21U, 0x4CU, 0x18U};
    append_le32(out, static_cast<std::uint32_t>(block.size()));
    out.insert(out.end(), block.begin(), block.end());
    return out;
}

std::vector<std::uint8_t> build_lzfse(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out{0x62U, 0x76U, 0x78U, 0x2DU};
    append_le32(out, static_cast<std::uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    out.push_back(0x62U);
    out.push_back(0x76U);
    out.push_back(0x78U);
    out.push_back(0x24U);
    return out;
}

std::vector<std::uint8_t> build_lzo1x(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out;
    const std::size_t count = payload.size();
    if(count >= 4U && count <= 18U) {
        out.push_back(static_cast<std::uint8_t>(count - 3U));
    } else if(count >= 19U) {
        out.push_back(0x00U);
        std::size_t remaining = count - 3U - 15U;
        while(remaining > 255U) {
            out.push_back(0x00U);
            remaining -= 255U;
        }
        out.push_back(static_cast<std::uint8_t>(remaining));
    }
    out.insert(out.end(), payload.begin(), payload.end());
    out.push_back(0x11U);
    out.push_back(0x00U);
    out.push_back(0x00U);
    return out;
}

std::vector<std::uint8_t> build_deflate_valid_then_corrupt(
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> out;
    out.push_back(0x00U);
    const auto len = static_cast<std::uint16_t>(payload.size());
    append_le16(out, len);
    append_le16(out, static_cast<std::uint16_t>(~len));
    out.insert(out.end(), payload.begin(), payload.end());
    out.push_back(0x01U);
    append_le16(out, 0x0004U);
    append_le16(out, 0x0000U);
    out.insert(out.end(), 4U, 0x00U);
    return out;
}

std::vector<std::uint8_t> build_zlib_bad_adler(const std::vector<std::uint8_t>& payload) {
    auto stream = build_zlib(payload);
    stream.back() = static_cast<std::uint8_t>(stream.back() ^ 0xFFU);
    return stream;
}

std::vector<std::uint8_t> build_gzip_bad_isize(const std::vector<std::uint8_t>& payload) {
    auto stream = build_gzip(payload);
    stream.back() = static_cast<std::uint8_t>(stream.back() ^ 0xFFU);
    return stream;
}

std::vector<std::uint8_t> build_xz_bad_footer(const std::vector<std::uint8_t>& payload) {
    auto stream = build_xz(payload);
    stream.back() = static_cast<std::uint8_t>(stream.back() ^ 0xFFU);
    return stream;
}

enum class garbage_policy {

    rejected,

    weak,

    needs_expected_size
};

using stream_builder = std::vector<std::uint8_t> (*)(const std::vector<std::uint8_t>&);

struct codec_entry {
    codec_id id;

    stream_builder build;

    stream_builder build_corrupt;
    bool needs_expected_size;

    bool exact_input_consumed;

    bool supports_empty_payload;

    bool cannot_offer_a_prefix;
    garbage_policy garbage;
};

const codec_entry kAllCodecs[] = {
    {codec_id::deflate, &build_deflate_stored, &build_deflate_valid_then_corrupt,
     false, true, true, false, garbage_policy::weak},
    {codec_id::zlib_stream, &build_zlib, &build_zlib_bad_adler,
     false, true, true, false, garbage_policy::rejected},
    {codec_id::gzip, &build_gzip, &build_gzip_bad_isize,
     false, true, true, false, garbage_policy::rejected},

    {codec_id::bzip2, nullptr, nullptr,
     false, false, false, false, garbage_policy::rejected},
    {codec_id::xz, &build_xz, &build_xz_bad_footer,
     false, true, true, false, garbage_policy::rejected},

    {codec_id::lzma_alone, nullptr, nullptr,
     false, false, false, false, garbage_policy::weak},

    {codec_id::lz4_frame, nullptr, nullptr,
     false, false, false, false, garbage_policy::rejected},

    {codec_id::lz4_legacy, &build_lz4_legacy, nullptr,
     false, false, false, false, garbage_policy::rejected},
    {codec_id::lz4_block, &build_lz4_block, nullptr,
     true, true, false, false, garbage_policy::needs_expected_size},
    {codec_id::zstd, &build_zstd, nullptr,
     false, true, true, false, garbage_policy::rejected},

    {codec_id::lzfse, &build_lzfse, nullptr,
     false, false, false, true, garbage_policy::rejected},

    {codec_id::lzvn, nullptr, nullptr,
     false, false, false, true, garbage_policy::weak},
    {codec_id::lzo1x, &build_lzo1x, nullptr,
     true, true, false, false, garbage_policy::needs_expected_size}
};

static_assert(
    std::size(kAllCodecs) == 13U,
    "every codec_id enumerator needs a row in kAllCodecs"
);

std::vector<std::uint8_t> small_payload() {
    return {0x62U, 0x69U, 0x6EU, 0x77U, 0x61U, 0x6CU, 0x6BU};
}

std::vector<std::uint8_t> prefix_payload() {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(256U);
    for(std::size_t i = 0; i < 256U; ++i) {
        bytes.push_back(static_cast<std::uint8_t>(((i * 37U) + 11U) & 0xFFU));
    }
    return bytes;
}

std::vector<std::uint8_t> bomb_payload() {
    return std::vector<std::uint8_t>(4096U, 0x00U);
}

constexpr std::uint8_t kDeflateOfBinwalk[] = {
    0x01U, 0x07U, 0x00U, 0xF8U, 0xFFU, 0x62U, 0x69U, 0x6EU, 0x77U, 0x61U, 0x6CU, 0x6BU
};
constexpr std::uint8_t kZlibOfBinwalk[] = {
    0x78U, 0x01U, 0x01U, 0x07U, 0x00U, 0xF8U, 0xFFU,
    0x62U, 0x69U, 0x6EU, 0x77U, 0x61U, 0x6CU, 0x6BU,
    0x0BU, 0x93U, 0x02U, 0xE9U
};

constexpr std::uint8_t kPrefixJunk[] = {0xDEU, 0xADU, 0xBEU, 0xEFU, 0x13U, 0x37U, 0x5CU};
constexpr std::size_t kJunkOffset = std::size(kPrefixJunk);
static_assert(kJunkOffset == 7U, "the offset test is documented as offset 7");

byte_view view_of(const std::vector<std::uint8_t>& bytes) noexcept {
    return byte_view(bytes.data(), bytes.size());
}

struct named_buffer {
    const char* label;
    std::vector<std::uint8_t> bytes;
};

std::vector<std::uint8_t> pseudo_random_bytes(std::size_t size, std::uint32_t seed) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(size);
    std::uint32_t state = seed;
    for(std::size_t i = 0; i < size; ++i) {
        state = (state * 1664525U) + 1013904223U;
        bytes.push_back(static_cast<std::uint8_t>((state >> 24) & 0xFFU));
    }
    return bytes;
}

std::vector<named_buffer> garbage_buffers() {
    std::vector<named_buffer> buffers;
    buffers.push_back({"all-zero", std::vector<std::uint8_t>(64U, 0x00U)});
    buffers.push_back({"all-ones", std::vector<std::uint8_t>(64U, 0xFFU)});

    buffers.push_back({"ascii-text", {
        0x6EU, 0x6FU, 0x74U, 0x20U, 0x61U, 0x20U, 0x63U, 0x6FU, 0x6DU, 0x70U,
        0x72U, 0x65U, 0x73U, 0x73U, 0x65U, 0x64U, 0x20U, 0x73U, 0x74U, 0x72U,
        0x65U, 0x61U, 0x6DU, 0x20U, 0x61U, 0x74U, 0x20U, 0x61U, 0x6CU, 0x6CU
    }});
    buffers.push_back({"pseudo-random", pseudo_random_bytes(256U, 0x5EEDU)});
    return buffers;
}

class temp_output_path {
public:
    explicit temp_output_path(const char* tag) {
        static unsigned counter = 0U;
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string test_name = (info != nullptr) ? std::string(info->name()) : "unknown";
        path_ = std::filesystem::temp_directory_path()
            / ("binwalk_codec_test_" + test_name + "_" + tag + "_"
               + std::to_string(counter++) + ".out");
        remove();
    }

    temp_output_path(const temp_output_path&) = delete;
    temp_output_path& operator=(const temp_output_path&) = delete;

    ~temp_output_path() { remove(); }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] std::string string() const { return path_.string(); }

    [[nodiscard]] bool exists() const {
        std::error_code error;
        return std::filesystem::exists(path_, error);
    }

    [[nodiscard]] std::uint64_t size() const {
        std::error_code error;
        const auto bytes = std::filesystem::file_size(path_, error);
        return error ? 0U : static_cast<std::uint64_t>(bytes);
    }

    void remove() const {
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

private:
    std::filesystem::path path_;
};

class temp_directory {
public:
    explicit temp_directory(const char* tag) {
        static unsigned counter = 0U;
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string test_name = (info != nullptr) ? std::string(info->name()) : "unknown";
        path_ = std::filesystem::temp_directory_path()
            / ("binwalk_codec_test_dir_" + test_name + "_" + tag + "_"
               + std::to_string(counter++));
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    temp_directory(const temp_directory&) = delete;
    temp_directory& operator=(const temp_directory&) = delete;

    ~temp_directory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

    [[nodiscard]] bool exists() const {
        std::error_code error;
        return std::filesystem::exists(path_, error);
    }

private:
    std::filesystem::path path_;
};

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::vector<std::uint8_t> bytes;
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return bytes;
    }
    char buffer[512];
    while(stream.good()) {
        stream.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
        const auto count = static_cast<std::size_t>(stream.gcount());
        if(count == 0U) {
            break;
        }
        for(std::size_t i = 0; i < count; ++i) {
            bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(buffer[i])));
        }
    }
    return bytes;
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    for(const std::uint8_t byte : bytes) {
        stream.put(static_cast<char>(byte));
    }
}

bool backend_present(codec_id id) {
    if(binwalk::codec_available(id)) {
        return true;
    }
    const std::string label = binwalk::codec_name(id);
    static constexpr std::uint8_t kProbe[] = {0x00U, 0x01U, 0x02U, 0x03U};
    const codec_result result =
        binwalk::codec_decompress(id, byte_view(kProbe, std::size(kProbe)), 0U, nullptr);
    EXPECT_EQ(result.status, codec_status::unsupported) << describe(id, result);
    EXPECT_TRUE(result.unsupported()) << label;
    EXPECT_FALSE(result.success()) << label;

    EXPECT_EQ(result.output_size, 0U) << describe(id, result);
    return false;
}

void expect_buffer_retention_invariants(
    codec_id id,
    const codec_result& result,
    const std::vector<std::uint8_t>& output,
    const std::string& context
) {
    const std::string where = context + " " + describe(id, result);
    EXPECT_EQ(static_cast<std::uint64_t>(output.size()), result.output_size)
        << where << ": output.size() must equal result.output_size";
    if(result.status != codec_status::ok && result.status != codec_status::truncated_data) {
        EXPECT_TRUE(output.empty()) << where << ": only truncated_data may retain bytes";
        EXPECT_EQ(result.output_size, 0U) << where << ": only truncated_data may retain bytes";
    }
}

void expect_consumed_within_view(
    codec_id id,
    const codec_result& result,
    std::size_t view_size,
    std::size_t offset,
    const std::string& context
) {
    const std::size_t available = (offset <= view_size) ? (view_size - offset) : 0U;
    EXPECT_LE(result.input_consumed, available)
        << context << " " << describe(id, result) << ": consumed past the end of the view";
}

void expect_rejected_as_data(codec_id id, const codec_result& result, const std::string& label) {
    const std::string context = label + " " + describe(id, result);
    EXPECT_FALSE(result.success()) << context;
    EXPECT_NE(result.status, codec_status::internal_error) << context;
    EXPECT_NE(result.status, codec_status::write_error) << context;
    EXPECT_TRUE(
        result.status == codec_status::invalid_data
        || result.status == codec_status::truncated_data
    ) << context;
}

bool decode_intact(
    const codec_entry& entry,
    const std::vector<std::uint8_t>& stream,
    const std::vector<std::uint8_t>& payload,
    std::vector<std::uint8_t>& full
) {
    codec_options options;
    if(entry.needs_expected_size) {
        options.expected_output_size = static_cast<std::uint64_t>(payload.size());
    }
    const codec_result result =
        binwalk::codec_decompress_to_buffer(entry.id, view_of(stream), 0U, full, options);
    EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
    if(result.status != codec_status::ok) {
        return false;
    }
    EXPECT_EQ(full, payload) << binwalk::codec_name(entry.id);
    return full == payload;
}

}

TEST(CodecName, EveryEnumeratorHasANonEmptyLowercaseName) {
    for(const auto& entry : kAllCodecs) {
        ASSERT_TRUE(codec_id_is_covered_by_this_file(entry.id));
        const std::string name = binwalk::codec_name(entry.id);
        EXPECT_FALSE(name.empty()) << "codec_id " << static_cast<int>(entry.id);
        for(const char character : name) {
            const bool is_lower = character >= 'a' && character <= 'z';
            const bool is_digit = character >= '0' && character <= '9';
            const bool is_separator = character == '_' || character == '-';
            EXPECT_TRUE(is_lower || is_digit || is_separator)
                << "codec_name returned \"" << name << "\" which is not a lowercase identifier";
        }
    }
}

TEST(CodecName, NamesAreDistinctAndStableAcrossCalls) {
    std::vector<std::string> names;
    for(const auto& entry : kAllCodecs) {
        const std::string first = binwalk::codec_name(entry.id);
        const std::string second = binwalk::codec_name(entry.id);
        EXPECT_EQ(first, second) << "codec_name is not stable for codec_id "
                                 << static_cast<int>(entry.id);
        names.push_back(first);
    }
    ASSERT_EQ(names.size(), std::size(kAllCodecs));

    std::vector<std::string> sorted = names;
    std::sort(sorted.begin(), sorted.end());
    const auto duplicate = std::adjacent_find(sorted.begin(), sorted.end());
    EXPECT_TRUE(duplicate == sorted.end())
        << "two codec_id values share the name \""
        << (duplicate == sorted.end() ? std::string() : *duplicate) << "\"";
}

TEST(CodecName, MatchesTheExamplesGivenInTheHeaderDoc) {

    EXPECT_EQ(binwalk::codec_name(codec_id::xz), "xz");
    EXPECT_EQ(binwalk::codec_name(codec_id::lz4_frame), "lz4_frame");
}

TEST(CodecAvailable, AnswerIsStableAcrossCalls) {
    for(const auto& entry : kAllCodecs) {
        const bool first = binwalk::codec_available(entry.id);
        const bool second = binwalk::codec_available(entry.id);
        const bool third = binwalk::codec_available(entry.id);
        EXPECT_EQ(first, second) << binwalk::codec_name(entry.id);
        EXPECT_EQ(first, third) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecAvailable, CompiledOutBackendsReportUnsupportedForAnyInput) {
    auto buffers = garbage_buffers();
    buffers.push_back({"empty", {}});

    for(const auto& entry : kAllCodecs) {
        if(binwalk::codec_available(entry.id)) {
            continue;
        }
        const std::string label = binwalk::codec_name(entry.id);

        for(const auto& buffer : buffers) {
            const byte_view data = view_of(buffer.bytes);
            const std::string context = label + " / " + buffer.label;

            const codec_result dry = binwalk::codec_decompress(entry.id, data, 0U, nullptr);
            EXPECT_EQ(dry.status, codec_status::unsupported) << context;
            EXPECT_TRUE(dry.unsupported()) << context;

            std::vector<std::uint8_t> output{0xAAU, 0xBBU};
            const codec_result buffered =
                binwalk::codec_decompress_to_buffer(entry.id, data, 0U, output);
            EXPECT_EQ(buffered.status, codec_status::unsupported) << context;
            expect_buffer_retention_invariants(entry.id, buffered, output, context);

            temp_output_path out("unsupported");
            const std::string path = out.string();
            const codec_result written =
                binwalk::codec_decompress(entry.id, data, 0U, &path);
            EXPECT_EQ(written.status, codec_status::unsupported) << context;
            EXPECT_FALSE(out.exists()) << context << ": wrote a file for a missing backend";
        }

        if(entry.build != nullptr) {
            const auto stream = entry.build(small_payload());
            codec_options options;
            if(entry.needs_expected_size) {
                options.expected_output_size = 7U;
            }
            const codec_result whole =
                binwalk::codec_decompress(entry.id, view_of(stream), 0U, nullptr, options);
            EXPECT_EQ(whole.status, codec_status::unsupported) << describe(entry.id, whole);
            EXPECT_EQ(whole.output_size, 0U) << describe(entry.id, whole);

            const auto cut = prefix_of(stream, stream.size() / 2U);
            std::vector<std::uint8_t> output{0x01U};
            const codec_result short_stream = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(cut), 0U, output, options
            );
            EXPECT_EQ(short_stream.status, codec_status::unsupported)
                << describe(entry.id, short_stream);
            EXPECT_TRUE(output.empty()) << label << ": unsupported must retain nothing";
        }
    }
}

TEST(CodecOptions, DefaultMaxOutputSizeMatchesContractSection5b) {
    static_assert(
        binwalk::codec_default_max_output_size == 100ULL * 1024ULL * 1024ULL,
        "contract 5b pins the shared ceiling at 100 MiB"
    );
    EXPECT_EQ(binwalk::codec_default_max_output_size, 100ULL * 1024ULL * 1024ULL);
    EXPECT_EQ(binwalk::codec_default_max_output_size, 104857600ULL);

    const codec_options defaults;
    EXPECT_EQ(defaults.max_output_size, binwalk::codec_default_max_output_size);
    EXPECT_FALSE(defaults.expected_output_size.has_value());

    const codec_result unset;
    EXPECT_EQ(unset.status, codec_status::internal_error);
    EXPECT_FALSE(unset.success());
    EXPECT_FALSE(unset.unsupported());
    EXPECT_EQ(unset.input_consumed, 0U);
    EXPECT_EQ(unset.output_size, 0U);
}

TEST(CodecTestVectors, HandBuiltStreamsMatchTheirAuditedBytes) {

    const std::vector<std::uint8_t> check{
        0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U
    };
    EXPECT_EQ(crc32(check), 0xCBF43926U);
    EXPECT_EQ(adler32(check.data(), check.size()), 0x091E01DEU);

    const auto payload = small_payload();
    const std::vector<std::uint8_t> expected_deflate(
        std::begin(kDeflateOfBinwalk), std::end(kDeflateOfBinwalk)
    );
    const std::vector<std::uint8_t> expected_zlib(
        std::begin(kZlibOfBinwalk), std::end(kZlibOfBinwalk)
    );
    EXPECT_EQ(build_deflate_stored(payload), expected_deflate);
    EXPECT_EQ(build_zlib(payload), expected_zlib);

    const auto gzip = build_gzip(payload);
    ASSERT_EQ(gzip.size(), 10U + expected_deflate.size() + 8U);
    EXPECT_EQ(gzip[0], 0x1FU);
    EXPECT_EQ(gzip[1], 0x8BU);
    EXPECT_EQ(gzip[2], 0x08U);

    const auto distinct = prefix_payload();
    ASSERT_EQ(distinct.size(), 256U);
    std::vector<std::uint8_t> sorted = distinct;
    std::sort(sorted.begin(), sorted.end());
    EXPECT_TRUE(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end())
        << "prefix_payload() must have 256 distinct bytes";

    for(const auto& entry : kAllCodecs) {
        const std::string label = binwalk::codec_name(entry.id);
        if(entry.build == nullptr) {
            EXPECT_EQ(entry.build_corrupt, nullptr) << label;
            continue;
        }
        const auto stream = entry.build(payload);
        EXPECT_FALSE(stream.empty()) << label;
        EXPECT_GT(entry.build(bomb_payload()).size(), stream.size()) << label;
        if(entry.build_corrupt != nullptr) {
            EXPECT_NE(entry.build_corrupt(payload), stream) << label;
        }
        if(entry.supports_empty_payload) {
            EXPECT_FALSE(entry.build({}).empty()) << label;
        }
    }
}

TEST(CodecDecompress, RoundTripsHandBuiltStreams) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output{0xAAU, 0xBBU, 0xCCU, 0xDDU};
        const codec_result result = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, options
        );

        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "round trip");
        expect_consumed_within_view(entry.id, result, stream.size(), 0U, "round trip");
        if(result.status != codec_status::ok) {
            continue;
        }
        EXPECT_TRUE(result.success());
        EXPECT_FALSE(result.unsupported());
        EXPECT_EQ(result.input_consumed, stream.size()) << describe(entry.id, result);
        EXPECT_EQ(result.output_size, static_cast<std::uint64_t>(payload.size()))
            << describe(entry.id, result);
        EXPECT_EQ(output, payload) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecDecompress, EmptyStreamIsOkWithZeroOutput) {

    const std::vector<std::uint8_t> empty_payload;
    for(const auto& entry : kAllCodecs) {
        if(!entry.supports_empty_payload || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(empty_payload);
        ASSERT_FALSE(stream.empty()) << binwalk::codec_name(entry.id);

        std::vector<std::uint8_t> output{0x42U, 0x43U};
        const codec_result result =
            binwalk::codec_decompress_to_buffer(entry.id, view_of(stream), 0U, output, {});
        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "empty stream");
        if(result.status != codec_status::ok) {
            continue;
        }
        EXPECT_EQ(result.output_size, 0U) << describe(entry.id, result);
        EXPECT_TRUE(output.empty()) << binwalk::codec_name(entry.id);
        EXPECT_EQ(result.input_consumed, stream.size()) << describe(entry.id, result);
    }
}

TEST(CodecDecompress, InputConsumedIsMeasuredFromOffset) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);

        std::vector<std::uint8_t> buffer(std::begin(kPrefixJunk), std::end(kPrefixJunk));
        buffer.insert(buffer.end(), stream.begin(), stream.end());

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output{0x99U};
        const codec_result result = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(buffer), kJunkOffset, output, options
        );

        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "offset 7");
        expect_consumed_within_view(entry.id, result, buffer.size(), kJunkOffset, "offset 7");
        if(result.status != codec_status::ok) {
            continue;
        }

        EXPECT_EQ(result.input_consumed, stream.size()) << describe(entry.id, result);
        EXPECT_NE(result.input_consumed, buffer.size()) << describe(entry.id, result);
        EXPECT_EQ(result.output_size, static_cast<std::uint64_t>(payload.size()))
            << describe(entry.id, result);
        EXPECT_EQ(output, payload) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecDecompress, TrailingDataIsNotCountedInInputConsumed) {

    const auto payload = small_payload();
    const std::vector<std::uint8_t> trailing{0x5AU, 0x5AU, 0x5AU, 0x5AU, 0x5AU, 0x5AU};

    for(const auto& entry : kAllCodecs) {
        if(!entry.exact_input_consumed || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(payload);

        std::vector<std::uint8_t> buffer(std::begin(kPrefixJunk), std::end(kPrefixJunk));
        buffer.insert(buffer.end(), stream.begin(), stream.end());
        buffer.insert(buffer.end(), trailing.begin(), trailing.end());

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output;
        const codec_result result = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(buffer), kJunkOffset, output, options
        );
        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "trailing data");
        if(result.status != codec_status::ok) {
            continue;
        }
        EXPECT_EQ(result.input_consumed, stream.size())
            << describe(entry.id, result) << ": trailing bytes were counted as stream";
        EXPECT_EQ(output, payload) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecDecompress, RawBlockCodecsRequireExpectedOutputSize) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!entry.needs_expected_size || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options without;
        EXPECT_FALSE(without.expected_output_size.has_value());
        std::vector<std::uint8_t> output{0x11U, 0x22U};
        const codec_result missing = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, without
        );
        EXPECT_EQ(missing.status, codec_status::invalid_data) << describe(entry.id, missing);
        expect_buffer_retention_invariants(entry.id, missing, output, label + " no size");

        codec_options with;
        with.expected_output_size = static_cast<std::uint64_t>(payload.size());
        const codec_result supplied = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, with
        );
        EXPECT_EQ(supplied.status, codec_status::ok) << describe(entry.id, supplied);
        if(supplied.status == codec_status::ok) {
            EXPECT_EQ(output, payload) << label;
        }
    }
}

TEST(CodecDecompress, ExpectedOutputSizeMismatchIsRejected) {

    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!entry.needs_expected_size || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options too_large;
        too_large.expected_output_size = static_cast<std::uint64_t>(payload.size()) + 64U;
        std::vector<std::uint8_t> output{0xABU};
        const codec_result large = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, too_large
        );
        EXPECT_EQ(large.status, codec_status::truncated_data) << describe(entry.id, large);
        expect_buffer_retention_invariants(entry.id, large, output, label + " size too large");

        codec_options too_small;
        too_small.expected_output_size = static_cast<std::uint64_t>(payload.size()) - 3U;
        output.assign({0xCDU});
        const codec_result small = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, too_small
        );
        EXPECT_EQ(small.status, codec_status::invalid_data) << describe(entry.id, small);
        expect_buffer_retention_invariants(entry.id, small, output, label + " size too small");
    }
}

TEST(CodecDecompress, ExpectedOutputSizeIsIgnoredBySelfTerminatingCodecs) {

    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(entry.needs_expected_size || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(payload);

        std::vector<std::uint8_t> baseline;
        const codec_result without =
            binwalk::codec_decompress_to_buffer(entry.id, view_of(stream), 0U, baseline, {});
        EXPECT_EQ(without.status, codec_status::ok) << describe(entry.id, without);

        codec_options nonsense;
        nonsense.expected_output_size = static_cast<std::uint64_t>(payload.size()) * 9U + 5U;
        std::vector<std::uint8_t> with;
        const codec_result result =
            binwalk::codec_decompress_to_buffer(entry.id, view_of(stream), 0U, with, nonsense);

        EXPECT_EQ(result.status, without.status) << describe(entry.id, result);
        EXPECT_EQ(result.input_consumed, without.input_consumed) << describe(entry.id, result);
        EXPECT_EQ(result.output_size, without.output_size) << describe(entry.id, result);
        EXPECT_EQ(with, baseline) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecDecompress, ExpectedOutputSizeAboveTheCeilingIsRefusedUpFront) {

    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!entry.needs_expected_size || entry.build == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options options;
        options.max_output_size = 32U;
        options.expected_output_size = 33U;

        std::vector<std::uint8_t> output{0x5FU};
        const codec_result buffered = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, options
        );
        EXPECT_EQ(buffered.status, codec_status::output_limit_exceeded)
            << describe(entry.id, buffered);
        expect_buffer_retention_invariants(entry.id, buffered, output, label + " declared > cap");

        temp_output_path out("declared");
        const std::string path = out.string();
        const codec_result written =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);
        EXPECT_EQ(written.status, codec_status::output_limit_exceeded)
            << describe(entry.id, written);
        EXPECT_FALSE(out.exists()) << label << ": wrote a file for a refused declared size";
    }
}

TEST(CodecDecompress, DryRunMatchesFileRunAndWritesNoFile) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }
        const std::string label = binwalk::codec_name(entry.id);

        temp_output_path never_written("dry");
        ASSERT_FALSE(never_written.exists()) << label;
        const codec_result dry =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, nullptr, options);
        EXPECT_FALSE(never_written.exists()) << label << ": dry run created a file";

        temp_output_path written("real");
        const std::string path = written.string();
        const codec_result real =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);

        EXPECT_EQ(dry.status, real.status)
            << label << " dry=" << status_name(dry.status)
            << " real=" << status_name(real.status);
        EXPECT_EQ(dry.input_consumed, real.input_consumed) << describe(entry.id, dry);
        EXPECT_EQ(dry.output_size, real.output_size) << describe(entry.id, dry);
        EXPECT_EQ(dry.status, codec_status::ok) << describe(entry.id, dry);
        EXPECT_EQ(dry.output_size, static_cast<std::uint64_t>(payload.size()))
            << describe(entry.id, dry);
    }
}

TEST(CodecDecompress, WritesExactDecompressedBytesToFile) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        temp_output_path out("file");
        const std::string path = out.string();
        const codec_result result =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);

        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        if(result.status != codec_status::ok) {
            continue;
        }
        ASSERT_TRUE(out.exists()) << binwalk::codec_name(entry.id) << ": no file written";
        EXPECT_EQ(out.size(), static_cast<std::uint64_t>(payload.size()))
            << binwalk::codec_name(entry.id);
        EXPECT_EQ(read_file(out.path()), payload) << binwalk::codec_name(entry.id);
    }
}

TEST(CodecDecompress, MissingParentDirectoryIsAWriteError) {

    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }
        const std::string label = binwalk::codec_name(entry.id);

        temp_directory absent("nodir");
        ASSERT_FALSE(absent.exists()) << label;
        const std::string path = (absent.path() / "output.bin").string();

        const codec_result result =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);
        EXPECT_EQ(result.status, codec_status::write_error) << describe(entry.id, result);
        EXPECT_EQ(result.output_size, 0U)
            << describe(entry.id, result) << ": write_error retains nothing";
        EXPECT_FALSE(absent.exists()) << label << ": invented a missing parent directory";
    }
}

TEST(CodecDecompressToBuffer, RetainsNothingExceptOnTruncatedData) {
    const auto payload = small_payload();
    const std::vector<std::uint8_t> junk{0xDEU, 0xADU, 0xC0U, 0xDEU, 0x00U, 0x01U};

    for(const auto& entry : kAllCodecs) {
        const std::string label = binwalk::codec_name(entry.id);
        const bool present = binwalk::codec_available(entry.id);

        {
            const std::vector<std::uint8_t> garbage(48U, 0xFFU);
            std::vector<std::uint8_t> output = junk;
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(garbage), 0U, output
            );
            EXPECT_NE(result.status, codec_status::ok) << describe(entry.id, result);
            expect_buffer_retention_invariants(entry.id, result, output, label + " garbage");
        }

        {
            std::vector<std::uint8_t> output = junk;
            const codec_result result =
                binwalk::codec_decompress_to_buffer(entry.id, byte_view{}, 0U, output);
            EXPECT_NE(result.status, codec_status::ok) << describe(entry.id, result);
            EXPECT_NE(result.status, codec_status::truncated_data)
                << describe(entry.id, result) << ": an absent stream is not a short one";
            expect_buffer_retention_invariants(entry.id, result, output, label + " empty span");
        }

        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);

        {
            codec_options options;
            options.max_output_size = 3U;
            if(entry.needs_expected_size) {
                options.expected_output_size = static_cast<std::uint64_t>(payload.size());
            }
            std::vector<std::uint8_t> output = junk;
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(stream), 0U, output, options
            );
            EXPECT_NE(result.status, codec_status::ok) << describe(entry.id, result);
            expect_buffer_retention_invariants(entry.id, result, output, label + " ceiling");
            if(present) {
                EXPECT_EQ(result.status, codec_status::output_limit_exceeded)
                    << describe(entry.id, result);
                EXPECT_TRUE(output.empty())
                    << label << ": a refused bomb must not leave its half behind";
            }
        }

        {
            const auto cut = prefix_of(stream, stream.size() / 2U);
            codec_options options;
            if(entry.needs_expected_size) {
                options.expected_output_size = static_cast<std::uint64_t>(payload.size());
            }
            std::vector<std::uint8_t> output = junk;
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(cut), 0U, output, options
            );
            EXPECT_NE(result.status, codec_status::ok) << describe(entry.id, result);
            expect_buffer_retention_invariants(entry.id, result, output, label + " truncated");
        }
    }
}

TEST(CodecDecompress, TruncatedStreamsRetainADecodedPrefix) {

    const auto payload = prefix_payload();

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        std::vector<std::uint8_t> full;
        if(!decode_intact(entry, stream, payload, full)) {
            continue;
        }

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        bool saw_a_non_empty_prefix = false;
        for(std::size_t length = 0; length < stream.size(); ++length) {
            const auto cut = prefix_of(stream, length);
            const std::string context =
                label + " cut to " + std::to_string(length) + "/" + std::to_string(stream.size());

            std::vector<std::uint8_t> output{0xF0U, 0x0DU, 0xBAU, 0xADU};
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(cut), 0U, output, options
            );

            ASSERT_NE(result.status, codec_status::ok) << context;

            ASSERT_TRUE(
                result.status == codec_status::truncated_data
                || result.status == codec_status::invalid_data
            ) << context << " " << describe(entry.id, result);

            expect_buffer_retention_invariants(entry.id, result, output, context);
            expect_consumed_within_view(entry.id, result, cut.size(), 0U, context);

            if(result.status != codec_status::truncated_data) {
                continue;
            }

            if(entry.cannot_offer_a_prefix) {

                EXPECT_EQ(result.output_size, 0U)
                    << context << ": " << label << " is documented as prefix-less";
                EXPECT_TRUE(output.empty()) << context;
                continue;
            }

            ASSERT_LE(output.size(), full.size()) << context << ": retained more than exists";
            EXPECT_EQ(output, prefix_of(full, output.size()))
                << context << ": retained bytes are not a prefix of the full output";
            if(!output.empty()) {
                saw_a_non_empty_prefix = true;
            }
        }

        if(!entry.cannot_offer_a_prefix) {
            EXPECT_TRUE(saw_a_non_empty_prefix)
                << label << ": no cut point retained a single byte, so truncated_data"
                            " never actually kept what it decoded";
        }
    }
}

TEST(CodecDecompress, TruncatedStreamKeepsItsFileAndOtherFailuresDoNot) {
    const auto payload = prefix_payload();

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        std::vector<std::uint8_t> full;
        if(!decode_intact(entry, stream, payload, full)) {
            continue;
        }

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        const std::size_t cuts[] = {
            stream.size() / 8U,   stream.size() / 4U,   stream.size() / 3U,
            stream.size() / 2U,   (stream.size() * 3U) / 4U,
            (stream.size() * 7U) / 8U, stream.size() - 1U
        };

        for(const std::size_t length : cuts) {
            const auto cut = prefix_of(stream, length);
            const std::string context = label + " cut to " + std::to_string(length);

            temp_output_path out("trunc");
            const std::string path = out.string();
            const codec_result result =
                binwalk::codec_decompress(entry.id, view_of(cut), 0U, &path, options);

            ASSERT_NE(result.status, codec_status::ok) << context;

            if(result.status == codec_status::truncated_data) {

                if(result.output_size > 0U) {
                    ASSERT_TRUE(out.exists())
                        << context << " " << describe(entry.id, result)
                        << ": truncated_data with bytes must leave its file";
                    EXPECT_EQ(out.size(), result.output_size) << context;
                    EXPECT_EQ(read_file(out.path()), prefix_of(full, out.size()))
                        << context << ": the kept file is not a prefix of the full output";
                } else if(out.exists()) {

                    EXPECT_EQ(out.size(), 0U) << context;
                }
            } else {

                EXPECT_EQ(result.status, codec_status::invalid_data)
                    << context << " " << describe(entry.id, result);
                EXPECT_EQ(result.output_size, 0U) << context;
                EXPECT_FALSE(out.exists())
                    << context << ": a non-truncated failure left a file behind";
            }
        }
    }
}

TEST(CodecDecompress, DryRunMatchesRealRunOnTruncatedStreams) {

    const auto payload = prefix_payload();

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        const std::size_t cuts[] = {
            stream.size() / 4U, stream.size() / 2U,
            (stream.size() * 3U) / 4U, stream.size() - 1U
        };

        for(const std::size_t length : cuts) {
            const auto cut = prefix_of(stream, length);
            const std::string context = label + " cut to " + std::to_string(length);

            temp_output_path never_written("dry");
            const codec_result dry =
                binwalk::codec_decompress(entry.id, view_of(cut), 0U, nullptr, options);
            EXPECT_FALSE(never_written.exists())
                << context << ": dry run created a file";

            temp_output_path out("real");
            const std::string path = out.string();
            const codec_result real =
                binwalk::codec_decompress(entry.id, view_of(cut), 0U, &path, options);

            EXPECT_EQ(dry.status, real.status)
                << context << " dry=" << status_name(dry.status)
                << " real=" << status_name(real.status);
            EXPECT_EQ(dry.input_consumed, real.input_consumed)
                << context << " dry=" << describe(entry.id, dry);
            EXPECT_EQ(dry.output_size, real.output_size)
                << context << " dry=" << describe(entry.id, dry)
                << " real=" << describe(entry.id, real);
        }
    }
}

TEST(CodecDecompress, CorruptStreamRetainsNothingDespiteDecodableBytes) {

    const auto payload = prefix_payload();

    for(const auto& entry : kAllCodecs) {
        if(entry.build_corrupt == nullptr) {
            continue;
        }
        if(!backend_present(entry.id)) {
            continue;
        }
        const auto stream = entry.build_corrupt(payload);
        const std::string label = binwalk::codec_name(entry.id);

        std::vector<std::uint8_t> output{0x7EU, 0x7EU, 0x7EU};
        const codec_result buffered = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, {}
        );
        EXPECT_EQ(buffered.status, codec_status::invalid_data) << describe(entry.id, buffered);
        expect_buffer_retention_invariants(entry.id, buffered, output, label + " corrupt");
        EXPECT_TRUE(output.empty())
            << label << ": invalid_data retained bytes it had decoded";

        temp_output_path out("corrupt");
        const std::string path = out.string();
        const codec_result written =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, {});
        EXPECT_EQ(written.status, codec_status::invalid_data) << describe(entry.id, written);
        EXPECT_EQ(written.output_size, 0U) << describe(entry.id, written);
        EXPECT_FALSE(out.exists()) << label << ": invalid_data left a file behind";
    }
}

TEST(CodecDecompress, EmptyInputIsInvalidData) {

    const std::vector<std::uint8_t> nothing;
    for(const auto& entry : kAllCodecs) {
        const std::string label = binwalk::codec_name(entry.id);
        const bool present = binwalk::codec_available(entry.id);

        std::vector<std::uint8_t> output{0x01U, 0x02U};
        const codec_result defaulted =
            binwalk::codec_decompress_to_buffer(entry.id, byte_view{}, 0U, output);
        expect_buffer_retention_invariants(entry.id, defaulted, output, label + " empty view");
        EXPECT_EQ(
            defaulted.status,
            present ? codec_status::invalid_data : codec_status::unsupported
        ) << describe(entry.id, defaulted);

        const codec_result via_vector =
            binwalk::codec_decompress(entry.id, view_of(nothing), 0U, nullptr);
        EXPECT_EQ(
            via_vector.status,
            present ? codec_status::invalid_data : codec_status::unsupported
        ) << describe(entry.id, via_vector);
        EXPECT_EQ(via_vector.output_size, 0U) << describe(entry.id, via_vector);
    }
}

TEST(CodecDecompress, GarbageInputIsRejectedWithoutCrashing) {
    const auto buffers = garbage_buffers();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        for(const auto& buffer : buffers) {
            const std::string label = std::string(buffer.label) + " ("
                + std::to_string(buffer.bytes.size()) + " bytes)";

            std::vector<std::uint8_t> output{0x33U};
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(buffer.bytes), 0U, output
            );
            expect_buffer_retention_invariants(entry.id, result, output, label);
            expect_consumed_within_view(entry.id, result, buffer.bytes.size(), 0U, label);

            switch(entry.garbage) {
                case garbage_policy::rejected:
                    expect_rejected_as_data(entry.id, result, label);
                    break;
                case garbage_policy::needs_expected_size:
                    EXPECT_EQ(result.status, codec_status::invalid_data)
                        << label << " " << describe(entry.id, result);
                    break;
                case garbage_policy::weak:

                    EXPECT_NE(result.status, codec_status::internal_error)
                        << label << " " << describe(entry.id, result);
                    EXPECT_NE(result.status, codec_status::write_error)
                        << label << " " << describe(entry.id, result);
                    break;
            }
        }
    }
}

TEST(CodecDecompress, TruncatedStreamsNeverReportOk) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        ASSERT_LE(stream.size(), 128U) << "vectors are kept small enough to cut exhaustively";

        codec_options options;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        for(std::size_t length = 0; length < stream.size(); ++length) {
            const auto cut = prefix_of(stream, length);
            const std::string label =
                binwalk::codec_name(entry.id) + " cut to " + std::to_string(length)
                + "/" + std::to_string(stream.size());

            const codec_result result =
                binwalk::codec_decompress(entry.id, view_of(cut), 0U, nullptr, options);
            EXPECT_FALSE(result.success()) << label << " " << describe(entry.id, result);
            EXPECT_TRUE(
                result.status == codec_status::truncated_data
                || result.status == codec_status::invalid_data
            ) << label << " " << describe(entry.id, result);
            if(result.status == codec_status::invalid_data) {
                EXPECT_EQ(result.output_size, 0U) << label;
            }
        }
    }
}

TEST(CodecDecompress, OffsetBeyondEndOfBufferIsInvalidData) {
    const auto payload = small_payload();
    for(const auto& entry : kAllCodecs) {
        const std::string label = binwalk::codec_name(entry.id);
        const bool present = binwalk::codec_available(entry.id);
        const std::vector<std::uint8_t> stream =
            (entry.build != nullptr) ? entry.build(payload) : std::vector<std::uint8_t>(16U, 0x00U);

        const std::size_t offsets[] = {
            stream.size(), stream.size() + 1U, stream.size() + 4096U
        };
        for(const std::size_t offset : offsets) {
            codec_options options;
            if(entry.needs_expected_size) {
                options.expected_output_size = static_cast<std::uint64_t>(payload.size());
            }
            std::vector<std::uint8_t> output{0x77U};
            const codec_result result = binwalk::codec_decompress_to_buffer(
                entry.id, view_of(stream), offset, output, options
            );
            const std::string context =
                label + " offset=" + std::to_string(offset) + " " + describe(entry.id, result);
            EXPECT_FALSE(result.success()) << context;
            EXPECT_EQ(
                result.status,
                present ? codec_status::invalid_data : codec_status::unsupported
            ) << context;
            expect_buffer_retention_invariants(entry.id, result, output, context);
        }
    }
}

TEST(CodecOptions, MaxOutputSizeBoundaryIsInclusive) {

    const auto payload = small_payload();
    const auto exact = static_cast<std::uint64_t>(payload.size());

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options at_the_line;
        at_the_line.max_output_size = exact;
        if(entry.needs_expected_size) {
            at_the_line.expected_output_size = exact;
        }
        std::vector<std::uint8_t> output;
        const codec_result allowed = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, at_the_line
        );
        EXPECT_EQ(allowed.status, codec_status::ok)
            << describe(entry.id, allowed) << ": output_size == max_output_size must be ok";
        expect_buffer_retention_invariants(entry.id, allowed, output, label + " at the line");
        if(allowed.status == codec_status::ok) {
            EXPECT_EQ(output, payload) << label;
        }

        codec_options one_short;
        one_short.max_output_size = exact - 1U;
        if(entry.needs_expected_size) {
            one_short.expected_output_size = exact;
        }
        output.assign({0x5AU});
        const codec_result refused = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, one_short
        );
        EXPECT_EQ(refused.status, codec_status::output_limit_exceeded)
            << describe(entry.id, refused) << ": one byte over the ceiling must be refused";
        expect_buffer_retention_invariants(entry.id, refused, output, label + " one over");
    }
}

TEST(CodecDecompress, TinyMaxOutputSizeIsEnforcedOnASmallStream) {
    const auto payload = small_payload();
    ASSERT_EQ(payload.size(), 7U);

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);

        codec_options options;
        options.max_output_size = 3U;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output{0xEEU, 0xEEU};
        const codec_result result = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, options
        );
        EXPECT_EQ(result.status, codec_status::output_limit_exceeded)
            << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "tiny ceiling");
        EXPECT_TRUE(output.empty()) << binwalk::codec_name(entry.id) << ": output not cleared";
        EXPECT_EQ(result.output_size, 0U) << describe(entry.id, result);
    }
}

TEST(CodecDecompress, DecompressionBombIsCappedAndLeavesNothingBehind) {

    const auto payload = bomb_payload();
    ASSERT_EQ(payload.size(), 4096U);
    constexpr std::uint64_t kCeiling = 16U;

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options options;
        options.max_output_size = kCeiling;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output{0x01U, 0x02U, 0x03U};
        const codec_result buffered = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, options
        );
        EXPECT_EQ(buffered.status, codec_status::output_limit_exceeded)
            << describe(entry.id, buffered);
        expect_buffer_retention_invariants(entry.id, buffered, output, label + " bomb");
        EXPECT_TRUE(output.empty()) << label << ": bomb output retained in the buffer";
        EXPECT_EQ(buffered.output_size, 0U) << describe(entry.id, buffered);

        const codec_result dry =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, nullptr, options);
        EXPECT_EQ(dry.status, codec_status::output_limit_exceeded) << describe(entry.id, dry);
        EXPECT_EQ(dry.output_size, buffered.output_size) << describe(entry.id, dry);
        EXPECT_EQ(dry.input_consumed, buffered.input_consumed) << describe(entry.id, dry);

        temp_output_path out("bomb");
        const std::string path = out.string();
        const codec_result written =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);
        EXPECT_EQ(written.status, codec_status::output_limit_exceeded)
            << describe(entry.id, written);
        EXPECT_EQ(written.output_size, 0U) << describe(entry.id, written);
        EXPECT_FALSE(out.exists())
            << label << ": a refused bomb left " << out.size() << " bytes on disk";
    }
}

TEST(CodecDecompress, RefusedBombRemovesAPreExistingFile) {

    const auto payload = bomb_payload();
    const std::vector<std::uint8_t> pre_existing(64U, 0x2AU);

    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);
        const std::string label = binwalk::codec_name(entry.id);

        codec_options options;
        options.max_output_size = 16U;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        temp_output_path out("preexisting");
        write_file(out.path(), pre_existing);
        ASSERT_TRUE(out.exists()) << label;
        ASSERT_EQ(out.size(), 64U) << label;

        const std::string path = out.string();
        const codec_result result =
            binwalk::codec_decompress(entry.id, view_of(stream), 0U, &path, options);
        EXPECT_EQ(result.status, codec_status::output_limit_exceeded)
            << describe(entry.id, result);
        EXPECT_FALSE(out.exists())
            << label << ": a refused bomb left a " << out.size() << "-byte file at output_path";
    }
}

TEST(CodecDecompress, GenerousMaxOutputSizeStillSucceeds) {
    const auto payload = bomb_payload();
    for(const auto& entry : kAllCodecs) {
        if(!backend_present(entry.id)) {
            continue;
        }
        if(entry.build == nullptr) {
            continue;
        }
        const auto stream = entry.build(payload);

        codec_options options;
        options.max_output_size = 1024ULL * 1024ULL;
        if(entry.needs_expected_size) {
            options.expected_output_size = static_cast<std::uint64_t>(payload.size());
        }

        std::vector<std::uint8_t> output;
        const codec_result result = binwalk::codec_decompress_to_buffer(
            entry.id, view_of(stream), 0U, output, options
        );
        EXPECT_EQ(result.status, codec_status::ok) << describe(entry.id, result);
        expect_buffer_retention_invariants(entry.id, result, output, "generous ceiling");
        if(result.status != codec_status::ok) {
            continue;
        }
        EXPECT_EQ(result.output_size, static_cast<std::uint64_t>(payload.size()))
            << describe(entry.id, result);
        EXPECT_EQ(result.input_consumed, stream.size()) << describe(entry.id, result);
        EXPECT_EQ(output.size(), payload.size()) << binwalk::codec_name(entry.id);
        EXPECT_EQ(output, payload) << binwalk::codec_name(entry.id);
    }
}
