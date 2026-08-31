#include "b1_compression.hpp"

#include "../builtin_extractors.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/codec.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct bzip2_format {};
struct compressd_format {};
struct gpg_signed_format {};
struct gzip_format {};
struct lz4_format {};
struct lzfse_format {};
struct lzma_format {};
struct lzop_format {};
struct xz_format {};
struct zlib_format {};
struct zstd_format {};

constexpr const char* decompressed_file_name = "decompressed.bin";

[[nodiscard]] bool bytes_equal(
    byte_view data,
    std::size_t offset,
    const std::uint8_t* expected,
    std::size_t length
) noexcept {
    if(!data.contains(offset, length)) {
        return false;
    }
    for(std::size_t index = 0; index < length; ++index) {
        if(data[offset + index] != expected[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool offset_safe(
    std::uint64_t available_data,
    std::uint64_t next_offset,
    std::optional<std::uint64_t> last_offset
) noexcept {
    if(next_offset >= available_data) {
        return false;
    }
    return !last_offset || *last_offset < next_offset;
}

[[nodiscard]] std::string hex_byte(std::uint8_t value) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string text = "0x";
    text.push_back(digits[(value >> 4U) & 0x0FU]);
    text.push_back(digits[value & 0x0FU]);
    return text;
}

constexpr std::uint32_t xxh32_prime1 = 2654435761U;
constexpr std::uint32_t xxh32_prime2 = 2246822519U;
constexpr std::uint32_t xxh32_prime3 = 3266489917U;
constexpr std::uint32_t xxh32_prime4 = 668265263U;
constexpr std::uint32_t xxh32_prime5 = 374761393U;

[[nodiscard]] constexpr std::uint32_t rotate_left32(std::uint32_t value, unsigned bits) noexcept {
    return static_cast<std::uint32_t>((value << bits) | (value >> (32U - bits)));
}

[[nodiscard]] std::uint32_t read_le32(const std::uint8_t* source) noexcept {
    return static_cast<std::uint32_t>(source[0])
        | (static_cast<std::uint32_t>(source[1]) << 8U)
        | (static_cast<std::uint32_t>(source[2]) << 16U)
        | (static_cast<std::uint32_t>(source[3]) << 24U);
}

[[nodiscard]] std::uint32_t xxh32_round(std::uint32_t accumulator, std::uint32_t value) noexcept {
    accumulator += value * xxh32_prime2;
    accumulator = rotate_left32(accumulator, 13U);
    accumulator *= xxh32_prime1;
    return accumulator;
}

[[nodiscard]] std::optional<std::uint32_t> xxh32(
    byte_view data,
    std::size_t offset,
    std::size_t length,
    std::uint32_t seed
) noexcept {
    if(!data.contains(offset, length)) {
        return std::nullopt;
    }
    const std::uint8_t* cursor = data.data() + offset;
    const std::uint8_t* const end = cursor + length;
    std::uint32_t hash = 0;

    if(length >= 16) {
        std::uint32_t first = seed + xxh32_prime1 + xxh32_prime2;
        std::uint32_t second = seed + xxh32_prime2;
        std::uint32_t third = seed;
        std::uint32_t fourth = seed - xxh32_prime1;
        const std::uint8_t* const limit = end - 16;
        do {
            first = xxh32_round(first, read_le32(cursor));
            cursor += 4;
            second = xxh32_round(second, read_le32(cursor));
            cursor += 4;
            third = xxh32_round(third, read_le32(cursor));
            cursor += 4;
            fourth = xxh32_round(fourth, read_le32(cursor));
            cursor += 4;
        } while(cursor <= limit);
        hash = rotate_left32(first, 1U) + rotate_left32(second, 7U)
            + rotate_left32(third, 12U) + rotate_left32(fourth, 18U);
    } else {
        hash = seed + xxh32_prime5;
    }

    hash += static_cast<std::uint32_t>(length);
    while(end - cursor >= 4) {
        hash += read_le32(cursor) * xxh32_prime3;
        hash = rotate_left32(hash, 17U) * xxh32_prime4;
        cursor += 4;
    }
    while(cursor < end) {
        hash += static_cast<std::uint32_t>(*cursor) * xxh32_prime5;
        hash = rotate_left32(hash, 11U) * xxh32_prime1;
        ++cursor;
    }

    hash ^= hash >> 15U;
    hash *= xxh32_prime2;
    hash ^= hash >> 13U;
    hash *= xxh32_prime3;
    hash ^= hash >> 16U;
    return hash;
}

[[nodiscard]] extractor sevenzip_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "7zz",
        "bin",
        {"x", "-y", "-o.", "-p''", "%e"},
        {0, 2},
        false
    };
}

[[nodiscard]] extractor zstd_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "zstd",
        "zst",
        {"-k", "-f", "-d", "%e"},
        {0},
        false
    };
}

[[nodiscard]] extractor lz4_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "lz4",
        "lz4",
        {"-f", "-d", "%e", "decompressed.bin"},
        {0},
        false
    };
}

[[nodiscard]] extractor lzop_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "lzop",
        "lzo",
        {"-p", "-N", "-d", "%e"},
        {0},
        false
    };
}

[[nodiscard]] extractor lzfse_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "lzfse",
        "bin",
        {"-decode", "-i", "%e", "-o", "decompressed.bin"},
        {0},
        false
    };
}

[[nodiscard]] bool decode_produced_output(
    codec_id identifier,
    byte_view data,
    std::size_t stream_offset
) {
    codec_options probe;
    probe.max_output_size = 0;
    const auto outcome = codec_decompress(identifier, data, stream_offset, nullptr, probe);
    return outcome.status == codec_status::output_limit_exceeded;
}

[[nodiscard]] extraction_result decompress_stream(
    codec_id identifier,
    byte_view data,
    std::size_t stream_offset,
    std::uint64_t size_prefix,
    const std::string* output_directory,
    bool require_output,
    bool accept_truncated = false
) {
    extraction_result result;

    if(!codec_available(identifier)) {
        result.failure = extraction_failure::unsupported;
        return result;
    }
    if(stream_offset > data.size()) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const codec_options options;
    std::vector<std::uint8_t> decoded;

    const auto outcome = output_directory == nullptr
        ? codec_decompress(identifier, data, stream_offset, nullptr, options)
        : codec_decompress_to_buffer(identifier, data, stream_offset, decoded, options);

    if(outcome.unsupported()) {
        result.failure = extraction_failure::unsupported;
        return result;
    }

    const bool truncated_but_productive = accept_truncated
        && outcome.status == codec_status::truncated_data
        && decode_produced_output(identifier, data, stream_offset);

    if(!outcome.success() && !truncated_but_productive) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    if(outcome.success() && require_output && outcome.output_size == 0) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.size = size_prefix + static_cast<std::uint64_t>(outcome.input_consumed);

    if(output_directory != nullptr) {
        if(truncated_but_productive) {

            result.failure = extraction_failure::invalid_data;
            result.size.reset();
            return result;
        }
        const chroot output(*output_directory);
        if(!output.create_file(decompressed_file_name, byte_view(decoded))) {
            result.failure = extraction_failure::write_error;
            result.size.reset();
            return result;
        }
    }
    result.success = true;
    return result;
}

constexpr std::array<std::uint8_t, 6> xz_magic_bytes{{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}};

[[nodiscard]] extraction_result extract_lzma_stream(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto identifier =
        bytes_equal(data, offset, xz_magic_bytes.data(), xz_magic_bytes.size())
            ? codec_id::xz
            : codec_id::lzma_alone;
    return decompress_stream(identifier, data, offset, 0, output_directory, true);
}

[[nodiscard]] extraction_result extract_bzip2_stream(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    return decompress_stream(
        codec_id::bzip2,
        data,
        static_cast<std::size_t>(signature.offset),
        0,
        output_directory,
        false
    );
}

[[nodiscard]] extraction_result extract_gpg_stream(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    constexpr std::uint64_t header_size = 2;
    const auto offset = static_cast<std::size_t>(signature.offset);
    if(!data.contains(offset, static_cast<std::size_t>(header_size))) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return decompress_stream(
        codec_id::deflate,
        data,
        offset + static_cast<std::size_t>(header_size),
        header_size,
        output_directory,
        true,
        true

    );
}

[[nodiscard]] bool parse_xz_header(byte_view data, std::size_t offset) {
    constexpr std::size_t header_size = 12;
    constexpr std::size_t crc_start = 6;
    constexpr std::size_t crc_end = 8;

    if(!data.contains(offset, header_size)) {
        return false;
    }
    const binary_reader<byte_order::little> reader(data);
    const auto stored_crc = reader.read<std::uint32_t>(offset + crc_end);
    if(!stored_crc) {
        return false;
    }
    return crc32(data, offset + crc_start, crc_end - crc_start) == *stored_crc;
}

struct lzma_header {
    std::uint8_t properties = 0;
    std::uint32_t dictionary_size = 0;
    std::uint64_t decompressed_size = 0;
};

[[nodiscard]] std::optional<lzma_header> parse_lzma_header(byte_view data, std::size_t offset) {

    constexpr std::uint64_t stream_size = 0xFFFFFFFFFFFFFFFFULL;
    constexpr std::uint64_t minimum_supported_size = 256;
    constexpr std::uint64_t maximum_supported_size = 0xFFFFFFFFULL;
    constexpr std::size_t structure_size = 14;

    if(!data.contains(offset, structure_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::little> reader(data);
    const auto dictionary_size = reader.read<std::uint32_t>(offset + 1);
    const auto decompressed_size = reader.read<std::uint64_t>(offset + 5);
    if(!dictionary_size || !decompressed_size) {
        return std::nullopt;
    }

    if(data[offset + 13] != 0) {
        return std::nullopt;
    }
    if(*decompressed_size < minimum_supported_size) {
        return std::nullopt;
    }
    if(*decompressed_size != stream_size && *decompressed_size > maximum_supported_size) {
        return std::nullopt;
    }
    return lzma_header{data[offset], *dictionary_size, *decompressed_size};
}

struct zstd_frame_header {
    std::uint64_t fixed_header_size = 5;
    std::uint64_t dictionary_id_flag = 0;
    bool content_checksum_present = false;
    bool single_segment_flag = false;
    std::uint64_t frame_content_flag = 0;
};

[[nodiscard]] std::optional<zstd_frame_header> parse_zstd_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint8_t unused_bits_mask = 0b0001'1000;
    constexpr std::uint8_t dictionary_id_mask = 0b11;
    constexpr std::uint8_t content_checksum_mask = 0b100;
    constexpr std::uint8_t single_segment_mask = 0b10'0000;
    constexpr std::uint8_t frame_content_mask = 0b1100'0000;
    constexpr unsigned frame_content_shift = 6;
    constexpr std::array<std::uint8_t, 4> magic{{0x28, 0xB5, 0x2F, 0xFD}};

    if(!data.contains(offset, 5)) {
        return std::nullopt;
    }

    if(!bytes_equal(data, offset, magic.data(), magic.size())) {
        return std::nullopt;
    }
    const auto descriptor = data[offset + 4];
    if((descriptor & unused_bits_mask) != 0) {
        return std::nullopt;
    }

    zstd_frame_header header;
    header.dictionary_id_flag = descriptor & dictionary_id_mask;
    header.content_checksum_present = (descriptor & content_checksum_mask) != 0;
    header.single_segment_flag = (descriptor & single_segment_mask) != 0;
    header.frame_content_flag =
        static_cast<std::uint64_t>((descriptor & frame_content_mask) >> frame_content_shift);
    return header;
}

struct zstd_block_header {
    std::uint64_t header_size = 3;
    std::uint64_t block_type = 0;
    std::uint64_t block_size = 0;
    bool last_block = false;
};

[[nodiscard]] std::optional<zstd_block_header> parse_zstd_block_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint32_t block_type_mask = 0b110;
    constexpr unsigned block_type_shift = 1;
    constexpr std::uint32_t rle_block_type = 1;
    constexpr std::uint32_t reserved_block_type = 3;
    constexpr std::uint32_t last_block_mask = 0b1;
    constexpr std::uint32_t block_size_mask = 0b1111'1111'1111'1111'1111'1000;
    constexpr unsigned block_size_shift = 3;

    const binary_reader<byte_order::little> reader(data);
    const auto info_bits = reader.read_u24(offset);
    if(!info_bits) {
        return std::nullopt;
    }

    zstd_block_header header;
    header.last_block = (*info_bits & last_block_mask) != 0;
    header.block_type = (*info_bits & block_type_mask) >> block_type_shift;
    header.block_size = (*info_bits & block_size_mask) >> block_size_shift;

    if(header.block_type == rle_block_type) {
        header.block_size = 1;
    }
    if(header.block_type == reserved_block_type) {
        return std::nullopt;
    }
    return header;
}

struct lz4_file_header {
    std::uint64_t header_size = 0;
    bool block_checksum_present = false;
    bool content_checksum_present = false;
};

[[nodiscard]] std::optional<lz4_file_header> parse_lz4_file_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::size_t magic_size = 4;
    constexpr std::size_t fixed_structure_size = 6;
    constexpr std::uint8_t bd_reserved_mask = 0b1000'1111;
    constexpr std::uint8_t flags_reserved_mask = 0b0000'0010;
    constexpr std::uint8_t flag_dictionary_present = 0b0000'0001;
    constexpr std::uint8_t flag_content_size_present = 0b0000'1000;
    constexpr std::uint8_t flag_block_checksum_present = 0b0001'0000;
    constexpr std::uint8_t flag_content_checksum_present = 0b0000'0100;
    constexpr std::size_t dictionary_length = 4;
    constexpr std::size_t content_size_length = 8;
    constexpr std::array<std::uint8_t, 4> magic{{0x04, 0x22, 0x4D, 0x18}};

    if(!data.contains(offset, fixed_structure_size)) {
        return std::nullopt;
    }

    if(!bytes_equal(data, offset, magic.data(), magic.size())) {
        return std::nullopt;
    }
    const auto flags = data[offset + 4];
    const auto block_descriptor = data[offset + 5];
    if((flags & flags_reserved_mask) != 0 || (block_descriptor & bd_reserved_mask) != 0) {
        return std::nullopt;
    }

    std::size_t crc_data_end = magic_size + (fixed_structure_size - magic_size);
    if((flags & flag_content_size_present) != 0) {
        crc_data_end += content_size_length;
    }
    if((flags & flag_dictionary_present) != 0) {
        crc_data_end += dictionary_length;
    }

    const auto digest = xxh32(data, offset + magic_size, crc_data_end - magic_size, 0);
    if(!digest || !data.contains(offset + crc_data_end, 1)) {
        return std::nullopt;
    }

    const auto expected = static_cast<std::uint8_t>((*digest >> 8U) & 0xFFU);
    if(data[offset + crc_data_end] != expected) {
        return std::nullopt;
    }

    lz4_file_header header;
    header.header_size = static_cast<std::uint64_t>(crc_data_end) + 1;
    header.block_checksum_present = (flags & flag_block_checksum_present) != 0;
    header.content_checksum_present = (flags & flag_content_checksum_present) != 0;
    return header;
}

struct lz4_block_header {
    std::uint64_t header_size = 4;
    std::uint64_t data_size = 0;
    std::uint64_t checksum_size = 0;
    bool last_block = false;
};

[[nodiscard]] std::optional<lz4_block_header> parse_lz4_block_header(
    byte_view data,
    std::size_t offset,
    bool checksum_present
) {
    constexpr std::uint32_t size_mask = 0x7FFFFFFFU;
    constexpr std::uint64_t checksum_size = 4;

    const binary_reader<byte_order::little> reader(data);
    const auto block_size = reader.read<std::uint32_t>(offset);
    if(!block_size) {
        return std::nullopt;
    }

    lz4_block_header header;
    header.last_block = *block_size == 0;
    if(checksum_present) {
        header.checksum_size = checksum_size;
    }

    header.data_size = *block_size & size_mask;
    return header;
}

struct lzop_file_header {
    std::uint64_t header_size = 0;
    bool block_checksum_present = false;
};

[[nodiscard]] std::optional<lzop_file_header> parse_lzop_file_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint16_t max_version = 0x1040;
    constexpr std::size_t header_size_part1 = 21;
    constexpr std::size_t header_size_part2 = 13;
    constexpr std::size_t filter_size = 4;
    constexpr std::uint32_t flag_filter = 0x0000'0800;
    constexpr std::uint32_t flag_crc32_c = 0x0000'0200;
    constexpr std::uint32_t flag_adler32_c = 0x0000'0002;
    constexpr std::uint64_t checksum_size = 4;
    constexpr std::array<std::uint8_t, 9> magic{
        {0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A}
    };

    if(!data.contains(offset, header_size_part1)) {
        return std::nullopt;
    }

    if(!bytes_equal(data, offset, magic.data(), magic.size())) {
        return std::nullopt;
    }

    const binary_reader<byte_order::big> reader(data);
    const auto version = reader.read<std::uint16_t>(offset + 9);
    const auto version_needed = reader.read<std::uint16_t>(offset + 13);
    const auto flags = reader.read<std::uint32_t>(offset + 17);
    if(!version || !version_needed || !flags) {
        return std::nullopt;
    }
    const auto method = data[offset + 15];
    if(method != 1 && method != 2 && method != 3) {
        return std::nullopt;
    }
    if(*version > max_version || *version < *version_needed) {
        return std::nullopt;
    }

    auto part2_start = offset + header_size_part1;
    if((*flags & flag_filter) != 0) {
        part2_start += filter_size;
    }
    const auto part2_end = part2_start + header_size_part2;
    if(!data.contains(part2_start, header_size_part2)) {
        return std::nullopt;
    }
    const auto file_name_length = data[part2_end - 1];

    lzop_file_header header;
    header.header_size = static_cast<std::uint64_t>(part2_end - offset)
        + static_cast<std::uint64_t>(file_name_length) + checksum_size;

    header.block_checksum_present = (*flags & flag_adler32_c & flag_crc32_c) != 0;

    if(header.header_size > static_cast<std::uint64_t>(data.size() - offset)) {
        return std::nullopt;
    }
    return header;
}

struct lzop_block_header {
    std::uint64_t header_size = 12;
    std::uint64_t compressed_size = 0;
    std::uint64_t checksum_size = 0;
};

[[nodiscard]] std::optional<lzop_block_header> parse_lzop_block_header(
    byte_view data,
    std::size_t offset,
    bool checksum_present
) {
    constexpr std::uint32_t max_uncompressed_block_size = 64U * 1024U * 1024U;
    constexpr std::uint64_t checksum_size = 4;

    const binary_reader<byte_order::big> reader(data);
    const auto uncompressed_size = reader.read<std::uint32_t>(offset);
    const auto compressed_size = reader.read<std::uint32_t>(offset + 4);
    const auto uncompressed_checksum = reader.read<std::uint32_t>(offset + 8);
    if(!uncompressed_size || !compressed_size || !uncompressed_checksum) {
        return std::nullopt;
    }
    if(*compressed_size == 0 || *uncompressed_size == 0 || *uncompressed_checksum == 0
        || *uncompressed_size > max_uncompressed_block_size) {
        return std::nullopt;
    }

    lzop_block_header header;
    header.compressed_size = *compressed_size;
    if(checksum_present) {
        header.checksum_size = checksum_size;
    }
    return header;
}

struct lzfse_block {
    bool end_of_stream = false;
    std::uint64_t data_size = 0;
    std::uint64_t header_size = 0;
};

[[nodiscard]] std::optional<lzfse_block> parse_lzfse_block_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint32_t end_of_stream_type = 0x24787662;
    constexpr std::uint32_t uncompressed_type = 0x2D787662;
    constexpr std::uint32_t compressed_v1_type = 0x31787662;
    constexpr std::uint32_t compressed_v2_type = 0x32787662;
    constexpr std::uint32_t compressed_lzvn_type = 0x6E787662;
    constexpr unsigned payload_shift_v2 = 20;
    constexpr unsigned lmd_payload_shift_v2 = 40;
    constexpr std::uint64_t payload_mask = 0xFFFFF;

    const binary_reader<byte_order::little> reader(data);
    const auto block_type = reader.read<std::uint32_t>(offset);
    if(!block_type) {
        return std::nullopt;
    }

    if(*block_type == end_of_stream_type) {
        return lzfse_block{true, 0, 4};
    }
    if(*block_type == uncompressed_type) {
        const auto raw_bytes = reader.read<std::uint32_t>(offset + 4);
        if(!raw_bytes) {
            return std::nullopt;
        }
        return lzfse_block{false, *raw_bytes, 8};
    }
    if(*block_type == compressed_v1_type) {

        constexpr std::uint64_t header_size = 770;
        if(!data.contains(offset, 50)) {
            return std::nullopt;
        }
        const auto literal_payload = reader.read<std::uint32_t>(offset + 20);
        const auto lmd_payload = reader.read<std::uint32_t>(offset + 24);
        if(!literal_payload || !lmd_payload) {
            return std::nullopt;
        }
        return lzfse_block{
            false,
            static_cast<std::uint64_t>(*literal_payload) + *lmd_payload,
            header_size
        };
    }
    if(*block_type == compressed_v2_type) {
        if(!data.contains(offset, 32)) {
            return std::nullopt;
        }
        const auto packed_first = reader.read<std::uint64_t>(offset + 8);
        const auto packed_second = reader.read<std::uint64_t>(offset + 16);
        const auto header_size = reader.read<std::uint32_t>(offset + 24);
        if(!packed_first || !packed_second || !header_size) {
            return std::nullopt;
        }
        const auto lmd_payload = (*packed_second >> lmd_payload_shift_v2) & payload_mask;
        const auto literal_payload = (*packed_first >> payload_shift_v2) & payload_mask;
        return lzfse_block{false, lmd_payload + literal_payload, *header_size};
    }
    if(*block_type == compressed_lzvn_type) {
        const auto payload_bytes = reader.read<std::uint32_t>(offset + 8);
        if(!payload_bytes) {
            return std::nullopt;
        }
        return lzfse_block{false, *payload_bytes, 12};
    }
    return std::nullopt;
}

}

template<>
struct format_traits<gzip_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "gzip"; }
    static std::string description() { return "gzip compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x1f, 0x8b, 0x08}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "gzip_built_in", detail::extract_gzip};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t trailer_size = 8;
        const auto info = detail::inspect_gzip(data, offset);
        if(!info) {
            return std::nullopt;
        }
        const auto total_size = info->header_size + info->deflate_size + trailer_size;

        if(!data.contains(offset, total_size)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_high;
        result.description = description() + ",";
        if(!info->original_name.empty()) {
            result.description += " original file name: \"" + info->original_name + "\",";
        }
        result.description += " operating system: " + info->operating_system
            + ", timestamp: " + epoch_to_string(info->timestamp)
            + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<xz_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "xz"; }
    static std::string description() { return "XZ compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{xz_magic_bytes.begin(), xz_magic_bytes.end()}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "xz_built_in", extract_lzma_stream};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        signature_result result;
        result.offset = offset;
        result.confidence = confidence_high;
        result.description = description();

        std::uint64_t next_offset = offset;
        std::optional<std::uint64_t> previous_offset;
        std::size_t stream_header_count = 0;

        const auto available_data = static_cast<std::uint64_t>(data.size());

        while(offset_safe(available_data, next_offset, previous_offset)) {
            if(!parse_xz_header(data, static_cast<std::size_t>(next_offset))) {
                break;
            }
            ++stream_header_count;

            signature_result probe;
            probe.offset = next_offset;
            const auto dry_run = dry_run_extractor(&extract_lzma_stream, data, probe);

            if(dry_run.success && dry_run.size) {
                previous_offset = next_offset;
                next_offset += *dry_run.size;
                result.size += *dry_run.size;
            } else {

                result.preferred_extractor = sevenzip_extractor_definition();
                result.description += ", valid header with malformed data stream";
                break;
            }
        }

        if(stream_header_count == 0) {
            return std::nullopt;
        }
        if(result.size > 0) {
            result.description += ", total size: " + std::to_string(result.size) + " bytes";
        }
        return result;
    }
};

template<>
struct format_traits<lzma_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "lzma"; }
    static std::string description() { return "LZMA compressed data"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        constexpr std::array<std::uint8_t, 4> properties{{0x5D, 0x6E, 0x6D, 0x6C}};
        constexpr std::array<std::uint32_t, 12> dictionary_sizes{{
            0x10000000, 0x20000000, 0x01000000, 0x02000000,
            0x04000000, 0x00800000, 0x00400000, 0x00200000,
            0x00100000, 0x00080000, 0x00020000, 0x00010000
        }};

        std::vector<std::vector<std::uint8_t>> patterns;
        patterns.reserve(properties.size() * dictionary_sizes.size());
        for(const auto property : properties) {
            for(const auto dictionary_size : dictionary_sizes) {
                patterns.push_back({
                    property,
                    static_cast<std::uint8_t>(dictionary_size & 0xFFU),
                    static_cast<std::uint8_t>((dictionary_size >> 8U) & 0xFFU),
                    static_cast<std::uint8_t>((dictionary_size >> 16U) & 0xFFU),
                    static_cast<std::uint8_t>((dictionary_size >> 24U) & 0xFFU)
                });
            }
        }
        return patterns;
    }

    static binwalk::extractor extractor() {
        return {extractor_type::internal, "lzma_built_in", extract_lzma_stream};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = parse_lzma_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result probe;
        probe.offset = offset;
        const auto dry_run = dry_run_extractor(&extract_lzma_stream, data, probe);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description()
            + ", properties: " + hex_byte(header->properties)
            + ", dictionary size: " + std::to_string(header->dictionary_size) + " bytes"
            + ", compressed size: " + std::to_string(result.size) + " bytes"
            + ", uncompressed size: "
            + std::to_string(static_cast<std::int64_t>(header->decompressed_size)) + " bytes";
        return result;
    }
};

template<>
struct format_traits<bzip2_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "bzip2"; }
    static std::string description() { return "bzip2 compressed data"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        std::vector<std::vector<std::uint8_t>> patterns;
        patterns.reserve(9);
        for(char digit = '9'; digit >= '1'; --digit) {
            patterns.push_back({
                'B', 'Z', 'h', static_cast<std::uint8_t>(digit),
                '1', 'A', 'Y', '&', 'S', 'Y'
            });
        }
        return patterns;
    }

    static binwalk::extractor extractor() {
        return {extractor_type::internal, "bzip2_built_in", extract_bzip2_stream};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        signature_result probe;
        probe.offset = offset;
        const auto dry_run = dry_run_extractor(&extract_bzip2_stream, data, probe);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description =
            description() + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<zstd_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "zstd"; }
    static std::string description() { return "ZSTD compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x28, 0xb5, 0x2f, 0xfd}}; }
    static binwalk::extractor extractor() { return zstd_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::uint64_t eof_checksum_size = 4;
        constexpr std::size_t minimum_block_count = 2;

        const auto header = parse_zstd_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        std::uint64_t next_block = static_cast<std::uint64_t>(offset) + header->fixed_header_size;
        if(!header->single_segment_flag) {
            next_block += 1;
        }
        if(header->dictionary_id_flag == 1) {
            next_block += 1;
        } else if(header->dictionary_id_flag == 2) {
            next_block += 2;
        } else if(header->dictionary_id_flag == 3) {
            next_block += 4;
        }
        if(header->frame_content_flag == 0 && header->single_segment_flag) {
            next_block += 1;
        } else if(header->frame_content_flag == 1) {
            next_block += 2;
        } else if(header->frame_content_flag == 2) {
            next_block += 4;
        } else if(header->frame_content_flag == 3) {
            next_block += 8;
        }

        const auto available_data = static_cast<std::uint64_t>(data.size());
        std::optional<std::uint64_t> previous_block;
        std::size_t block_count = 0;

        while(offset_safe(available_data, next_block, previous_block)) {
            const auto block = parse_zstd_block_header(data, static_cast<std::size_t>(next_block));
            if(!block) {
                break;
            }
            ++block_count;
            previous_block = next_block;
            next_block += block->header_size + block->block_size;

            if(!block->last_block) {
                continue;
            }
            auto total_size = next_block - offset;
            if(header->content_checksum_present) {
                total_size += eof_checksum_size;
            }

            if(block_count < minimum_block_count) {
                break;
            }

            signature_result result;
            result.offset = offset;
            result.size = total_size;
            result.confidence = confidence_high;
            result.description =
                description() + ", total size: " + std::to_string(total_size) + " bytes";
            return result;
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<lz4_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "lz4"; }
    static std::string description() { return "LZ4 compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x04, 0x22, 0x4d, 0x18}}; }
    static binwalk::extractor extractor() { return lz4_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::uint64_t content_checksum_length = 4;

        const auto header = parse_lz4_file_header(data, offset);
        if(!header) {
            return std::nullopt;
        }
        const auto data_start = static_cast<std::uint64_t>(offset) + header->header_size;
        if(data_start > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        const auto available_data = static_cast<std::uint64_t>(data.size());
        std::uint64_t next_block = data_start;
        std::optional<std::uint64_t> previous_block;
        std::optional<std::uint64_t> data_size;

        while(offset_safe(available_data, next_block, previous_block)) {
            const auto block = parse_lz4_block_header(
                data, static_cast<std::size_t>(next_block), header->block_checksum_present
            );
            if(!block) {
                break;
            }
            previous_block = next_block;
            next_block += block->header_size + block->data_size + block->checksum_size;

            if(block->last_block) {
                data_size = next_block - data_start;
                break;
            }
        }
        if(!data_size) {
            return std::nullopt;
        }

        auto total_size = header->header_size + *data_size;
        if(header->content_checksum_present) {
            total_size += content_checksum_length;
        }

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_medium;
        result.description =
            description() + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<lzop_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "lzop"; }
    static std::string description() { return "LZO compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x89, 'L', 'Z', 'O', 0x00, 0x0D, 0x0A, 0x1A, 0x0A}};
    }
    static binwalk::extractor extractor() { return lzop_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t minimum_block_count = 2;
        constexpr std::uint64_t eof_marker_size = 4;

        const auto header = parse_lzop_file_header(data, offset);
        if(!header) {
            return std::nullopt;
        }
        const auto data_start = static_cast<std::uint64_t>(offset) + header->header_size;
        if(data_start > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        const auto available_data = static_cast<std::uint64_t>(data.size());
        std::uint64_t next_block = data_start;
        std::optional<std::uint64_t> previous_block;
        std::size_t block_count = 0;

        while(offset_safe(available_data, next_block, previous_block)) {
            const auto block = parse_lzop_block_header(
                data, static_cast<std::size_t>(next_block), header->block_checksum_present
            );
            if(!block) {
                break;
            }
            ++block_count;
            previous_block = next_block;
            next_block += block->header_size + block->compressed_size + block->checksum_size;
        }
        if(block_count < minimum_block_count) {
            return std::nullopt;
        }

        if(next_block > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }
        const binary_reader<byte_order::big> reader(data);
        const auto marker = reader.read<std::uint32_t>(static_cast<std::size_t>(next_block));
        if(!marker || *marker != 0) {
            return std::nullopt;
        }

        const auto total_size = (next_block + eof_marker_size) - offset;

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_high;
        result.description =
            description() + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<zlib_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "zlib"; }
    static std::string description() { return "Zlib compressed file"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x78, 0x9c}, {0x78, 0xda}, {0x78, 0x5e}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "zlib_built_in", detail::extract_zlib};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto info = detail::inspect_zlib(data, offset);
        if(!info) {
            return std::nullopt;
        }
        signature_result result;
        result.offset = offset;
        result.size = info->total_size;
        result.confidence = confidence_high;
        result.description = description() + ", total size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<gpg_signed_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "gpg_signed"; }
    static std::string description() { return "GPG signed file"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0xa3, 0x01}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "gpg_signed_built_in", extract_gpg_stream};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        signature_result probe;
        probe.offset = offset;
        const auto dry_run = dry_run_extractor(&extract_gpg_stream, data, probe);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description =
            description() + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<compressd_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "compressd"; }
    static std::string description() { return "compress'd data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x1f, 0x9d, 0x90}}; }
    static binwalk::extractor extractor() { return sevenzip_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::array<std::uint8_t, 3> magic{{0x1F, 0x9D, 0x90}};
        if(!bytes_equal(data, offset, magic.data(), magic.size())) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.description = description();
        result.confidence = offset == 0 ? confidence_medium : confidence_low;
        return result;
    }
};

template<>
struct format_traits<lzfse_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "lzfse"; }
    static std::string description() { return "LZFSE compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {'b', 'v', 'x', '-'},
            {'b', 'v', 'x', '1'},
            {'b', 'v', 'x', '2'},
            {'b', 'v', 'x', 'n'}
        };
    }
    static binwalk::extractor extractor() { return lzfse_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto available_data = static_cast<std::uint64_t>(data.size());
        std::uint64_t next_block = offset;
        std::optional<std::uint64_t> previous_block;

        while(offset_safe(available_data, next_block, previous_block)) {
            previous_block = next_block;

            const auto block = parse_lzfse_block_header(data, static_cast<std::size_t>(next_block));
            if(!block) {

                break;
            }
            next_block += block->header_size + block->data_size;

            if(block->end_of_stream) {
                const auto total_size = next_block - offset;
                signature_result result;
                result.offset = offset;
                result.size = total_size;
                result.confidence = confidence_high;
                result.description =
                    description() + ", total size: " + std::to_string(total_size) + " bytes";
                return result;
            }
        }
        return std::nullopt;
    }
};

namespace formats {

std::vector<signature> b1_compression_signatures() {
    return make_signatures(type_list<
        gzip_format,
        xz_format,
        lzma_format,
        bzip2_format,
        zstd_format,
        lz4_format,
        lzop_format,
        zlib_format,
        gpg_signed_format,
        compressd_format,
        lzfse_format
    >{});
}

}
}
