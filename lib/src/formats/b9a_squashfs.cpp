#include "b9a_squashfs.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace binwalk {
namespace {

struct squashfs_format {};

[[nodiscard]] extractor sasquatch_definition(
    const char* command,
    std::vector<std::string> arguments
) {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        command,
        "sqsh",
        std::move(arguments),
        {0, 2},
        false
    };
}

[[nodiscard]] extractor squashfs_extractor_definition() {
    return sasquatch_definition("sasquatch", {"%e"});
}

[[nodiscard]] extractor squashfs_le_extractor_definition() {
    return sasquatch_definition("sasquatch", {"-le", "%e"});
}

[[nodiscard]] extractor squashfs_be_extractor_definition() {
    return sasquatch_definition("sasquatch", {"-be", "%e"});
}

[[nodiscard]] extractor squashfs_v4_be_extractor_definition() {
    return sasquatch_definition("sasquatch-v4be", {"%e"});
}

template<byte_order Order>
[[nodiscard]] std::optional<std::uint64_t> read_uint_ordered(
    byte_view data,
    std::size_t offset,
    std::size_t width
) noexcept {
    const binary_reader<Order> reader(data);
    switch(width) {
    case 1: {
        const auto value = reader.template read<std::uint8_t>(offset);
        return value ? std::optional<std::uint64_t>{*value} : std::nullopt;
    }
    case 2: {
        const auto value = reader.template read<std::uint16_t>(offset);
        return value ? std::optional<std::uint64_t>{*value} : std::nullopt;
    }
    case 4: {
        const auto value = reader.template read<std::uint32_t>(offset);
        return value ? std::optional<std::uint64_t>{*value} : std::nullopt;
    }
    case 8:
        return reader.template read<std::uint64_t>(offset);
    default:
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::uint64_t> read_uint(
    byte_view data,
    std::size_t offset,
    std::size_t width,
    bool little_endian
) noexcept {
    return little_endian
        ? read_uint_ordered<byte_order::little>(data, offset, width)
        : read_uint_ordered<byte_order::big>(data, offset, width);
}

[[nodiscard]] std::uint64_t integer_log2(std::uint64_t value) noexcept {
    std::uint64_t result = 0;
    while(value > 1) {
        value >>= 1U;
        ++result;
    }
    return result;
}

[[nodiscard]] std::optional<std::uint64_t> checked_add(
    std::uint64_t left,
    std::uint64_t right
) noexcept {
    if(left > std::numeric_limits<std::uint64_t>::max() - right) {
        return std::nullopt;
    }
    return left + right;
}

constexpr std::uint64_t min_squashfs_header_size = 120;

constexpr std::size_t squashfs_version_offset = 28;

constexpr std::uint64_t max_squashfs_version = 4;

constexpr std::uint64_t squashfs_v4_structure_size = 56;

constexpr std::uint64_t squashfs_v3_structure_size = 119;

struct squashfs_superblock {
    std::uint64_t timestamp = 0;
    std::uint64_t block_size = 0;
    std::uint64_t image_size = 0;
    std::uint64_t header_size = 0;
    std::uint64_t inode_count = 0;
    std::uint64_t compression = 0;
    std::uint64_t major_version = 0;
    std::uint64_t minor_version = 0;
    std::uint64_t uid_table_start = 0;
    bool little_endian = true;
};

[[nodiscard]] std::optional<squashfs_superblock> parse_squashfs_header(byte_view image) {

    if(static_cast<std::uint64_t>(image.size()) <= min_squashfs_header_size) {
        return std::nullopt;
    }

    squashfs_superblock header;

    auto version = read_uint(image, squashfs_version_offset, 2, true);
    if(!version) {
        return std::nullopt;
    }
    if(*version == 0 || *version > max_squashfs_version) {
        header.little_endian = false;
        version = read_uint(image, squashfs_version_offset, 2, false);
        if(!version) {
            return std::nullopt;
        }
    }
    if(*version == 0 || *version > max_squashfs_version) {
        return std::nullopt;
    }

    const bool little = header.little_endian;

    std::uint64_t image_size = 0;
    std::uint64_t uid_start = 0;
    std::uint64_t block_size = 0;
    std::uint64_t block_log = 0;
    std::uint64_t modification_time = 0;
    std::uint64_t inode_count = 0;
    std::uint64_t major_version = 0;
    std::uint64_t minor_version = 0;

    if(*version == max_squashfs_version) {

        const auto raw_inode_count = read_uint(image, 4, 4, little);
        const auto raw_modification_time = read_uint(image, 8, 4, little);
        const auto raw_block_size = read_uint(image, 12, 4, little);
        const auto raw_compression = read_uint(image, 20, 2, little);
        const auto raw_block_log = read_uint(image, 22, 2, little);
        const auto raw_major = read_uint(image, 28, 2, little);
        const auto raw_minor = read_uint(image, 30, 2, little);
        const auto raw_image_size = read_uint(image, 40, 8, little);
        const auto raw_uid_start = read_uint(image, 48, 8, little);
        if(!raw_inode_count || !raw_modification_time || !raw_block_size || !raw_compression
            || !raw_block_log || !raw_major || !raw_minor || !raw_image_size || !raw_uid_start) {
            return std::nullopt;
        }

        header.header_size = squashfs_v4_structure_size;

        header.compression = *raw_compression;

        inode_count = *raw_inode_count;
        modification_time = *raw_modification_time;
        block_size = *raw_block_size;
        block_log = *raw_block_log;
        major_version = *raw_major;
        minor_version = *raw_minor;
        image_size = *raw_image_size;
        uid_start = *raw_uid_start;
    } else {

        const auto raw_inode_count = read_uint(image, 4, 4, little);
        const auto raw_bytes_used_2 = read_uint(image, 8, 4, little);
        const auto raw_uid_start_2 = read_uint(image, 12, 4, little);
        const auto raw_major = read_uint(image, 28, 2, little);
        const auto raw_minor = read_uint(image, 30, 2, little);
        const auto raw_block_log = read_uint(image, 34, 2, little);
        const auto raw_modification_time = read_uint(image, 39, 4, little);
        const auto raw_block_size = read_uint(image, 51, 4, little);
        const auto raw_image_size = read_uint(image, 63, 8, little);
        const auto raw_uid_start = read_uint(image, 71, 8, little);

        const auto raw_lookup_table_start = read_uint(image, 111, 8, little);
        if(!raw_inode_count || !raw_bytes_used_2 || !raw_uid_start_2 || !raw_major || !raw_minor
            || !raw_block_log || !raw_modification_time || !raw_block_size || !raw_image_size
            || !raw_uid_start || !raw_lookup_table_start) {
            return std::nullopt;
        }

        header.header_size = squashfs_v3_structure_size;

        inode_count = *raw_inode_count;
        modification_time = *raw_modification_time;
        block_size = *raw_block_size;
        block_log = *raw_block_log;
        major_version = *raw_major;
        minor_version = *raw_minor;
        image_size = *raw_image_size;
        uid_start = *raw_uid_start;

        if(*version < 3) {
            uid_start = *raw_uid_start_2;
            image_size = *raw_bytes_used_2;
        }
    }

    header.image_size = image_size;

    if(image_size <= min_squashfs_header_size) {
        return std::nullopt;
    }

    if(block_size == 0 || block_log != integer_log2(block_size)) {
        return std::nullopt;
    }

    header.timestamp = modification_time;
    header.block_size = block_size;
    header.inode_count = inode_count;
    header.major_version = major_version;
    header.minor_version = minor_version;
    header.uid_table_start = uid_start;
    return header;
}

[[nodiscard]] std::optional<std::uint64_t> parse_squashfs_uid_entry(
    byte_view data,
    std::size_t entry_offset,
    std::uint64_t major_version,
    bool little_endian
) noexcept {
    const std::size_t width = major_version == max_squashfs_version ? 8 : 4;
    return read_uint(data, entry_offset, width, little_endian);
}

[[nodiscard]] const char* squashfs_compression_name(std::uint64_t compression_id) noexcept {
    switch(compression_id) {
    case 0: return "unknown";
    case 1: return "gzip";
    case 2: return "lzma";
    case 3: return "lzo";
    case 4: return "xz";
    case 5: return "lz4";
    case 6: return "zstd";
    default: return nullptr;
    }
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>> squashfs_magic_patterns() {
    return {
        {'s', 'q', 's', 'h'},
        {'h', 's', 'q', 's'},
        {'s', 'q', 'l', 'z'},
        {'q', 's', 'h', 's'},
        {'t', 'q', 's', 'h'},
        {'h', 's', 'q', 't'},
        {'s', 'h', 's', 'q'}
    };
}

[[nodiscard]] bool matches_squashfs_magic(byte_view image) noexcept {
    if(!image.contains(0, 4)) {
        return false;
    }
    for(const auto& pattern : squashfs_magic_patterns()) {
        if(image[0] == pattern[0] && image[1] == pattern[1]
            && image[2] == pattern[2] && image[3] == pattern[3]) {
            return true;
        }
    }
    return false;
}

}

template<>
struct format_traits<squashfs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "squashfs"; }
    static std::string description() { return "SquashFS file system"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return squashfs_magic_patterns();
    }

    static binwalk::extractor extractor() {
        return squashfs_extractor_definition();
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset > data.size()) {
            return std::nullopt;
        }
        const auto available_data = static_cast<std::uint64_t>(data.size() - offset);

        const byte_view image = data.subview(offset, data.size() - offset);

        if(!matches_squashfs_magic(image)) {
            return std::nullopt;
        }

        const auto header = parse_squashfs_header(image);
        if(!header) {
            return std::nullopt;
        }

        if(header->image_size > available_data) {
            return std::nullopt;
        }

        const auto uid_table_start = checked_add(
            static_cast<std::uint64_t>(offset),
            header->uid_table_start
        );
        if(!uid_table_start) {
            return std::nullopt;
        }
        if(*uid_table_start <= header->header_size) {
            return std::nullopt;
        }

        if(*uid_table_start > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        const auto uid_entry = parse_squashfs_uid_entry(
            data,
            static_cast<std::size_t>(*uid_table_start),
            header->major_version,
            header->little_endian
        );
        if(!uid_entry) {
            return std::nullopt;
        }

        const bool uid_entry_sane = *uid_entry == 0
            || (*uid_entry > header->header_size && *uid_entry <= header->image_size);
        if(!uid_entry_sane) {
            return std::nullopt;
        }

        const char* const compression_name = squashfs_compression_name(header->compression);
        if(compression_name == nullptr) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header->image_size;
        result.confidence = confidence_high;

        if(header->little_endian) {
            result.preferred_extractor = squashfs_le_extractor_definition();
        } else if(header->major_version == max_squashfs_version) {
            result.preferred_extractor = squashfs_v4_be_extractor_definition();
        } else {
            result.preferred_extractor = squashfs_be_extractor_definition();
        }

        result.description = description()
            + ", " + (header->little_endian ? "little" : "big") + " endian"
            + ", version: " + std::to_string(header->major_version)
            + "." + std::to_string(header->minor_version)
            + ", compression: " + compression_name
            + ", inode count: " + std::to_string(header->inode_count)
            + ", block size: " + std::to_string(header->block_size)
            + ", image size: " + std::to_string(header->image_size)
            + " bytes, created: "
            + epoch_to_string(static_cast<std::uint32_t>(header->timestamp));
        return result;
    }
};

namespace formats {

std::vector<signature> b9a_squashfs_signatures() {
    return make_signatures(type_list<squashfs_format>{});
}

}
}
