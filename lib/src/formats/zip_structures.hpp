#pragma once

#include <binwalk/binary_reader.hpp>
#include <binwalk/byte_view.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
namespace binwalk::formats::zip_structures {

struct local_header {
    std::size_t total_size = 0;
    std::uint16_t version_major = 0;
    std::uint16_t version_minor = 0;
};

[[nodiscard]] inline std::optional<local_header> parse_local_header(
    byte_view data,
    std::size_t offset,
    std::uint8_t magic_0 = 'P',
    std::uint8_t magic_1 = 'K'
) {
    constexpr std::size_t fixed_size = 30;
    constexpr std::uint16_t unused_flags_mask = 0xd780;
    static constexpr std::array<std::uint16_t, 23> allowed_compression_methods{
        0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 20, 93, 94, 95, 96, 97, 98, 99,
        0xffff
    };
    if(!data.contains(offset, fixed_size)
        || data[offset] != magic_0
        || data[offset + 1] != magic_1
        || data[offset + 2] != 0x03
        || data[offset + 3] != 0x04) {
        return std::nullopt;
    }
    binary_reader<byte_order::little> reader(data);
    const auto version = reader.read<std::uint16_t>(offset + 4);
    const auto flags = reader.read<std::uint16_t>(offset + 6);
    const auto compression = reader.read<std::uint16_t>(offset + 8);
    const auto compressed_size = reader.read<std::uint32_t>(offset + 18);
    const auto uncompressed_size = reader.read<std::uint32_t>(offset + 22);
    const auto name_size = reader.read<std::uint16_t>(offset + 26);
    const auto extra_size = reader.read<std::uint16_t>(offset + 28);
    if(!version || !flags || !compression || !compressed_size || !uncompressed_size
        || !name_size || !extra_size
        || (*flags & unused_flags_mask) != 0
        || std::find(
            allowed_compression_methods.begin(),
            allowed_compression_methods.end() - 1,
            *compression
        ) == allowed_compression_methods.end() - 1) {
        return std::nullopt;
    }
    const auto header_size = fixed_size + *name_size + *extra_size;
    const auto data_size = *compressed_size > 0 ? *compressed_size : *uncompressed_size;
    if(header_size > data.size() - offset
        || data_size > data.size() - offset - header_size) {
        return std::nullopt;
    }
    return local_header{
        header_size + data_size,
        static_cast<std::uint16_t>(*version / 10U),
        static_cast<std::uint16_t>(*version % 10U)
    };
}

struct eocd_info {
    std::size_t end = 0;
    std::uint16_t file_count = 0;
};

[[nodiscard]] inline std::optional<eocd_info> find_eocd(byte_view data, std::size_t offset) {
    constexpr std::size_t fixed_size = 22;
    binary_reader<byte_order::little> reader(data);
    for(std::size_t cursor = offset; data.contains(cursor, 8); ++cursor) {
        if(data[cursor] != 'P' || data[cursor + 1] != 'K'
            || data[cursor + 2] != 0x05 || data[cursor + 3] != 0x06
            || data[cursor + 4] != 0 || data[cursor + 5] != 0
            || data[cursor + 6] != 0 || data[cursor + 7] != 0
            || !data.contains(cursor, fixed_size)) {
            continue;
        }
        const auto disk_entries = reader.read<std::uint16_t>(cursor + 8);
        const auto total_entries = reader.read<std::uint16_t>(cursor + 10);
        const auto comment_size = reader.read<std::uint16_t>(cursor + 20);
        if(!disk_entries || !total_entries || !comment_size
            || *disk_entries != *total_entries || *total_entries == 0
            || !data.contains(cursor, fixed_size + *comment_size)) {
            continue;
        }
        return eocd_info{cursor + fixed_size + *comment_size, *total_entries};
    }
    return std::nullopt;
}

}
