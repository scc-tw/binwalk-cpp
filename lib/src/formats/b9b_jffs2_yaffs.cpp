#include "b9b_jffs2_yaffs.hpp"

#include <binwalk/binary_reader.hpp>
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

struct jffs2_format {};
struct yaffs_format {};

constexpr std::size_t jffs2_node_struct_size = 12;

constexpr std::size_t jffs2_header_crc_size = 8;

constexpr std::uint16_t jffs2_correct_magic = 0x1985;

constexpr std::uint64_t jffs2_max_page_size = 0x20000;

constexpr std::uint64_t jffs2_min_valid_node_count = 2;

struct jffs2_node {
    std::uint64_t size = 0;
    std::uint16_t node_type = 0;
    bool big_endian = false;
};

[[nodiscard]] std::uint32_t jffs2_node_crc(byte_view header_bytes) noexcept {
    return ~crc32_update(0xFFFFFFFFU, header_bytes);
}

[[nodiscard]] constexpr std::uint64_t jffs2_roundup(std::uint64_t value) noexcept {
    return (value + 3U) & ~static_cast<std::uint64_t>(3U);
}

[[nodiscard]] std::optional<jffs2_node> parse_jffs2_node_header(
    byte_view data,
    std::size_t offset
) {

    if(!data.contains(offset, jffs2_node_struct_size)) {
        return std::nullopt;
    }

    const binary_reader<byte_order::little> little(data);
    const binary_reader<byte_order::big> big(data);

    jffs2_node node;
    auto magic = little.read<std::uint16_t>(offset);
    if(!magic) {
        return std::nullopt;
    }
    if(*magic != jffs2_correct_magic) {
        node.big_endian = true;
        magic = big.read<std::uint16_t>(offset);
        if(!magic || *magic != jffs2_correct_magic) {
            return std::nullopt;
        }
    }

    const auto read_u16 = [&](std::size_t field_offset) {
        return node.big_endian ? big.read<std::uint16_t>(field_offset)
                               : little.read<std::uint16_t>(field_offset);
    };
    const auto read_u32 = [&](std::size_t field_offset) {
        return node.big_endian ? big.read<std::uint32_t>(field_offset)
                               : little.read<std::uint32_t>(field_offset);
    };

    const auto node_type = read_u16(offset + 2);
    const auto node_size = read_u32(offset + 4);
    const auto stored_crc = read_u32(offset + 8);
    if(!node_type || !node_size || !stored_crc) {
        return std::nullopt;
    }

    const auto calculated_crc = jffs2_node_crc(data.subview(offset, jffs2_header_crc_size));
    if(calculated_crc != *stored_crc) {
        return std::nullopt;
    }

    node.size = *node_size;
    node.node_type = *node_type;
    return node;
}

[[nodiscard]] extraction_result extract_jffs2_unsupported(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    (void)data;
    (void)signature;
    (void)output_directory;

    extraction_result result;
    result.success = false;
    result.failure = extraction_failure::unsupported;
    return result;
}

constexpr std::uint64_t yaffs_min_number_of_objs = 2;

constexpr std::uint64_t yaffs_max_obj_size = 16896;

constexpr std::size_t yaffs_obj_header_struct_size = 10;

constexpr std::size_t yaffs_file_info_struct_size = 28;

constexpr std::size_t yaffs_info_struct_start = 268;

constexpr std::size_t yaffs_file_size_field_offset = 24;

constexpr std::uint16_t yaffs_unused_name_checksum = 0xFFFF;

constexpr std::uint32_t yaffs_max_obj_type = 5;

constexpr std::uint32_t yaffs_file_type = 1;

constexpr std::uint8_t yaffs_big_endian_first_byte = 0;

[[nodiscard]] std::optional<std::uint32_t> parse_yaffs_obj_header(
    byte_view data,
    std::size_t offset,
    bool big_endian
) {
    if(!data.contains(offset, yaffs_obj_header_struct_size)) {
        return std::nullopt;
    }

    const binary_reader<byte_order::little> little(data);
    const binary_reader<byte_order::big> big(data);

    const auto obj_type = big_endian ? big.read<std::uint32_t>(offset)
                                     : little.read<std::uint32_t>(offset);
    const auto parent_id = big_endian ? big.read<std::uint32_t>(offset + 4)
                                      : little.read<std::uint32_t>(offset + 4);
    const auto name_checksum = big_endian ? big.read<std::uint16_t>(offset + 8)
                                          : little.read<std::uint16_t>(offset + 8);
    if(!obj_type || !parent_id || !name_checksum) {
        return std::nullopt;
    }

    if(*obj_type > yaffs_max_obj_type
       || *parent_id == 0
       || *name_checksum != yaffs_unused_name_checksum) {
        return std::nullopt;
    }
    return obj_type;
}

[[nodiscard]] std::optional<std::uint32_t> parse_yaffs_file_size(
    byte_view data,
    std::size_t offset,
    bool big_endian
) {
    if(!data.contains(offset, yaffs_file_info_struct_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::little> little(data);
    const binary_reader<byte_order::big> big(data);
    const auto field = offset + yaffs_file_size_field_offset;
    return big_endian ? big.read<std::uint32_t>(field) : little.read<std::uint32_t>(field);
}

[[nodiscard]] std::optional<std::uint64_t> yaffs_page_size(byte_view data, std::size_t base) {
    static constexpr std::uint64_t page_sizes[] = {512, 1024, 2048, 4096, 8192, 16384};

    static constexpr std::uint8_t magic_a[] = {0x00, 0x00, 0x10, 0x00};
    static constexpr std::uint8_t magic_b[] = {0x00, 0x10, 0x00, 0x00};
    static constexpr std::uint8_t magic_c[] = {0xFF, 0xFF, 0x00, 0x00, 0x10, 0x00};
    static constexpr std::uint8_t magic_d[] = {0xFF, 0xFF, 0x00, 0x10, 0x00, 0x00};
    const std::array<byte_view, 4> spare_magics{
        byte_view(magic_a, sizeof(magic_a)),
        byte_view(magic_b, sizeof(magic_b)),
        byte_view(magic_c, sizeof(magic_c)),
        byte_view(magic_d, sizeof(magic_d))
    };

    for(const auto page_size : page_sizes) {
        for(const auto& spare_magic : spare_magics) {
            const auto start = static_cast<std::uint64_t>(base) + page_size;
            if(!is_range_safe(data.size(), static_cast<std::size_t>(start), spare_magic.size())) {
                continue;
            }
            const auto candidate = data.subview(
                static_cast<std::size_t>(start), spare_magic.size()
            );
            bool equal = true;
            for(std::size_t index = 0; index < spare_magic.size(); ++index) {
                if(candidate[index] != spare_magic[index]) {
                    equal = false;
                    break;
                }
            }
            if(equal) {
                return page_size;
            }
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> yaffs_spare_size(
    byte_view data,
    std::size_t base,
    std::uint64_t page_size,
    bool big_endian
) {
    static constexpr std::uint64_t spare_sizes[] = {16, 32, 64, 128, 256, 512};

    for(const auto spare_size : spare_sizes) {

        const auto next_obj_offset = (page_size + spare_size) * yaffs_min_number_of_objs;
        const auto absolute = static_cast<std::uint64_t>(base) + next_obj_offset;
        if(absolute > static_cast<std::uint64_t>(data.size())) {
            continue;
        }
        if(parse_yaffs_obj_header(data, static_cast<std::size_t>(absolute), big_endian)) {
            return spare_size;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> yaffs_file_block_count(
    byte_view data,
    std::size_t obj_offset,
    std::uint64_t page_size,
    bool big_endian
) {
    const auto info_offset = static_cast<std::uint64_t>(obj_offset) + yaffs_info_struct_start;
    if(info_offset > static_cast<std::uint64_t>(data.size())) {
        return std::nullopt;
    }
    const auto file_size = parse_yaffs_file_size(
        data, static_cast<std::size_t>(info_offset), big_endian
    );
    if(!file_size) {
        return std::nullopt;
    }
    return (static_cast<std::uint64_t>(*file_size) + page_size - 1) / page_size;
}

[[nodiscard]] std::optional<std::uint64_t> yaffs_image_size(
    byte_view data,
    std::size_t base,
    std::uint64_t page_size,
    std::uint64_t spare_size,
    bool big_endian
) {

    if(base >= data.size()) {
        return std::nullopt;
    }
    const auto available = static_cast<std::uint64_t>(data.size()) - base;
    const auto block_size = page_size + spare_size;

    std::uint64_t image_size = 0;
    std::uint64_t next_obj_offset = 0;
    std::optional<std::size_t> previous_obj_offset;

    const std::uint64_t iteration_budget = available / block_size + 64;
    std::uint64_t iterations = 0;

    while(next_obj_offset < available
          && is_offset_safe(
              static_cast<std::size_t>(available),
              static_cast<std::size_t>(next_obj_offset),
              previous_obj_offset
          )) {
        if(++iterations > iteration_budget) {
            return std::nullopt;
        }

        const auto obj_offset = static_cast<std::size_t>(base + next_obj_offset);
        const auto obj_type = parse_yaffs_obj_header(data, obj_offset, big_endian);
        if(!obj_type) {

            break;
        }

        std::uint64_t data_blocks = 1;
        if(*obj_type == yaffs_file_type) {
            const auto block_count =
                yaffs_file_block_count(data, obj_offset, page_size, big_endian);
            if(!block_count) {
                return std::nullopt;
            }
            data_blocks += *block_count;
        }

        const auto added = checked_multiply(data_blocks, block_size);
        if(!added) {
            return std::nullopt;
        }
        previous_obj_offset = static_cast<std::size_t>(next_obj_offset);
        image_size += *added;
        next_obj_offset = image_size;
    }

    const auto minimum = block_size * yaffs_min_number_of_objs;
    if(image_size > minimum && image_size <= available) {
        return image_size;
    }
    return std::nullopt;
}

[[nodiscard]] extractor unyaffs_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "unyaffs",
        "img",
        {"%e", "yaffs-root"},
        {0},
        false
    };
}

}

template<>
struct format_traits<jffs2_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jffs2"; }
    static std::string description() { return "JFFS2 filesystem"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x19, 0x85, 0xE0, 0x01},
            {0x19, 0x85, 0xE0, 0x02},
            {0x19, 0x85, 0x20, 0x03},
            {0x85, 0x19, 0x01, 0xE0},
            {0x85, 0x19, 0x02, 0xE0},
            {0x85, 0x19, 0x03, 0x20}
        };
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "jffs2_built_in", &extract_jffs2_unsupported,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto first_node = parse_jffs2_node_header(data, offset);
        if(!first_node) {
            return std::nullopt;
        }

        std::uint64_t jffs2_eof =
            static_cast<std::uint64_t>(offset) + jffs2_roundup(first_node->size);

        if(jffs2_eof >= static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        const std::uint8_t magic_first = first_node->big_endian ? 0x19 : 0x85;
        const std::uint8_t magic_second = first_node->big_endian ? 0x85 : 0x19;

        const auto grep_offset = static_cast<std::size_t>(jffs2_eof);
        std::uint64_t node_count = 1;

        const std::uint64_t node_budget =
            static_cast<std::uint64_t>(data.size() - grep_offset) / 2 + 64;

        for(std::size_t header_start = grep_offset;
            data.contains(header_start, 2);
            ++header_start) {
            if(data[header_start] != magic_first || data[header_start + 1] != magic_second) {
                continue;
            }

            const auto absolute_start = static_cast<std::uint64_t>(header_start);

            if(absolute_start < jffs2_eof) {
                continue;
            }

            if((absolute_start - jffs2_eof) > jffs2_max_page_size) {
                break;
            }

            if(!data.contains(header_start, jffs2_node_struct_size)) {
                break;
            }

            if(const auto node = parse_jffs2_node_header(data, header_start)) {
                if(++node_count > node_budget) {
                    return std::nullopt;
                }
                jffs2_eof = absolute_start + jffs2_roundup(node->size);
            }
        }

        if(node_count <= jffs2_min_valid_node_count) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = jffs2_eof - result.offset;
        result.confidence = confidence_high;

        result.description = description() + ", "
            + (first_node->big_endian ? "big" : "little") + " endian, nodes: "
            + std::to_string(node_count) + ", total size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<yaffs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "yaffs"; }
    static std::string description() { return "YAFFSv2 filesystem"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF},
            {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF},
            {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF},
            {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF}
        };
    }

    static binwalk::extractor extractor() { return unyaffs_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto required_min_offset =
            static_cast<std::uint64_t>(offset) + yaffs_max_obj_size * yaffs_min_number_of_objs;
        if(required_min_offset >= static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        if(!data.contains(offset, 1)) {
            return std::nullopt;
        }

        const bool big_endian = data[offset] == yaffs_big_endian_first_byte;

        const auto page_size = yaffs_page_size(data, offset);
        if(!page_size) {
            return std::nullopt;
        }
        const auto spare_size = yaffs_spare_size(data, offset, *page_size, big_endian);
        if(!spare_size) {
            return std::nullopt;
        }
        const auto image_size =
            yaffs_image_size(data, offset, *page_size, *spare_size, big_endian);
        if(!image_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *image_size;

        result.confidence = confidence_medium;
        result.description = description() + ", "
            + (big_endian ? "big" : "little") + " endian, page size: "
            + std::to_string(*page_size) + ", spare size: "
            + std::to_string(*spare_size) + ", image size: "
            + std::to_string(*image_size) + " bytes";
        return result;
    }
};

namespace formats {

std::vector<signature> b9b_jffs2_yaffs_signatures() {
    return make_signatures(type_list<
        jffs2_format,
        yaffs_format
    >{});
}

}
}
