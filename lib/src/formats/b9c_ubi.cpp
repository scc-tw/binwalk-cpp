#include "b9c_ubi.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
namespace binwalk {
namespace {

struct qnx_ifs_format {};
struct ubi_format {};
struct ubifs_format {};

[[nodiscard]] byte_view tail_from(byte_view data, std::size_t offset) noexcept {
    if(offset > data.size()) {
        return byte_view{};
    }
    return data.subview(offset, data.size() - offset);
}

[[nodiscard]] std::uint32_t ubi_crc(byte_view data) noexcept {
    return crc32_jamcrc(data);
}

constexpr std::size_t ubi_ec_header_size = 64;
constexpr std::size_t ubi_ec_crc_size = ubi_ec_header_size - sizeof(std::uint32_t);
constexpr std::uint32_t ubi_ec_magic = 0x55424923U;

struct ubi_ec_header {
    std::uint32_t version = 0;
    std::uint32_t data_offset = 0;
    std::uint32_t volume_id_offset = 0;
};

[[nodiscard]] std::optional<ubi_ec_header> parse_ubi_ec_header(byte_view data) noexcept {
    const binary_reader<byte_order::big> reader(data);

    const auto magic = reader.read<std::uint32_t>(0);
    const auto version = reader.read<std::uint8_t>(4);
    const auto volume_id_offset = reader.read<std::uint32_t>(16);
    const auto data_offset = reader.read<std::uint32_t>(20);
    const auto header_crc = reader.read<std::uint32_t>(60);
    if(!magic || !version || !volume_id_offset || !data_offset || !header_crc) {
        return std::nullopt;
    }

    if(*magic != ubi_ec_magic) {
        return std::nullopt;
    }

    if(*data_offset < ubi_ec_header_size || *volume_id_offset < ubi_ec_header_size) {
        return std::nullopt;
    }

    const auto crc_region = data.subview(0, ubi_ec_crc_size);
    if(crc_region.size() != ubi_ec_crc_size || ubi_crc(crc_region) != *header_crc) {
        return std::nullopt;
    }

    ubi_ec_header header;
    header.version = *version;
    header.data_offset = *data_offset;
    header.volume_id_offset = *volume_id_offset;
    return header;
}

constexpr std::size_t ubi_volume_header_size = 64;
constexpr std::size_t ubi_volume_crc_size = ubi_volume_header_size - sizeof(std::uint32_t);
constexpr std::uint32_t ubi_volume_magic = 0x55424921U;

constexpr std::uint8_t ubi_volume_search[5] = {'U', 'B', 'I', '!', 0x01};

[[nodiscard]] bool parse_ubi_volume_header(byte_view data) noexcept {
    const binary_reader<byte_order::big> reader(data);

    const auto magic = reader.read<std::uint32_t>(0);
    const auto padding1 = reader.read<std::uint32_t>(16);
    const auto padding2 = reader.read<std::uint32_t>(36);
    const auto padding3 = reader.read<std::uint64_t>(48);
    const auto padding4 = reader.read<std::uint32_t>(56);
    const auto header_crc = reader.read<std::uint32_t>(60);
    if(!magic || !padding1 || !padding2 || !padding3 || !padding4 || !header_crc) {
        return false;
    }

    if(*magic != ubi_volume_magic) {
        return false;
    }

    if(*padding1 != 0 || *padding2 != 0 || *padding3 != 0 || *padding4 != 0) {
        return false;
    }

    const auto crc_region = data.subview(0, ubi_volume_crc_size);
    if(crc_region.size() != ubi_volume_crc_size) {
        return false;
    }
    return ubi_crc(crc_region) == *header_crc;
}

constexpr std::size_t max_volume_headers = 1U << 20;
constexpr std::size_t max_leb_candidates = 1U << 20;

struct ubi_image_geometry {
    std::uint64_t total_size = 0;
    std::uint64_t block_count = 0;
    std::uint64_t leb_size = 0;
};

[[nodiscard]] std::optional<ubi_image_geometry> get_ubi_image_size(byte_view ubi_data) {

    std::vector<std::pair<std::uint64_t, std::uint64_t>> candidates;

    std::unordered_map<std::uint64_t, std::size_t> candidate_index;

    std::uint64_t block_count = 0;
    std::size_t previous_volume_offset = 0;

    if(ubi_data.size() < sizeof(ubi_volume_search)) {
        return std::nullopt;
    }

    const std::size_t search_limit = ubi_data.size() - sizeof(ubi_volume_search);
    for(std::size_t position = 0; position <= search_limit; ++position) {

        if(!ubi_data.contains(position, sizeof(ubi_volume_search))) {
            break;
        }
        bool matched = true;
        for(std::size_t index = 0; index < sizeof(ubi_volume_search); ++index) {
            if(ubi_data[position + index] != ubi_volume_search[index]) {
                matched = false;
                break;
            }
        }
        if(!matched) {
            continue;
        }

        const auto candidate = ubi_data.subview(position, ubi_data.size() - position);
        if(!parse_ubi_volume_header(candidate)) {
            continue;
        }

        ++block_count;
        if(block_count > max_volume_headers) {
            return std::nullopt;
        }

        if(previous_volume_offset != 0) {
            const auto leb_size = static_cast<std::uint64_t>(position - previous_volume_offset);
            const auto existing = candidate_index.find(leb_size);
            if(existing != candidate_index.end()) {
                ++candidates[existing->second].second;
            } else {
                if(candidates.size() >= max_leb_candidates) {
                    return std::nullopt;
                }
                candidate_index.emplace(leb_size, candidates.size());
                candidates.emplace_back(leb_size, std::uint64_t{1});
            }
        }

        previous_volume_offset = position;
    }

    std::uint64_t leb_size = 0;
    std::uint64_t best_count = 0;
    for(const auto& candidate : candidates) {
        if(candidate.second > best_count) {
            leb_size = candidate.first;
            best_count = candidate.second;
        }
    }

    if(leb_size == 0 || block_count == 0) {
        return std::nullopt;
    }
    const auto total = checked_multiply(block_count, leb_size);
    if(!total) {
        return std::nullopt;
    }

    ubi_image_geometry geometry;
    geometry.total_size = *total;
    geometry.block_count = block_count;
    geometry.leb_size = leb_size;
    return geometry;
}

constexpr std::size_t ubifs_declared_size = 128;
constexpr std::size_t ubifs_extra_size = 3968;
constexpr std::size_t ubifs_struct_size = ubifs_declared_size + ubifs_extra_size;
constexpr std::size_t ubifs_crc_start = 8;
constexpr std::uint32_t ubifs_node_magic = 0x06101831U;
constexpr std::uint8_t ubifs_superblock_node_type = 6;
constexpr std::uint8_t ubifs_max_group_type = 2;

struct ubifs_superblock_header {
    std::uint32_t leb_size = 0;
    std::uint32_t leb_count = 0;

    std::uint32_t format_version = 0;
};

[[nodiscard]] std::optional<ubifs_superblock_header> parse_ubifs_superblock_header(
    byte_view data
) noexcept {
    const binary_reader<byte_order::little> reader(data);

    const auto magic = reader.read<std::uint32_t>(0);
    const auto header_crc = reader.read<std::uint32_t>(4);
    const auto node_type = reader.read<std::uint8_t>(20);
    const auto group_type = reader.read<std::uint8_t>(21);
    const auto padding1 = reader.read<std::uint32_t>(22);
    const auto leb_size = reader.read<std::uint32_t>(36);
    const auto leb_count = reader.read<std::uint32_t>(40);
    const auto format_version = reader.read<std::uint32_t>(80);
    const auto padding2 = reader.read<std::uint16_t>(86);
    if(!magic || !header_crc || !node_type || !group_type || !padding1
       || !leb_size || !leb_count || !format_version || !padding2) {
        return std::nullopt;
    }

    if(*magic != ubifs_node_magic) {
        return std::nullopt;
    }
    if(*padding1 != 0 || *padding2 != 0) {
        return std::nullopt;
    }

    if(*node_type != ubifs_superblock_node_type) {
        return std::nullopt;
    }
    if(*group_type > ubifs_max_group_type) {
        return std::nullopt;
    }

    const auto crc_region = data.subview(ubifs_crc_start, ubifs_struct_size - ubifs_crc_start);
    if(crc_region.size() != ubifs_struct_size - ubifs_crc_start) {
        return std::nullopt;
    }
    if(ubi_crc(crc_region) != *header_crc) {
        return std::nullopt;
    }

    ubifs_superblock_header header;
    header.leb_size = *leb_size;
    header.leb_count = *leb_count;
    header.format_version = *format_version;
    return header;
}

constexpr std::size_t qnx_ifs_header_size = 64;
constexpr std::uint32_t qnx_ifs_magic_value = 0x00FF7EEBU;
constexpr std::uint16_t qnx_ifs_version = 1;

struct qnx_ifs_header {
    std::uint32_t total_size = 0;
};

[[nodiscard]] std::optional<qnx_ifs_header> parse_qnx_ifs_header(byte_view data) noexcept {
    const binary_reader<byte_order::little> reader(data);

    const auto magic = reader.read<std::uint32_t>(0);
    const auto version = reader.read<std::uint16_t>(4);
    const auto flags2 = reader.read<std::uint8_t>(7);
    const auto stored_size = reader.read<std::uint32_t>(36);
    const auto zero_0 = reader.read<std::uint16_t>(50);
    const auto zero_1 = reader.read<std::uint32_t>(52);
    const auto zero_2 = reader.read<std::uint32_t>(56);
    const auto zero_3 = reader.read<std::uint32_t>(60);
    if(!magic || !version || !flags2 || !stored_size
       || !zero_0 || !zero_1 || !zero_2 || !zero_3) {
        return std::nullopt;
    }

    if(*magic != qnx_ifs_magic_value || *version != qnx_ifs_version) {
        return std::nullopt;
    }

    if(*flags2 != 0) {
        return std::nullopt;
    }
    if(*zero_0 != 0 || *zero_1 != 0 || *zero_2 != 0 || *zero_3 != 0) {
        return std::nullopt;
    }

    qnx_ifs_header header;
    header.total_size = *stored_size;
    return header;
}

[[nodiscard]] extraction_result extract_ubi_unsupported(
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

[[nodiscard]] extraction_result extract_ubifs_unsupported(
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

[[nodiscard]] extractor ubi_extractor_definition() {
    return extractor{
        extractor_type::internal,
        "ubi_built_in",
        &extract_ubi_unsupported,
        std::string{},
        std::string{},
        {},
        {},
        false
    };
}

[[nodiscard]] extractor ubifs_extractor_definition() {
    return extractor{
        extractor_type::internal,
        "ubifs_built_in",
        &extract_ubifs_unsupported,
        std::string{},
        std::string{},
        {},
        {},
        false
    };
}

[[nodiscard]] extractor dumpifs_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "dumpifs",
        "ifs",
        {"-x", "%e"},
        {0},
        false
    };
}

}

template<>
struct format_traits<qnx_ifs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "qnx_ifs"; }
    static std::string description() { return "QNX IFS image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0xEB, 0x7E, 0xFF, 0x00, 0x01, 0x00}};
    }

    static binwalk::extractor extractor() { return dumpifs_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto ifs_data = tail_from(data, offset);
        const auto header = parse_qnx_ifs_header(ifs_data);
        if(!header) {
            return std::nullopt;
        }

        const auto size = static_cast<std::uint64_t>(header->total_size);
        if(size > static_cast<std::uint64_t>(ifs_data.size())) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = size;

        result.confidence = confidence_low;
        result.description = description() + ", total size: " + std::to_string(size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<ubi_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "ubi"; }
    static std::string description() { return "UBI image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'U', 'B', 'I', '#', 0x01}};
    }

    static binwalk::extractor extractor() { return ubi_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto ubi_data = tail_from(data, offset);
        const auto header = parse_ubi_ec_header(ubi_data);
        if(!header) {
            return std::nullopt;
        }

        const auto available = static_cast<std::uint64_t>(ubi_data.size());
        if(available <= static_cast<std::uint64_t>(header->data_offset)
           || available <= static_cast<std::uint64_t>(header->volume_id_offset)) {
            return std::nullopt;
        }

        const auto geometry = get_ubi_image_size(ubi_data);
        if(!geometry) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = geometry->total_size;
        result.confidence = confidence_high;

        result.description = description() + ", version: " + std::to_string(header->version)
            + ", erase block size: " + std::to_string(geometry->leb_size)
            + ", block count: " + std::to_string(geometry->block_count)
            + ", image size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<ubifs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "ubifs"; }
    static std::string description() { return "UBIFS image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x31, 0x18, 0x10, 0x06}};
    }

    static binwalk::extractor extractor() { return ubifs_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto ubifs_data = tail_from(data, offset);
        const auto header = parse_ubifs_superblock_header(ubifs_data);
        if(!header) {
            return std::nullopt;
        }

        const auto size = checked_multiply(
            static_cast<std::uint64_t>(header->leb_count),
            static_cast<std::uint64_t>(header->leb_size)
        );
        if(!size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *size;
        result.confidence = confidence_high;

        result.description = description() + ", format version: "
            + std::to_string(header->format_version)
            + ", LEB size: " + std::to_string(header->leb_size)
            + ", LEB count: " + std::to_string(header->leb_count)
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

namespace formats {

std::vector<signature> b9c_ubi_signatures() {
    return make_signatures(type_list<
        qnx_ifs_format,
        ubi_format,
        ubifs_format
    >{});
}

}
}
