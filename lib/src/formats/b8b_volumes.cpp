#include "b8b_volumes.hpp"

#include "../builtin_extractors.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

[[nodiscard]] extractor tsk_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "tsk_recover",
        "img",
        {"-i", "raw", "-a", "%e", "rootfs"},
        {0},
        false
    };
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

[[nodiscard]] constexpr std::optional<std::size_t> rewind_to_structure_start(
    std::size_t magic_position,
    std::size_t back_offset
) noexcept {
    if(magic_position < back_offset) {
        return std::nullopt;
    }
    return magic_position - back_offset;
}

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

[[nodiscard]] std::uint32_t crc32c(
    byte_view data,
    std::size_t offset,
    std::size_t size
) noexcept {
    if(!data.contains(offset, size)) {
        return 0;
    }
    std::uint32_t crc = 0xffffffffU;
    for(std::size_t index = 0; index < size; ++index) {
        crc ^= static_cast<std::uint32_t>(data[offset + index]);
        for(int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ (0x82f63b78U & (0U - (crc & 1U)));
        }
    }
    return crc ^ 0xffffffffU;
}

struct apfs_format {};
struct btrfs_format {};
struct efigpt_format {};
struct ext_format {};
struct fat_format {};
struct mbr_format {};
struct ntfs_format {};

}

template<>
struct format_traits<ext_format> {
    static std::string name() { return "ext"; }
    static std::string description() { return "EXT filesystem"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x53, 0xef, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0x53, 0xef, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00},
            {0x53, 0xef, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00},
            {0x53, 0xef, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0x53, 0xef, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00},
            {0x53, 0xef, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00}
        };
    }

    static binwalk::extractor extractor() { return tsk_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t magic_back_offset = 1080;

        constexpr std::size_t superblock_offset = 1024;
        constexpr std::size_t superblock_size = 1024;
        constexpr std::size_t max_block_log = 2;
        constexpr std::uint16_t superblock_magic = 0xef53;

        const auto image = rewind_to_structure_start(offset, magic_back_offset);
        if(!image) {
            return std::nullopt;
        }

        if(!data.contains(*image, superblock_offset + superblock_size)) {
            return std::nullopt;
        }

        const auto superblock = *image + superblock_offset;
        binary_reader<byte_order::little> reader(data);
        const auto inodes_count = reader.read<std::uint32_t>(superblock + 0);
        const auto blocks_count = reader.read<std::uint32_t>(superblock + 4);
        const auto reserved_blocks_count = reader.read<std::uint32_t>(superblock + 8);
        const auto free_blocks_count = reader.read<std::uint32_t>(superblock + 12);
        const auto first_data_block = reader.read<std::uint32_t>(superblock + 20);
        const auto log_block_size = reader.read<std::uint32_t>(superblock + 24);
        const auto magic_field = reader.read<std::uint16_t>(superblock + 56);
        const auto creator_os = reader.read<std::uint32_t>(superblock + 72);
        const auto revision_level = reader.read<std::uint32_t>(superblock + 76);

        if(!inodes_count || !blocks_count || !reserved_blocks_count || !free_blocks_count
            || !first_data_block || !log_block_size || !magic_field || !creator_os
            || !revision_level) {
            return std::nullopt;
        }

        if(*magic_field != superblock_magic) {
            return std::nullopt;
        }

        std::string operating_system;
        switch(*creator_os) {
        case 0: operating_system = "Linux"; break;
        case 1: operating_system = "GNU HURD"; break;
        case 2: operating_system = "MASIX"; break;
        case 3: operating_system = "FreeBSD"; break;
        case 4: operating_system = "Lites"; break;
        default: return std::nullopt;
        }
        if(*revision_level > 1 || *first_data_block > 1 || *log_block_size > max_block_log) {
            return std::nullopt;
        }

        const std::uint64_t block_size = std::uint64_t{1024} << *log_block_size;
        const auto image_size = checked_multiply(block_size, *blocks_count);
        if(!image_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);
        result.size = *image_size;
        result.confidence = confidence_medium;

        result.description = description() + " for " + operating_system
            + ", inodes: " + std::to_string(*inodes_count)
            + ", block size: " + std::to_string(block_size)
            + ", block count: " + std::to_string(*blocks_count)
            + ", free blocks: " + std::to_string(*free_blocks_count)
            + ", reserved blocks: " + std::to_string(*reserved_blocks_count)
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<mbr_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0x1fe;

    static constexpr bool always_display = true;

    static std::string name() { return "mbr"; }
    static std::string description() { return "DOS Master Boot Record"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x55, 0xaa}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "mbr_built_in", detail::extract_mbr};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t block_size = 512;
        constexpr std::uint64_t min_image_size = block_size * 2;
        constexpr std::size_t partition_table_offset = 446;
        constexpr std::size_t partition_entry_size = 16;
        constexpr std::size_t partition_count = 4;

        if(offset != magic_offset) {
            return std::nullopt;
        }
        const auto image = rewind_to_structure_start(offset, magic_offset);
        if(!image) {
            return std::nullopt;
        }

        if(!data.contains(
            *image + partition_table_offset,
            partition_entry_size * partition_count
        )) {
            return std::nullopt;
        }
        const auto available_data = data.size() - *image;

        struct partition {
            std::uint64_t start;
            std::uint64_t size;
            std::string name;
        };
        std::vector<partition> partitions;
        std::uint64_t image_size = 0;
        binary_reader<byte_order::little> reader(data);

        const auto partition_name = [](std::uint8_t type) -> std::string {
            switch(type) {
            case 0x07: return "NTFS_IFS_HPFS_exFAT";
            case 0x0b:
            case 0x0c: return "FAT32";
            case 0x43:
            case 0x83: return "Linux";
            case 0x4d: return "QNX Primary Volume";
            case 0x4e: return "QNX Secondary Volume";
            case 0x81: return "Minix";
            case 0x8e: return "Linux LVM";
            case 0x96: return "ISO-9660";
            case 0xb1:
            case 0xb2:
            case 0xb3: return "QNXv6 File System";
            case 0xee: return "EFI GPT Protective";
            case 0xef: return "EFI System Partition";
            default: return "Unknown";
            }
        };

        for(std::size_t index = 0; index < partition_count; ++index) {
            const auto entry = *image + partition_table_offset + index * partition_entry_size;
            const auto status = data[entry];
            const auto type = data[entry + 4];
            const auto lba_start = reader.read<std::uint32_t>(entry + 8);
            const auto lba_size = reader.read<std::uint32_t>(entry + 12);
            if(!lba_start || !lba_size) {

                return std::nullopt;
            }

            if(type == 0 && *lba_size == 0) {
                continue;
            }
            if(status != 0 && status != 0x80) {
                continue;
            }

            const auto start = static_cast<std::uint64_t>(*lba_start) * block_size;
            const auto size = static_cast<std::uint64_t>(*lba_size) * block_size;

            const auto end = start + size;

            if(end > static_cast<std::uint64_t>(available_data)) {
                continue;
            }

            if(start != 0) {
                partitions.push_back({start, size, partition_name(type)});
            }
            image_size = std::max(image_size, end);
        }

        if(partitions.empty() || image_size <= min_image_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);
        result.size = image_size;
        result.confidence = confidence_medium;
        result.description = description();
        for(const auto& value : partitions) {
            result.description += ", partition: " + value.name;
        }
        result.description += ", image size: " + std::to_string(result.size) + " bytes";

        for(const auto& value : partitions) {
            if(value.start == result.offset) {
                result.extraction_declined = true;
            }
        }
        return result;
    }
};

template<>
struct format_traits<fat_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0x1fe;

    static std::string name() { return "fat"; }
    static std::string description() { return "FAT file system"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x55, 0xaa}}; }
    static binwalk::extractor extractor() { return tsk_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t magic_back_offset = 0x1fe;
        constexpr std::size_t boot_sector_structure_size = 36;
        constexpr std::size_t expected_fat_count = 2;

        const auto image = rewind_to_structure_start(offset, magic_back_offset);
        if(!image) {
            return std::nullopt;
        }

        static constexpr std::uint8_t boot_signature[] = {0x55, 0xaa};
        if(!bytes_equal(data, offset, boot_signature, sizeof(boot_signature))) {
            return std::nullopt;
        }
        if(!data.contains(*image, boot_sector_structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto opcode1 = data[*image];
        const auto bytes_per_sector = reader.read<std::uint16_t>(*image + 11);
        const auto sectors_per_cluster = data[*image + 13];
        const auto reserved_sectors = reader.read<std::uint16_t>(*image + 14);
        const auto fat_count = data[*image + 16];
        const auto total_sectors_16 = reader.read<std::uint16_t>(*image + 19);
        const auto media_type = data[*image + 21];
        const auto fat_size_16 = reader.read<std::uint16_t>(*image + 22);
        const auto total_sectors_32 = reader.read<std::uint32_t>(*image + 32);
        if(!bytes_per_sector || !reserved_sectors || !total_sectors_16 || !fat_size_16
            || !total_sectors_32) {
            return std::nullopt;
        }

        if(opcode1 != 0xeb && opcode1 != 0xe9) {
            return std::nullopt;
        }
        if(*bytes_per_sector != 512 && *bytes_per_sector != 1024
            && *bytes_per_sector != 2048 && *bytes_per_sector != 4096) {
            return std::nullopt;
        }

        if(sectors_per_cluster == 0 || sectors_per_cluster > 128
            || (sectors_per_cluster & (sectors_per_cluster - 1)) != 0) {
            return std::nullopt;
        }
        if(*reserved_sectors == 0 || fat_count != expected_fat_count) {
            return std::nullopt;
        }
        switch(media_type) {
        case 0xf0:
        case 0xf8:
        case 0xf9:
        case 0xfa:
        case 0xfb:
        case 0xfc:
        case 0xfd:
        case 0xfe: break;
        default: return std::nullopt;
        }

        const bool is_fat32 = *fat_size_16 == 0;

        const auto total_sectors = *total_sectors_16 != 0
            ? static_cast<std::uint64_t>(*total_sectors_16)
            : static_cast<std::uint64_t>(*total_sectors_32);
        const auto total_size = checked_multiply(
            total_sectors,
            static_cast<std::uint64_t>(*bytes_per_sector)
        );

        if(!total_size || *total_size == 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);
        result.size = *total_size;
        result.confidence = confidence_medium;
        result.description = description()
            + ", type: " + (is_fat32 ? "FAT32" : "FAT12/16")
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<efigpt_format> {
    static std::string name() { return "efigpt"; }
    static std::string description() { return "EFI Global Partition Table"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x55, 0xaa, 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'}};
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_back_offset = 0x1fe;
        constexpr std::size_t block_size = 512;
        constexpr std::size_t gpt_header_size = 92;
        constexpr std::size_t partition_entry_structure_size = 56;
        constexpr std::uint32_t expected_revision = 0x00010000;

        if(offset > data.size()) {
            return std::nullopt;
        }

        const auto available_data = data.size() - offset;

        const auto image = rewind_to_structure_start(offset, magic_back_offset);
        if(!image) {
            return std::nullopt;
        }

        static constexpr std::uint8_t gpt_magic[] = {
            0x55, 0xaa, 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'
        };
        if(!bytes_equal(data, offset, gpt_magic, sizeof(gpt_magic))) {
            return std::nullopt;
        }

        const auto header = *image + block_size;
        if(!data.contains(header, gpt_header_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto revision = reader.read<std::uint32_t>(header + 8);
        const auto reserved = reader.read<std::uint32_t>(header + 20);
        const auto partition_entry_lba = reader.read<std::uint64_t>(header + 72);
        const auto partition_entry_count = reader.read<std::uint32_t>(header + 80);
        const auto partition_entry_size = reader.read<std::uint32_t>(header + 84);
        const auto partition_entries_crc = reader.read<std::uint32_t>(header + 88);
        if(!revision || !reserved || !partition_entry_lba || !partition_entry_count
            || !partition_entry_size || !partition_entries_crc) {
            return std::nullopt;
        }
        if(*reserved != 0 || *revision != expected_revision) {
            return std::nullopt;
        }

        const auto entries_relative = checked_multiply(*partition_entry_lba, block_size);
        const auto entries_length = checked_multiply(
            static_cast<std::uint64_t>(*partition_entry_count),
            static_cast<std::uint64_t>(*partition_entry_size)
        );
        if(!entries_relative || !entries_length) {
            return std::nullopt;
        }

        if(*entries_relative > data.size() - *image) {
            return std::nullopt;
        }
        const auto entries = *image + static_cast<std::size_t>(*entries_relative);
        if(*entries_length > data.size() - entries) {
            return std::nullopt;
        }
        const auto entries_size = static_cast<std::size_t>(*entries_length);

        if(crc32(data, entries, entries_size) != *partition_entries_crc) {
            return std::nullopt;
        }

        std::uint64_t total_size = 0;
        std::size_t next_entry = 0;
        std::optional<std::size_t> previous_entry;
        while(is_offset_safe(entries_size, next_entry, previous_entry)) {
            const auto entry = entries + next_entry;
            if(data.contains(entry, partition_entry_structure_size)) {
                const auto type_guid_high = reader.read<std::uint64_t>(entry + 0);
                const auto type_guid_low = reader.read<std::uint64_t>(entry + 8);
                const auto starting_lba = reader.read<std::uint64_t>(entry + 32);
                const auto ending_lba = reader.read<std::uint64_t>(entry + 40);

                if(type_guid_high && type_guid_low && starting_lba && ending_lba
                    && *type_guid_high != 0 && *type_guid_low != 0) {
                    const auto start_offset = checked_multiply(*starting_lba, block_size);
                    const auto end_offset = checked_multiply(*ending_lba, block_size);
                    if(start_offset && end_offset
                        && *start_offset < *end_offset && *end_offset > total_size) {
                        total_size = *end_offset;
                    }
                }
            }
            previous_entry = next_entry;

            next_entry += *partition_entry_size;
        }

        if(total_size == 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);

        result.size = total_size > static_cast<std::uint64_t>(available_data)
            ? static_cast<std::uint64_t>(available_data)
            : total_size;

        result.confidence = confidence_high;
        result.description = description() + ", total size: " + std::to_string(result.size);
        return result;
    }
};

template<>
struct format_traits<ntfs_format> {
    static std::string name() { return "ntfs"; }
    static std::string description() { return "NTFS partition"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0xeb, 0x52, 0x90, 'N', 'T', 'F', 'S', ' ', ' ', ' ', ' '}};
    }

    static binwalk::extractor extractor() { return tsk_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t boot_sector_structure_size = 48;

        static constexpr std::uint8_t ntfs_magic[] = {
            0xeb, 0x52, 0x90, 'N', 'T', 'F', 'S', ' ', ' ', ' ', ' '
        };

        if(!bytes_equal(data, offset, ntfs_magic, sizeof(ntfs_magic))) {
            return std::nullopt;
        }
        if(!data.contains(offset, boot_sector_structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto bytes_per_sector = reader.read<std::uint16_t>(offset + 11);
        const auto unused1 = reader.read<std::uint16_t>(offset + 14);
        const auto unused2 = reader.read_u24(offset + 16);
        const auto unused3 = reader.read<std::uint16_t>(offset + 19);
        const auto unused4 = reader.read<std::uint16_t>(offset + 22);
        const auto unused5 = reader.read<std::uint32_t>(offset + 32);
        const auto sector_count = reader.read<std::uint64_t>(offset + 40);
        if(!bytes_per_sector || !unused1 || !unused2 || !unused3 || !unused4 || !unused5
            || !sector_count) {
            return std::nullopt;
        }

        if(*unused1 != 0 || *unused2 != 0 || *unused3 != 0 || *unused4 != 0 || *unused5 != 0) {
            return std::nullopt;
        }

        if(*sector_count == std::numeric_limits<std::uint64_t>::max()) {
            return std::nullopt;
        }
        const auto total_size = checked_multiply(
            static_cast<std::uint64_t>(*bytes_per_sector),
            *sector_count + 1
        );
        if(!total_size) {
            return std::nullopt;
        }

        if(*total_size <= static_cast<std::uint64_t>(*bytes_per_sector)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(offset);
        result.size = *total_size;
        result.confidence = confidence_medium;
        result.description = description()
            + ", number of sectors: " + std::to_string(*sector_count)
            + ", bytes per sector: " + std::to_string(*bytes_per_sector)
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<apfs_format> {
    static std::string name() { return "apfs"; }

    static std::string description() { return "Apple File System"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'N', 'X', 'S', 'B'}};
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t magic_back_offset = 0x20;
        constexpr std::size_t superblock_structure_size = 152;
        constexpr std::size_t mbr_block_size = 512;
        constexpr std::size_t fs_count_block_size = 512;
        constexpr std::uint64_t max_fs_count = 100;

        const auto image = rewind_to_structure_start(offset, magic_back_offset);
        if(!image) {
            return std::nullopt;
        }

        if(!data.contains(offset, superblock_structure_size)) {
            return std::nullopt;
        }
        const auto available_data = data.size() - *image;

        binary_reader<byte_order::little> reader(data);
        const auto magic_field = reader.read<std::uint32_t>(offset + 0);
        const auto block_size = reader.read<std::uint32_t>(offset + 4);
        const auto block_count = reader.read<std::uint64_t>(offset + 8);
        const auto features = reader.read<std::uint64_t>(offset + 16);
        const auto ro_compat_features = reader.read<std::uint64_t>(offset + 24);
        const auto incompat_features = reader.read<std::uint64_t>(offset + 32);
        const auto test_type = reader.read<std::uint32_t>(offset + 144);
        const auto max_file_systems = reader.read<std::uint32_t>(offset + 148);
        if(!magic_field || !block_size || !block_count || !features || !ro_compat_features
            || !incompat_features || !test_type || !max_file_systems) {
            return std::nullopt;
        }

        constexpr std::uint32_t nxsb_magic = 0x4253584e;
        if(*magic_field != nxsb_magic) {
            return std::nullopt;
        }
        if(*block_size == 0 || *block_count == 0) {
            return std::nullopt;
        }
        if(*features > 3 || *ro_compat_features != 0) {
            return std::nullopt;
        }
        switch(*incompat_features) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 0x100:
        case 0x101:
        case 0x102:
        case 0x103: break;
        default: return std::nullopt;
        }

        if(*test_type != 0) {
            return std::nullopt;
        }

        const auto fs_count = (static_cast<std::uint64_t>(*max_file_systems)
            + fs_count_block_size - 1) / fs_count_block_size;
        if(fs_count == 0 || fs_count > max_fs_count) {
            return std::nullopt;
        }

        const auto image_size = checked_multiply(
            *block_count,
            static_cast<std::uint64_t>(*block_size)
        );
        if(!image_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);
        result.size = *image_size;
        result.confidence = confidence_medium;

        std::string truncated_message;
        if(result.size > static_cast<std::uint64_t>(available_data)) {
            const auto truncated_size = result.size - static_cast<std::uint64_t>(available_data);
            if(truncated_size == mbr_block_size) {
                result.size -= truncated_size;
                truncated_message = " (truncated by " + std::to_string(truncated_size)
                    + " bytes)";
            }
        }

        result.description = description()
            + ", block size: " + std::to_string(*block_size) + " bytes"
            + ", block count: " + std::to_string(*block_count)
            + ", total size: " + std::to_string(result.size) + " bytes"
            + truncated_message;
        return result;
    }
};

template<>
struct format_traits<btrfs_format> {

    static constexpr bool always_display = true;

    static std::string name() { return "btrfs"; }
    static std::string description() { return "BTRFS file system"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'_', 'B', 'H', 'R', 'f', 'S', '_', 'M'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t magic_back_offset = 0x10040;
        constexpr std::size_t superblock_offset = 0x10000;
        constexpr std::size_t superblock_size = 0x1000;
        constexpr std::size_t crc_start = 0x20;

        const auto image = rewind_to_structure_start(offset, magic_back_offset);
        if(!image) {
            return std::nullopt;
        }

        const auto superblock = *image + superblock_offset;
        if(!data.contains(superblock, superblock_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto header_checksum = reader.read<std::uint32_t>(superblock + 0);
        const auto total_bytes = reader.read<std::uint64_t>(superblock + 112);
        const auto bytes_used = reader.read<std::uint64_t>(superblock + 120);
        const auto sector_size = reader.read<std::uint32_t>(superblock + 144);
        const auto node_size = reader.read<std::uint32_t>(superblock + 148);
        const auto leaf_size = reader.read<std::uint32_t>(superblock + 152);
        const auto stripe_size = reader.read<std::uint32_t>(superblock + 156);
        if(!header_checksum || !total_bytes || !bytes_used || !sector_size || !node_size
            || !leaf_size || !stripe_size) {
            return std::nullopt;
        }

        static constexpr std::uint8_t btrfs_magic[] = {'_', 'B', 'H', 'R', 'f', 'S', '_', 'M'};
        if(!bytes_equal(data, superblock + 0x40, btrfs_magic, sizeof(btrfs_magic))) {
            return std::nullopt;
        }

        const auto computed = crc32c(data, superblock + crc_start, superblock_size - crc_start);
        if(computed != *header_checksum) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = static_cast<std::uint64_t>(*image);
        result.size = *total_bytes;
        result.confidence = confidence_medium;
        result.description = description()
            + ", node size: " + std::to_string(*node_size)
            + ", sector size: " + std::to_string(*sector_size)
            + ", leaf size: " + std::to_string(*leaf_size)
            + ", stripe size: " + std::to_string(*stripe_size)
            + ", bytes used: " + std::to_string(*bytes_used)
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

namespace formats {

std::vector<signature> b8b_volumes_signatures() {
    return make_signatures(type_list<
        ext_format,
        mbr_format,
        fat_format,
        efigpt_format,
        ntfs_format,
        apfs_format,
        btrfs_format
    >{});
}

}
}
