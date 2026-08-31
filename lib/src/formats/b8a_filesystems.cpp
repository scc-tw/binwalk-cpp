#include "b8a_filesystems.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct cramfs_format {};
struct romfs_format {};
struct android_sparse_format {};
struct dtb_format {};

[[nodiscard]] std::optional<std::uint64_t> checked_add(
    std::uint64_t left,
    std::uint64_t right
) noexcept {
    if(left > std::numeric_limits<std::uint64_t>::max() - right) {
        return std::nullopt;
    }
    return left + right;
}

[[nodiscard]] bool range_in_bounds(
    byte_view data,
    std::uint64_t offset,
    std::uint64_t size
) noexcept {
    const auto end = checked_add(offset, size);
    return end && *end <= static_cast<std::uint64_t>(data.size());
}

constexpr std::size_t max_name_length = 4096;

[[nodiscard]] std::string bounded_cstring(byte_view data, std::uint64_t offset) {
    if(offset >= static_cast<std::uint64_t>(data.size())) {
        return std::string{};
    }
    const auto start = static_cast<std::size_t>(offset);
    const auto available = data.size() - start;
    return get_cstring(data, start, std::min(available, max_name_length));
}

[[nodiscard]] bool is_valid_utf8(byte_view data) noexcept {
    static constexpr std::uint32_t minimum_code_point[5] = {0, 0, 0x80, 0x800, 0x10000};

    std::size_t index = 0;
    while(index < data.size()) {
        const std::uint8_t lead = data[index];
        std::size_t length = 0;
        std::uint32_t code_point = 0;

        if(lead < 0x80U) {
            length = 1;
            code_point = lead;
        } else if((lead & 0xE0U) == 0xC0U) {
            length = 2;
            code_point = static_cast<std::uint32_t>(lead & 0x1FU);
        } else if((lead & 0xF0U) == 0xE0U) {
            length = 3;
            code_point = static_cast<std::uint32_t>(lead & 0x0FU);
        } else if((lead & 0xF8U) == 0xF0U) {
            length = 4;
            code_point = static_cast<std::uint32_t>(lead & 0x07U);
        } else {
            return false;
        }

        if(!data.contains(index, length)) {
            return false;
        }
        for(std::size_t part = 1; part < length; ++part) {
            const std::uint8_t continuation = data[index + part];
            if((continuation & 0xC0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | static_cast<std::uint32_t>(continuation & 0x3FU);
        }

        if(code_point < minimum_code_point[length] || code_point > 0x10FFFFU) {
            return false;
        }
        if(code_point >= 0xD800U && code_point <= 0xDFFFU) {
            return false;
        }
        index += length;
    }
    return true;
}

[[nodiscard]] extraction_result dry_run_at(
    internal_extractor function,
    byte_view data,
    std::size_t offset
) {
    signature_result probe;
    probe.offset = offset;
    return dry_run_extractor(function, data, probe);
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

struct cramfs_info {
    std::uint32_t size = 0;
    std::uint32_t checksum = 0;
    std::uint32_t file_count = 0;
    bool big_endian = false;
};

constexpr std::size_t cramfs_header_structure_size = 48;
constexpr std::size_t cramfs_signature_offset = 16;
constexpr std::size_t cramfs_crc_start_offset = 32;
constexpr std::size_t cramfs_crc_end_offset = 36;
constexpr std::uint32_t cramfs_little_endian_magic = 0x28CD3D45U;
constexpr std::uint32_t cramfs_big_endian_magic = 0x453DCD28U;

[[nodiscard]] std::optional<cramfs_info> parse_cramfs_header(byte_view data, std::size_t offset) {
    if(!data.contains(offset, cramfs_header_structure_size)) {
        return std::nullopt;
    }

    const binary_reader<byte_order::little> little(data);
    const auto raw_magic = little.read<std::uint32_t>(offset);
    if(!raw_magic) {
        return std::nullopt;
    }

    cramfs_info info;
    if(*raw_magic == cramfs_little_endian_magic) {
        info.big_endian = false;
    } else if(*raw_magic == cramfs_big_endian_magic) {
        info.big_endian = true;
    } else {
        return std::nullopt;
    }

    const auto read_field = [&](std::size_t field_offset) -> std::uint32_t {
        if(info.big_endian) {
            const binary_reader<byte_order::big> big(data);
            return big.read<std::uint32_t>(offset + field_offset).value_or(0);
        }
        return little.read<std::uint32_t>(offset + field_offset).value_or(0);
    };

    info.size = read_field(4);
    info.checksum = read_field(32);
    info.file_count = read_field(44);

    if(info.size <= cramfs_header_structure_size) {
        return std::nullopt;
    }
    return info;
}

[[nodiscard]] std::uint32_t cramfs_image_crc32(
    byte_view data,
    std::size_t offset,
    std::size_t size
) noexcept {
    static const std::uint8_t zeroed_checksum[4] = {0, 0, 0, 0};

    auto crc = crc32_update(0, data.subview(offset, cramfs_crc_start_offset));
    crc = crc32_update(crc, byte_view(zeroed_checksum, sizeof(zeroed_checksum)));
    return crc32_update(
        crc,
        data.subview(offset + cramfs_crc_end_offset, size - cramfs_crc_end_offset)
    );
}

constexpr std::size_t romfs_header_structure_size = 16;
constexpr std::size_t romfs_file_header_structure_size = 16;
constexpr std::size_t romfs_max_header_crc_data_len = 512;
constexpr std::uint64_t romfs_magic = 0x2D726F6D3166732DULL;

constexpr std::uint32_t romfs_type_hardlink = 0;
constexpr std::uint32_t romfs_type_directory = 1;
constexpr std::uint32_t romfs_type_regular = 2;
constexpr std::uint32_t romfs_type_symlink = 3;
constexpr std::uint32_t romfs_type_block_device = 4;
constexpr std::uint32_t romfs_type_char_device = 5;
constexpr std::uint32_t romfs_type_socket = 6;
constexpr std::uint32_t romfs_type_fifo = 7;

[[nodiscard]] std::uint64_t romfs_align(std::uint64_t value) noexcept {
    const auto remainder = value % 16U;
    return remainder == 0 ? value : value + (16U - remainder);
}

struct romfs_header_info {
    std::uint32_t image_size = 0;
    std::uint64_t header_size = 0;
    std::string volume_name;
};

[[nodiscard]] bool romfs_crc_valid(byte_view data, std::size_t offset, std::size_t length) noexcept {
    if(length % sizeof(std::uint32_t) != 0 || !data.contains(offset, length)) {
        return false;
    }
    const binary_reader<byte_order::big> reader(data);
    std::uint32_t sum = 0;
    for(std::size_t index = 0; index < length; index += sizeof(std::uint32_t)) {
        sum += reader.read<std::uint32_t>(offset + index).value_or(0);
    }
    return sum == 0;
}

[[nodiscard]] std::optional<romfs_header_info> parse_romfs_header(
    byte_view data,
    std::size_t offset
) {
    if(!data.contains(offset, romfs_header_structure_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(data);

    const auto magic = reader.read<std::uint64_t>(offset);
    if(!magic || *magic != romfs_magic) {
        return std::nullopt;
    }
    const auto image_size = reader.read<std::uint32_t>(offset + 8);
    if(!image_size) {
        return std::nullopt;
    }

    if(*image_size <= romfs_header_structure_size) {
        return std::nullopt;
    }

    romfs_header_info info;
    info.image_size = *image_size;
    info.volume_name = bounded_cstring(data, offset + romfs_header_structure_size);

    std::size_t crc_data_len = romfs_max_header_crc_data_len;
    if(*image_size < crc_data_len) {
        crc_data_len = static_cast<std::size_t>(*image_size);
    }
    if(!romfs_crc_valid(data, offset, crc_data_len)) {
        return std::nullopt;
    }

    info.header_size = romfs_header_structure_size
        + romfs_align(static_cast<std::uint64_t>(info.volume_name.size()) + 1U);
    return info;
}

struct romfs_file_header {
    std::uint32_t info = 0;
    std::uint32_t size = 0;
    std::string name;

    std::uint64_t data_offset = 0;
    std::uint32_t file_type = 0;
    bool executable = false;

    std::uint32_t next_header_offset = 0;
};

[[nodiscard]] std::optional<romfs_file_header> parse_romfs_file_entry(
    byte_view romfs_data,
    std::size_t offset
) {
    constexpr std::uint32_t file_type_mask = 0x7U;
    constexpr std::uint32_t file_exec_mask = 0x8U;
    constexpr std::uint32_t next_offset_mask = 0xFFFFFFF0U;

    if(!romfs_data.contains(offset, romfs_file_header_structure_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(romfs_data);
    const auto next_header_offset = reader.read<std::uint32_t>(offset);
    const auto info = reader.read<std::uint32_t>(offset + 4);
    const auto size = reader.read<std::uint32_t>(offset + 8);

    if(!next_header_offset || !info || !size) {
        return std::nullopt;
    }

    romfs_file_header header;
    header.name = bounded_cstring(
        romfs_data,
        static_cast<std::uint64_t>(offset) + romfs_file_header_structure_size
    );

    if(header.name.empty()) {
        return std::nullopt;
    }

    header.size = *size;
    header.info = *info;
    header.data_offset = romfs_file_header_structure_size
        + romfs_align(static_cast<std::uint64_t>(header.name.size()) + 1U);
    header.file_type = *next_header_offset & file_type_mask;
    header.executable = (*next_header_offset & file_exec_mask) != 0;
    header.next_header_offset = *next_header_offset & next_offset_mask;
    return header;
}

struct romfs_entry {
    std::uint32_t info = 0;
    std::uint32_t size = 0;
    std::string name;

    std::size_t offset = 0;
    std::uint32_t file_type = 0;
    bool executable = false;
    std::string symlink_target;
    std::uint32_t device_major = 0;
    std::uint32_t device_minor = 0;
    std::vector<romfs_entry> children;
};

constexpr std::size_t romfs_max_directory_depth = 64;

[[nodiscard]] bool process_romfs_entries(
    byte_view romfs_data,
    std::uint64_t start_offset,
    std::size_t depth,
    std::size_t& entry_budget,
    std::vector<romfs_entry>& entries
) {
    if(depth > romfs_max_directory_depth) {
        return false;
    }

    const std::size_t available_data = romfs_data.size();
    std::optional<std::size_t> previous_file_offset;
    std::uint64_t file_offset = start_offset;

    while(file_offset != 0
        && file_offset <= static_cast<std::uint64_t>(available_data)
        && is_offset_safe(
            available_data,
            static_cast<std::size_t>(file_offset),
            previous_file_offset
        )) {
        if(entry_budget == 0) {
            return false;
        }
        --entry_budget;

        const auto current_offset = static_cast<std::size_t>(file_offset);
        const auto file_header = parse_romfs_file_entry(romfs_data, current_offset);
        if(!file_header) {

            break;
        }

        romfs_entry entry;
        entry.size = file_header->size;
        entry.info = file_header->info;
        entry.name = file_header->name;
        entry.file_type = file_header->file_type;
        entry.executable = file_header->executable;

        const auto data_offset = checked_add(file_offset, file_header->data_offset);
        if(!data_offset) {
            return false;
        }

        if(!range_in_bounds(romfs_data, *data_offset, file_header->size)) {
            return false;
        }
        entry.offset = static_cast<std::size_t>(*data_offset);

        if(entry.name != "." && entry.name != "..") {
            if(entry.file_type == romfs_type_symlink) {
                const auto target = romfs_data.subview(entry.offset, entry.size);
                if(!is_valid_utf8(target)) {
                    return false;
                }
                entry.symlink_target.assign(
                    reinterpret_cast<const char*>(target.data()),
                    target.size()
                );
            } else if(entry.file_type == romfs_type_block_device
                || entry.file_type == romfs_type_char_device) {
                entry.device_minor = entry.info & 0xFFFFU;
                entry.device_major = (entry.info >> 16U) & 0xFFFFU;
            }

            if(entry.file_type == romfs_type_directory) {
                if(!process_romfs_entries(
                    romfs_data,
                    entry.info,
                    depth + 1,
                    entry_budget,
                    entry.children
                )) {
                    return false;
                }
            }

            if(entry.file_type == romfs_type_directory
                || entry.file_type == romfs_type_symlink
                || entry.file_type == romfs_type_regular) {
                entries.push_back(std::move(entry));
            }
        }

        previous_file_offset = current_offset;
        file_offset = file_header->next_header_offset;
    }

    return true;
}

[[nodiscard]] std::size_t extract_romfs_entries(
    byte_view romfs_data,
    const std::vector<romfs_entry>& romfs_files,
    const std::string& parent_directory,
    const chroot& output
) {
    std::size_t file_count = 0;

    for(const auto& entry : romfs_files) {

        const auto file_path = output.safe_path_join(parent_directory, entry.name);

        bool extraction_success = false;
        switch(entry.file_type) {
        case romfs_type_directory:
            extraction_success = output.create_directory(file_path);
            break;
        case romfs_type_regular:
            extraction_success =
                output.carve_file(file_path, romfs_data, entry.offset, entry.size);
            break;
        case romfs_type_symlink:
            extraction_success = output.create_symlink(file_path, entry.symlink_target);
            break;
        case romfs_type_fifo:
            extraction_success = output.create_fifo(file_path);
            break;
        case romfs_type_socket:
            extraction_success = output.create_socket(file_path);
            break;
        case romfs_type_block_device:
            extraction_success =
                output.create_block_device(file_path, entry.device_major, entry.device_minor);
            break;
        case romfs_type_char_device:
            extraction_success =
                output.create_character_device(file_path, entry.device_major, entry.device_minor);
            break;
        default:

            continue;
        }

        if(!extraction_success) {

            continue;
        }

        ++file_count;

        if(entry.file_type == romfs_type_directory && !entry.children.empty()) {
            file_count += extract_romfs_entries(romfs_data, entry.children, file_path, output);
        }
        if(entry.file_type == romfs_type_regular && entry.executable) {
            (void)output.make_executable(file_path);
        }
    }

    return file_count;
}

[[nodiscard]] extraction_result extract_romfs(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    extraction_result result;

    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = parse_romfs_header(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    if(!range_in_bounds(data, offset, header->image_size)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto romfs_data = data.subview(offset, static_cast<std::size_t>(header->image_size));

    std::size_t entry_budget = romfs_data.size() / 16U + 64U;

    std::vector<romfs_entry> root_entries;
    if(!process_romfs_entries(
        romfs_data,
        header->header_size,
        0,
        entry_budget,
        root_entries
    )) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    if(root_entries.empty()) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = header->image_size;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output_root{*output_directory};
    const auto romfs_chroot_dir = output_root.chrooted_path(header->volume_name);

    std::size_t file_count = 0;
    if(output_root.create_directory(romfs_chroot_dir)) {
        const chroot volume_root{romfs_chroot_dir};
        file_count = extract_romfs_entries(romfs_data, root_entries, std::string{}, volume_root);
    }

    if(file_count == 0) {
        result.success = false;
        result.failure = extraction_failure::write_error;
    }
    return result;
}

constexpr std::uint32_t android_sparse_magic = 0xED26FF3AU;
constexpr std::size_t android_sparse_header_structure_size = 28;
constexpr std::size_t android_sparse_chunk_header_size = 12;

constexpr std::uint64_t android_sparse_max_unsparsed_size = 16ULL * 1024ULL * 1024ULL * 1024ULL;

struct android_sparse_header_info {
    std::uint32_t major_version = 0;
    std::uint32_t minor_version = 0;
    std::uint32_t header_size = 0;
    std::uint32_t block_size = 0;

    std::uint32_t block_count = 0;
    std::uint32_t chunk_count = 0;
};

[[nodiscard]] std::optional<android_sparse_header_info> parse_android_sparse_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint32_t expected_major_version = 1;
    constexpr std::uint32_t expected_minor_version = 0;
    constexpr std::uint32_t block_alignment = 4;

    if(!data.contains(offset, android_sparse_header_structure_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::little> reader(data);

    const auto magic = reader.read<std::uint32_t>(offset);
    if(!magic || *magic != android_sparse_magic) {
        return std::nullopt;
    }

    android_sparse_header_info header;
    header.major_version = reader.read<std::uint16_t>(offset + 4).value_or(0);
    header.minor_version = reader.read<std::uint16_t>(offset + 6).value_or(0);
    header.header_size = reader.read<std::uint16_t>(offset + 8).value_or(0);
    const auto chunk_header_size = reader.read<std::uint16_t>(offset + 10).value_or(0);
    header.block_size = reader.read<std::uint32_t>(offset + 12).value_or(0);
    header.block_count = reader.read<std::uint32_t>(offset + 16).value_or(0);
    header.chunk_count = reader.read<std::uint32_t>(offset + 20).value_or(0);

    if(header.major_version != expected_major_version
        || header.minor_version != expected_minor_version
        || header.header_size != android_sparse_header_structure_size
        || chunk_header_size != android_sparse_chunk_header_size
        || (header.block_size % block_alignment) != 0) {
        return std::nullopt;
    }
    return header;
}

struct android_sparse_chunk_info {
    std::size_t header_size = android_sparse_chunk_header_size;
    std::uint32_t data_size = 0;
    std::uint32_t block_count = 0;
    bool is_crc = false;
    bool is_raw = false;
    bool is_fill = false;
    bool is_dont_care = false;
};

[[nodiscard]] std::optional<android_sparse_chunk_info> parse_android_sparse_chunk_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::uint32_t chunk_type_raw = 0xCAC1U;
    constexpr std::uint32_t chunk_type_fill = 0xCAC2U;
    constexpr std::uint32_t chunk_type_dont_care = 0xCAC3U;
    constexpr std::uint32_t chunk_type_crc = 0xCAC4U;

    constexpr std::uint32_t fill_data_size = 4;
    constexpr std::uint32_t dont_care_data_size = 0;
    constexpr std::uint32_t crc_data_size = 4;

    if(!data.contains(offset, android_sparse_chunk_header_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::little> reader(data);
    const auto chunk_type = reader.read<std::uint16_t>(offset);
    const auto reserved = reader.read<std::uint16_t>(offset + 2);
    const auto output_block_count = reader.read<std::uint32_t>(offset + 4);
    const auto total_size = reader.read<std::uint32_t>(offset + 8);
    if(!chunk_type || !reserved || !output_block_count || !total_size) {
        return std::nullopt;
    }

    if(*reserved != 0) {
        return std::nullopt;
    }

    if(*total_size < android_sparse_chunk_header_size) {
        return std::nullopt;
    }

    android_sparse_chunk_info chunk;
    chunk.data_size = *total_size - static_cast<std::uint32_t>(android_sparse_chunk_header_size);
    chunk.block_count = *output_block_count;
    chunk.is_crc = *chunk_type == chunk_type_crc;
    chunk.is_raw = *chunk_type == chunk_type_raw;
    chunk.is_fill = *chunk_type == chunk_type_fill;
    chunk.is_dont_care = *chunk_type == chunk_type_dont_care;

    if(!(chunk.is_crc || chunk.is_raw || chunk.is_fill || chunk.is_dont_care)) {
        return std::nullopt;
    }

    if(chunk.is_fill && chunk.data_size != fill_data_size) {
        return std::nullopt;
    }
    if(chunk.is_dont_care && chunk.data_size != dont_care_data_size) {
        return std::nullopt;
    }
    if(chunk.is_crc && chunk.data_size != crc_data_size) {
        return std::nullopt;
    }
    return chunk;
}

[[nodiscard]] bool append_pattern(
    const chroot& output,
    const std::string& outfile,
    byte_view pattern,
    std::uint64_t total_bytes
) {
    if(total_bytes == 0) {
        return true;
    }
    if(pattern.empty()) {
        return false;
    }

    constexpr std::size_t target_buffer_size = 1U << 20U;
    std::size_t repeats = target_buffer_size / pattern.size();
    if(repeats == 0) {
        repeats = 1;
    }

    std::vector<std::uint8_t> buffer;
    buffer.reserve(repeats * pattern.size());
    for(std::size_t repeat = 0; repeat < repeats; ++repeat) {
        buffer.insert(buffer.end(), pattern.data(), pattern.data() + pattern.size());
    }

    std::uint64_t written = 0;
    while(written < total_bytes) {
        const auto remaining = total_bytes - written;
        const auto slice = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size()))
        );
        if(!output.append_to_file(outfile, byte_view(buffer.data(), slice))) {
            return false;
        }
        written += slice;
    }
    return true;
}

[[nodiscard]] bool extract_android_sparse_chunk(
    const android_sparse_header_info& header,
    const android_sparse_chunk_info& chunk,
    byte_view chunk_data,
    const std::string& outfile,
    const chroot& output
) {
    if(chunk.is_raw) {

        return output.append_to_file(outfile, chunk_data);
    }

    if(chunk.is_crc || chunk.block_count == 0) {
        return true;
    }

    const auto total_bytes = checked_multiply(chunk.block_count, header.block_size);
    if(!total_bytes) {
        return false;
    }

    if(chunk.is_fill) {

        if(chunk_data.empty()) {
            return false;
        }
        return append_pattern(output, outfile, chunk_data, *total_bytes);
    }

    if(chunk.is_dont_care) {
        static const std::uint8_t null_byte[1] = {0};
        return append_pattern(output, outfile, byte_view(null_byte, 1), *total_bytes);
    }

    return true;
}

[[nodiscard]] extraction_result extract_android_sparse(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const std::string outfile_name = "unsparsed.img";

    extraction_result result;

    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = parse_android_sparse_header(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto declared_output_size = checked_multiply(header->block_count, header->block_size);
    if(!declared_output_size || *declared_output_size > android_sparse_max_unsparsed_size) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const std::size_t available_data = data.size();
    std::optional<std::size_t> last_chunk_offset;
    std::uint64_t processed_chunk_count = 0;
    std::uint64_t blocks_written = 0;

    const auto first_chunk_offset = checked_add(offset, header->header_size);
    if(!first_chunk_offset) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    std::uint64_t next_chunk_offset = *first_chunk_offset;

    std::optional<chroot> output;
    if(output_directory != nullptr) {
        output.emplace(*output_directory);
    }

    while(next_chunk_offset <= static_cast<std::uint64_t>(available_data)
        && is_offset_safe(
            available_data,
            static_cast<std::size_t>(next_chunk_offset),
            last_chunk_offset
        )) {
        const auto current_offset = static_cast<std::size_t>(next_chunk_offset);
        const auto chunk = parse_android_sparse_chunk_header(data, current_offset);
        if(!chunk) {
            break;
        }

        const auto new_blocks_written = checked_add(blocks_written, chunk->block_count);
        if(!new_blocks_written || *new_blocks_written > header->block_count) {
            break;
        }
        blocks_written = *new_blocks_written;

        if(chunk->is_raw) {
            const auto expected = checked_multiply(chunk->block_count, header->block_size);
            if(!expected || *expected != chunk->data_size) {
                break;
            }
        }

        if(output) {
            const auto chunk_data_start = checked_add(current_offset, chunk->header_size);
            if(!chunk_data_start
                || !range_in_bounds(data, *chunk_data_start, chunk->data_size)) {
                break;
            }
            const auto chunk_data = data.subview(
                static_cast<std::size_t>(*chunk_data_start),
                chunk->data_size
            );
            if(!extract_android_sparse_chunk(*header, *chunk, chunk_data, outfile_name, *output)) {
                break;
            }
        }

        ++processed_chunk_count;
        last_chunk_offset = current_offset;

        const auto step = checked_add(chunk->header_size, chunk->data_size);
        const auto advanced = step ? checked_add(next_chunk_offset, *step) : std::nullopt;
        if(!advanced) {
            break;
        }
        next_chunk_offset = *advanced;
    }

    if(processed_chunk_count == header->chunk_count) {
        result.success = true;
        result.size = next_chunk_offset - offset;
    } else {
        result.failure = extraction_failure::invalid_data;
    }
    return result;
}

constexpr std::uint32_t dtb_magic = 0xD00DFEEDU;
constexpr std::size_t dtb_header_structure_size = 40;

struct dtb_header_info {
    std::uint32_t total_size = 0;
    std::uint32_t version = 0;
    std::uint32_t cpu_id = 0;
    std::uint32_t struct_offset = 0;
    std::uint32_t strings_offset = 0;
    std::uint32_t struct_size = 0;
    std::uint32_t strings_size = 0;
};

[[nodiscard]] std::optional<dtb_header_info> parse_dtb_header(byte_view data, std::size_t offset) {
    constexpr std::uint32_t expected_version = 17;
    constexpr std::uint32_t expected_compat_version = 16;
    constexpr std::uint32_t struct_alignment = 4;
    constexpr std::uint32_t mem_reservation_alignment = 8;

    if(!data.contains(offset, dtb_header_structure_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(data);

    const auto magic = reader.read<std::uint32_t>(offset);
    if(!magic || *magic != dtb_magic) {
        return std::nullopt;
    }

    dtb_header_info header;
    header.total_size = reader.read<std::uint32_t>(offset + 4).value_or(0);
    header.struct_offset = reader.read<std::uint32_t>(offset + 8).value_or(0);
    header.strings_offset = reader.read<std::uint32_t>(offset + 12).value_or(0);
    const auto mem_reservation_offset = reader.read<std::uint32_t>(offset + 16).value_or(0);
    header.version = reader.read<std::uint32_t>(offset + 20).value_or(0);
    const auto min_compatible_version = reader.read<std::uint32_t>(offset + 24).value_or(0);
    header.cpu_id = reader.read<std::uint32_t>(offset + 28).value_or(0);
    header.strings_size = reader.read<std::uint32_t>(offset + 32).value_or(0);
    header.struct_size = reader.read<std::uint32_t>(offset + 36).value_or(0);

    if(header.version != expected_version || min_compatible_version != expected_compat_version) {
        return std::nullopt;
    }

    if((header.struct_offset & struct_alignment) != 0) {
        return std::nullopt;
    }
    if((mem_reservation_offset % mem_reservation_alignment) != 0) {
        return std::nullopt;
    }

    if(header.struct_offset < dtb_header_structure_size
        || header.strings_offset < dtb_header_structure_size
        || mem_reservation_offset < dtb_header_structure_size) {
        return std::nullopt;
    }
    return header;
}

struct dtb_node {
    bool begin = false;
    bool end = false;
    bool eof = false;
    bool nop = false;
    bool property = false;
    std::string name;
    std::vector<std::uint8_t> data;
    std::uint64_t total_size = 0;
};

[[nodiscard]] std::uint64_t dtb_aligned(std::uint64_t length) noexcept {
    const auto remainder = length % 4U;
    return remainder == 0 ? length : length + (4U - remainder);
}

[[nodiscard]] dtb_node parse_dtb_node(
    const dtb_header_info& header,
    byte_view dtb_data,
    std::size_t node_offset
) {
    constexpr std::uint32_t fdt_begin_node = 1;
    constexpr std::uint32_t fdt_end_node = 2;
    constexpr std::uint32_t fdt_prop = 3;
    constexpr std::uint32_t fdt_nop = 4;
    constexpr std::uint32_t fdt_end = 9;

    constexpr std::uint64_t node_token_size = 4;
    constexpr std::uint64_t node_property_size = 8;

    dtb_node node;

    const binary_reader<byte_order::big> reader(dtb_data);
    const auto token = reader.read<std::uint32_t>(node_offset);
    if(!token) {

        return node;
    }

    node.total_size = node_token_size;
    const auto node_data_length =
        static_cast<std::uint64_t>(dtb_data.size()) - static_cast<std::uint64_t>(node_offset);

    if(*token == fdt_end_node) {
        node.end = true;
    } else if(*token == fdt_nop) {
        node.nop = true;
    } else if(*token == fdt_end) {
        node.eof = true;
    } else if(node_data_length > node.total_size) {

        if(*token == fdt_begin_node) {

            node.begin = true;
            node.name = bounded_cstring(dtb_data, node_offset + node_token_size);
            node.total_size += dtb_aligned(static_cast<std::uint64_t>(node.name.size()) + 1U);
        } else if(*token == fdt_prop) {
            const auto data_length = reader.read<std::uint32_t>(node_offset + 4);
            const auto name_offset = reader.read<std::uint32_t>(node_offset + 8);
            if(!data_length || !name_offset) {
                return node;
            }
            node.total_size += node_property_size;

            const auto property_start =
                checked_add(static_cast<std::uint64_t>(node_offset), node.total_size);
            if(!property_start || !range_in_bounds(dtb_data, *property_start, *data_length)) {
                return node;
            }
            const auto property_data = dtb_data.subview(
                static_cast<std::size_t>(*property_start),
                *data_length
            );
            node.data.assign(
                property_data.data(),
                property_data.data() + property_data.size()
            );
            node.total_size += dtb_aligned(static_cast<std::uint64_t>(node.data.size()));

            const auto name_position =
                checked_add(header.strings_offset, *name_offset);
            if(!name_position) {
                return node;
            }
            node.name = bounded_cstring(dtb_data, *name_position);
            if(!node.name.empty()) {
                node.property = true;
            }
        }
    }

    return node;
}

[[nodiscard]] extraction_result extract_dtb(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    extraction_result result;

    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = parse_dtb_header(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    if(!range_in_bounds(data, offset, header->total_size)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto dtb_data = data.subview(offset, static_cast<std::size_t>(header->total_size));

    std::optional<chroot> output;
    if(output_directory != nullptr) {
        output.emplace(*output_directory);
    }

    std::vector<std::string> hierarchy;
    const std::size_t available_data = dtb_data.size();
    std::optional<std::size_t> previous_entry_offset;
    std::uint64_t entry_offset = header->struct_offset;

    while(entry_offset <= static_cast<std::uint64_t>(available_data)
        && is_offset_safe(
            available_data,
            static_cast<std::size_t>(entry_offset),
            previous_entry_offset
        )) {
        const auto current_offset = static_cast<std::size_t>(entry_offset);
        const auto node = parse_dtb_node(*header, dtb_data, current_offset);

        if(node.begin) {
            if(!node.name.empty()) {
                hierarchy.push_back(node.name);
            }
        } else if(node.end) {
            if(!hierarchy.empty()) {
                hierarchy.pop_back();
            }
        } else if(node.eof) {

            result.success = true;
            result.size = available_data;
            break;
        } else if(node.property) {
            if(output) {
                std::string directory_path;
                for(const auto& component : hierarchy) {
                    if(!directory_path.empty()) {
                        directory_path.push_back('/');
                    }
                    directory_path += component;
                }
                const auto file_path = output->safe_path_join(directory_path, node.name);
                if(!output->create_directory(directory_path)) {
                    break;
                }
                if(!output->create_file(file_path, byte_view(node.data))) {
                    break;
                }
            }
        } else if(!node.nop) {

            break;
        }

        previous_entry_offset = current_offset;
        const auto advanced = checked_add(entry_offset, node.total_size);
        if(!advanced) {
            break;
        }
        entry_offset = *advanced;
    }

    if(!result.success) {
        result.failure = extraction_failure::invalid_data;
    }
    return result;
}

}

template<>
struct format_traits<cramfs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "cramfs"; }
    static std::string description() { return "CramFS filesystem"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'C', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd', ' ',
                 'R', 'O', 'M', 'F', 'S'}};
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset < cramfs_signature_offset) {
            return std::nullopt;
        }
        const auto start = offset - cramfs_signature_offset;

        const auto header = parse_cramfs_header(data, start);
        if(!header) {
            return std::nullopt;
        }
        if(!range_in_bounds(data, start, header->size)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start;
        result.size = header->size;
        result.confidence = confidence_high;

        std::string error_message;
        if(cramfs_image_crc32(data, start, header->size) != header->checksum) {
            error_message = " (checksum error)";
            result.confidence = confidence_medium;
        }

        result.description = description() + ", "
            + (header->big_endian ? "big" : "little") + " endian, "
            + std::to_string(header->file_count) + " files, total size: "
            + std::to_string(header->size) + " bytes" + error_message;
        return result;
    }
};

template<>
struct format_traits<romfs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "romfs"; }
    static std::string description() { return "RomFS filesystem"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'-', 'r', 'o', 'm', '1', 'f', 's', '-'}};
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "romfs_built_in", &extract_romfs,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&extract_romfs, data, offset);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }
        const auto header = parse_romfs_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description() + ", volume name: \"" + header->volume_name
            + "\", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<android_sparse_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "android_sparse"; }
    static std::string description() { return "Android sparse image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x3A, 0xFF, 0x26, 0xED}};
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "android_sparse_built_in", &extract_android_sparse,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&extract_android_sparse, data, offset);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }
        const auto header = parse_android_sparse_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description() + ", version "
            + std::to_string(header->major_version) + "."
            + std::to_string(header->minor_version) + ", header size: "
            + std::to_string(header->header_size) + ", block size: "
            + std::to_string(header->block_size) + ", chunk count: "
            + std::to_string(header->chunk_count) + ", total size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<dtb_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dtb"; }
    static std::string description() { return "Device tree blob (DTB)"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0xD0, 0x0D, 0xFE, 0xED}};
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "dtb_built_in", &extract_dtb,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = parse_dtb_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        const auto struct_start = checked_add(offset, header->struct_offset);
        const auto strings_start = checked_add(offset, header->strings_offset);
        if(!struct_start || !strings_start) {
            return std::nullopt;
        }
        const auto struct_end = checked_add(*struct_start, header->struct_size);
        const auto strings_end = checked_add(*strings_start, header->strings_size);
        if(!struct_end || !strings_end) {
            return std::nullopt;
        }
        const auto available = static_cast<std::uint64_t>(data.size());
        if(available < *struct_end || available < *strings_end) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header->total_size;
        result.confidence = confidence_medium;
        result.description = description() + ", version: " + std::to_string(header->version)
            + ", CPU ID: " + std::to_string(header->cpu_id) + ", total size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

namespace formats {

std::vector<signature> b8a_filesystems_signatures() {
    return make_signatures(type_list<
        cramfs_format,
        romfs_format,
        android_sparse_format,
        dtb_format
    >{});
}

}
}
