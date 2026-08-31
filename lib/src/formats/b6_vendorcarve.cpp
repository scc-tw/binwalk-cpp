#include "b6_vendorcarve.hpp"

#include "b4_encrypted.hpp"
#include "zip_structures.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/codec.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
namespace binwalk {
namespace {

struct trx_format {};
struct jboot_arm_format {};
struct jboot_stag_format {};
struct jboot_sch2_format {};
struct wince_format {};
struct dahua_zip_format {};
struct mh01_format {};
struct csman_format {};
struct dlke_format {};

[[nodiscard]] bool bytes_equal(
    byte_view data,
    std::size_t offset,
    const std::vector<std::uint8_t>& expected
) noexcept {
    if(!data.contains(offset, expected.size())) {
        return false;
    }
    for(std::size_t index = 0; index < expected.size(); ++index) {
        if(data[offset + index] != expected[index]) {
            return false;
        }
    }
    return true;
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

[[nodiscard]] bool range_in_bounds(
    byte_view data,
    std::uint64_t offset,
    std::uint64_t size
) noexcept {
    const auto end = checked_add(offset, size);
    return end && *end <= static_cast<std::uint64_t>(data.size());
}

[[nodiscard]] std::string to_hex_prefixed(std::uint64_t value) {
    static const char digits[] = "0123456789ABCDEF";
    if(value == 0) {
        return "0x0";
    }
    std::string text;
    while(value != 0) {
        text.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    text.append("x0");
    std::reverse(text.begin(), text.end());
    return text;
}

[[nodiscard]] std::string to_hex_bare(std::uint64_t value) {
    static const char digits[] = "0123456789ABCDEF";
    if(value == 0) {
        return "0";
    }
    std::string text;
    while(value != 0) {
        text.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    std::reverse(text.begin(), text.end());
    return text;
}

[[nodiscard]] std::string to_hex_padded8(std::uint32_t value) {
    static const char digits[] = "0123456789ABCDEF";
    std::string text;
    for(int shift = 28; shift >= 0; shift -= 4) {
        text.push_back(digits[static_cast<std::size_t>((value >> shift) & 0xFU)]);
    }
    return text;
}

[[nodiscard]] std::string trim_ascii(std::string text) {
    const auto is_space = [](unsigned char value) {
        return value == ' ' || value == '\t' || value == '\n' || value == '\r'
            || value == '\v' || value == '\f';
    };
    std::size_t begin = 0;
    while(begin < text.size() && is_space(static_cast<unsigned char>(text[begin]))) {
        ++begin;
    }
    std::size_t end = text.size();
    while(end > begin && is_space(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(begin, end - begin);
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

}

namespace formats {

struct trx_info {
    std::uint16_t version = 0;
    std::uint32_t checksum = 0;
    std::uint32_t total_size = 0;
    std::size_t header_size = 0;
    std::vector<std::uint32_t> partitions;
};

[[nodiscard]] std::optional<trx_info> inspect_trx(byte_view data, std::size_t offset) {

    constexpr std::size_t structure_size = 32;
    static const std::vector<std::uint8_t> trx_magic{'H', 'D', 'R', '0'};

    if(!bytes_equal(data, offset, trx_magic) || !data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto total_size = reader.read<std::uint32_t>(offset + 4);
    const auto checksum = reader.read<std::uint32_t>(offset + 8);
    const auto version = reader.read<std::uint16_t>(offset + 14);
    const auto partition1 = reader.read<std::uint32_t>(offset + 16);
    const auto partition2 = reader.read<std::uint32_t>(offset + 20);
    const auto partition3 = reader.read<std::uint32_t>(offset + 24);
    const auto partition4 = reader.read<std::uint32_t>(offset + 28);
    if(!total_size || !checksum || !version || !partition1 || !partition2 || !partition3
        || !partition4) {
        return std::nullopt;
    }

    if(*partition1 > *total_size || *partition2 > *total_size || *partition3 > *total_size) {
        return std::nullopt;
    }
    if(static_cast<std::uint64_t>(*total_size) <= structure_size) {
        return std::nullopt;
    }
    if(*version != 1 && *version != 2) {
        return std::nullopt;
    }

    trx_info info;
    info.version = *version;
    info.checksum = *checksum;
    info.total_size = *total_size;

    info.header_size = *version == 2 ? structure_size : structure_size - 4;
    for(const auto partition : {*partition1, *partition2, *partition3}) {
        if(partition != 0) {
            info.partitions.push_back(partition);
        }
    }
    if(*version == 2 && *partition4 != 0) {
        info.partitions.push_back(*partition4);
    }
    return info;
}

[[nodiscard]] extraction_result extract_trx(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {

    constexpr std::uint64_t crc_data_start_offset = 12;

    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_trx(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto crc_start = checked_add(signature.offset, crc_data_start_offset);
    if(!crc_start) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto crc_length =
        static_cast<std::uint64_t>(header->total_size) - crc_data_start_offset;
    if(!range_in_bounds(data, *crc_start, crc_length)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto computed = crc32_jamcrc(
        data.subview(static_cast<std::size_t>(*crc_start), static_cast<std::size_t>(crc_length))
    );
    if(computed != header->checksum) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = header->total_size;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    for(std::size_t index = 0; index < header->partitions.size(); ++index) {
        const auto partition_offset = static_cast<std::uint64_t>(header->partitions[index]);
        std::uint64_t partition_size = 0;
        if(index + 1 < header->partitions.size()) {
            const auto next_offset = static_cast<std::uint64_t>(header->partitions[index + 1]);

            if(next_offset < partition_offset) {
                result.success = false;
                result.failure = extraction_failure::invalid_data;
                return result;
            }
            partition_size = next_offset - partition_offset;
        } else {
            partition_size = static_cast<std::uint64_t>(header->total_size) - partition_offset;
        }

        const auto absolute = checked_add(signature.offset, partition_offset);
        if(!absolute || !range_in_bounds(data, *absolute, partition_size)) {
            result.success = false;
            result.failure = extraction_failure::invalid_data;
            return result;
        }
        if(!output.carve_file(
               "partition_" + std::to_string(index) + ".bin",
               data,
               static_cast<std::size_t>(*absolute),
               static_cast<std::size_t>(partition_size)
           )) {
            result.success = false;
            result.failure = extraction_failure::write_error;
            return result;
        }
    }
    return result;
}

struct jboot_arm_info {
    std::size_t header_size = 0;
    std::uint32_t data_size = 0;
    std::uint32_t data_offset = 0;
    std::uint32_t erase_offset = 0;
    std::uint32_t erase_size = 0;
    std::string rom_id;
};

[[nodiscard]] std::optional<jboot_arm_info> inspect_jboot_arm(
    byte_view data,
    std::size_t header_start
) {
    constexpr std::size_t structure_offset = 12;
    constexpr std::size_t structure_size = 68;
    constexpr std::size_t header_size = structure_offset + structure_size;
    constexpr std::uint32_t lpvs_value = 1;
    constexpr std::uint32_t mbz_value = 0;
    constexpr std::uint16_t header_id_value = 0x4842;
    constexpr std::uint16_t header_max_version = 4;

    if(!data.contains(header_start, header_size)) {
        return std::nullopt;
    }
    const auto base = header_start + structure_offset;

    binary_reader<byte_order::little> reader(data);
    const auto reserved2 = reader.read<std::uint32_t>(base + 8);
    const auto reserved3 = reader.read<std::uint16_t>(base + 12);
    const auto lpvs = reader.read<std::uint8_t>(base + 14);
    const auto mbz = reader.read<std::uint8_t>(base + 15);
    const auto erase_start = reader.read<std::uint32_t>(base + 20);
    const auto erase_size = reader.read<std::uint32_t>(base + 24);
    const auto data_start = reader.read<std::uint32_t>(base + 28);
    const auto data_size = reader.read<std::uint32_t>(base + 32);
    const auto reserved4 = reader.read<std::uint32_t>(base + 36);
    const auto reserved5 = reader.read<std::uint32_t>(base + 40);
    const auto reserved6 = reader.read<std::uint32_t>(base + 44);
    const auto reserved7 = reader.read<std::uint32_t>(base + 48);
    const auto header_id = reader.read<std::uint16_t>(base + 52);
    const auto header_version = reader.read<std::uint16_t>(base + 54);
    const auto reserved8 = reader.read<std::uint16_t>(base + 56);
    if(!reserved2 || !reserved3 || !lpvs || !mbz || !erase_start || !erase_size || !data_start
        || !data_size || !reserved4 || !reserved5 || !reserved6 || !reserved7 || !header_id
        || !header_version || !reserved8) {
        return std::nullopt;
    }

    if(*reserved2 != 0 || *reserved3 != 0 || *reserved4 != 0 || *reserved5 != 0
        || *reserved6 != 0 || *reserved7 != 0 || *reserved8 != 0) {
        return std::nullopt;
    }
    if(*lpvs != lpvs_value || *mbz != mbz_value || *header_id != header_id_value
        || *header_version > header_max_version) {
        return std::nullopt;
    }

    jboot_arm_info info;
    info.header_size = header_size;
    info.rom_id = get_cstring(data, header_start, structure_offset);
    info.data_size = *data_size;
    info.data_offset = *data_start;
    info.erase_offset = *erase_start;
    info.erase_size = *erase_size;
    return info;
}

struct jboot_stag_info {
    std::size_t header_size = 0;
    std::uint32_t image_size = 0;
    bool is_sysupgrade_image = false;
};

[[nodiscard]] std::optional<jboot_stag_info> inspect_jboot_stag(
    byte_view data,
    std::size_t offset
) {

    constexpr std::size_t structure_size = 16;
    constexpr std::uint8_t factory_image_marker = 0xFF;

    if(!data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    if(data[offset + 2] != 0x24 || data[offset + 3] != 0x2B) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto image_size = reader.read<std::uint32_t>(offset + 8);
    if(!image_size) {
        return std::nullopt;
    }
    if(static_cast<std::uint64_t>(*image_size) <= structure_size) {
        return std::nullopt;
    }

    const auto cmark = data[offset];
    const auto identifier = data[offset + 1];
    const bool is_factory = cmark == factory_image_marker;
    const bool is_sysupgrade = cmark == identifier;
    if(!is_factory && !is_sysupgrade) {
        return std::nullopt;
    }

    jboot_stag_info info;
    info.header_size = structure_size;
    info.image_size = *image_size;
    info.is_sysupgrade_image = is_sysupgrade;
    return info;
}

struct jboot_sch2_info {
    std::size_t header_size = 0;
    std::string compression;
    std::uint32_t kernel_size = 0;
    std::uint32_t kernel_entry_point = 0;
    std::uint32_t kernel_checksum = 0;
};

[[nodiscard]] std::optional<jboot_sch2_info> inspect_jboot_sch2(
    byte_view data,
    std::size_t offset
) {
    constexpr std::size_t structure_size = 40;
    constexpr std::uint8_t version_value = 2;

    constexpr std::size_t header_crc_start = 32;
    constexpr std::size_t header_crc_end = 36;
    static const char* const compression_names[] = {"none", "jz", "gzip", "lzma"};

    if(!data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    if(data[offset] != 0x24 || data[offset + 1] != 0x21) {
        return std::nullopt;
    }

    const auto compression_type = data[offset + 2];
    const auto version = data[offset + 3];
    if(version != version_value || compression_type > 3) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto entry_point = reader.read<std::uint32_t>(offset + 4);
    const auto kernel_size = reader.read<std::uint32_t>(offset + 8);
    const auto kernel_crc = reader.read<std::uint32_t>(offset + 12);
    const auto header_crc = reader.read<std::uint32_t>(offset + header_crc_start);
    const auto declared_header_size = reader.read<std::uint16_t>(offset + 36);
    if(!entry_point || !kernel_size || !kernel_crc || !header_crc || !declared_header_size) {
        return std::nullopt;
    }
    if(*declared_header_size != structure_size) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> crc_data(structure_size);
    for(std::size_t index = 0; index < structure_size; ++index) {
        crc_data[index] = index >= header_crc_start && index < header_crc_end
            ? std::uint8_t{0}
            : data[offset + index];
    }
    if(crc32(byte_view(crc_data)) != *header_crc) {
        return std::nullopt;
    }

    jboot_sch2_info info;
    info.header_size = structure_size;
    info.compression = compression_names[compression_type];
    info.kernel_size = *kernel_size;
    info.kernel_entry_point = *entry_point;
    info.kernel_checksum = *kernel_crc;
    return info;
}

[[nodiscard]] extraction_result extract_jboot_sch2(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const char* const outfile_name = "kernel.bin";

    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_jboot_sch2(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto kernel_start = checked_add(signature.offset, header->header_size);
    if(!kernel_start || !range_in_bounds(data, *kernel_start, header->kernel_size)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto kernel = data.subview(
        static_cast<std::size_t>(*kernel_start), static_cast<std::size_t>(header->kernel_size)
    );
    if(crc32(kernel) != header->kernel_checksum) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = static_cast<std::uint64_t>(header->header_size) + header->kernel_size;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    result.success = output.carve_file(
        outfile_name,
        data,
        static_cast<std::size_t>(*kernel_start),
        static_cast<std::size_t>(header->kernel_size)
    );
    if(!result.success) {
        result.failure = extraction_failure::write_error;
    }
    return result;
}

struct wince_header_info {
    std::uint32_t base_address = 0;
    std::uint32_t image_size = 0;
    std::size_t header_size = 0;
};

[[nodiscard]] std::optional<wince_header_info> inspect_wince_header(
    byte_view data,
    std::size_t offset
) {

    constexpr std::size_t structure_size = 15;
    static const std::vector<std::uint8_t> wince_magic{'B', '0', '0', '0', 'F', 'F', '\n'};

    if(!bytes_equal(data, offset, wince_magic) || !data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto image_start = reader.read<std::uint32_t>(offset + 7);
    const auto image_size = reader.read<std::uint32_t>(offset + 11);
    if(!image_start || !image_size) {
        return std::nullopt;
    }

    wince_header_info info;
    info.base_address = *image_start;
    info.image_size = *image_size;
    info.header_size = structure_size;
    return info;
}

struct wince_block_info {
    std::uint32_t address = 0;
    std::size_t offset = 0;
    std::uint32_t size = 0;
};

struct wince_block_set {
    std::uint64_t total_size = 0;
    std::vector<wince_block_info> entries;
};

[[nodiscard]] std::optional<wince_block_set> process_wince_blocks(
    byte_view data,
    std::size_t block_area_start
) {

    constexpr std::size_t minimum_entry_count = 5;
    constexpr std::size_t block_header_size = 12;

    if(block_area_start > data.size()) {
        return std::nullopt;
    }
    const auto available = data.size() - block_area_start;

    wince_block_set blocks;
    std::size_t next_offset = 0;
    std::optional<std::size_t> previous_offset;
    binary_reader<byte_order::little> reader(data);

    while(is_offset_safe(available, next_offset, previous_offset)) {
        const auto base = block_area_start + next_offset;
        const auto address = reader.read<std::uint32_t>(base);
        const auto size = reader.read<std::uint32_t>(base + 4);
        const auto checksum = reader.read<std::uint32_t>(base + 8);
        if(!address || !size || !checksum) {
            break;
        }

        blocks.total_size += block_header_size;

        if(*address == 0) {
            if(blocks.entries.size() > minimum_entry_count) {
                return blocks;
            }
            break;
        }

        blocks.total_size += *size;
        blocks.entries.push_back(
            wince_block_info{*address, next_offset + block_header_size, *size}
        );

        previous_offset = next_offset;
        const auto step = static_cast<std::uint64_t>(block_header_size) + *size;
        if(step > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() - next_offset)) {
            break;
        }
        next_offset += static_cast<std::size_t>(step);
    }
    return std::nullopt;
}

[[nodiscard]] extraction_result extract_wince(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_wince_header(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto block_area_start = checked_add(signature.offset, header->header_size);
    if(!block_area_start || *block_area_start > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto blocks =
        process_wince_blocks(data, static_cast<std::size_t>(*block_area_start));

    if(!blocks || blocks->entries.empty()
        || blocks->entries[0].address != header->base_address) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = static_cast<std::uint64_t>(header->header_size) + blocks->total_size;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    for(const auto& block : blocks->entries) {
        const auto absolute = checked_add(*block_area_start, block.offset);
        if(!absolute || !range_in_bounds(data, *absolute, block.size)) {
            result.success = false;
            result.failure = extraction_failure::invalid_data;
            return result;
        }
        if(!output.carve_file(
               to_hex_bare(block.address) + ".bin",
               data,
               static_cast<std::size_t>(*absolute),
               static_cast<std::size_t>(block.size)
           )) {
            result.success = false;
            result.failure = extraction_failure::write_error;
            return result;
        }
    }
    return result;
}

struct mh01_info {
    std::string iv;
    std::size_t iv_offset = 0;
    std::uint32_t iv_size = 0;
    std::uint64_t signature_offset = 0;
    std::uint32_t signature_size = 0;
    std::uint64_t encrypted_data_offset = 0;
    std::uint32_t encrypted_data_size = 0;
    std::uint64_t total_size = 0;
};

[[nodiscard]] std::optional<mh01_info> inspect_mh01(byte_view data, std::size_t offset) {

    constexpr std::size_t structure_size = 32;
    constexpr std::uint64_t second_header_offset = 16;
    static const std::vector<std::uint8_t> mh01_magic{'M', 'H', '0', '1'};

    if(!data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    if(!bytes_equal(data, offset, mh01_magic)
        || !bytes_equal(data, offset + static_cast<std::size_t>(second_header_offset), mh01_magic)) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto relative_signature_offset = reader.read<std::uint32_t>(offset + 4);
    const auto signature_size = reader.read<std::uint32_t>(offset + 8);
    const auto iv_size = reader.read<std::uint32_t>(offset + 20);
    const auto encrypted_data_size = reader.read<std::uint32_t>(offset + 24);
    if(!relative_signature_offset || !signature_size || !iv_size || !encrypted_data_size) {
        return std::nullopt;
    }

    mh01_info info;
    info.iv_offset = structure_size;
    info.iv_size = *iv_size;
    info.encrypted_data_size = *encrypted_data_size;

    const auto encrypted_offset = checked_add(structure_size, *iv_size);
    const auto signature_offset = checked_add(second_header_offset, *relative_signature_offset);
    if(!encrypted_offset || !signature_offset) {
        return std::nullopt;
    }
    info.encrypted_data_offset = *encrypted_offset;
    info.signature_offset = *signature_offset;
    info.signature_size = *signature_size;

    const auto iv_absolute = checked_add(static_cast<std::uint64_t>(offset), info.iv_offset);
    if(!iv_absolute || !range_in_bounds(data, *iv_absolute, info.iv_size)) {
        return std::nullopt;
    }
    const auto iv_string =
        get_cstring(data, static_cast<std::size_t>(*iv_absolute), info.iv_size);
    if(iv_string.size() != info.iv_size) {
        return std::nullopt;
    }
    info.iv = trim_ascii(iv_string);

    const auto total_size = checked_add(info.signature_offset, info.signature_size);
    if(!total_size) {
        return std::nullopt;
    }
    info.total_size = *total_size;
    return info;
}

[[nodiscard]] std::optional<std::string> describe_openssl_container(
    byte_view data,
    std::size_t offset
) {
    constexpr std::size_t salt_length = 8;

    binary_reader<byte_order::big> reader(data);
    const auto salt = reader.read<std::uint64_t>(offset + salt_length);
    if(!salt || *salt == 0) {
        return std::nullopt;
    }

    std::size_t bad_byte_count = 0;
    for(std::size_t index = 0; index < salt_length; ++index) {
        const auto salt_byte = static_cast<std::uint8_t>((*salt >> (8U * index)) & 0xFFU);
        if(salt_byte == 0 || is_printable_ascii(salt_byte)) {
            ++bad_byte_count;
        }
    }
    if(bad_byte_count == salt_length) {
        return std::nullopt;
    }

    return "OpenSSL encryption, salt: " + to_hex_prefixed(*salt);
}

[[nodiscard]] extraction_result extract_mh01(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const char* const iv_file_name = "iv.bin";
    static const char* const signature_file_name = "signature.bin";
    static const char* const encrypted_file_name = "encrypted.bin";

    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_mh01(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.size = header->total_size;
    result.success = true;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    const struct {
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    } parts[] = {
        {iv_file_name, header->iv_offset, header->iv_size},
        {signature_file_name, header->signature_offset, header->signature_size},
        {encrypted_file_name, header->encrypted_data_offset, header->encrypted_data_size}
    };

    for(const auto& part : parts) {
        const auto absolute = checked_add(signature.offset, part.offset);
        if(!absolute || !range_in_bounds(data, *absolute, part.size)) {
            result.success = false;
            result.failure = extraction_failure::invalid_data;
            return result;
        }
        if(!output.carve_file(
               part.name,
               data,
               static_cast<std::size_t>(*absolute),
               static_cast<std::size_t>(part.size)
           )) {
            result.success = false;
            result.failure = extraction_failure::write_error;
            return result;
        }
    }
    return result;
}

struct csman_header_info {
    bool compressed = false;
    std::uint32_t data_size = 0;
    bool big_endian = true;
    std::size_t header_size = 0;
};

[[nodiscard]] std::optional<csman_header_info> inspect_csman_header(
    byte_view data,
    std::size_t offset
) {

    constexpr std::size_t structure_size = 16;
    constexpr std::uint16_t big_endian_magic = 0x5343;
    constexpr std::uint16_t little_endian_magic = 0x4353;
    constexpr std::uint8_t compressed_magic = 0x78;

    if(!data.contains(offset, structure_size)) {
        return std::nullopt;
    }

    binary_reader<byte_order::big> big_reader(data);
    const auto magic = big_reader.read<std::uint16_t>(offset);
    if(!magic) {
        return std::nullopt;
    }

    csman_header_info info;

    if(*magic == little_endian_magic) {
        info.big_endian = false;
    } else if(*magic == big_endian_magic) {
        info.big_endian = true;
    } else {
        return std::nullopt;
    }

    std::optional<std::uint32_t> compressed_size;
    std::optional<std::uint32_t> decompressed_size;
    if(info.big_endian) {
        compressed_size = big_reader.read<std::uint32_t>(offset + 4);
        decompressed_size = big_reader.read<std::uint32_t>(offset + 12);
    } else {
        binary_reader<byte_order::little> little_reader(data);
        compressed_size = little_reader.read<std::uint32_t>(offset + 4);
        decompressed_size = little_reader.read<std::uint32_t>(offset + 12);
    }
    if(!compressed_size || !decompressed_size) {
        return std::nullopt;
    }

    info.header_size = structure_size;
    info.data_size = *compressed_size;
    info.compressed = *compressed_size != *decompressed_size;

    if(info.compressed && data.contains(offset + structure_size, 1)
        && data[offset + structure_size] != compressed_magic) {
        return std::nullopt;
    }
    return info;
}

struct csman_entry {
    std::size_t size = 0;
    bool eof = false;
    std::uint32_t key = 0;
    std::size_t value_offset = 0;
    std::uint16_t value_size = 0;
};

[[nodiscard]] std::optional<csman_entry> parse_csman_entry(
    byte_view entries,
    std::size_t position,
    bool big_endian
) {
    constexpr std::size_t entry_header_size = 6;
    constexpr std::size_t eof_entry_size = 4;

    const auto read_u32 = [&](std::size_t at) {
        return big_endian ? binary_reader<byte_order::big>(entries).read<std::uint32_t>(at)
                          : binary_reader<byte_order::little>(entries).read<std::uint32_t>(at);
    };
    const auto read_u16 = [&](std::size_t at) {
        return big_endian ? binary_reader<byte_order::big>(entries).read<std::uint16_t>(at)
                          : binary_reader<byte_order::little>(entries).read<std::uint16_t>(at);
    };

    if(entries.contains(position, entry_header_size)) {
        const auto key = read_u32(position);
        const auto value_size = read_u16(position + 4);
        if(!key || !value_size) {
            return std::nullopt;
        }
        if(!entries.contains(position + entry_header_size, *value_size)) {
            return std::nullopt;
        }
        csman_entry entry;
        entry.size = entry_header_size + *value_size;
        entry.key = *key;
        entry.value_offset = position + entry_header_size;
        entry.value_size = *value_size;
        return entry;
    }

    if(entries.contains(position, eof_entry_size)) {
        const auto marker = read_u32(position);
        if(marker && *marker == 0) {
            csman_entry entry;
            entry.size = eof_entry_size;
            entry.eof = true;
            return entry;
        }
    }
    return std::nullopt;
}

[[nodiscard]] extraction_result extract_csman(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {

    constexpr std::size_t compressed_header_size = 2;

    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_csman_header(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto entries_start = checked_add(signature.offset, header->header_size);
    if(!entries_start || !range_in_bounds(data, *entries_start, header->data_size)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto raw_entries = data.subview(
        static_cast<std::size_t>(*entries_start), static_cast<std::size_t>(header->data_size)
    );

    std::vector<std::uint8_t> decompressed;
    byte_view entries = raw_entries;
    if(header->compressed) {
        if(!codec_available(codec_id::deflate)) {
            result.failure = extraction_failure::unsupported;
            return result;
        }
        codec_options options;
        options.max_output_size = codec_default_max_output_size;
        const auto decoded = codec_decompress_to_buffer(
            codec_id::deflate, raw_entries, compressed_header_size, decompressed, options
        );
        if(!decoded.success()) {
            result.failure = decoded.unsupported() ? extraction_failure::unsupported
                                                   : extraction_failure::invalid_data;
            return result;
        }
        entries = byte_view(decompressed);
    }

    std::vector<csman_entry> parsed_entries;
    std::size_t next_offset = 0;
    std::optional<std::size_t> previous_offset;
    const auto available = entries.size();
    bool saw_eof = false;

    while(is_offset_safe(available, next_offset, previous_offset)) {
        const auto entry = parse_csman_entry(entries, next_offset, header->big_endian);
        if(!entry) {
            break;
        }
        if(entry->eof) {

            saw_eof = true;
            break;
        }
        parsed_entries.push_back(*entry);
        previous_offset = next_offset;
        next_offset += entry->size;
    }

    if(!saw_eof || parsed_entries.empty()) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = static_cast<std::uint64_t>(header->header_size) + header->data_size;

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);

    std::unordered_map<std::uint32_t, std::size_t> seen_keys;
    for(const auto& entry : parsed_entries) {
        auto file_name = to_hex_padded8(entry.key) + ".dat";
        const auto existing = seen_keys.find(entry.key);
        if(existing == seen_keys.end()) {
            seen_keys.emplace(entry.key, std::size_t{1});
        } else {
            file_name += "_" + std::to_string(existing->second);
            ++existing->second;
        }
        if(!output.create_file(
               file_name, entries.subview(entry.value_offset, entry.value_size)
           )) {
            result.success = false;
            result.failure = extraction_failure::write_error;
            return result;
        }
    }
    return result;
}

[[nodiscard]] extraction_result extract_dahua_zip(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const char* const outfile_name = "dahua.zip";
    static const std::vector<std::uint8_t> zip_header{'P', 'K'};

    extraction_result result;
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto eocd = zip_structures::find_eocd(data, offset);
    if(!eocd || eocd->end <= offset) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto total_size = static_cast<std::uint64_t>(eocd->end - offset);
    result.success = true;
    result.size = total_size;

    if(output_directory == nullptr) {
        return result;
    }

    const auto body_start = checked_add(signature.offset, zip_header.size());
    if(!body_start || total_size < zip_header.size()) {
        result.success = false;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto body_size = total_size - zip_header.size();
    if(!range_in_bounds(data, *body_start, body_size)) {
        result.success = false;
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const chroot output(*output_directory);
    if(!output.create_file(outfile_name, byte_view(zip_header))) {
        result.success = false;
        result.failure = extraction_failure::write_error;
        return result;
    }

    result.success = output.append_to_file(
        outfile_name,
        data.subview(static_cast<std::size_t>(*body_start), static_cast<std::size_t>(body_size))
    );
    if(!result.success) {
        result.failure = extraction_failure::write_error;
    }
    return result;
}

}

template<>
struct format_traits<trx_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "trx"; }
    static std::string description() { return "TRX firmware image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'H', 'D', 'R', '0'}}; }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "trx_built_in", &formats::extract_trx,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&formats::extract_trx, data, offset);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }
        const auto header = formats::inspect_trx(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description() + ", version " + std::to_string(header->version)
            + ", partition count: " + std::to_string(header->partitions.size())
            + ", header size: " + std::to_string(header->header_size)
            + " bytes, total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<jboot_arm_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jboot_arm"; }
    static std::string description() { return "JBOOT firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0x48}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_distance = 48;

        if(offset < magic_distance) {
            return std::nullopt;
        }
        const auto header_start = offset - magic_distance;

        const auto header = formats::inspect_jboot_arm(data, header_start);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;

        result.offset = header_start;
        result.size = header->header_size;
        result.confidence = confidence_medium;
        result.description = description() + ", header size: "
            + std::to_string(header->header_size) + " bytes, ROM ID: " + header->rom_id
            + ", erase offset: " + to_hex_prefixed(header->erase_offset)
            + ", erase size: " + to_hex_prefixed(header->erase_size)
            + ", data flash offset: " + to_hex_prefixed(header->data_offset)
            + ", data size: " + to_hex_prefixed(header->data_size);
        return result;
    }
};

template<>
struct format_traits<jboot_stag_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jboot_stag"; }
    static std::string description() { return "JBOOT STAG header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x04, 0x04, 0x24, 0x2B}, {0xFF, 0x04, 0x24, 0x2B}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = formats::inspect_jboot_stag(data, offset);
        if(!header) {
            return std::nullopt;
        }

        const auto described_end = checked_add(
            checked_add(offset, header->header_size).value_or(
                std::numeric_limits<std::uint64_t>::max()
            ),
            header->image_size
        );
        if(!described_end || *described_end >= static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;

        result.size = header->header_size;
        result.confidence = confidence_low;
        result.description = description() + ", "
            + (header->is_sysupgrade_image ? "system upgrade image" : "factory image")
            + ", header size: " + std::to_string(header->header_size)
            + " bytes, kernel data size: " + std::to_string(header->image_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<jboot_sch2_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jboot_sch2"; }
    static std::string description() { return "JBOOT SCH2 header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x24, 0x21, 0x00, 0x02},
            {0x24, 0x21, 0x01, 0x02},
            {0x24, 0x21, 0x02, 0x02},
            {0x24, 0x21, 0x03, 0x02}
        };
    }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "jboot_sch2_built_in", &formats::extract_jboot_sch2,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&formats::extract_jboot_sch2, data, offset);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }
        const auto header = formats::inspect_jboot_sch2(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description() + ", header size: "
            + std::to_string(header->header_size) + " bytes, kernel size: "
            + std::to_string(header->kernel_size) + " bytes, kernel compression: "
            + header->compression + ", kernel entry point: "
            + to_hex_prefixed(header->kernel_entry_point);
        return result;
    }
};

template<>
struct format_traits<wince_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "wince"; }
    static std::string description() { return "Windows CE binary image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'B', '0', '0', '0', 'F', 'F', '\n'}};
    }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "wince_built_in", &formats::extract_wince,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&formats::extract_wince, data, offset);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }
        const auto header = formats::inspect_wince_header(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description = description() + ", base address: "
            + to_hex_prefixed(header->base_address) + ", image size: "
            + std::to_string(header->image_size) + " bytes, file size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<dahua_zip_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dahua_zip"; }
    static std::string description() { return "Dahua ZIP archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'D', 'H', 0x03, 0x04}}; }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "dahua_zip_built_in", &formats::extract_dahua_zip,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto first = formats::zip_structures::parse_local_header(data, offset, 'D', 'H');
        if(!first) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_high;

        if(const auto eocd = formats::zip_structures::find_eocd(data, offset)) {
            result.size = eocd->end - offset;
            result.description = description() + ", version: "
                + std::to_string(first->version_major) + "."
                + std::to_string(first->version_minor) + ", file count: "
                + std::to_string(eocd->file_count) + ", total size: "
                + std::to_string(result.size) + " bytes";
            return result;
        }

        auto cursor = offset + first->total_size;
        while(cursor < data.size()) {
            const auto next = formats::zip_structures::parse_local_header(data, cursor);
            if(!next) {
                break;
            }
            cursor += next->total_size;
        }
        if(cursor <= offset) {
            return std::nullopt;
        }
        result.size = cursor - offset;
        result.description = description() + ", version: "
            + std::to_string(first->version_major) + "."
            + std::to_string(first->version_minor)
            + ", missing end-of-central-directory header, total size: "
            + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<mh01_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "mh01"; }
    static std::string description() { return "D-Link MH01 firmware image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'M', 'H', '0', '1'}}; }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "mh01_built_in", &formats::extract_mh01,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = formats::inspect_mh01(data, offset);
        if(!header) {
            return std::nullopt;
        }

        const auto payload_start = checked_add(offset, header->encrypted_data_offset);
        if(!payload_start || *payload_start > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }
        const auto openssl = formats::describe_openssl_container(
            data, static_cast<std::size_t>(*payload_start)
        );
        if(!openssl) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header->total_size;
        result.confidence = confidence_high;
        result.description = description() + ", signed, encrypted with " + *openssl
            + ", IV: " + header->iv + ", total size: " + std::to_string(header->total_size)
            + " bytes";
        return result;
    }
};

template<>
struct format_traits<csman_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "csman"; }
    static std::string description() { return "CSman DAT file"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{'S', 'C'}, {'C', 'S'}};
    }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "csman_built_in", &formats::extract_csman,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto dry_run = dry_run_at(&formats::extract_csman, data, offset);
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
struct format_traits<dlke_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dlke"; }
    static std::string description() { return "DLK encrypted firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {
            {'D', 'L', 'K', '6', 'E', '8', '2', '0', '2', '0', '0', '1'},
            {'D', 'L', 'K', '6', 'E', '6', '1', '1', '0', '0', '0', '2'}
        };
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal, "dlke_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        const auto signature_header = formats::inspect_jboot_arm(data, offset);
        if(!signature_header) {
            return std::nullopt;
        }

        const auto crypt_header_offset = checked_add(
            checked_add(offset, signature_header->header_size)
                .value_or(std::numeric_limits<std::uint64_t>::max()),
            signature_header->data_size
        );
        if(!crypt_header_offset
            || *crypt_header_offset > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }
        const auto crypt_header =
            formats::inspect_jboot_arm(data, static_cast<std::size_t>(*crypt_header_offset));
        if(!crypt_header) {
            return std::nullopt;
        }

        const auto total_size = checked_add(
            checked_add(signature_header->header_size, signature_header->data_size)
                .value_or(std::numeric_limits<std::uint64_t>::max()),
            static_cast<std::uint64_t>(crypt_header->header_size) + crypt_header->data_size
        );
        if(!total_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *total_size;
        result.confidence = confidence_high;
        result.description = description() + ", signature size: "
            + std::to_string(signature_header->data_size) + " bytes, encrypted data size: "
            + std::to_string(crypt_header->data_size) + " bytes";
        return result;
    }
};

namespace formats {

std::vector<signature> b6_vendorcarve_signatures() {
    return make_signatures(type_list<
        trx_format,
        jboot_arm_format,
        jboot_stag_format,
        jboot_sch2_format,
        wince_format,
        dahua_zip_format,
        mh01_format,
        csman_format,
        dlke_format
    >{});
}

}
}
