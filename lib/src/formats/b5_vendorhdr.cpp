#include "b5_vendorhdr.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct dlob_format {};
struct packimg_format {};
struct chk_format {};
struct cfe_format {};
struct seama_format {};
struct rtk_format {};
struct binhdr_format {};
struct tplink_format {};
struct tplink_rtos_format {};
struct uboot_format {};
struct logfs_format {};
struct android_bootimg_format {};

[[nodiscard]] bool magic_matches(
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

template<std::size_t Length>
[[nodiscard]] bool magic_matches(
    byte_view data,
    std::size_t offset,
    const std::array<std::uint8_t, Length>& expected
) noexcept {
    return magic_matches(data, offset, expected.data(), Length);
}

[[nodiscard]] std::uint64_t available_from(byte_view data, std::size_t offset) noexcept {
    return offset >= data.size() ? 0 : static_cast<std::uint64_t>(data.size() - offset);
}

[[nodiscard]] std::string to_hex(std::uint64_t value) {
    static constexpr char digits[] = "0123456789ABCDEF";
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

[[nodiscard]] std::string to_hex_prefixed(std::uint64_t value) {
    return "0x" + to_hex(value);
}

constexpr std::uint32_t dlink_header_magic_value = 0x5EA3A417U;

}

template<>
struct format_traits<dlob_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dlob"; }
    static std::string description() { return "DLOB firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x5e, 0xa3, 0xa4, 0x17}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::uint64_t header_part_one_size = 12;

        constexpr std::uint64_t header_part_two_size = 28;

        const auto available = available_from(data, offset);
        if(available < header_part_one_size) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto magic_p1 = reader.read<std::uint32_t>(offset);
        const auto metadata_size_p1 = reader.read<std::uint32_t>(offset + 4);
        const auto data_size_p1 = reader.read<std::uint32_t>(offset + 8);
        if(!magic_p1 || !metadata_size_p1 || !data_size_p1) {
            return std::nullopt;
        }

        if(*magic_p1 != dlink_header_magic_value) {
            return std::nullopt;
        }

        if(*data_size_p1 != 0) {
            return std::nullopt;
        }

        const auto part_two_relative = header_part_one_size
            + static_cast<std::uint64_t>(*metadata_size_p1);
        if(part_two_relative > available
            || header_part_two_size > available - part_two_relative) {
            return std::nullopt;
        }
        const auto part_two_offset = offset + static_cast<std::size_t>(part_two_relative);

        const auto magic_p2 = reader.read<std::uint32_t>(part_two_offset);
        const auto metadata_size_p2 = reader.read<std::uint32_t>(part_two_offset + 4);
        const auto data_size_p2 = reader.read<std::uint32_t>(part_two_offset + 8);
        if(!magic_p2 || !metadata_size_p2 || !data_size_p2) {
            return std::nullopt;
        }
        if(*magic_p2 != *magic_p1) {
            return std::nullopt;
        }

        const auto header_size = part_two_relative + header_part_two_size
            + static_cast<std::uint64_t>(*metadata_size_p2);
        const auto data_size = static_cast<std::uint64_t>(*data_size_p2);

        if(header_size >= data_size) {
            return std::nullopt;
        }

        if(available < header_size || data_size > available - header_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;

        result.size = header_size;
        result.confidence = confidence_medium;
        result.description = description() + ", header size: " + std::to_string(header_size)
            + " bytes, data size: " + std::to_string(data_size);
        return result;
    }
};

template<>
struct format_traits<packimg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "packimg"; }
    static std::string description() { return "PackImg firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'-', '-', 'P', 'a', 'C', 'k', 'I', 'm', 'G', 's', '-', '-'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::uint64_t packimg_header_size = 32;
        constexpr std::size_t structure_size = 20;
        static constexpr std::array<std::uint8_t, 12> packimg_magic{
            '-', '-', 'P', 'a', 'C', 'k', 'I', 'm', 'G', 's', '-', '-'
        };

        if(!magic_matches(data, offset, packimg_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto data_size = reader.read<std::uint32_t>(offset + 16);
        if(!data_size) {
            return std::nullopt;
        }

        const auto available = available_from(data, offset);
        const auto payload_size = static_cast<std::uint64_t>(*data_size);
        if(available < packimg_header_size || payload_size > available - packimg_header_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = packimg_header_size;

        result.confidence = confidence_low;
        result.description = description() + ", header size: "
            + std::to_string(packimg_header_size) + " bytes, data size: "
            + std::to_string(payload_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<chk_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "chk"; }
    static std::string description() { return "CHK firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x2A, 0x23, 0x24, 0x5E}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t structure_size = 40;

        constexpr std::uint32_t maximum_header_size = 100;
        static constexpr std::array<std::uint8_t, 4> chk_magic{0x2A, 0x23, 0x24, 0x5E};

        if(!magic_matches(data, offset, chk_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto header_size = reader.read<std::uint32_t>(offset + 4);
        const auto rootfs_size = reader.read<std::uint32_t>(offset + 24);
        const auto kernel_size = reader.read<std::uint32_t>(offset + 28);
        if(!header_size || !rootfs_size || !kernel_size) {
            return std::nullopt;
        }
        if(*header_size <= structure_size || *header_size > maximum_header_size) {
            return std::nullopt;
        }

        const auto board_id_length = static_cast<std::size_t>(*header_size) - structure_size;
        const auto board_id = get_cstring(data, offset + structure_size, board_id_length);
        if(board_id.empty()) {
            return std::nullopt;
        }

        const auto available = available_from(data, offset);
        const auto payload_size = static_cast<std::uint64_t>(*kernel_size)
            + static_cast<std::uint64_t>(*rootfs_size);
        const auto image_total_size = static_cast<std::uint64_t>(*header_size) + payload_size;
        if(available < image_total_size || image_total_size <= *header_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *header_size;
        result.confidence = confidence_medium;
        result.description = description() + ", board ID: " + board_id + ", header size: "
            + std::to_string(*header_size) + " bytes, data size: "
            + std::to_string(payload_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<cfe_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "cfe"; }
    static std::string description() { return "CFE bootloader"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'C', 'F', 'E', '1', 'C', 'F', 'E', '1'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t cfe_magic_offset = 28;
        static constexpr std::array<std::uint8_t, 8> cfe_magic{
            'C', 'F', 'E', '1', 'C', 'F', 'E', '1'
        };

        if(offset < cfe_magic_offset) {
            return std::nullopt;
        }

        if(!magic_matches(data, offset, cfe_magic)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset - cfe_magic_offset;
        result.description = description();

        result.confidence = result.offset == 0 ? confidence_medium : confidence_low;
        return result;
    }
};

template<>
struct format_traits<seama_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "seama"; }
    static std::string description() { return "SEAMA firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x5E, 0xA3, 0xA4, 0x17, 0x00, 0x00},
            {0x17, 0xA4, 0xA3, 0x5E, 0x00, 0x00}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::uint64_t structure_size = 28;

        const auto available = available_from(data, offset);
        if(available < structure_size) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> little(data);
        binary_reader<byte_order::big> big(data);

        const auto magic_little = little.read<std::uint32_t>(offset);
        if(!magic_little) {
            return std::nullopt;
        }
        const bool big_endian = *magic_little != dlink_header_magic_value;

        std::optional<std::uint32_t> description_size;
        std::optional<std::uint32_t> data_size;
        if(big_endian) {
            const auto magic_big = big.read<std::uint32_t>(offset);
            if(!magic_big || *magic_big != dlink_header_magic_value) {
                return std::nullopt;
            }
            description_size = big.read<std::uint32_t>(offset + 4);
            data_size = big.read<std::uint32_t>(offset + 8);
        } else {
            description_size = little.read<std::uint32_t>(offset + 4);
            data_size = little.read<std::uint32_t>(offset + 8);
        }
        if(!description_size || !data_size) {
            return std::nullopt;
        }

        const auto header_size = structure_size + static_cast<std::uint64_t>(*description_size);
        if(available < header_size) {
            return std::nullopt;
        }
        const auto payload_size = static_cast<std::uint64_t>(*data_size);
        if(payload_size > available - header_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header_size;
        result.confidence = confidence_low;
        result.description = description() + (big_endian ? ", big endian" : ", little endian")
            + ", header size: " + std::to_string(header_size) + " bytes, data size: "
            + std::to_string(payload_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<rtk_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "rtk"; }
    static std::string description() { return "RTK firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'R', 'T', 'K', '0'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t structure_size = 32;
        constexpr std::uint64_t magic_size = 4;
        static constexpr std::array<std::uint8_t, 4> rtk_magic{'R', 'T', 'K', '0'};

        if(!magic_matches(data, offset, rtk_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto image_size = reader.read<std::uint32_t>(offset + 4);
        const auto declared_header_size = reader.read<std::uint32_t>(offset + 16);
        if(!image_size || !declared_header_size) {
            return std::nullopt;
        }

        if(static_cast<std::uint64_t>(*image_size) != available_from(data, offset)) {
            return std::nullopt;
        }

        const auto header_size = static_cast<std::uint64_t>(*declared_header_size) + magic_size;

        signature_result result;
        result.offset = offset;
        result.size = header_size;
        result.confidence = confidence_medium;
        result.description = description() + ", header size: " + std::to_string(header_size)
            + " bytes, image size: " + std::to_string(*image_size);
        return result;
    }
};

template<>
struct format_traits<binhdr_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "binhdr"; }
    static std::string description() { return "BIN firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'U', '2', 'N', 'D'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_back_offset = 14;

        constexpr std::size_t structure_offset = 4;

        constexpr std::size_t structure_size = 26;
        constexpr std::size_t header_size = structure_offset + structure_size;
        static constexpr std::array<std::uint8_t, 4> binhdr_magic{'U', '2', 'N', 'D'};
        static constexpr std::array<const char*, 4> known_hardware_revisions{
            "4702", "4712", "4712L", "4704"
        };

        if(offset < magic_back_offset) {
            return std::nullopt;
        }
        const auto header_offset = offset - magic_back_offset;
        if(!data.contains(header_offset, header_size)) {
            return std::nullopt;
        }

        if(!magic_matches(data, offset, binhdr_magic)) {
            return std::nullopt;
        }

        const auto structure_start = header_offset + structure_offset;
        binary_reader<byte_order::little> reader(data);
        const auto reserved1 = reader.read<std::uint32_t>(structure_start);
        const auto version_major = reader.read<std::uint8_t>(structure_start + 8);
        const auto version_minor = reader.read<std::uint8_t>(structure_start + 9);
        const auto hardware_id = reader.read<std::uint8_t>(structure_start + 14);
        const auto reserved2 = reader.read_u24(structure_start + 15);
        const auto reserved3 = reader.read<std::uint64_t>(structure_start + 18);
        if(!reserved1 || !version_major || !version_minor || !hardware_id || !reserved2
            || !reserved3) {
            return std::nullopt;
        }
        if(*reserved1 != 0 || *reserved2 != 0 || *reserved3 != 0) {
            return std::nullopt;
        }
        if(*hardware_id >= known_hardware_revisions.size()) {
            return std::nullopt;
        }

        const auto board_id = get_cstring(data, header_offset, structure_offset);
        if(board_id.size() != structure_offset) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = header_offset;
        result.confidence = confidence_medium;
        result.description = description() + ", board ID: " + board_id
            + ", hardware revision: " + known_hardware_revisions[*hardware_id]
            + ", firmware version: " + std::to_string(*version_major) + "."
            + std::to_string(*version_minor);
        return result;
    }
};

template<>
struct format_traits<tplink_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "tplink"; }
    static std::string description() { return "TP-Link firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{
            0x01, 0x00, 0x00, 0x00,
            'T', 'P', '-', 'L', 'I', 'N', 'K', ' ', 'T', 'e', 'c', 'h', 'n', 'o', 'l', 'o',
            'g', 'i', 'e', 's',
            0x00, 0x00, 0x00, 0x00,
            'v', 'e', 'r', '.', ' ', '1', '.', '0'
        }};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t structure_offset = 0x40;
        constexpr std::uint64_t header_size = 0x200;

        constexpr std::size_t structure_size = 98;
        static constexpr std::array<std::uint8_t, 36> tplink_magic{
            0x01, 0x00, 0x00, 0x00,
            'T', 'P', '-', 'L', 'I', 'N', 'K', ' ', 'T', 'e', 'c', 'h', 'n', 'o', 'l', 'o',
            'g', 'i', 'e', 's',
            0x00, 0x00, 0x00, 0x00,
            'v', 'e', 'r', '.', ' ', '1', '.', '0'
        };

        if(!magic_matches(data, offset, tplink_magic)) {
            return std::nullopt;
        }

        if(available_from(data, offset) < header_size) {
            return std::nullopt;
        }
        if(!data.contains(offset + structure_offset, structure_size)) {
            return std::nullopt;
        }

        const auto structure_start = offset + structure_offset;
        binary_reader<byte_order::little> reader(data);
        const auto reserved1 = reader.read<std::uint32_t>(structure_start + 8);
        const auto reserved2 = reader.read<std::uint32_t>(structure_start + 28);
        const auto reserved3 = reader.read<std::uint32_t>(structure_start + 48);
        const auto kernel_load_address = reader.read<std::uint32_t>(structure_start + 52);
        const auto kernel_entry_point = reader.read<std::uint32_t>(structure_start + 56);
        const auto reserved4 = reader.read<std::uint32_t>(structure_start + 94);
        if(!reserved1 || !reserved2 || !reserved3 || !reserved4 || !kernel_load_address
            || !kernel_entry_point) {
            return std::nullopt;
        }
        if(*reserved1 != 0 || *reserved2 != 0 || *reserved3 != 0 || *reserved4 != 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header_size;
        result.confidence = confidence_medium;

        result.description = description() + ", kernel load address: "
            + to_hex_prefixed(*kernel_load_address) + ", kernel entry point: "
            + to_hex_prefixed(*kernel_entry_point) + ", header size: "
            + std::to_string(header_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<tplink_rtos_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "tplink_rtos"; }
    static std::string description() { return "TP-Link RTOS firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x00, 0x14, 0x2F, 0xC0}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t structure_size = 32;
        constexpr std::uint64_t header_size = 0x94;
        constexpr std::uint32_t second_magic_value = 0x494D4730U;
        constexpr std::uint64_t total_size_offset = 20;
        static constexpr std::array<std::uint8_t, 4> rtos_magic{0x00, 0x14, 0x2F, 0xC0};

        if(!magic_matches(data, offset, rtos_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto second_magic = reader.read<std::uint32_t>(offset + 20);
        const auto data_size = reader.read<std::uint32_t>(offset + 24);
        const auto model_number = reader.read<std::uint16_t>(offset + 28);
        const auto hardware_major = reader.read<std::uint8_t>(offset + 30);
        const auto hardware_minor = reader.read<std::uint8_t>(offset + 31);
        if(!second_magic || !data_size || !model_number || !hardware_major || !hardware_minor) {
            return std::nullopt;
        }
        if(*second_magic != second_magic_value) {
            return std::nullopt;
        }

        const auto total_size = static_cast<std::uint64_t>(*data_size) + total_size_offset;

        signature_result result;
        result.offset = offset;

        result.confidence = confidence_medium;
        result.description = description() + ", model number: " + to_hex(*model_number)
            + ", hardware version: " + to_hex(*hardware_major) + "."
            + to_hex(*hardware_minor) + ", header size: " + std::to_string(header_size)
            + " bytes, total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<uboot_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "uboot"; }
    static std::string description() { return "U-Boot version string"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'U', '-', 'B', 'o', 'o', 't', ' '}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t number_offset = 7;

        constexpr std::size_t description_limit = 100;
        static constexpr std::array<std::uint8_t, 7> uboot_magic{
            'U', '-', 'B', 'o', 'o', 't', ' '
        };

        if(!magic_matches(data, offset, uboot_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, number_offset + 1)) {
            return std::nullopt;
        }
        if(!is_ascii_number(data[offset + number_offset])) {
            return std::nullopt;
        }

        const auto version_start = offset + number_offset;
        const auto version = get_cstring(
            data.subview(version_start, data.size() - version_start)
        );
        if(version.empty()) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = version.size();
        result.confidence = confidence_medium;
        result.description = description() + ": " + version.substr(
            0, std::min(version.size(), description_limit)
        );
        return result;
    }
};

template<>
struct format_traits<logfs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "logfs"; }
    static std::string description() { return "LogFS file system"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x7A, 0x3A, 0x8E, 0x5C, 0xB9, 0xD5, 0xBF, 0x67}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t logfs_magic_offset = 0x18;

        constexpr std::size_t structure_size = 88;
        static constexpr std::array<std::uint8_t, 8> logfs_magic{
            0x7A, 0x3A, 0x8E, 0x5C, 0xB9, 0xD5, 0xBF, 0x67
        };

        if(offset < logfs_magic_offset) {
            return std::nullopt;
        }

        if(!magic_matches(data, offset, logfs_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto pad0 = reader.read<std::uint32_t>(offset + 18);
        const auto pad1 = reader.read<std::uint16_t>(offset + 22);
        const auto filesystem_size = reader.read<std::uint64_t>(offset + 24);
        if(!pad0 || !pad1 || !filesystem_size) {
            return std::nullopt;
        }
        if(*pad0 != 0 || *pad1 != 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset - logfs_magic_offset;

        result.size = *filesystem_size;
        result.confidence = confidence_medium;
        result.description = description() + ", total size: " + std::to_string(result.size)
            + " bytes";
        return result;
    }
};

template<>
struct format_traits<android_bootimg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "android_bootimg"; }
    static std::string description() { return "Android boot image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t structure_size = 24;
        static constexpr std::array<std::uint8_t, 8> bootimg_magic{
            'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'
        };

        if(!magic_matches(data, offset, bootimg_magic)) {
            return std::nullopt;
        }
        if(!data.contains(offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto kernel_size = reader.read<std::uint32_t>(offset + 8);
        const auto kernel_load_address = reader.read<std::uint32_t>(offset + 12);
        const auto ramdisk_size = reader.read<std::uint32_t>(offset + 16);
        const auto ramdisk_load_address = reader.read<std::uint32_t>(offset + 20);
        if(!kernel_size || !kernel_load_address || !ramdisk_size || !ramdisk_load_address) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;

        result.confidence = offset == 0 ? confidence_medium : confidence_low;
        result.description = description() + ", kernel size: " + std::to_string(*kernel_size)
            + " bytes, kernel load address: " + to_hex_prefixed(*kernel_load_address)
            + ", ramdisk size: " + std::to_string(*ramdisk_size)
            + " bytes, ramdisk load address: " + to_hex_prefixed(*ramdisk_load_address);
        return result;
    }
};

namespace formats {

std::vector<signature> b5_vendorhdr_signatures() {
    return make_signatures(type_list<
        dlob_format,
        packimg_format,
        chk_format,
        cfe_format,
        seama_format,
        rtk_format,
        binhdr_format,
        tplink_format,
        tplink_rtos_format,
        uboot_format,
        logfs_format,
        android_bootimg_format
    >{});
}

}
}
