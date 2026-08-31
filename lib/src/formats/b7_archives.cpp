#include "b7_archives.hpp"

#include "zip_structures.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/common.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct arj_format {};
struct cab_format {};
struct cpio_format {};
struct deb_format {};
struct iso9660_format {};
struct matter_ota_format {};
struct rar_format {};
struct sevenzip_format {};
struct srecord_format {};
struct srecord_generic_format {};
struct tarball_format {};
struct zip_format {};

[[nodiscard]] extractor sevenzip_extractor_definition(const char* extension) {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "7zz",
        extension,
        {"x", "-y", "-o.", "-p''", "%e"},
        {0, 2},
        false
    };
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

[[nodiscard]] bool is_ascii_space(std::uint8_t value) noexcept {
    return value == 0x20 || value == 0x09 || value == 0x0a || value == 0x0b
        || value == 0x0c || value == 0x0d;
}

[[nodiscard]] std::optional<std::uint64_t> parse_ascii_decimal(
    byte_view data,
    std::size_t offset,
    std::size_t length
) noexcept {
    if(!data.contains(offset, length)) {
        return std::nullopt;
    }
    std::size_t begin = 0;
    std::size_t end = length;
    while(begin < end && is_ascii_space(data[offset + begin])) {
        ++begin;
    }
    while(end > begin && is_ascii_space(data[offset + end - 1])) {
        --end;
    }
    if(begin < end && data[offset + begin] == '+') {
        ++begin;
    }
    if(begin >= end) {
        return std::nullopt;
    }
    constexpr auto limit = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t value = 0;
    for(std::size_t index = begin; index < end; ++index) {
        const std::uint8_t character = data[offset + index];
        if(character < '0' || character > '9') {
            return std::nullopt;
        }
        const auto digit = static_cast<std::uint64_t>(character - '0');
        if(value > (limit - digit) / 10U) {
            return std::nullopt;
        }
        value = value * 10U + digit;
    }
    return value;
}

[[nodiscard]] std::optional<std::uint64_t> parse_ascii_hex(
    byte_view data,
    std::size_t offset,
    std::size_t length
) noexcept {
    if(!data.contains(offset, length)) {
        return std::nullopt;
    }
    std::size_t begin = 0;
    if(begin < length && data[offset + begin] == '+') {
        ++begin;
    }
    if(begin >= length) {
        return std::nullopt;
    }
    constexpr auto limit = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t value = 0;
    for(std::size_t index = begin; index < length; ++index) {
        const std::uint8_t character = data[offset + index];
        std::uint64_t digit = 0;
        if(character >= '0' && character <= '9') {
            digit = static_cast<std::uint64_t>(character - '0');
        } else if(character >= 'a' && character <= 'f') {
            digit = static_cast<std::uint64_t>(character - 'a') + 10U;
        } else if(character >= 'A' && character <= 'F') {
            digit = static_cast<std::uint64_t>(character - 'A') + 10U;
        } else {
            return std::nullopt;
        }
        if(value > (limit - digit) / 16U) {
            return std::nullopt;
        }
        value = value * 16U + digit;
    }
    return value;
}

[[nodiscard]] bool is_valid_utf8(byte_view data, std::size_t offset, std::size_t length) noexcept {
    if(!data.contains(offset, length)) {
        return false;
    }
    std::size_t index = 0;
    while(index < length) {
        const std::uint8_t lead = data[offset + index];
        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        if(lead < 0x80U) {
            ++index;
            continue;
        }
        if((lead & 0xe0U) == 0xc0U) {
            continuation_count = 1;
            code_point = lead & 0x1fU;
        } else if((lead & 0xf0U) == 0xe0U) {
            continuation_count = 2;
            code_point = lead & 0x0fU;
        } else if((lead & 0xf8U) == 0xf0U) {
            continuation_count = 3;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if(length - index - 1 < continuation_count) {
            return false;
        }
        for(std::size_t step = 1; step <= continuation_count; ++step) {
            const std::uint8_t continuation = data[offset + index + step];
            if((continuation & 0xc0U) != 0x80U) {
                return false;
            }
            code_point = static_cast<std::uint32_t>((code_point << 6U) | (continuation & 0x3fU));
        }
        if((continuation_count == 1 && code_point < 0x80U)
            || (continuation_count == 2 && code_point < 0x800U)
            || (continuation_count == 3 && code_point < 0x10000U)
            || code_point > 0x10ffffU
            || (code_point >= 0xd800U && code_point <= 0xdfffU)) {
            return false;
        }
        index += continuation_count + 1;
    }
    return true;
}

[[nodiscard]] std::string lowercase_hex(std::uint64_t value) {
    if(value == 0) {
        return "0";
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    while(value != 0) {
        text.insert(text.begin(), digits[value & 0x0fU]);
        value >>= 4U;
    }
    return text;
}

[[nodiscard]] std::string lowercase_hex_bytes(byte_view data, std::size_t offset, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    if(!data.contains(offset, length)) {
        return text;
    }
    text.reserve(length * 2);
    for(std::size_t index = 0; index < length; ++index) {
        const std::uint8_t value = data[offset + index];
        text.push_back(digits[(value >> 4U) & 0x0fU]);
        text.push_back(digits[value & 0x0fU]);
    }
    return text;
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

}

template<>
struct format_traits<deb_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "deb"; }
    static std::string description() { return "Debian package file"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{
            '!', '<', 'a', 'r', 'c', 'h', '>', '\n',
            'd', 'e', 'b', 'i', 'a', 'n', '-', 'b', 'i', 'n', 'a', 'r', 'y',
            0x20, 0x20, 0x20
        }};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        constexpr std::size_t end_marker_size = 2;
        constexpr std::size_t data_file_size_length = 10;
        constexpr std::size_t data_file_size_offset = 48;
        constexpr std::size_t control_file_size_start = 120;
        constexpr std::size_t control_file_size_length = 10;
        constexpr std::size_t control_file_size_end =
            control_file_size_start + control_file_size_length;

        if(offset >= data.size()) {
            return std::nullopt;
        }
        const auto control_file_size = parse_ascii_decimal(
            data, offset + control_file_size_start, control_file_size_length
        );
        if(!control_file_size) {
            return std::nullopt;
        }

        const auto data_file_size_start = checked_add(
            *control_file_size,
            control_file_size_end + end_marker_size + data_file_size_offset
        );
        if(!data_file_size_start) {
            return std::nullopt;
        }
        const auto data_file_size_end = checked_add(*data_file_size_start, data_file_size_length);
        if(!data_file_size_end || *data_file_size_start > data.size() - offset) {
            return std::nullopt;
        }
        const auto data_file_size = parse_ascii_decimal(
            data,
            offset + static_cast<std::size_t>(*data_file_size_start),
            data_file_size_length
        );
        if(!data_file_size) {
            return std::nullopt;
        }

        const auto total_size = checked_add(
            *data_file_size_end, end_marker_size + *data_file_size
        );
        if(!total_size || *total_size > data.size() - offset) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *total_size;
        result.confidence = confidence_high;
        result.description = description() + ", total size: "
            + std::to_string(*total_size) + " bytes";
        return result;
    }
};

namespace {

constexpr std::size_t tarball_block_size = 512;
constexpr std::size_t tarball_magic_offset = 257;
constexpr std::size_t tarball_magic_size = 5;
constexpr std::size_t tarball_size_offset = 124;
constexpr std::size_t tarball_size_length = 11;
constexpr std::size_t tarball_min_expected_headers = 10;

[[nodiscard]] std::uint64_t tarball_octal(
    byte_view data,
    std::size_t offset,
    std::size_t length
) noexcept {
    std::uint64_t value = 0;
    for(std::size_t index = 0; index < length; ++index) {
        const std::uint8_t character = data[offset + index];
        if(character < 0x30 || character > 0x39) {
            break;
        }

        value = value * 8U + static_cast<std::uint64_t>(character - 0x30);
    }
    return value;
}

[[nodiscard]] bool tarball_checksum_is_valid(byte_view data, std::size_t block) noexcept {
    constexpr std::size_t checksum_start = 148;
    constexpr std::size_t checksum_end = 156;
    const std::uint64_t reported = tarball_octal(
        data, block + checksum_start, checksum_end - checksum_start
    );
    std::uint64_t sum = 0;
    for(std::size_t index = 0; index < tarball_block_size; ++index) {
        if(index >= checksum_start && index < checksum_end) {
            sum += 0x20U;
        } else {
            sum += data[block + index];
        }
    }
    return sum == reported;
}

[[nodiscard]] std::optional<std::uint64_t> tarball_entry_size(
    byte_view data,
    std::size_t block
) noexcept {
    static constexpr std::uint8_t universal_magic[tarball_magic_size] = {
        'u', 's', 't', 'a', 'r'
    };
    if(!bytes_equal(data, block + tarball_magic_offset, universal_magic, tarball_magic_size)) {
        return std::nullopt;
    }
    const std::uint64_t reported = tarball_octal(
        data, block + tarball_size_offset, tarball_size_length
    );

    const std::uint64_t block_count = 1U + (reported / tarball_block_size)
        + ((reported % tarball_block_size) != 0 ? 1U : 0U);
    return block_count * tarball_block_size;
}

}

template<>
struct format_traits<tarball_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "tarball"; }
    static std::string description() { return "POSIX tar archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {'u', 's', 't', 'a', 'r', 0x00},
            {'u', 's', 't', 'a', 'r', 0x20, 0x20, 0x00}
        };
    }
    static binwalk::extractor extractor() {

        return extractor_definition();
    }

    static binwalk::extractor extractor_definition() {
        return binwalk::extractor{
            extractor_type::external,
            std::string{},
            nullptr,
            "tar",
            "tar",
            {"-x", "-f", "%e"},
            {0, 2},
            false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset < tarball_magic_offset) {
            return std::nullopt;
        }
        const std::size_t start_offset = offset - tarball_magic_offset;

        std::uint64_t total_size = 0;
        std::size_t valid_header_count = 0;
        std::size_t next_header_start = start_offset;
        std::optional<std::size_t> previous_header_start;
        const std::size_t available_data = data.size();

        while(is_offset_safe(available_data, next_header_start, previous_header_start)) {
            if(!data.contains(next_header_start, tarball_block_size)) {
                break;
            }
            if(!tarball_checksum_is_valid(data, next_header_start)) {
                break;
            }
            ++valid_header_count;

            const auto entry_size = tarball_entry_size(data, next_header_start);
            if(!entry_size) {
                break;
            }
            const auto new_total = checked_add(total_size, *entry_size);
            if(!new_total) {
                break;
            }
            total_size = *new_total;

            previous_header_start = next_header_start;
            const auto next = checked_add(
                static_cast<std::uint64_t>(next_header_start), *entry_size
            );
            if(!next || *next > static_cast<std::uint64_t>(available_data)) {

                break;
            }
            next_header_start = static_cast<std::size_t>(*next);
        }

        if(total_size < tarball_block_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start_offset;
        result.size = total_size;
        result.confidence = valid_header_count >= tarball_min_expected_headers
            ? confidence_high
            : confidence_medium;
        result.description = description() + ", file count: "
            + std::to_string(valid_header_count);
        return result;
    }
};

namespace {

constexpr std::size_t cpio_header_size = 110;

struct cpio_entry_header {
    std::uint64_t data_size = 0;
    std::uint64_t header_size = 0;
    std::string file_name;
};

[[nodiscard]] std::uint64_t cpio_byte_padding(std::uint64_t value) noexcept {
    const std::uint64_t modulus = value % 4U;
    return modulus == 0 ? 0U : 4U - modulus;
}

[[nodiscard]] std::optional<cpio_entry_header> parse_cpio_entry_header(
    byte_view data,
    std::size_t offset
) {
    constexpr std::size_t magic_length = 6;
    constexpr std::size_t file_size_start = 54;
    constexpr std::size_t file_name_size_start = 94;
    constexpr std::size_t ascii_hex_field_length = 8;

    if(!data.contains(offset, cpio_header_size + 1)) {
        return std::nullopt;
    }

    static constexpr std::uint8_t magic_new_ascii[magic_length] = {'0', '7', '0', '7', '0', '1'};
    static constexpr std::uint8_t magic_new_crc[magic_length] = {'0', '7', '0', '7', '0', '2'};
    if(!bytes_equal(data, offset, magic_new_ascii, magic_length)
        && !bytes_equal(data, offset, magic_new_crc, magic_length)) {
        return std::nullopt;
    }

    const auto file_data_size = parse_ascii_hex(
        data, offset + file_size_start, ascii_hex_field_length
    );
    const auto file_name_size = parse_ascii_hex(
        data, offset + file_name_size_start, ascii_hex_field_length
    );
    if(!file_data_size || !file_name_size) {
        return std::nullopt;
    }

    if(*file_name_size == 0) {
        return std::nullopt;
    }

    const std::uint64_t name_length = *file_name_size - 1U;
    const auto name_start = checked_add(static_cast<std::uint64_t>(offset), cpio_header_size);
    if(!name_start || name_length > static_cast<std::uint64_t>(data.size())) {
        return std::nullopt;
    }
    const auto name_start_size = static_cast<std::size_t>(*name_start);
    const auto name_length_size = static_cast<std::size_t>(name_length);
    if(!data.contains(name_start_size, name_length_size)
        || !is_valid_utf8(data, name_start_size, name_length_size)) {
        return std::nullopt;
    }

    cpio_entry_header header;
    header.file_name.assign(
        reinterpret_cast<const char*>(data.data()) + name_start_size, name_length_size
    );
    header.data_size = *file_data_size + cpio_byte_padding(*file_data_size);
    const std::uint64_t header_total = cpio_header_size + *file_name_size;
    header.header_size = header_total + cpio_byte_padding(header_total);
    return header;
}

}

template<>
struct format_traits<cpio_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "cpio"; }
    static std::string description() { return "CPIO ASCII archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {'0', '7', '0', '7', '0', '1'},
            {'0', '7', '0', '7', '0', '2'}
        };
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition("bin"); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        static const std::string eof_marker = "TRAILER!!!";

        std::size_t header_count = 0;
        std::uint64_t total_size = 0;
        std::size_t next_header_offset = offset;
        std::optional<std::size_t> previous_header_offset;
        const std::size_t available_data = data.size();

        while(is_offset_safe(available_data, next_header_offset, previous_header_offset)) {
            const auto header = parse_cpio_entry_header(data, next_header_offset);
            if(!header) {
                break;
            }
            ++header_count;

            const auto entry_size = checked_add(header->header_size, header->data_size);
            if(!entry_size) {
                break;
            }
            const auto new_total = checked_add(total_size, *entry_size);
            if(!new_total) {
                break;
            }
            total_size = *new_total;

            if(header->file_name == eof_marker) {

                if(header_count <= 1) {
                    break;
                }
                signature_result result;
                result.offset = offset;
                result.size = total_size;
                result.confidence = confidence_high;
                result.description = description() + ", file count: "
                    + std::to_string(header_count - 1);
                return result;
            }

            previous_header_offset = next_header_offset;
            const auto next = checked_add(static_cast<std::uint64_t>(offset), total_size);
            if(!next || *next > static_cast<std::uint64_t>(available_data)) {
                break;
            }
            next_header_offset = static_cast<std::size_t>(*next);
        }

        return std::nullopt;
    }
};

template<>
struct format_traits<iso9660_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "iso9660"; }
    static std::string description() { return "ISO9660 primary volume"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x01, 'C', 'D', '0', '0', '1', 0x01, 0x00}};
    }
    static binwalk::extractor extractor() {

        return sevenzip_extractor_definition("iso");
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t iso_magic_offset = 32768;

        constexpr std::size_t iso_struct_start = 32840;
        constexpr std::size_t iso_struct_size = 68;

        if(offset < iso_magic_offset) {
            return std::nullopt;
        }
        const std::size_t image_start = offset - iso_magic_offset;
        const std::size_t fields = image_start + iso_struct_start;
        if(!data.contains(fields, iso_struct_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> little(data);
        binary_reader<byte_order::big> big(data);
        const auto unused1 = little.read<std::uint64_t>(fields);
        const auto volume_size_lsb = little.read<std::uint32_t>(fields + 8);
        const auto volume_size_msb = big.read<std::uint32_t>(fields + 12);
        const auto unused2 = little.read<std::uint64_t>(fields + 16);
        const auto unused3 = little.read<std::uint64_t>(fields + 24);
        const auto unused4 = little.read<std::uint64_t>(fields + 32);
        const auto unused5 = little.read<std::uint64_t>(fields + 40);
        const auto set_size_lsb = little.read<std::uint16_t>(fields + 48);
        const auto set_size_msb = big.read<std::uint16_t>(fields + 50);
        const auto sequence_lsb = little.read<std::uint16_t>(fields + 52);
        const auto sequence_msb = big.read<std::uint16_t>(fields + 54);
        const auto block_size_lsb = little.read<std::uint16_t>(fields + 56);
        const auto block_size_msb = big.read<std::uint16_t>(fields + 58);
        const auto path_table_size_lsb = little.read<std::uint32_t>(fields + 60);
        const auto path_table_size_msb = big.read<std::uint32_t>(fields + 64);
        if(!unused1 || !volume_size_lsb || !volume_size_msb || !unused2 || !unused3
            || !unused4 || !unused5 || !set_size_lsb || !set_size_msb || !sequence_lsb
            || !sequence_msb || !block_size_lsb || !block_size_msb
            || !path_table_size_lsb || !path_table_size_msb) {
            return std::nullopt;
        }

        if(*unused1 != 0 || *unused2 != 0 || *unused3 != 0 || *unused4 != 0 || *unused5 != 0
            || *volume_size_lsb != *volume_size_msb
            || *set_size_lsb != *set_size_msb
            || *sequence_lsb != *sequence_msb
            || *block_size_lsb != *block_size_msb
            || *path_table_size_lsb != *path_table_size_msb) {
            return std::nullopt;
        }

        const auto image_size = checked_multiply(*volume_size_lsb, *block_size_lsb);
        if(!image_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = image_start;
        result.size = *image_size;
        result.confidence = confidence_high;
        result.description = description() + ", total size: "
            + std::to_string(*image_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<cab_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "cab"; }
    static std::string description() { return "Microsoft Cabinet archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{'M', 'S', 'C', 'F', 0x00, 0x00, 0x00, 0x00}};
    }
    static binwalk::extractor extractor() {

        return binwalk::extractor{
            extractor_type::external,
            std::string{},
            nullptr,
            "cabextract",
            "cab",
            {"%e"},
            {0},
            false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t cab_struct_size = 40;
        constexpr std::size_t cab_extra_struct_size = 20;
        constexpr std::uint16_t flag_extra_data_present = 4;
        constexpr std::uint8_t major_version = 1;
        constexpr std::uint8_t minor_version = 3;

        static constexpr std::uint8_t cab_magic[4] = {'M', 'S', 'C', 'F'};
        if(!bytes_equal(data, offset, cab_magic, sizeof(cab_magic))
            || !data.contains(offset, cab_struct_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto reserved1 = reader.read<std::uint32_t>(offset + 4);
        const auto cabinet_size = reader.read<std::uint32_t>(offset + 8);
        const auto reserved2 = reader.read<std::uint32_t>(offset + 12);
        const auto reserved3 = reader.read<std::uint32_t>(offset + 20);
        const auto minor = reader.read<std::uint8_t>(offset + 24);
        const auto major = reader.read<std::uint8_t>(offset + 25);
        const auto folder_count = reader.read<std::uint16_t>(offset + 26);
        const auto file_count = reader.read<std::uint16_t>(offset + 28);
        const auto flags = reader.read<std::uint16_t>(offset + 30);
        const auto extra_header_size = reader.read<std::uint16_t>(offset + 36);
        if(!reserved1 || !cabinet_size || !reserved2 || !reserved3 || !minor || !major
            || !folder_count || !file_count || !flags || !extra_header_size) {
            return std::nullopt;
        }
        if(*reserved1 != 0 || *reserved2 != 0 || *reserved3 != 0
            || *major != major_version || *minor != minor_version) {
            return std::nullopt;
        }

        std::uint64_t total_size = *cabinet_size;
        if((*flags & flag_extra_data_present) != 0
            && *extra_header_size == cab_extra_struct_size) {
            const std::size_t extra_start = offset + cab_struct_size;
            if(!data.contains(extra_start, cab_extra_struct_size)) {
                return std::nullopt;
            }
            const auto data_offset = reader.read<std::uint32_t>(extra_start + 4);
            const auto data_size = reader.read<std::uint32_t>(extra_start + 8);
            if(!data_offset || !data_size || *data_offset != *cabinet_size) {
                return std::nullopt;
            }
            const auto extended = checked_add(total_size, *data_size);
            if(!extended) {
                return std::nullopt;
            }
            total_size = *extended;
        }

        if(total_size > data.size() - offset) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_medium;
        result.description = description() + ", file count: " + std::to_string(*file_count)
            + ", folder count: " + std::to_string(*folder_count)
            + ", header size: " + std::to_string(cab_struct_size)
            + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<rar_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "rar"; }
    static std::string description() { return "RAR archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'R', 'a', 'r', '!', 0x1a, 0x07}};
    }
    static binwalk::extractor extractor() {

        return binwalk::extractor{
            extractor_type::external,
            std::string{},
            nullptr,
            "unrar",
            "rar",
            {"x", "-y", "-ppassword", "%e"},
            {0},
            false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static constexpr std::uint8_t rar_magic[6] = {'R', 'a', 'r', '!', 0x1a, 0x07};

        if(!bytes_equal(data, offset, rar_magic, sizeof(rar_magic))
            || !data.contains(offset, sizeof(rar_magic) + 1)) {
            return std::nullopt;
        }

        std::uint32_t version = 0;
        switch(data[offset + 6]) {
            case 0: version = 4; break;
            case 1: version = 5; break;
            default: return std::nullopt;
        }

        static constexpr std::uint8_t eof_marker_v4[7] = {
            0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00
        };
        static constexpr std::uint8_t eof_marker_v5[8] = {
            0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00
        };
        const std::uint8_t* marker = version == 4 ? eof_marker_v4 : eof_marker_v5;
        const std::size_t marker_length = version == 4 ? sizeof(eof_marker_v4)
                                                       : sizeof(eof_marker_v5);

        signature_result result;
        result.offset = offset;

        std::optional<std::uint64_t> total_size;
        for(std::size_t cursor = offset;
            data.contains(cursor, marker_length);
            ++cursor) {
            if(bytes_equal(data, cursor, marker, marker_length)) {
                total_size = static_cast<std::uint64_t>(cursor - offset) + marker_length;
                break;
            }
        }

        std::string extra;
        if(total_size) {
            result.size = *total_size;
            result.confidence = confidence_medium;
        } else {
            extra = " (failed to locate RAR EOF)";
        }
        result.description = description() + ", version: " + std::to_string(version)
            + ", total size: " + std::to_string(result.size) + " bytes" + extra;
        return result;
    }
};

namespace {

enum class tlv_kind {
    container,
    end_of_container,
    unsigned_integer,
    utf8_string,
    octet_string
};

struct tlv_element {
    tlv_kind kind = tlv_kind::container;
    bool has_tag = false;
    std::uint64_t tag = 0;
    std::uint64_t unsigned_value = 0;
    std::string string_value;
    std::string octet_hex;
    std::size_t consumed = 0;
};

[[nodiscard]] std::optional<tlv_element> parse_tlv_element(byte_view data, std::size_t position) {
    if(!data.contains(position, 1)) {
        return std::nullopt;
    }
    const std::uint8_t control_octet = data[position];
    const auto element_type = static_cast<std::uint8_t>(control_octet & 0x1fU);
    const auto tag_control = static_cast<std::uint8_t>(control_octet >> 5U);

    std::size_t field_width = 0;
    switch(element_type & 0x03U) {
        case 0: field_width = 1; break;
        case 1: field_width = 2; break;
        case 2: field_width = 4; break;
        default: field_width = 8; break;
    }

    tlv_element element;
    std::size_t field_offset = 0;
    if(tag_control == 0) {

        field_offset = 1;
    } else if(tag_control == 1) {
        if(!data.contains(position + 1, 1)) {
            return std::nullopt;
        }
        element.has_tag = true;
        element.tag = data[position + 1];
        field_offset = 2;
    } else {

        return std::nullopt;
    }

    const std::size_t field_start = position + field_offset;
    if(field_start > data.size()) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto read_field = [&](std::size_t at) -> std::optional<std::uint64_t> {
        switch(field_width) {
            case 1: {
                const auto value = reader.read<std::uint8_t>(at);
                return value ? std::optional<std::uint64_t>(*value) : std::nullopt;
            }
            case 2: {
                const auto value = reader.read<std::uint16_t>(at);
                return value ? std::optional<std::uint64_t>(*value) : std::nullopt;
            }
            case 4: {
                const auto value = reader.read<std::uint32_t>(at);
                return value ? std::optional<std::uint64_t>(*value) : std::nullopt;
            }
            default:
                return reader.read<std::uint64_t>(at);
        }
    };

    if(element_type == 0x15U) {
        element.kind = tlv_kind::container;
        element.consumed = field_offset;
        return element;
    }
    if(element_type == 0x18U) {
        element.kind = tlv_kind::end_of_container;
        element.consumed = field_offset;
        return element;
    }
    if(element_type >= 0x04U && element_type <= 0x07U) {
        const auto value = read_field(field_start);
        if(!value) {
            return std::nullopt;
        }
        element.kind = tlv_kind::unsigned_integer;
        element.unsigned_value = *value;
        element.consumed = field_offset + field_width;
        return element;
    }
    if((element_type >= 0x0cU && element_type <= 0x0fU)
        || (element_type >= 0x10U && element_type <= 0x13U)) {
        const auto declared_length = read_field(field_start);
        if(!declared_length) {
            return std::nullopt;
        }
        const std::size_t payload_start = field_start + field_width;
        if(payload_start > data.size()
            || *declared_length > static_cast<std::uint64_t>(data.size() - payload_start)) {
            return std::nullopt;
        }
        const auto payload_length = static_cast<std::size_t>(*declared_length);
        if(element_type <= 0x0fU) {

            element.kind = tlv_kind::utf8_string;
            element.string_value = get_cstring(data, payload_start, payload_length);
        } else {
            element.kind = tlv_kind::octet_string;
            element.octet_hex = lowercase_hex_bytes(data, payload_start, payload_length);
        }
        element.consumed = field_offset + field_width + payload_length;
        return element;
    }
    return std::nullopt;
}

}

namespace formats {

std::optional<matter_ota_header> inspect_matter_ota(byte_view data, std::size_t offset) {
    constexpr std::size_t fixed_header_size = matter_ota_fixed_header_size;

    constexpr std::uint64_t tag_vendor_id = 0;
    constexpr std::uint64_t tag_product_id = 1;
    constexpr std::uint64_t tag_software_version_string = 3;
    constexpr std::uint64_t tag_payload_size = 4;
    constexpr std::uint64_t tag_image_digest_type = 8;
    constexpr std::uint64_t tag_image_digest = 9;
    constexpr std::uint64_t tag_count = 10;

    static constexpr std::uint8_t ota_magic[4] = {0x1e, 0xf1, 0xee, 0x1b};
    if(!bytes_equal(data, offset, ota_magic, sizeof(ota_magic))
        || !data.contains(offset, fixed_header_size)) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto total_size = reader.read<std::uint64_t>(offset + 4);
    const auto declared_header_size = reader.read<std::uint32_t>(offset + 12);
    if(!total_size || !declared_header_size) {
        return std::nullopt;
    }

    const std::size_t tlv_start = offset + fixed_header_size;
    if(!data.contains(tlv_start, static_cast<std::size_t>(*declared_header_size))) {
        return std::nullopt;
    }
    const byte_view tlv = data.subview(tlv_start, static_cast<std::size_t>(*declared_header_size));

    matter_ota_header header;
    header.total_size = *total_size;
    header.header_size = *declared_header_size;

    std::size_t next_offset = 0;
    std::optional<std::size_t> last_offset;
    while(is_offset_safe(tlv.size(), next_offset, last_offset)) {
        const auto element = parse_tlv_element(tlv, next_offset);
        if(!element) {
            return std::nullopt;
        }
        last_offset = next_offset;

        next_offset += element->consumed;

        if(!element->has_tag) {
            continue;
        }
        if(element->tag >= tag_count) {
            return std::nullopt;
        }
        switch(element->tag) {
            case tag_vendor_id:
                if(element->kind == tlv_kind::unsigned_integer) {
                    header.vendor_id = element->unsigned_value;
                }
                break;
            case tag_product_id:
                if(element->kind == tlv_kind::unsigned_integer) {
                    header.product_id = element->unsigned_value;
                }
                break;
            case tag_software_version_string:
                if(element->kind == tlv_kind::utf8_string) {
                    header.version = element->string_value;
                }
                break;
            case tag_payload_size:
                if(element->kind == tlv_kind::unsigned_integer) {
                    header.payload_size = element->unsigned_value;
                }
                break;
            case tag_image_digest_type:
                if(element->kind == tlv_kind::unsigned_integer) {
                    header.image_digest_type = element->unsigned_value;
                }
                break;
            case tag_image_digest:
                if(element->kind == tlv_kind::octet_string) {
                    header.image_digest = element->octet_hex;
                }
                break;
            default:

                break;
        }
    }

    const auto claimed = checked_add(header.payload_size, fixed_header_size + header.header_size);
    if(!claimed || *claimed != header.total_size) {
        return std::nullopt;
    }
    return header;
}

extraction_result extract_matter_ota(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string outfile_name = "matter_payload.bin";

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_matter_ota(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const std::uint64_t total_header_size =
        matter_ota_fixed_header_size + header->header_size;

    result.success = true;
    result.size = header->total_size;

    const auto payload_start = checked_add(
        static_cast<std::uint64_t>(offset), total_header_size
    );
    if(!payload_start) {
        return result;
    }
    const auto payload_end = checked_add(*payload_start, header->payload_size);
    if(!payload_end || *payload_end > static_cast<std::uint64_t>(data.size())) {

        return result;
    }

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    result.success = output.carve_file(
        outfile_name,
        data,
        static_cast<std::size_t>(*payload_start),
        static_cast<std::size_t>(header->payload_size)
    );
    if(!result.success) {
        result.failure = extraction_failure::write_error;
    }
    return result;
}

}

template<>
struct format_traits<matter_ota_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "matter_ota"; }
    static std::string description() { return "Matter OTA firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x1e, 0xf1, 0xee, 0x1b}};
    }
    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal,
            "matter_ota_built_in",
            &formats::extract_matter_ota,
            std::string{},
            std::string{},
            {},
            {},
            false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = formats::inspect_matter_ota(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;

        result.size = header->header_size;
        result.confidence = confidence_high;
        result.description = description()
            + ", total size: " + std::to_string(header->total_size) + " bytes"
            + ", tlv header size: " + std::to_string(header->header_size) + " bytes"
            + ", vendor id: 0x" + lowercase_hex(header->vendor_id)
            + ", product id: 0x" + lowercase_hex(header->product_id)
            + ", version: " + header->version
            + ", payload size: " + std::to_string(header->payload_size) + " bytes"
            + ", digest type: " + std::to_string(header->image_digest_type)
            + ", payload digest: " + header->image_digest;
        return result;
    }
};

namespace {

[[nodiscard]] std::optional<signature_result> parse_srecord(byte_view data, std::size_t offset) {
    constexpr std::uint8_t unix_terminator = 0x0a;
    constexpr std::uint8_t windows_terminator = 0x0d;
    constexpr std::size_t footer_length = 3;

    if(offset >= data.size()) {
        return std::nullopt;
    }
    const std::size_t available_data = data.size();

    for(std::size_t cursor = offset; data.contains(cursor, footer_length); ++cursor) {
        if(data[cursor] != unix_terminator || data[cursor + 1] != 'S') {
            continue;
        }
        const std::uint8_t record_type = data[cursor + 2];
        if(record_type != '9' && record_type != '8' && record_type != '7') {
            continue;
        }

        const char* os_type = "Unix";
        std::size_t srec_eof = cursor + footer_length;
        std::optional<std::size_t> last_srec_eof;
        while(is_offset_safe(available_data, srec_eof, last_srec_eof)) {
            const std::uint8_t current = data[srec_eof];
            if(current != unix_terminator && current != windows_terminator) {
                last_srec_eof = srec_eof;
                ++srec_eof;
                continue;
            }
            if(current == windows_terminator) {
                ++srec_eof;
                os_type = "Windows";
            }
            if(data.contains(srec_eof) && data[srec_eof] == unix_terminator) {
                ++srec_eof;
                signature_result result;
                result.offset = offset;
                result.size = static_cast<std::uint64_t>(srec_eof - offset);
                result.confidence = confidence_high;
                result.description = std::string("Motorola S-record, origin OS: ") + os_type
                    + ", total size: " + std::to_string(result.size) + " bytes";
                return result;
            }

            return std::nullopt;
        }

    }
    return std::nullopt;
}

[[nodiscard]] binwalk::extractor srecord_extractor_definition() {

    return binwalk::extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "srec_cat",
        "hex",
        {"-output", "s-record.bin", "-binary", "%e"},
        {0},
        false
    };
}

}

template<>
struct format_traits<srecord_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "srecord"; }
    static std::string description() { return "Motorola S-record"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{
            'S', '0', '0', '6', '0', '0', '0', '0',
            '4', '8', '4', '4', '5', '2', '1', 'B'
        }};
    }
    static binwalk::extractor extractor() { return srecord_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_srecord(data, offset);
    }
};

template<>
struct format_traits<srecord_generic_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "srecord_generic"; }
    static std::string description() { return "Motorola S-record (generic)"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'S', '0'}}; }
    static binwalk::extractor extractor() { return srecord_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_srecord(data, offset);
    }
};

template<>
struct format_traits<arj_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "arj"; }
    static std::string description() { return "ARJ archive data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x60, 0xea}}; }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition("bin"); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t arj_struct_size = 24;
        static constexpr std::uint8_t arj_magic[2] = {0x60, 0xea};

        if(!bytes_equal(data, offset, arj_magic, sizeof(arj_magic))
            || !data.contains(offset, arj_struct_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto extra_header_size = reader.read<std::uint8_t>(offset + 4);
        const auto archiver_version = reader.read<std::uint8_t>(offset + 5);
        const auto min_version = reader.read<std::uint8_t>(offset + 6);
        const auto host_os_value = reader.read<std::uint8_t>(offset + 7);
        const auto internal_flags = reader.read<std::uint8_t>(offset + 8);
        const auto compression_value = reader.read<std::uint8_t>(offset + 9);
        const auto file_type_value = reader.read<std::uint8_t>(offset + 10);
        const auto datetime_file = reader.read<std::uint32_t>(offset + 12);
        const auto compressed_filesize = reader.read<std::uint32_t>(offset + 16);
        const auto original_filesize = reader.read<std::uint32_t>(offset + 20);
        if(!extra_header_size || !archiver_version || !min_version || !host_os_value
            || !internal_flags || !compression_value || !file_type_value || !datetime_file
            || !compressed_filesize || !original_filesize) {
            return std::nullopt;
        }

        if(*archiver_version < 1 || *archiver_version > 16
            || *min_version < 1 || *min_version > 16
            || *archiver_version < *min_version) {
            return std::nullopt;
        }

        std::string flags = (*internal_flags & 0x01U) != 0 ? "password" : "no password";
        if((*internal_flags & 0x04U) != 0) {
            flags += "|multi-volume";
        }
        if((*internal_flags & 0x10U) != 0) {
            flags += "|slash-switched";
        }
        if((*internal_flags & 0x20U) != 0) {
            flags += "|backup";
        }

        std::string host_os;
        switch(*host_os_value) {
            case 0: host_os = "MS-DOS"; break;
            case 1: host_os = "PRIMOS"; break;
            case 2: host_os = "UNIX"; break;
            case 3: host_os = "AMIGA"; break;
            case 4: host_os = "MAX-OS"; break;
            case 5: host_os = "OS/2"; break;
            case 6: host_os = "APPLE GS"; break;
            case 7: host_os = "ATARI ST"; break;
            case 8: host_os = "NeXT"; break;
            case 9: host_os = "VAX VMS"; break;
            default: return std::nullopt;
        }

        std::string compression_method;
        switch(*compression_value) {
            case 0: compression_method = "stored"; break;
            case 1: compression_method = "compressed most"; break;
            case 2: compression_method = "compressed"; break;
            case 3: compression_method = "compressed faster"; break;
            case 4: compression_method = "compressed fastest"; break;
            default: return std::nullopt;
        }

        std::string file_type;
        switch(*file_type_value) {
            case 0: file_type = "binary"; break;
            case 1: file_type = "7-bit text"; break;
            case 2: file_type = "comment header"; break;
            case 3: file_type = "directory"; break;
            case 4: file_type = "volume label"; break;
            default: return std::nullopt;
        }

        if((*compressed_filesize & 0x80000000U) != 0 || (*original_filesize & 0x80000000U) != 0) {
            return std::nullopt;
        }

        const std::uint64_t header_size = *extra_header_size;

        std::string original_name;
        const std::size_t name_start = offset + static_cast<std::size_t>(header_size) + 4;
        if(name_start < data.size()) {
            original_name = get_cstring(data, name_start, data.size() - name_start);
        }

        if(header_size > data.size() - offset) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = header_size;
        result.confidence = confidence_medium;

        result.extraction_declined = file_type != "comment header";
        result.description = description()
            + ", header size: " + std::to_string(header_size)
            + ", version " + std::to_string(*archiver_version)
            + ", minimum version to extract: " + std::to_string(*min_version)
            + ", flags: " + flags
            + ", compression method: " + compression_method
            + ", file type: " + file_type
            + ", original name: " + original_name
            + ", original file date: " + epoch_to_string(*datetime_file)
            + ", compressed file size: " + std::to_string(*compressed_filesize)
            + ", uncompressed file size: " + std::to_string(*original_filesize)
            + ", os: " + host_os;
        return result;
    }
};

template<>
struct format_traits<sevenzip_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "7zip"; }
    static std::string description() { return "7-zip archive data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}};
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition("bin"); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t header_size = 32;
        constexpr std::size_t header_crc_start = 12;
        constexpr std::size_t header_crc_size = 20;
        if(!data.contains(offset, header_size)) {
            return std::nullopt;
        }
        binary_reader<byte_order::little> reader(data);
        const auto header_crc = reader.read<std::uint32_t>(offset + 8);
        const auto next_offset = reader.read<std::uint64_t>(offset + 12);
        const auto next_size = reader.read<std::uint64_t>(offset + 20);
        const auto next_crc = reader.read<std::uint32_t>(offset + 28);
        if(!header_crc || !next_offset || !next_size || !next_crc
            || crc32(data, offset + header_crc_start, header_crc_size) != *header_crc
            || *next_offset > data.size() - offset - header_size
            || *next_size > data.size() - offset - header_size - *next_offset) {
            return std::nullopt;
        }
        const auto next_start = offset + header_size + static_cast<std::size_t>(*next_offset);
        if(crc32(data, next_start, static_cast<std::size_t>(*next_size)) != *next_crc) {
            return std::nullopt;
        }
        const auto total_size = header_size + *next_offset + *next_size;
        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_high;
        result.description = description() + ", version "
            + std::to_string(data[offset + 6]) + "." + std::to_string(data[offset + 7])
            + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<zip_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "zip"; }
    static std::string description() { return "ZIP archive"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'P', 'K', 0x03, 0x04}};
    }

    static binwalk::extractor extractor() { return sevenzip_extractor_definition("bin"); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto first = formats::zip_structures::parse_local_header(data, offset);
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

namespace formats {

std::vector<signature> b7_archives_signatures() {
    return make_signatures(type_list<
        deb_format,
        sevenzip_format,
        tarball_format,
        cpio_format,
        iso9660_format,
        zip_format,
        cab_format,
        srecord_format,
        srecord_generic_format,
        rar_format,
        matter_ota_format,
        arj_format
    >{});
}

}
}
