#include "b10b_executables.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct pchrom_format {};
struct uefi_pi_volume_format {};
struct uefi_capsule_format {};
struct pe_format {};
struct copyright_format {};
struct dmg_format {};
struct pjl_format {};
struct qcow_format {};

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

[[nodiscard]] bool matches_any(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& patterns
) noexcept {
    for(const auto& pattern : patterns) {
        if(bytes_equal(data, offset, pattern.data(), pattern.size())) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<std::size_t> first_match(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& patterns
) noexcept {
    for(std::size_t index = 0; index < patterns.size(); ++index) {
        if(bytes_equal(data, offset, patterns[index].data(), patterns[index].size())) {
            return index;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::string to_lower_hex(std::uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    if(value == 0) {
        return "0x0";
    }
    std::string text;
    while(value != 0) {
        text.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    std::string result = "0x";
    for(std::size_t index = text.size(); index > 0; --index) {
        result.push_back(text[index - 1]);
    }
    return result;
}

[[nodiscard]] std::string to_upper_hex(std::uint64_t value) {
    static const char digits[] = "0123456789ABCDEF";
    if(value == 0) {
        return "0x0";
    }
    std::string text;
    while(value != 0) {
        text.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    std::string result = "0x";
    for(std::size_t index = text.size(); index > 0; --index) {
        result.push_back(text[index - 1]);
    }
    return result;
}

[[nodiscard]] std::string truncate_characters(const std::string& text, std::size_t max_characters) {
    std::size_t characters = 0;
    std::size_t index = 0;
    while(index < text.size() && characters < max_characters) {
        const auto lead = static_cast<std::uint8_t>(text[index]);
        std::size_t width = 1;
        if((lead & 0xE0U) == 0xC0U) {
            width = 2;
        } else if((lead & 0xF0U) == 0xE0U) {
            width = 3;
        } else if((lead & 0xF8U) == 0xF0U) {
            width = 4;
        }
        if(index + width > text.size()) {
            break;
        }
        index += width;
        ++characters;
    }
    return text.substr(0, index);
}

[[nodiscard]] std::optional<std::size_t> find_bytes(
    byte_view data,
    std::size_t from,
    const char* needle,
    std::size_t needle_length
) noexcept {
    if(needle_length == 0 || !data.contains(from, needle_length)) {
        return std::nullopt;
    }
    const auto last = data.size() - needle_length;
    for(std::size_t start = from; start <= last; ++start) {
        std::size_t index = 0;
        while(index < needle_length
            && data[start + index] == static_cast<std::uint8_t>(needle[index])) {
            ++index;
        }
        if(index == needle_length) {
            return start;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool is_valid_utf8(byte_view data, std::size_t offset, std::size_t length) noexcept {
    if(!data.contains(offset, length)) {
        return false;
    }
    std::size_t index = 0;
    while(index < length) {
        const auto lead = data[offset + index];
        std::size_t width = 0;
        std::uint32_t code_point = 0;
        if(lead < 0x80U) {
            width = 1;
            code_point = lead;
        } else if((lead & 0xE0U) == 0xC0U) {
            width = 2;
            code_point = lead & 0x1FU;
        } else if((lead & 0xF0U) == 0xE0U) {
            width = 3;
            code_point = lead & 0x0FU;
        } else if((lead & 0xF8U) == 0xF0U) {
            width = 4;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if(index + width > length) {
            return false;
        }
        for(std::size_t extra = 1; extra < width; ++extra) {
            const auto continuation = data[offset + index + extra];
            if((continuation & 0xC0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }
        if(width == 2 && code_point < 0x80U) {
            return false;
        }
        if(width == 3 && code_point < 0x800U) {
            return false;
        }
        if(width == 4 && code_point < 0x10000U) {
            return false;
        }
        if(code_point > 0x10FFFFU || (code_point >= 0xD800U && code_point <= 0xDFFFU)) {
            return false;
        }
        index += width;
    }
    return true;
}

[[nodiscard]] extraction_result extract_uefi_unsupported(
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

[[nodiscard]] extractor uefi_extractor_definition() {
    return extractor{
        extractor_type::internal,
        "uefi_built_in",
        &extract_uefi_unsupported,
        std::string{},
        std::string{},
        {},
        {},
        true
    };
}

[[nodiscard]] extractor dmg_extractor_definition() {
    return extractor{
        extractor_type::external,
        std::string{},
        nullptr,
        "dmg2img",
        "dmg",
        {"-i", "%e", "-o", "mbr.img"},
        {0, 1},
        false
    };
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>> pe_magic_patterns() {

    return {
        {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
        {0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>> uefi_capsule_magic_patterns() {

    return {
        {0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40,
         0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0},
        {0x8B, 0xA6, 0x3C, 0x4A, 0x23, 0x77, 0xFB, 0x48,
         0x80, 0x3D, 0x57, 0x8C, 0xC1, 0xFE, 0xC4, 0x4D},
        {0xB9, 0x82, 0x91, 0x53, 0xB5, 0xAB, 0x91, 0x43,
         0xB6, 0x9A, 0xE3, 0xA9, 0x43, 0xF7, 0x2F, 0xCC}
    };
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>> copyright_magic_patterns() {
    return {
        {'c', 'o', 'p', 'y', 'r', 'i', 'g', 'h', 't'},
        {'C', 'o', 'p', 'y', 'r', 'i', 'g', 'h', 't'},
        {'C', 'O', 'P', 'Y', 'R', 'I', 'G', 'H', 'T'}
    };
}

struct machine_entry {
    std::uint16_t value;
    const char* name;
};

constexpr machine_entry pe_machine_types[] = {
    {0x0000, "Unknown"},
    {0x0184, "Alpha32"},
    {0x0284, "Alpha64"},
    {0x01D3, "Matsushita AM33"},
    {0x8664, "Intel x86-64"},
    {0x01C0, "ARM"},
    {0xAA64, "ARM-64"},
    {0x01C4, "ARM Thumb2"},
    {0x0EBC, "EFI"},
    {0x014C, "Intel x86"},
    {0x0200, "Intel Itanium"},
    {0x6232, "LoongArch 32-bit"},
    {0x6264, "LoongArch 64-bit"},
    {0x9041, "Mitsubishi M32R"},
    {0x0266, "MIPS16"},
    {0x0366, "MIPS with FPU"},
    {0x0466, "MIPS16 with FPU"},
    {0x01F0, "PowerPC"},
    {0x01F1, "PowerPC with FPU"},
    {0x5032, "RISC-V 32-bit"},
    {0x5064, "RISC-V 64-bit"},
    {0x5128, "RISC-V 128-bit"},
    {0x01A2, "Hitachi SH3"},
    {0x01A3, "Hitachi SH3 DSP"},
    {0x01A6, "Hitachi SH4"},
    {0x01A8, "Hitachi SH5"},
    {0x01C2, "Thumb"},
    {0x0169, "MIPS WCEv2"}
};

[[nodiscard]] const char* lookup_pe_machine(std::uint16_t value) noexcept {
    for(const auto& entry : pe_machine_types) {
        if(entry.value == value) {
            return entry.name;
        }
    }
    return nullptr;
}

}

template<>
struct format_traits<pchrom_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pchrom"; }
    static std::string description() { return "Intel serial flash for PCH ROM"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x5A, 0xA5, 0xF0, 0x0F}};
    }

    static binwalk::extractor extractor() { return uefi_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_back_offset = 16;
        constexpr std::size_t structure_offset = 16;
        constexpr std::size_t structure_size = 8;
        constexpr std::size_t region_count = 5;
        constexpr std::size_t region_entry_size = 4;
        constexpr std::uint8_t expected_fcba = 3;
        constexpr std::uint16_t expected_frba_nr = 4;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        if(offset < magic_back_offset) {
            return std::nullopt;
        }
        const auto image_offset = offset - magic_back_offset;

        if(!data.contains(image_offset + structure_offset, structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto fcba = reader.read<std::uint8_t>(image_offset + structure_offset + 4);
        const auto nc = reader.read<std::uint8_t>(image_offset + structure_offset + 5);
        const auto frba_nr = reader.read<std::uint16_t>(image_offset + structure_offset + 6);
        if(!fcba || !nc || !frba_nr) {
            return std::nullopt;
        }
        if(*fcba != expected_fcba || *frba_nr != expected_frba_nr) {
            return std::nullopt;
        }
        if(*nc != 0 && *nc != 1) {
            return std::nullopt;
        }

        const auto region_base_address =
            static_cast<std::size_t>(((static_cast<std::uint32_t>(*fcba) >> 16U) & 0xFFU) << 4U);

        std::uint64_t image_size = 0;
        for(std::size_t index = 0; index < region_count; ++index) {
            const auto entry_offset =
                image_offset + region_base_address + (index * region_entry_size);
            const auto value = reader.read<std::uint32_t>(entry_offset);
            if(!value) {

                return std::nullopt;
            }
            const auto region_start = static_cast<std::uint64_t>(*value & 0x1FFFU) << 12U;
            const auto region_limit =
                static_cast<std::uint64_t>(((*value & 0x1FFF0000U) >> 4U) | 0xFFFFU) + 1U;

            if(region_limit != region_start && region_limit > image_size) {
                image_size = region_limit;
            }
        }
        if(image_size == 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = image_offset;
        result.size = static_cast<std::uint64_t>(magic_back_offset) + image_size;

        result.confidence = confidence_low;
        result.description = "Intel serial flash for PCH ROM";
        return result;
    }
};

template<>
struct format_traits<uefi_pi_volume_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "uefi_pi_volume"; }
    static std::string description() { return "UEFI PI firmware volume"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'_', 'F', 'V', 'H'}};
    }
    static binwalk::extractor extractor() { return uefi_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_back_offset = 40;
        constexpr std::size_t volume_size_offset = 32;
        constexpr std::size_t header_size_offset = 48;
        constexpr std::size_t header_crc_offset = 50;
        constexpr std::size_t reserved_offset = 54;
        constexpr std::size_t revision_offset = 55;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        if(offset < magic_back_offset) {
            return std::nullopt;
        }
        const auto volume_offset = offset - magic_back_offset;

        binary_reader<byte_order::little> reader(data);
        const auto volume_size = reader.read<std::uint64_t>(volume_offset + volume_size_offset);
        const auto header_size = reader.read<std::uint16_t>(volume_offset + header_size_offset);
        const auto header_crc = reader.read<std::uint16_t>(volume_offset + header_crc_offset);
        const auto reserved = reader.read<std::uint8_t>(volume_offset + reserved_offset);
        const auto revision = reader.read<std::uint8_t>(volume_offset + revision_offset);
        if(!volume_size || !header_size || !header_crc || !reserved || !revision) {
            return std::nullopt;
        }

        if(static_cast<std::uint64_t>(*header_size) >= *volume_size) {
            return std::nullopt;
        }
        if(*reserved != 0) {
            return std::nullopt;
        }
        if(*revision != 1 && *revision != 2) {
            return std::nullopt;
        }

        if(*volume_size > static_cast<std::uint64_t>(data.size() - volume_offset)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = volume_offset;
        result.size = *volume_size;
        result.confidence = confidence_medium;
        result.description = "UEFI PI firmware volume, header CRC: " + to_upper_hex(*header_crc)
            + ", header size: " + std::to_string(*header_size)
            + " bytes, total size: " + std::to_string(*volume_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<uefi_capsule_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "uefi_capsule"; }
    static std::string description() { return "UEFI capsule image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return uefi_capsule_magic_patterns(); }
    static binwalk::extractor extractor() { return uefi_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t header_size_offset = 16;
        constexpr std::size_t total_size_offset = 24;
        constexpr std::size_t capsule_structure_size = 28;
        static const char* const guid_names[] = {"EFI", "EFI2", "UEFI"};

        const auto matched = first_match(data, offset, magic());
        if(!matched) {
            return std::nullopt;
        }
        if(!data.contains(offset, capsule_structure_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto header_size = reader.read<std::uint32_t>(offset + header_size_offset);
        const auto total_size = reader.read<std::uint32_t>(offset + total_size_offset);
        if(!header_size || !total_size) {
            return std::nullopt;
        }
        if(*header_size >= *total_size) {
            return std::nullopt;
        }

        const auto available = static_cast<std::uint64_t>(data.size() - offset);
        if(static_cast<std::uint64_t>(*total_size) > available) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *total_size;
        result.confidence = confidence_medium;
        result.description = "UEFI capsule image, header size: " + std::to_string(*header_size)
            + " bytes, total size: " + std::to_string(*total_size)
            + " bytes, capsule GUID: " + guid_names[*matched];
        return result;
    }
};

template<>
struct format_traits<pe_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pe"; }
    static std::string description() { return "Windows PE binary"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return pe_magic_patterns(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t dos_header_size = 64;
        constexpr std::size_t lfanew_offset = 60;
        constexpr std::size_t coff_header_size = 24;
        constexpr std::size_t coff_machine_offset = 4;
        constexpr std::uint32_t pe_signature = 0x00004550;

        constexpr std::size_t reserved_offsets[] = {
            28, 30, 32, 34, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58
        };

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        if(!data.contains(offset, dos_header_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        for(const auto reserved_offset : reserved_offsets) {
            const auto value = reader.read<std::uint16_t>(offset + reserved_offset);
            if(!value || *value != 0) {
                return std::nullopt;
            }
        }

        const auto lfanew = reader.read<std::uint32_t>(offset + lfanew_offset);
        if(!lfanew) {
            return std::nullopt;
        }

        const auto available = data.size() - offset;
        if(!is_range_safe(available, static_cast<std::size_t>(*lfanew), coff_header_size)) {
            return std::nullopt;
        }
        const auto coff_offset = offset + static_cast<std::size_t>(*lfanew);

        const auto signature_value = reader.read<std::uint32_t>(coff_offset);
        const auto machine = reader.read<std::uint16_t>(coff_offset + coff_machine_offset);
        if(!signature_value || !machine) {
            return std::nullopt;
        }
        if(*signature_value != pe_signature) {
            return std::nullopt;
        }
        const auto* machine_name = lookup_pe_machine(*machine);
        if(machine_name == nullptr) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_medium;
        result.description = std::string("Windows PE binary, machine type: ") + machine_name;
        return result;
    }
};

template<>
struct format_traits<copyright_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "copyright"; }
    static std::string description() { return "Copyright text"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return copyright_magic_patterns(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_size = 9;
        constexpr std::size_t description_characters = 100;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        if(offset > data.size()) {
            return std::nullopt;
        }

        const auto text = get_cstring(data, offset, data.size() - offset);
        if(text.size() <= magic_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = static_cast<std::uint64_t>(text.size());
        result.confidence = confidence_high;
        result.description =
            "Copyright text: \"" + truncate_characters(text, description_characters) + "\"";
        return result;
    }
};

template<>
struct format_traits<dmg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dmg"; }
    static std::string description() { return "Apple Disk iMaGe"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {{'k', 'o', 'l', 'y', 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00}};
    }
    static binwalk::extractor extractor() { return dmg_extractor_definition(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t footer_size = 512;
        constexpr std::size_t version_offset = 4;
        constexpr std::size_t header_size_offset = 8;
        constexpr std::size_t data_fork_length_offset = 32;
        constexpr std::size_t xml_length_offset = 224;
        constexpr char xml_signature[] = "<?xml";
        constexpr std::size_t xml_signature_length = 5;
        constexpr std::size_t minimum_xml_length = 1024;
        constexpr char blkx_key[] = "<key>blkx</key>";
        constexpr std::size_t blkx_key_length = 15;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        if(!data.contains(offset, footer_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto version = reader.read<std::uint32_t>(offset + version_offset);
        const auto header_size = reader.read<std::uint32_t>(offset + header_size_offset);
        const auto data_length = reader.read<std::uint64_t>(offset + data_fork_length_offset);
        const auto xml_length = reader.read<std::uint64_t>(offset + xml_length_offset);
        if(!version || !header_size || !data_length || !xml_length) {
            return std::nullopt;
        }

        if(*header_size != footer_size) {
            return std::nullopt;
        }

        if(*data_length > static_cast<std::uint64_t>(offset)) {
            return std::nullopt;
        }
        if(*xml_length > static_cast<std::uint64_t>(offset) - *data_length) {
            return std::nullopt;
        }

        std::optional<std::size_t> xml_offset;
        std::size_t search_from = 0;
        while(auto candidate =
                  find_bytes(data, search_from, xml_signature, xml_signature_length)) {
            if(data.contains(*candidate, minimum_xml_length)
                && is_valid_utf8(data, *candidate, minimum_xml_length)) {

                const auto window = data.subview(*candidate, minimum_xml_length);
                if(find_bytes(window, 0, blkx_key, blkx_key_length)) {
                    xml_offset = *candidate;
                    break;
                }
            }
            search_from = *candidate + 1;
        }
        if(!xml_offset) {
            return std::nullopt;
        }
        if(static_cast<std::uint64_t>(*xml_offset) < *data_length) {
            return std::nullopt;
        }

        const auto image_offset = static_cast<std::uint64_t>(*xml_offset) - *data_length;
        const auto footer_end = static_cast<std::uint64_t>(offset) + footer_size;

        if(image_offset >= footer_end) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = image_offset;
        result.size = footer_end - image_offset;
        result.confidence = static_cast<std::uint8_t>(confidence_high + 1);
        result.description = "Apple Disk iMaGe, version: " + std::to_string(*version)
            + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<pjl_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pjl"; }
    static std::string description() { return "HP Printer Job Language data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x1B, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t commands_offset = 9;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }
        const auto text_offset = offset + commands_offset;
        if(text_offset > data.size()) {
            return std::nullopt;
        }
        const auto text = get_cstring(data, text_offset, data.size() - text_offset);
        if(text.empty()) {
            return std::nullopt;
        }

        std::string display;
        display.reserve(text.size());
        for(const auto character : text) {
            if(character == '\r') {
                display.push_back(' ');
            } else if(character != '\n') {
                display.push_back(character);
            }
        }

        signature_result result;
        result.offset = offset;
        result.size = static_cast<std::uint64_t>(text.size());
        result.confidence = confidence_low;
        result.description = "HP Printer Job Language data: \"" + display + "\"";
        return result;
    }
};

template<>
struct format_traits<qcow_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "qcow"; }
    static std::string description() { return "QEMU QCOW Image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'Q', 'F', 'I', 0xFB}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t version_offset = 4;
        constexpr std::uint32_t minimum_cluster_bits = 9;
        constexpr std::uint32_t maximum_cluster_bits = 21;

        if(!matches_any(data, offset, magic())) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto version = reader.read<std::uint32_t>(offset + version_offset);
        if(!version) {
            return std::nullopt;
        }

        std::optional<std::uint32_t> cluster_block_bits;
        std::optional<std::uint64_t> storage_media_size;
        std::optional<std::uint32_t> encryption_method;
        std::optional<std::uint64_t> level1_table_offset;
        std::optional<std::uint64_t> refcount_table_offset;
        std::optional<std::uint64_t> snapshot_offset;

        if(*version == 1) {

            if(!data.contains(offset + 8, 40)) {
                return std::nullopt;
            }
            const auto bits = reader.read<std::uint8_t>(offset + 32);
            if(!bits) {
                return std::nullopt;
            }
            cluster_block_bits = static_cast<std::uint32_t>(*bits);
            storage_media_size = reader.read<std::uint64_t>(offset + 24);
            encryption_method = reader.read<std::uint32_t>(offset + 36);
            level1_table_offset = reader.read<std::uint64_t>(offset + 40);
        } else if(*version == 2 || *version == 3) {

            const auto structure_length = (*version == 2) ? std::size_t{64} : std::size_t{96};
            if(!data.contains(offset + 8, structure_length)) {
                return std::nullopt;
            }
            cluster_block_bits = reader.read<std::uint32_t>(offset + 20);
            storage_media_size = reader.read<std::uint64_t>(offset + 24);
            encryption_method = reader.read<std::uint32_t>(offset + 32);
            level1_table_offset = reader.read<std::uint64_t>(offset + 40);
            refcount_table_offset = reader.read<std::uint64_t>(offset + 48);
            snapshot_offset = reader.read<std::uint64_t>(offset + 64);
        } else {
            return std::nullopt;
        }

        if(!cluster_block_bits || !storage_media_size || !encryption_method
            || !level1_table_offset) {
            return std::nullopt;
        }

        const char* encryption_name = nullptr;
        switch(*encryption_method) {
        case 0:
            encryption_name = "None";
            break;
        case 1:
            encryption_name = "AES128-CBC";
            break;
        case 2:
            encryption_name = "LUKS";
            break;
        default:
            return std::nullopt;
        }

        if(*cluster_block_bits < minimum_cluster_bits
            || *cluster_block_bits > maximum_cluster_bits) {
            return std::nullopt;
        }
        const auto cluster_size = std::uint64_t{1} << *cluster_block_bits;

        if((*level1_table_offset % cluster_size) != 0) {
            return std::nullopt;
        }
        if(refcount_table_offset && (*refcount_table_offset % cluster_size) != 0) {
            return std::nullopt;
        }
        if(snapshot_offset && (*snapshot_offset % cluster_size) != 0) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_medium;
        result.description = "QEMU QCOW Image, version: " + std::to_string(*version)
            + ", storage media size: " + to_lower_hex(*storage_media_size)
            + " bytes, cluster block size: " + to_lower_hex(cluster_size)
            + " bytes, encryption method: " + encryption_name;
        return result;
    }
};

namespace formats {

std::vector<signature> b10b_executables_signatures() {
    return make_signatures(type_list<
        pchrom_format,
        uefi_pi_volume_format,
        uefi_capsule_format,
        pe_format,
        copyright_format,
        dmg_format,
        pjl_format,
        qcow_format
    >{});
}

}
}
