#include "b2_media.hpp"

#include "../builtin_extractors.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
namespace binwalk {
namespace {

struct bmp_format {};
struct jpeg_format {};
struct pdf_format {};
struct png_format {};
struct riff_format {};
struct gif_format {};
struct svg_format {};
struct dxbc_format {};
struct pem_certificate_format {};
struct pem_public_key_format {};
struct pem_private_key_format {};
struct pcapng_format {};

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

[[nodiscard]] bool literal_at(byte_view data, std::size_t offset, std::string_view text) noexcept {
    if(!data.contains(offset, text.size())) {
        return false;
    }
    for(std::size_t index = 0; index < text.size(); ++index) {
        if(data[offset + index] != static_cast<std::uint8_t>(text[index])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<std::size_t> find_literal(
    byte_view data,
    std::size_t from,
    std::string_view text
) noexcept {
    if(text.empty() || data.size() < text.size()) {
        return std::nullopt;
    }
    for(std::size_t at = from; at <= data.size() - text.size(); ++at) {
        if(literal_at(data, at, text)) {
            return at;
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
        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        if(lead < 0x80U) {
            ++index;
            continue;
        }
        if((lead & 0xE0U) == 0xC0U) {
            continuation_count = 1;
            code_point = lead & 0x1FU;
        } else if((lead & 0xF0U) == 0xE0U) {
            continuation_count = 2;
            code_point = lead & 0x0FU;
        } else if((lead & 0xF8U) == 0xF0U) {
            continuation_count = 3;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if(length - index <= continuation_count) {
            return false;
        }
        for(std::size_t step = 1; step <= continuation_count; ++step) {
            const auto continuation = data[offset + index + step];
            if((continuation & 0xC0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }

        if(continuation_count == 1 && code_point < 0x80U) {
            return false;
        }
        if(continuation_count == 2 && code_point < 0x800U) {
            return false;
        }
        if(continuation_count == 3 && code_point < 0x10000U) {
            return false;
        }
        if(code_point > 0x10FFFFU || (code_point >= 0xD800U && code_point <= 0xDFFFU)) {
            return false;
        }
        index += continuation_count + 1;
    }
    return true;
}

[[nodiscard]] std::string trimmed_ascii(std::string text) {
    const auto is_space = [](char value) {
        return std::isspace(static_cast<unsigned char>(value)) != 0;
    };
    while(!text.empty() && is_space(text.back())) {
        text.pop_back();
    }
    while(!text.empty() && is_space(text.front())) {
        text.erase(text.begin());
    }
    return text;
}

[[nodiscard]] extraction_result carve_range(
    byte_view data,
    std::size_t offset,
    std::size_t size,
    const std::string* output_directory,
    const char* name
) {
    extraction_result result;
    if(size == 0 || !data.contains(offset, size)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    result.size = size;
    result.success = true;
    if(output_directory != nullptr) {
        const chroot writer(*output_directory);
        result.success = writer.carve_file(name, data, offset, size);
        if(!result.success) {
            result.failure = extraction_failure::write_error;
        }
    }
    return result;
}

constexpr std::size_t gif_header_structure_size = 13;

[[nodiscard]] std::size_t gif_color_table_size(std::uint8_t flags) noexcept {
    constexpr std::uint8_t has_color_table = 0x80;
    if((flags & has_color_table) == 0) {
        return 0;
    }
    const auto encoded = static_cast<unsigned>(flags & 0x07U) + 1U;
    return static_cast<std::size_t>(3U) << encoded;
}

[[nodiscard]] std::optional<std::size_t> gif_sub_blocks_size(byte_view data, std::size_t base) {
    if(base > data.size()) {
        return std::nullopt;
    }
    const auto available = data.size() - base;
    std::size_t next = 0;
    std::optional<std::size_t> previous;
    while(is_offset_safe(available, next, previous)) {
        const auto block_size = data[base + next];
        if(block_size == 0) {
            return next + 1;
        }
        previous = next;
        next += static_cast<std::size_t>(block_size) + 1;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::size_t> gif_image_descriptor_size(byte_view data, std::size_t at) {

    constexpr std::size_t descriptor_structure_size = 10;
    constexpr std::size_t lzw_code_size = 1;
    if(!data.contains(at, descriptor_structure_size)) {
        return std::nullopt;
    }
    const auto flags = data[at + 9];
    const auto prefix = descriptor_structure_size + gif_color_table_size(flags) + lzw_code_size;
    const auto sub_blocks = gif_sub_blocks_size(data, at + prefix);
    if(!sub_blocks) {
        return std::nullopt;
    }
    return prefix + *sub_blocks;
}

[[nodiscard]] std::optional<std::size_t> gif_extension_size(byte_view data, std::size_t at) {
    constexpr std::size_t extension_structure_size = 3;
    constexpr std::size_t extension_header_size = 2;
    constexpr std::uint8_t plain_text_extension = 0x01;
    constexpr std::uint8_t application_extension = 0xFF;
    if(!data.contains(at, extension_structure_size)) {
        return std::nullopt;
    }
    const auto extension_type = data[at + 1];
    std::size_t sub_blocks_offset = extension_header_size;

    if(extension_type == application_extension || extension_type == plain_text_extension) {
        sub_blocks_offset += static_cast<std::size_t>(data[at + 2]) + 1;
    }
    const auto sub_blocks = gif_sub_blocks_size(data, at + sub_blocks_offset);
    if(!sub_blocks) {
        return std::nullopt;
    }
    return sub_blocks_offset + *sub_blocks;
}

[[nodiscard]] std::optional<std::size_t> gif_data_size(byte_view data, std::size_t base) {
    constexpr std::uint8_t extension_block = 0x21;
    constexpr std::uint8_t terminator_block = 0x3B;
    constexpr std::uint8_t image_descriptor_block = 0x2C;
    if(base > data.size()) {
        return std::nullopt;
    }
    const auto available = data.size() - base;
    std::size_t next = 0;
    std::optional<std::size_t> previous;
    while(is_offset_safe(available, next, previous)) {
        const auto block_type = data[base + next];
        std::optional<std::size_t> block_size;
        if(block_type == image_descriptor_block) {
            block_size = gif_image_descriptor_size(data, base + next);
        } else if(block_type == extension_block) {
            block_size = gif_extension_size(data, base + next);
        } else if(block_type == terminator_block) {
            return next + 1;
        } else {
            break;
        }
        if(!block_size) {
            break;
        }
        previous = next;
        next += *block_size;
    }
    return std::nullopt;
}

struct gif_info {
    std::size_t total_size = 0;
    std::uint16_t image_width = 0;
    std::uint16_t image_height = 0;
};

[[nodiscard]] std::optional<gif_info> inspect_gif(byte_view data, std::size_t offset) {
    static const std::vector<std::uint8_t> magic87{'G', 'I', 'F', '8', '7', 'a'};
    static const std::vector<std::uint8_t> magic89{'G', 'I', 'F', '8', '9', 'a'};

    if(!bytes_equal(data, offset, magic87) && !bytes_equal(data, offset, magic89)) {
        return std::nullopt;
    }
    if(!data.contains(offset, gif_header_structure_size)) {
        return std::nullopt;
    }
    binary_reader<byte_order::little> reader(data);
    const auto image_width = reader.read<std::uint16_t>(offset + 6);
    const auto image_height = reader.read<std::uint16_t>(offset + 8);
    if(!image_width || !image_height) {
        return std::nullopt;
    }
    const auto header_size = gif_header_structure_size + gif_color_table_size(data[offset + 10]);
    const auto payload_size = gif_data_size(data, offset + header_size);
    if(!payload_size) {
        return std::nullopt;
    }
    return gif_info{header_size + *payload_size, *image_width, *image_height};
}

extraction_result extract_gif(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto info = inspect_gif(data, offset);
    if(!info) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return carve_range(data, offset, info->total_size, output_directory, "image.gif");
}

[[nodiscard]] std::optional<std::size_t> inspect_svg(byte_view data, std::size_t offset) {
    constexpr std::string_view open_tag = "<svg ";
    constexpr std::string_view close_tag = "</svg>";
    constexpr std::string_view head_magic = "xmlns=\"http://www.w3.org/2000/svg\"";
    constexpr std::uint8_t tag_end = 0x3E;

    if(offset >= data.size()) {
        return std::nullopt;
    }

    std::size_t head_tag_count = 0;
    std::size_t unclosed_tags = 0;

    for(std::size_t at = offset; at < data.size(); ++at) {
        const bool opens = literal_at(data, at, open_tag);
        const bool closes = literal_at(data, at, close_tag);
        if(!opens && !closes) {
            continue;
        }

        std::optional<std::size_t> tag_length;
        for(std::size_t cursor = at; cursor < data.size(); ++cursor) {
            if(data[cursor] != tag_end) {
                continue;
            }
            const auto candidate_length = cursor - at + 1;
            if(is_valid_utf8(data, at, candidate_length)) {
                tag_length = candidate_length;
                break;
            }
        }
        if(!tag_length) {
            break;
        }

        bool is_head = false;
        if(*tag_length >= head_magic.size()) {
            for(std::size_t probe = at; probe + head_magic.size() <= at + *tag_length; ++probe) {
                if(literal_at(data, probe, head_magic)) {
                    is_head = true;
                    break;
                }
            }
        }

        if(is_head) {
            ++head_tag_count;
        }
        if(opens) {
            ++unclosed_tags;
        }
        if(closes) {

            if(unclosed_tags == 0) {
                return std::nullopt;
            }
            --unclosed_tags;
        }

        if(head_tag_count > 1) {
            break;
        }
        if(head_tag_count == 1 && unclosed_tags == 0) {
            return (at - offset) + close_tag.size();
        }
    }
    return std::nullopt;
}

extraction_result extract_svg(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto total_size = inspect_svg(data, offset);
    if(!total_size) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return carve_range(data, offset, *total_size, output_directory, "image.svg");
}

[[nodiscard]] const std::array<std::string_view, 7>& pem_end_markers() noexcept {
    static const std::array<std::string_view, 7> markers{
        "-----END PUBLIC KEY-----",
        "-----END CERTIFICATE-----",
        "-----END PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        "-----END DSA PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----"
    };
    return markers;
}

[[nodiscard]] std::optional<std::size_t> inspect_pem(byte_view data, std::size_t offset) {
    if(offset >= data.size()) {
        return std::nullopt;
    }
    std::optional<std::size_t> best_start;
    std::size_t best_length = 0;
    for(const auto marker : pem_end_markers()) {
        const auto found = find_literal(data, offset, marker);
        if(!found) {
            continue;
        }
        if(!best_start || *found < *best_start) {
            best_start = *found;
            best_length = marker.size();
        }
    }
    if(!best_start) {
        return std::nullopt;
    }

    auto pem_size = (*best_start - offset) + best_length;

    while(offset + pem_size < data.size()) {
        const auto value = data[offset + pem_size];
        if(value != 0x0D && value != 0x0A) {
            break;
        }
        ++pem_size;
    }
    return pem_size;
}

[[nodiscard]] bool is_valid_base64(const std::string& text) noexcept {
    if(text.empty() || (text.size() % 4) != 0) {
        return false;
    }
    std::size_t padding = 0;
    for(std::size_t index = 0; index < text.size(); ++index) {
        const auto value = text[index];
        if(value == '=') {
            ++padding;
            if(padding > 2 || index < text.size() - 2) {
                return false;
            }
            continue;
        }
        if(padding != 0) {
            return false;
        }
        const bool valid = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
            || (value >= '0' && value <= '9') || value == '+' || value == '/';
        if(!valid) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool pem_body_decodes(byte_view data, std::size_t offset, std::size_t size) {
    if(!data.contains(offset, size) || !is_valid_utf8(data, offset, size)) {
        return false;
    }
    std::string base64_text;
    std::size_t delimiter_count = 0;
    std::size_t line_start = 0;
    while(line_start <= size) {
        std::size_t line_end = line_start;
        while(line_end < size && data[offset + line_end] != '\n') {
            ++line_end;
        }
        auto trimmed_end = line_end;
        if(trimmed_end > line_start && data[offset + trimmed_end - 1] == '\r') {
            --trimmed_end;
        }
        const auto line_length = trimmed_end - line_start;
        if(line_length >= 2 && data[offset + line_start] == '-'
            && data[offset + line_start + 1] == '-') {
            ++delimiter_count;
            if(delimiter_count == 2) {
                break;
            }
        } else {
            for(std::size_t index = 0; index < line_length; ++index) {
                base64_text.push_back(static_cast<char>(data[offset + line_start + index]));
            }
        }
        if(line_end >= size) {
            break;
        }
        line_start = line_end + 1;
    }
    return !base64_text.empty() && is_valid_base64(base64_text);
}

extraction_result extract_pem_named(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory,
    const char* name
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto pem_size = inspect_pem(data, offset);
    if(!pem_size) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return carve_range(data, offset, *pem_size, output_directory, name);
}

extraction_result extract_pem_certificate(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    return extract_pem_named(data, signature, output_directory, "pem.crt");
}

extraction_result extract_pem_key(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    return extract_pem_named(data, signature, output_directory, "pem.key");
}

[[nodiscard]] std::optional<signature_result> parse_pem(byte_view data, std::size_t offset) {
    constexpr std::size_t minimum_pem_length = 26;
    static const std::array<std::string_view, 4> public_prefixes{
        "-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-", "-----BEGIN DSA PUBLIC KEY-",
        "-----BEGIN ECDSA PUBLIC KE"
    };
    static const std::array<std::string_view, 8> private_prefixes{
        "-----BEGIN PRIVATE KEY----", "-----BEGIN EC PRIVATE KEY-", "-----BEGIN RSA PRIVATE KEY",
        "-----BEGIN DSA PRIVATE KEY", "-----BEGIN OPENSSH PRIVATE", "-----BEGIN ANY PRIVATE KEY",
        "-----BEGIN ENCRYPTED PRIVA", "-----BEGIN TSS2 PRIVATE KE"
    };
    constexpr std::string_view certificate_prefix = "-----BEGIN CERTIFICATE----";

    if(!data.contains(offset, minimum_pem_length)) {
        return std::nullopt;
    }

    std::string description;
    for(const auto prefix : public_prefixes) {
        if(literal_at(data, offset, prefix)) {
            description = "PEM public key";
            break;
        }
    }
    if(description.empty()) {
        for(const auto prefix : private_prefixes) {
            if(literal_at(data, offset, prefix)) {
                description = "PEM private key";
                break;
            }
        }
    }
    if(description.empty() && literal_at(data, offset, certificate_prefix)) {
        description = "PEM certificate";
    }
    if(description.empty()) {
        return std::nullopt;
    }

    const auto pem_size = inspect_pem(data, offset);
    if(!pem_size || !pem_body_decodes(data, offset, *pem_size)) {
        return std::nullopt;
    }

    signature_result result;
    result.offset = offset;
    result.size = *pem_size;
    result.confidence = confidence_high;
    result.description = description;
    result.extraction_declined = offset == 0 && *pem_size == data.size();
    return result;
}

struct pcapng_block {
    std::uint32_t block_type = 0;
    std::uint32_t block_size = 0;
};

[[nodiscard]] std::optional<pcapng_block> parse_pcapng_block(
    byte_view data,
    std::size_t at,
    bool big_endian
) {
    constexpr std::uint32_t reserved_mask = 0x80000000U;
    constexpr std::size_t footer_size = 4;
    constexpr std::size_t header_size = 8;

    if(!data.contains(at, header_size)) {
        return std::nullopt;
    }
    binary_reader<byte_order::little> little(data);
    binary_reader<byte_order::big> big(data);
    const auto block_type = big_endian ? big.read<std::uint32_t>(at) : little.read<std::uint32_t>(at);
    const auto block_size =
        big_endian ? big.read<std::uint32_t>(at + 4) : little.read<std::uint32_t>(at + 4);
    if(!block_type || !block_size) {
        return std::nullopt;
    }
    if((*block_type & reserved_mask) != 0) {
        return std::nullopt;
    }

    if(*block_size < footer_size) {
        return std::nullopt;
    }
    const auto footer_at = at + static_cast<std::size_t>(*block_size) - footer_size;
    if(!data.contains(footer_at, footer_size)) {
        return std::nullopt;
    }
    const auto footer = big_endian ? big.read<std::uint32_t>(footer_at)
                                   : little.read<std::uint32_t>(footer_at);
    if(!footer || *footer != *block_size) {
        return std::nullopt;
    }
    return pcapng_block{*block_type, *block_size};
}

struct pcapng_section {
    std::uint32_t block_size = 0;
    bool big_endian = false;
};

[[nodiscard]] std::optional<pcapng_section> parse_pcapng_section(byte_view data, std::size_t at) {
    constexpr std::size_t section_structure_size = 20;
    constexpr std::uint32_t section_block_type = 0x0A0D0D0AU;
    constexpr std::uint32_t endian_magic_little = 0x1A2B3C4DU;
    constexpr std::uint32_t endian_magic_big = 0x4D3C2B1AU;

    if(!data.contains(at, section_structure_size)) {
        return std::nullopt;
    }
    binary_reader<byte_order::little> little(data);
    const auto endian_magic = little.read<std::uint32_t>(at + 8);
    if(!endian_magic) {
        return std::nullopt;
    }
    bool big_endian = false;
    if(*endian_magic == endian_magic_little) {
        big_endian = false;
    } else if(*endian_magic == endian_magic_big) {
        big_endian = true;
    } else {
        return std::nullopt;
    }
    const auto block = parse_pcapng_block(data, at, big_endian);
    if(!block || block->block_type != section_block_type) {
        return std::nullopt;
    }
    return pcapng_section{block->block_size, big_endian};
}

[[nodiscard]] std::optional<std::size_t> inspect_pcapng(byte_view data, std::size_t offset) {

    constexpr std::size_t minimum_block_count = 2;

    const auto section = parse_pcapng_section(data, offset);
    if(!section) {
        return std::nullopt;
    }

    std::size_t block_count = 1;

    std::size_t next = offset + static_cast<std::size_t>(section->block_size);
    std::optional<std::size_t> previous;
    while(is_offset_safe(data.size(), next, previous)) {
        const auto block = parse_pcapng_block(data, next, section->big_endian);
        if(!block) {
            break;
        }
        ++block_count;
        previous = next;
        next += static_cast<std::size_t>(block->block_size);
    }
    if(block_count < minimum_block_count || next < offset) {
        return std::nullopt;
    }
    return next - offset;
}

extraction_result extract_pcapng(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto total_size = inspect_pcapng(data, offset);
    if(!total_size) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return carve_range(data, offset, *total_size, output_directory, "capture.pcapng");
}

struct dxbc_info {
    std::uint32_t total_size = 0;
    bool shader_model_4 = false;
    bool shader_model_5 = false;
};

[[nodiscard]] std::optional<dxbc_info> inspect_dxbc(byte_view data, std::size_t offset) {

    constexpr std::size_t header_structure_size = 32;

    constexpr std::uint32_t maximum_chunk_count = 32;
    static const std::vector<std::uint8_t> dxbc_magic{'D', 'X', 'B', 'C'};

    if(!bytes_equal(data, offset, dxbc_magic)) {
        return std::nullopt;
    }
    if(!data.contains(offset, header_structure_size)) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto one = reader.read<std::uint32_t>(offset + 20);
    const auto total_size = reader.read<std::uint32_t>(offset + 24);
    const auto chunk_count = reader.read<std::uint32_t>(offset + 28);
    if(!one || !total_size || !chunk_count) {
        return std::nullopt;
    }
    if(*one != 1 || *chunk_count > maximum_chunk_count) {
        return std::nullopt;
    }

    dxbc_info info;
    info.total_size = *total_size;
    for(std::uint32_t index = 0; index < *chunk_count; ++index) {
        const auto table_at = offset + header_structure_size + (static_cast<std::size_t>(index) * 4);
        const auto chunk_offset = reader.read<std::uint32_t>(table_at);
        if(!chunk_offset) {
            return std::nullopt;
        }
        const auto chunk_at = offset + static_cast<std::size_t>(*chunk_offset);
        if(!data.contains(chunk_at, 4)) {
            return std::nullopt;
        }
        if(literal_at(data, chunk_at, "SHDR")) {
            info.shader_model_4 = true;
        } else if(literal_at(data, chunk_at, "SHEX")) {
            info.shader_model_5 = true;
        }
    }
    return info;
}

extraction_result extract_dxbc(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto info = inspect_dxbc(data, offset);
    if(!info) {
        extraction_result result;
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    return carve_range(data, offset, info->total_size, output_directory, "shader.dxbc");
}

}

template<>
struct format_traits<bmp_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "bmp"; }
    static std::string description() { return "BMP image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'B', 'M'}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "bmp_built_in", detail::extract_bmp, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t file_header_size = 14;
        constexpr std::size_t minimum_header_size = file_header_size + 4;
        if(!data.contains(offset, minimum_header_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto file_size = reader.read<std::uint32_t>(offset + 2);
        const auto pixel_offset = reader.read<std::uint32_t>(offset + 10);
        const auto dib_size = reader.read<std::uint32_t>(offset + 14);
        static constexpr std::array<std::uint32_t, 4> valid_dib_sizes{12, 40, 108, 124};
        const auto available = data.size() - offset;
        if(!file_size || !pixel_offset || !dib_size
            || *file_size == 0
            || *pixel_offset == 0
            || *file_size > available
            || *pixel_offset > available
            || std::find(valid_dib_sizes.begin(), valid_dib_sizes.end(), *dib_size)
                == valid_dib_sizes.end()
            || *pixel_offset < file_header_size + *dib_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *file_size;
        result.confidence = confidence_medium;
        result.description = "BMP image, total size: " + std::to_string(*file_size);
        return result;
    }
};

template<>
struct format_traits<jpeg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jpeg"; }
    static std::string description() { return "JPEG image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
            {0xff, 0xd8, 0xff, 0xe1},
            {0xff, 0xd8, 0xff, 0xdb}
        };
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal,
            "jpeg_built_in",
            detail::extract_jpeg,
            {}, {}, {}, {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static constexpr std::array<std::uint8_t, 12> no_length_markers{
            0x00, 0x01, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9
        };
        static constexpr std::array<std::uint8_t, 9> scan_skip_markers{
            0x00, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
        };
        constexpr std::uint8_t marker_prefix = 0xff;
        constexpr std::uint8_t start_of_scan = 0xda;
        constexpr std::uint8_t end_of_image = 0xd9;

        std::size_t cursor = offset;
        while(data.contains(cursor, 2)) {
            if(data[cursor] != marker_prefix) {
                return std::nullopt;
            }
            const auto marker = data[cursor + 1];
            cursor += 2;

            if(std::find(no_length_markers.begin(), no_length_markers.end(), marker)
                == no_length_markers.end()) {
                binary_reader<byte_order::big> reader(data);
                const auto marker_size = reader.read<std::uint16_t>(cursor);
                if(!marker_size || *marker_size < 2 || !data.contains(cursor, *marker_size)) {
                    return std::nullopt;
                }
                cursor += *marker_size;
            }

            if(marker == start_of_scan) {
                bool found_next_marker = false;
                while(data.contains(cursor, 2)) {
                    if(data[cursor] == marker_prefix
                        && std::find(
                            scan_skip_markers.begin(), scan_skip_markers.end(), data[cursor + 1]
                        ) == scan_skip_markers.end()) {
                        found_next_marker = true;
                        break;
                    }
                    ++cursor;
                }
                if(!found_next_marker) {
                    return std::nullopt;
                }
            }

            if(marker == end_of_image) {
                signature_result result;
                result.offset = offset;
                result.size = cursor - offset;
                result.confidence = confidence_medium;
                result.description = "JPEG image, total size: " + std::to_string(result.size)
                    + " bytes";
                result.extraction_declined = offset == 0 && result.size == data.size();
                return result;
            }
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<pdf_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pdf"; }
    static std::string description() { return "PDF document"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'%', 'P', 'D', 'F', '-', '1', '.'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t minimum_size = 16;
        if(!data.contains(offset, minimum_size)) {
            return std::nullopt;
        }
        const auto minor = data[offset + 7];
        if(minor < '0' || minor > '9') {
            return std::nullopt;
        }

        for(std::size_t cursor = offset + 8; cursor < offset + minimum_size; ++cursor) {
            const auto value = data[cursor];
            if(value == '\n' || value == '\r') {
                continue;
            }
            if(value == '%') {
                signature_result result;
                result.offset = offset;
                result.description = "PDF document, version 1.";
                result.description.push_back(static_cast<char>(minor));
                return result;
            }
            break;
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<png_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "png"; }
    static std::string description() { return "PNG image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 'I', 'H', 'D', 'R'}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "png_built_in", detail::extract_png, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static const std::vector<std::uint8_t> png_prefix{
            0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
        };
        if(!bytes_equal(data, offset, png_prefix)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        std::size_t cursor = offset + png_prefix.size();
        bool first_chunk = true;

        while(data.contains(cursor, 12)) {
            const auto payload_size = reader.read<std::uint32_t>(cursor);
            const auto chunk_type = reader.read<std::uint32_t>(cursor + 4);
            if(!payload_size || !chunk_type) {
                return std::nullopt;
            }

            constexpr std::uint32_t ihdr = 0x49484452U;
            constexpr std::uint32_t iend = 0x49454e44U;
            if(first_chunk && (*chunk_type != ihdr || *payload_size != 13)) {
                return std::nullopt;
            }
            first_chunk = false;

            constexpr std::size_t chunk_overhead = 12;
            if(*payload_size > std::numeric_limits<std::size_t>::max() - chunk_overhead) {
                return std::nullopt;
            }
            const auto chunk_size = static_cast<std::size_t>(*payload_size) + chunk_overhead;

            if(!data.contains(cursor, chunk_size)) {
                return std::nullopt;
            }
            cursor += chunk_size;

            if(*chunk_type == iend) {

                signature_result result;
                result.offset = offset;
                result.size = cursor - offset;
                result.confidence = confidence_high;
                result.description = "PNG image, total size: " + std::to_string(result.size) + " bytes";
                result.extraction_declined = offset == 0;
                return result;
            }
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<riff_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "riff"; }
    static std::string description() { return "RIFF image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'R', 'I', 'F', 'F'}}; }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal,
            "riff_built_in",
            detail::extract_riff,
            {}, {}, {}, {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        if(!data.contains(offset, 12)) {
            return std::nullopt;
        }
        binary_reader<byte_order::little> reader(data);
        const auto payload_size = reader.read<std::uint32_t>(offset + 4);
        if(!payload_size) {
            return std::nullopt;
        }
        const auto total_size = static_cast<std::uint64_t>(*payload_size) + 8;

        if(total_size > data.size() - offset) {
            return std::nullopt;
        }

        if(!is_valid_utf8(data, offset + 8, 4)) {
            return std::nullopt;
        }
        std::string chunk_type;
        for(std::size_t index = 0; index < 4; ++index) {
            chunk_type.push_back(static_cast<char>(data[offset + 8 + index]));
        }
        chunk_type = trimmed_ascii(std::move(chunk_type));

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_medium;
        result.description = "RIFF image, encoding type: " + chunk_type
            + ", total size: " + std::to_string(result.size) + " bytes";
        result.extraction_declined = offset == 0 && result.size == data.size();
        return result;
    }
};

template<>
struct format_traits<gif_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "gif"; }
    static std::string description() { return "GIF image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'G', 'I', 'F', '8', '7', 'a'}, {'G', 'I', 'F', '8', '9', 'a'}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "gif_built_in", extract_gif, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto info = inspect_gif(data, offset);
        if(!info) {
            return std::nullopt;
        }
        signature_result result;
        result.offset = offset;
        result.size = info->total_size;
        result.confidence = confidence_high;
        result.description = "GIF image, " + std::to_string(info->image_width) + "x"
            + std::to_string(info->image_height) + " pixels, total size: "
            + std::to_string(info->total_size) + " bytes";

        result.extraction_declined = offset == 0;
        return result;
    }
};

template<>
struct format_traits<svg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "svg"; }
    static std::string description() { return "SVG image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'<', 's', 'v', 'g', ' '}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "svg_built_in", extract_svg, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto total_size = inspect_svg(data, offset);
        if(!total_size) {
            return std::nullopt;
        }
        signature_result result;
        result.offset = offset;
        result.size = *total_size;
        result.confidence = confidence_medium;
        result.description = "SVG image, total size: " + std::to_string(*total_size) + " bytes";
        result.extraction_declined = offset == 0;
        return result;
    }
};

template<>
struct format_traits<dxbc_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dxbc"; }
    static std::string description() { return "DirectX shader bytecode"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'D', 'X', 'B', 'C'}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "dxbc_built_in", extract_dxbc, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto info = inspect_dxbc(data, offset);
        if(!info) {
            return std::nullopt;
        }
        const char* shader_model = "Unknown Shader Model";
        if(info->shader_model_4) {
            shader_model = "Shader Model 4";
        } else if(info->shader_model_5) {
            shader_model = "Shader Model 5";
        }

        signature_result result;
        result.offset = offset;
        result.size = info->total_size;
        result.confidence = confidence_high;
        result.description = std::string("DirectX shader bytecode, ") + shader_model;
        return result;
    }
};

template<>
struct format_traits<pem_certificate_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pem_certificate"; }
    static std::string description() { return "PEM certificate"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        const std::string text = "-----BEGIN CERTIFICATE-----";
        return {std::vector<std::uint8_t>(text.begin(), text.end())};
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "pem_certificate_built_in", extract_pem_certificate,
            {}, {}, {}, {}, true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_pem(data, offset);
    }
};

template<>
struct format_traits<pem_public_key_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "pem_public_key"; }
    static std::string description() { return "PEM public key"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        static const std::array<std::string_view, 4> texts{
            "-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN DSA PUBLIC KEY-----", "-----BEGIN ECDSA PUBLIC KEY-----"
        };
        std::vector<std::vector<std::uint8_t>> patterns;
        patterns.reserve(texts.size());
        for(const auto text : texts) {
            patterns.emplace_back(text.begin(), text.end());
        }
        return patterns;
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "pem_key_built_in", extract_pem_key, {}, {}, {}, {}, true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_pem(data, offset);
    }
};

template<>
struct format_traits<pem_private_key_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "pem_private_key"; }
    static std::string description() { return "PEM private key"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        static const std::array<std::string_view, 8> texts{
            "-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN ANY PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN TSS2 PRIVATE KEY-----"
        };
        std::vector<std::vector<std::uint8_t>> patterns;
        patterns.reserve(texts.size());
        for(const auto text : texts) {
            patterns.emplace_back(text.begin(), text.end());
        }
        return patterns;
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "pem_key_built_in", extract_pem_key, {}, {}, {}, {}, true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_pem(data, offset);
    }
};

template<>
struct format_traits<pcapng_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pcapng"; }
    static std::string description() { return "Pcap-NG capture file"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x0A, 0x0D, 0x0D, 0x0A}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "pcapng_built_in", extract_pcapng, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto total_size = inspect_pcapng(data, offset);
        if(!total_size) {
            return std::nullopt;
        }
        signature_result result;
        result.offset = offset;
        result.size = *total_size;
        result.confidence = confidence_high;
        result.description = "Pcap-NG capture file, total size: " + std::to_string(*total_size)
            + " bytes";
        result.extraction_declined = offset == 0 && *total_size == data.size();
        return result;
    }
};

namespace formats {

std::vector<signature> b2_media_signatures() {
    return make_signatures(type_list<
        bmp_format,
        pdf_format,
        png_format,
        jpeg_format,
        riff_format,
        gif_format,
        svg_format,
        dxbc_format,
        pem_certificate_format,
        pem_public_key_format,
        pem_private_key_format,
        pcapng_format
    >{});
}

}
}
