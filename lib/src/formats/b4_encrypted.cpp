#include "b4_encrypted.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/codec.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace binwalk {
namespace {

struct arcadyan_format {};
struct autel_format {};
struct dkbs_format {};
struct dlink_tlv_format {};
struct dms_format {};
struct encfw_format {};
struct encrpted_img_format {};
struct openssl_format {};
struct shrs_format {};

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

template<std::size_t Length>
[[nodiscard]] bool bytes_equal(
    byte_view data,
    std::size_t offset,
    const std::array<std::uint8_t, Length>& expected
) noexcept {
    return bytes_equal(data, offset, expected.data(), Length);
}

[[nodiscard]] std::string to_hex_upper(std::uint64_t value) {
    static const char digits[] = "0123456789ABCDEF";
    if(value == 0) {
        return "0x0";
    }
    std::string body;
    while(value != 0) {
        body.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    std::string text = "0x";
    for(std::size_t index = body.size(); index > 0; --index) {
        text.push_back(body[index - 1]);
    }
    return text;
}

[[nodiscard]] std::string to_hex_lower(byte_view data, std::size_t offset, std::size_t length) {
    static const char digits[] = "0123456789abcdef";
    if(!data.contains(offset, length)) {
        return std::string{};
    }
    std::string text;
    text.reserve(length * 2);
    for(std::size_t index = 0; index < length; ++index) {
        const auto value = data[offset + index];
        text.push_back(digits[static_cast<std::size_t>(value >> 4U)]);
        text.push_back(digits[static_cast<std::size_t>(value & 0x0FU)]);
    }
    return text;
}

[[nodiscard]] constexpr std::uint32_t md5_rotate_left(std::uint32_t value, unsigned bits) noexcept {
    return static_cast<std::uint32_t>((value << bits) | (value >> (32U - bits)));
}

[[nodiscard]] std::string md5_hex(byte_view data) {
    static const std::array<std::uint32_t, 64> sine_table{{
        0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU,
        0xa8304613U, 0xfd469501U, 0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
        0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U, 0xf61e2562U, 0xc040b340U,
        0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
        0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U,
        0x676f02d9U, 0x8d2a4c8aU, 0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
        0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U, 0x289b7ec6U, 0xeaa127faU,
        0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
        0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U,
        0xffeff47dU, 0x85845dd1U, 0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
        0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
    }};
    static const std::array<unsigned, 64> shifts{{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    }};

    std::uint32_t state[4] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};
    const auto message_length = data.size();

    const std::size_t padded_length = ((message_length + 8) / 64 + 1) * 64;
    const auto bit_length = static_cast<std::uint64_t>(message_length) * 8U;

    for(std::size_t chunk = 0; chunk < padded_length; chunk += 64) {
        std::array<std::uint32_t, 16> words{};
        for(std::size_t index = 0; index < 64; ++index) {
            const auto position = chunk + index;
            std::uint8_t value = 0;
            if(position < message_length) {
                value = data[position];
            } else if(position == message_length) {
                value = 0x80U;
            } else if(position >= padded_length - 8) {
                const auto shift = (position - (padded_length - 8)) * 8U;
                value = static_cast<std::uint8_t>((bit_length >> shift) & 0xFFU);
            }
            words[index / 4] |= static_cast<std::uint32_t>(value) << ((index % 4) * 8U);
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        for(std::size_t index = 0; index < 64; ++index) {
            std::uint32_t mixed = 0;
            std::size_t word_index = 0;
            if(index < 16) {
                mixed = (b & c) | (~b & d);
                word_index = index;
            } else if(index < 32) {
                mixed = (d & b) | (~d & c);
                word_index = (5 * index + 1) % 16;
            } else if(index < 48) {
                mixed = b ^ c ^ d;
                word_index = (3 * index + 5) % 16;
            } else {
                mixed = c ^ (b | ~d);
                word_index = (7 * index) % 16;
            }
            const std::uint32_t sum = a + mixed + sine_table[index] + words[word_index];
            a = d;
            d = c;
            c = b;
            b = b + md5_rotate_left(sum, shifts[index]);
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    static const char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(32);
    for(const auto word : state) {
        for(unsigned byte_index = 0; byte_index < 4; ++byte_index) {
            const auto value = static_cast<std::uint8_t>((word >> (byte_index * 8U)) & 0xFFU);
            text.push_back(digits[static_cast<std::size_t>(value >> 4U)]);
            text.push_back(digits[static_cast<std::size_t>(value & 0x0FU)]);
        }
    }
    return text;
}

constexpr std::array<std::uint8_t, 8> openssl_magic_bytes{{'S', 'a', 'l', 't', 'e', 'd', '_', '_'}};
constexpr std::array<std::uint8_t, 4> shrs_magic_bytes{{'S', 'H', 'R', 'S'}};
constexpr std::array<std::uint8_t, 6> dkbs_magic_bytes{{'_', 'd', 'k', 'b', 's', '_'}};
constexpr std::array<std::uint8_t, 4> dlink_tlv_magic_bytes{{0x64, 0x80, 0x19, 0x40}};
constexpr std::array<std::uint8_t, 4> arcadyan_magic_bytes{{0x00, 0xD5, 0x08, 0x00}};
constexpr std::array<std::uint8_t, 4> dms_magic_bytes{{'0', '>', '<', '1'}};
constexpr std::array<std::uint8_t, 12> encrpted_img_magic_bytes{
    {'e', 'n', 'c', 'r', 'p', 't', 'e', 'd', '_', 'i', 'm', 'g'}
};

template<std::size_t Length>
[[nodiscard]] std::vector<std::vector<std::uint8_t>> single_magic(
    const std::array<std::uint8_t, Length>& pattern
) {
    return {{pattern.begin(), pattern.end()}};
}

[[nodiscard]] bool salt_is_invalid(std::uint64_t salt) noexcept {
    std::size_t bad_byte_count = 0;
    for(unsigned index = 0; index < 8; ++index) {
        const auto value = static_cast<std::uint8_t>((salt >> (8U * index)) & 0xFFU);
        if(value == 0 || is_printable_ascii(value)) {
            ++bad_byte_count;
        }
    }
    return bad_byte_count == 8;
}

[[nodiscard]] std::optional<std::uint64_t> inspect_openssl_salt(
    byte_view data,
    std::size_t offset
) noexcept {
    if(!bytes_equal(data, offset, openssl_magic_bytes)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(data);
    const auto salt = reader.read<std::uint64_t>(offset + openssl_magic_bytes.size());
    if(!salt || *salt == 0 || salt_is_invalid(*salt)) {
        return std::nullopt;
    }
    return salt;
}

struct encfw_entry {
    std::array<std::uint8_t, 4> magic;
    const char* model;
};

[[nodiscard]] const std::array<encfw_entry, 5>& encfw_known_firmware() {
    static const std::array<encfw_entry, 5> table{{
        {{{0xdf, 0x8c, 0x39, 0x0d}}, "D-Link DIR-822 rev C"},
        {{{0x35, 0x66, 0x6f, 0x68}}, "D-Link DAP-1665"},
        {{{0xf5, 0x2a, 0xa0, 0xb4}}, "D-Link DIR-842 rev C"},
        {{{0xe3, 0x13, 0x00, 0x5b}}, "D-Link DIR-850 rev A"},
        {{{0x0a, 0x14, 0xe4, 0x24}}, "D-Link DIR-850 rev B"}
    }};
    return table;
}

constexpr std::uint64_t shrs_header_size = 0x6DC;
constexpr std::size_t shrs_iv_offset = 12;
constexpr std::size_t shrs_iv_length = 16;

struct shrs_header {
    std::uint64_t data_size = 0;
};

[[nodiscard]] std::optional<shrs_header> inspect_shrs(byte_view data, std::size_t offset) noexcept {

    if(!bytes_equal(data, offset, shrs_magic_bytes)) {
        return std::nullopt;
    }
    if(!data.contains(offset, shrs_iv_offset + shrs_iv_length)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(data);
    const auto data_size = reader.read<std::uint32_t>(offset + 8);
    if(!data_size) {
        return std::nullopt;
    }
    return shrs_header{*data_size};
}

constexpr std::size_t dkbs_magic_offset = 7;
constexpr std::uint64_t dkbs_header_size = 0xA0;

struct dkbs_header {
    std::uint64_t data_size = 0;
    std::string board_id;
    std::string version;
    std::string boot_device;
    const char* endianness = "big";
};

[[nodiscard]] std::optional<dkbs_header> inspect_dkbs(byte_view data, std::size_t offset) {
    constexpr std::size_t board_id_start = 0;
    constexpr std::size_t version_start = 0x28;
    constexpr std::size_t boot_device_start = 0x70;
    constexpr std::size_t string_length = 0x20;
    constexpr std::size_t data_size_start = 0x68;

    if(!data.contains(offset, static_cast<std::size_t>(dkbs_header_size))) {
        return std::nullopt;
    }

    if(!bytes_equal(data, offset + dkbs_magic_offset, dkbs_magic_bytes)) {
        return std::nullopt;
    }

    dkbs_header header;
    header.board_id = get_cstring(data, offset + board_id_start, string_length);
    header.version = get_cstring(data, offset + version_start, string_length);
    header.boot_device = get_cstring(data, offset + boot_device_start, string_length);
    if(header.board_id.empty() || header.version.empty() || header.boot_device.empty()) {
        return std::nullopt;
    }

    const binary_reader<byte_order::big> big_reader(data);
    const binary_reader<byte_order::little> little_reader(data);
    const auto big_value = big_reader.read<std::uint32_t>(offset + data_size_start);
    const auto little_value = little_reader.read<std::uint32_t>(offset + data_size_start);
    if(!big_value || !little_value) {
        return std::nullopt;
    }
    if((*big_value & 0xFF000000U) == 0) {
        header.data_size = *big_value;
        header.endianness = "big";
    } else {
        header.data_size = *little_value;
        header.endianness = "little";
    }
    if(header.data_size == 0) {
        return std::nullopt;
    }
    return header;
}

constexpr std::uint64_t dlink_tlv_header_size = 0x74;

constexpr std::uint64_t dlink_tlv_checksum_offset = 8;

struct dlink_tlv_header {
    std::string model_name;
    std::string board_id;
    std::string data_checksum;
    std::uint64_t data_size = 0;
};

[[nodiscard]] std::optional<dlink_tlv_header> inspect_dlink_tlv(
    byte_view data,
    std::size_t offset
) {
    constexpr std::size_t model_name_start = 4;
    constexpr std::size_t board_id_start = 0x24;
    constexpr std::size_t md5_start = 0x4C;
    constexpr std::size_t data_tlv_start = 0x6C;
    constexpr std::size_t string_length = 0x20;
    constexpr std::uint32_t expected_data_type = 1;

    if(!data.contains(offset, static_cast<std::size_t>(dlink_tlv_header_size))) {
        return std::nullopt;
    }
    if(!bytes_equal(data, offset, dlink_tlv_magic_bytes)) {
        return std::nullopt;
    }

    dlink_tlv_header header;
    header.model_name = get_cstring(data, offset + model_name_start, string_length);
    header.board_id = get_cstring(data, offset + board_id_start, string_length);

    header.data_checksum = get_cstring(data, offset + md5_start, string_length);
    if(header.model_name.empty() || header.board_id.empty()) {
        return std::nullopt;
    }

    const binary_reader<byte_order::little> reader(data);
    const auto data_type = reader.read<std::uint32_t>(offset + data_tlv_start);
    const auto data_length = reader.read<std::uint32_t>(offset + data_tlv_start + 4);
    if(!data_type || !data_length || *data_type != expected_data_type) {
        return std::nullopt;
    }
    header.data_size = *data_length;
    return header;
}

constexpr std::array<std::uint8_t, 8> autel_magic_bytes{{'E', 'C', 'C', '0', '1', '0', '1', 0x00}};
constexpr std::uint64_t autel_expected_header_size = 0x20;

constexpr std::size_t autel_copyright_offset = 16;
constexpr std::size_t autel_copyright_length = 16;
constexpr std::size_t autel_block_size = 256;

struct autel_header {
    std::uint64_t data_size = 0;
    std::uint64_t header_size = autel_expected_header_size;
};

[[nodiscard]] std::optional<autel_header> inspect_autel(byte_view data, std::size_t offset) {

    if(!bytes_equal(data, offset, autel_magic_bytes)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::little> reader(data);
    const auto data_size = reader.read<std::uint32_t>(offset + 8);
    const auto header_size = reader.read<std::uint32_t>(offset + 12);
    if(!data_size || !header_size || *header_size != autel_expected_header_size) {
        return std::nullopt;
    }
    if(get_cstring(data, offset + autel_copyright_offset, autel_copyright_length)
        != "Copyright Autel") {
        return std::nullopt;
    }
    return autel_header{*data_size, *header_size};
}

[[nodiscard]] const std::array<std::array<std::uint16_t, 2>, autel_block_size>& autel_table() {
    static const std::array<std::array<std::uint16_t, 2>, autel_block_size> table{{
        {{54, 147}},  {{96, 129}},  {{59, 193}},  {{191, 0}},   {{45, 130}},  {{96, 144}},
        {{27, 129}},  {{152, 0}},   {{44, 180}},  {{118, 141}}, {{115, 129}}, {{210, 0}},
        {{13, 164}},  {{27, 133}},  {{20, 192}},  {{139, 0}},   {{28, 166}},  {{17, 133}},
        {{19, 193}},  {{224, 0}},   {{20, 161}},  {{145, 0}},   {{14, 193}},  {{12, 132}},
        {{18, 161}},  {{17, 140}},  {{29, 192}},  {{246, 0}},   {{115, 178}}, {{28, 132}},
        {{155, 0}},   {{12, 132}},  {{31, 165}},  {{20, 136}},  {{27, 193}},  {{142, 0}},
        {{96, 164}},  {{18, 133}},  {{145, 0}},   {{23, 132}},  {{13, 165}},  {{13, 148}},
        {{23, 193}},  {{19, 132}},  {{27, 178}},  {{83, 137}},  {{146, 0}},   {{145, 0}},
        {{18, 166}},  {{96, 148}},  {{13, 193}},  {{159, 0}},   {{96, 166}},  {{20, 129}},
        {{20, 193}},  {{27, 132}},  {{9, 160}},   {{96, 148}},  {{13, 192}},  {{159, 0}},
        {{96, 180}},  {{142, 0}},   {{31, 193}},  {{155, 0}},   {{7, 166}},   {{224, 0}},
        {{20, 192}},  {{27, 132}},  {{28, 160}},  {{17, 149}},  {{19, 193}},  {{96, 132}},
        {{76, 164}},  {{208, 0}},   {{80, 192}},  {{78, 132}},  {{96, 160}},  {{27, 144}},
        {{24, 193}},  {{140, 0}},   {{96, 178}},  {{17, 141}},  {{12, 193}},  {{224, 0}},
        {{14, 161}},  {{17, 141}},  {{151, 0}},   {{14, 132}},  {{16, 165}},  {{96, 137}},
        {{13, 193}},  {{155, 0}},   {{20, 161}},  {{29, 141}},  {{23, 192}},  {{24, 132}},
        {{27, 178}},  {{10, 133}},  {{96, 192}},  {{140, 0}},   {{14, 180}},  {{17, 133}},
        {{16, 192}},  {{144, 0}},   {{11, 163}},  {{13, 141}},  {{96, 192}},  {{17, 132}},
        {{12, 178}},  {{96, 141}},  {{28, 192}},  {{27, 132}},  {{27, 130}},  {{18, 141}},
        {{96, 193}},  {{31, 132}},  {{96, 181}},  {{13, 140}},  {{23, 193}},  {{224, 0}},
        {{27, 166}},  {{142, 0}},   {{27, 192}},  {{24, 132}},  {{12, 183}},  {{96, 133}},
        {{84, 192}},  {{14, 132}},  {{27, 178}},  {{10, 140}},  {{155, 0}},   {{9, 132}},
        {{17, 160}},  {{56, 133}},  {{96, 192}},  {{82, 132}},  {{13, 160}},  {{27, 137}},
        {{20, 193}},  {{139, 0}},   {{28, 161}},  {{145, 0}},   {{19, 192}},  {{118, 132}},
        {{115, 165}}, {{20, 132}},  {{145, 0}},   {{14, 132}},  {{12, 167}},  {{146, 0}},
        {{17, 193}},  {{29, 132}},  {{96, 176}},  {{28, 144}},  {{27, 193}},  {{140, 0}},
        {{31, 180}},  {{148, 0}},   {{27, 192}},  {{14, 132}},  {{83, 160}},  {{18, 137}},
        {{17, 193}},  {{23, 132}},  {{13, 165}},  {{13, 145}},  {{151, 0}},   {{147, 0}},
        {{27, 178}},  {{96, 137}},  {{19, 193}},  {{159, 0}},   {{14, 160}},  {{25, 148}},
        {{17, 193}},  {{142, 0}},   {{16, 180}},  {{27, 136}},  {{14, 193}},  {{224, 0}},
        {{17, 178}},  {{12, 144}},  {{224, 0}},   {{28, 132}},  {{27, 160}},  {{13, 141}},
        {{11, 193}},  {{96, 132}},  {{27, 165}},  {{30, 140}},  {{224, 0}},   {{146, 0}},
        {{31, 165}},  {{29, 129}},  {{96, 192}},  {{140, 0}},   {{31, 161}},  {{24, 145}},
        {{140, 0}},   {{96, 132}},  {{27, 165}},  {{29, 140}},  {{31, 192}},  {{154, 0}},
        {{14, 161}},  {{27, 145}},  {{140, 0}},   {{18, 132}},  {{23, 167}},  {{96, 140}},
        {{21, 129}},  {{14, 132}},  {{17, 165}},  {{9, 137}},   {{12, 193}},  {{155, 0}},
        {{18, 161}},  {{96, 141}},  {{27, 192}},  {{148, 0}},   {{29, 178}},  {{23, 133}},
        {{24, 192}},  {{155, 0}},   {{10, 180}},  {{96, 133}},  {{28, 192}},  {{14, 132}},
        {{31, 130}},  {{28, 129}},  {{18, 193}},  {{31, 132}},  {{12, 180}},  {{13, 144}},
        {{96, 193}},  {{31, 132}},  {{96, 160}},  {{13, 141}},  {{27, 193}},  {{18, 132}},
        {{23, 181}},  {{26, 140}},  {{27, 193}},  {{156, 0}},   {{96, 166}},  {{79, 141}},
        {{211, 0}},   {{76, 132}},  {{77, 160}},  {{75, 133}},  {{206, 0}},   {{182, 0}},
        {{96, 129}},  {{59, 133}},  {{191, 0}},   {{173, 0}}
    }};
    return table;
}

constexpr std::size_t arcadyan_magic_offset = 0x68;
constexpr std::size_t arcadyan_lzma_data_offset = 4;
constexpr std::size_t arcadyan_min_data_size = 0x100;
constexpr std::size_t arcadyan_max_data_size = 0x1B0000;

[[nodiscard]] std::vector<std::uint8_t> arcadyan_deobfuscate(byte_view source) {
    constexpr std::size_t block_size = 32;
    constexpr std::size_t block1_start = 4;
    constexpr std::size_t block1_end = block1_start + block_size;
    constexpr std::size_t block2_start = 0x68;
    constexpr std::size_t block2_end = block2_start + block_size;

    std::vector<std::uint8_t> out;
    if(source.size() < block2_end) {
        return out;
    }
    out.reserve(source.size());

    const auto append = [&](std::size_t start, std::size_t length) {
        for(std::size_t index = 0; index < length; ++index) {
            out.push_back(source[start + index]);
        }
    };

    append(0, block1_start);
    append(block2_start, block_size);
    append(block1_end, block2_start - block1_end);
    append(block1_start, block_size);
    append(block2_end, source.size() - block2_end);

    for(std::size_t index = block1_start; index < block1_end; ++index) {
        const auto value = out[index];
        out[index] = static_cast<std::uint8_t>(
            ((value & 0x0FU) << 4U) | ((value & 0xF0U) >> 4U)
        );
    }
    for(std::size_t index = block1_start; index < block1_end; index += 2) {
        std::swap(out[index], out[index + 1]);
    }
    return out;
}

constexpr std::size_t dms_magic_offset = 4;
constexpr std::size_t dms_minimum_size = 0x100;
constexpr std::size_t dms_swap_width = 2;

[[nodiscard]] std::vector<std::uint8_t> byte_swap(byte_view data, std::size_t width) {
    std::vector<std::uint8_t> out;
    if(width == 0) {
        return out;
    }
    const std::size_t chunk_size = width * 2;
    const std::size_t whole_chunks = data.size() / chunk_size;
    out.reserve(whole_chunks * chunk_size);
    for(std::size_t chunk = 0; chunk < whole_chunks; ++chunk) {
        const auto start = chunk * chunk_size;
        for(std::size_t index = 0; index < width; ++index) {
            out.push_back(data[start + width + index]);
        }
        for(std::size_t index = 0; index < width; ++index) {
            out.push_back(data[start + index]);
        }
    }
    return out;
}

struct dms_header {
    std::uint64_t image_size = 0;
};

[[nodiscard]] std::optional<dms_header> inspect_dms_swapped(byte_view swapped) noexcept {
    constexpr std::uint16_t magic_p1 = 0x4D47;
    constexpr std::uint32_t magic_p2 = 0x3C31303E;

    const binary_reader<byte_order::big> reader(swapped);
    const auto part1 = reader.read<std::uint16_t>(2);
    const auto part2 = reader.read<std::uint32_t>(4);
    const auto image_size = reader.read<std::uint32_t>(12);
    if(!part1 || !part2 || !image_size) {
        return std::nullopt;
    }
    if(*part1 != magic_p1 || *part2 != magic_p2) {
        return std::nullopt;
    }
    return dms_header{*image_size};
}

}

namespace formats {

extraction_result encfw_decrypt(
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

extraction_result autel_deobfuscate(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string output_file_name = "autel.decoded";

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_autel(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    if(!is_range_safe(data.size(), offset, static_cast<std::size_t>(header->header_size))) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto data_start = offset + static_cast<std::size_t>(header->header_size);
    if(header->data_size > static_cast<std::uint64_t>(data.size() - data_start)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto payload_size = static_cast<std::size_t>(header->data_size);

    std::vector<std::uint8_t> decoded_block;
    decoded_block.reserve(autel_block_size);
    const auto& table = autel_table();

    const chroot* output = nullptr;
    std::optional<chroot> output_storage;
    if(output_directory != nullptr) {
        output_storage.emplace(*output_directory);
        output = &*output_storage;
    }

    for(std::size_t block_start = 0; block_start < payload_size; block_start += autel_block_size) {
        const auto block_length = (payload_size - block_start) < autel_block_size
            ? (payload_size - block_start)
            : autel_block_size;

        decoded_block.clear();
        for(std::size_t index = 0; index < block_length; ++index) {
            const auto raw = static_cast<std::uint32_t>(data[data_start + block_start + index]);
            const auto added = raw + static_cast<std::uint32_t>(table[index][0]);
            const auto mixed = added ^ static_cast<std::uint32_t>(table[index][1]);
            decoded_block.push_back(static_cast<std::uint8_t>(mixed & 0xFFU));
        }

        if(output != nullptr) {

            if(!output->append_to_file(output_file_name, byte_view(decoded_block))) {
                result.failure = extraction_failure::write_error;
                return result;
            }
        }
    }

    result.success = true;
    result.size = header->data_size;
    return result;
}

extraction_result extract_obfuscated_lzma(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string output_file_name = "decompressed.bin";

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);
    const auto available_data = data.size() - offset;

    if(available_data <= arcadyan_min_data_size || available_data > arcadyan_max_data_size) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    if(!codec_available(codec_id::lzma_alone)) {
        result.failure = extraction_failure::unsupported;
        return result;
    }

    const auto deobfuscated = arcadyan_deobfuscate(data.subview(offset, available_data));
    if(deobfuscated.size() <= arcadyan_lzma_data_offset) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const byte_view deobfuscated_view(deobfuscated);
    const codec_options options;
    std::vector<std::uint8_t> decoded;

    const auto outcome = output_directory == nullptr
        ? codec_decompress(
              codec_id::lzma_alone, deobfuscated_view, arcadyan_lzma_data_offset, nullptr, options
          )
        : codec_decompress_to_buffer(
              codec_id::lzma_alone, deobfuscated_view, arcadyan_lzma_data_offset, decoded, options
          );

    if(outcome.unsupported()) {
        result.failure = extraction_failure::unsupported;
        return result;
    }

    if(!outcome.success() || outcome.output_size == 0) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.size = static_cast<std::uint64_t>(outcome.input_consumed);

    if(output_directory != nullptr) {

        const chroot output(*output_directory);
        if(!output.create_file(output_file_name, byte_view(decoded))) {
            result.failure = extraction_failure::write_error;
            result.size.reset();
            return result;
        }
    }
    result.success = true;
    return result;
}

extraction_result extract_swapped_u16(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string output_file_name = "swapped.bin";

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto swapped = byte_swap(data.subview(offset, data.size() - offset), dms_swap_width);
    if(swapped.empty()) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.size = static_cast<std::uint64_t>(swapped.size());
    if(output_directory != nullptr) {
        const chroot output(*output_directory);
        if(!output.create_file(output_file_name, byte_view(swapped))) {
            result.failure = extraction_failure::write_error;
            result.size.reset();
            return result;
        }
    }
    result.success = true;
    return result;
}

}

template<>
struct format_traits<arcadyan_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "arcadyan"; }
    static std::string description() { return "Arcadyan obfuscated LZMA"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(arcadyan_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "arcadyan_built_in", &formats::extract_obfuscated_lzma,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset < arcadyan_magic_offset) {
            return std::nullopt;
        }
        const auto start_offset = offset - arcadyan_magic_offset;

        signature_result probe;
        probe.offset = start_offset;
        const auto dry_run =
            dry_run_extractor(&formats::extract_obfuscated_lzma, data, probe);
        if(!dry_run.success) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start_offset;
        result.confidence = confidence_high;
        result.description = description();

        return result;
    }
};

template<>
struct format_traits<openssl_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "openssl"; }
    static std::string description() { return "OpenSSL encryption"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(openssl_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "openssl_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto salt = inspect_openssl_salt(data, offset);
        if(!salt) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;

        result.confidence = offset == 0 ? confidence_medium : confidence_low;
        result.description = description() + ", salt: " + to_hex_upper(*salt);
        return result;
    }
};

template<>
struct format_traits<autel_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "autel"; }
    static std::string description() { return "Autel obfuscated firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(autel_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "autel_built_in", &formats::autel_deobfuscate,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = inspect_autel(data, offset);
        if(!header) {
            return std::nullopt;
        }
        const auto total_size = header->header_size + header->data_size;

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_medium;
        result.description = description()
            + ", header size: " + std::to_string(header->header_size) + " bytes"
            + ", data size: " + std::to_string(header->data_size)
            + ", total size: " + std::to_string(total_size);
        return result;
    }
};

template<>
struct format_traits<dlink_tlv_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dlink_tlv"; }
    static std::string description() { return "D-Link TLV firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(dlink_tlv_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "dlink_tlv_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = inspect_dlink_tlv(data, offset);
        if(!header) {
            return std::nullopt;
        }

        const auto data_start = static_cast<std::uint64_t>(offset)
            + dlink_tlv_header_size - dlink_tlv_checksum_offset;
        const auto hashed_length = header->data_size + dlink_tlv_checksum_offset;
        if(data_start > static_cast<std::uint64_t>(data.size())
            || hashed_length > static_cast<std::uint64_t>(data.size())
                - static_cast<std::uint64_t>(data_start)) {
            return std::nullopt;
        }

        if(!header->data_checksum.empty()) {
            const auto digest = md5_hex(data.subview(
                static_cast<std::size_t>(data_start), static_cast<std::size_t>(hashed_length)
            ));
            if(digest != header->data_checksum) {
                return std::nullopt;
            }
        }

        signature_result result;
        result.offset = offset;
        result.size = dlink_tlv_header_size + header->data_size;
        result.confidence = confidence_high;
        result.description = description()
            + ", model name: " + header->model_name
            + ", board ID: " + header->board_id
            + ", header size: " + std::to_string(dlink_tlv_header_size) + " bytes"
            + ", data size: " + std::to_string(header->data_size) + " bytes";

        const auto payload_offset = static_cast<std::uint64_t>(offset) + dlink_tlv_header_size;
        if(payload_offset <= static_cast<std::uint64_t>(data.size())) {
            const auto salt =
                inspect_openssl_salt(data, static_cast<std::size_t>(payload_offset));
            if(salt) {
                result.description += ", OpenSSL encryption, salt: " + to_hex_upper(*salt);
            }
        }
        return result;
    }
};

template<>
struct format_traits<shrs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "shrs"; }
    static std::string description() { return "SHRS encrypted firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(shrs_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "shrs_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = inspect_shrs(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = shrs_header_size + header->data_size;
        result.confidence = offset == 0 ? confidence_medium : confidence_low;
        result.description = description()
            + ", header size: " + std::to_string(shrs_header_size) + " bytes"
            + ", encrypted data size: " + std::to_string(header->data_size) + " bytes"
            + ", IV: " + to_hex_lower(data, offset + shrs_iv_offset, shrs_iv_length);
        return result;
    }
};

template<>
struct format_traits<encrpted_img_format> {

    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "encrpted_img"; }

    static std::string description() { return "D-Link Encrpted Image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(encrpted_img_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "encrpted_img_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        if(!bytes_equal(data, offset, encrpted_img_magic_bytes)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = offset == 0 ? confidence_medium : confidence_low;
        result.description = description();
        return result;
    }
};

template<>
struct format_traits<dms_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dms"; }
    static std::string description() { return "DMS firmware image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(dms_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "dms_built_in", &formats::extract_swapped_u16,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset < dms_magic_offset) {
            return std::nullopt;
        }
        const auto start_offset = offset - dms_magic_offset;
        if(!data.contains(start_offset, dms_minimum_size)) {
            return std::nullopt;
        }

        const auto swapped =
            byte_swap(data.subview(start_offset, dms_minimum_size), dms_swap_width);
        const auto header = inspect_dms_swapped(byte_view(swapped));
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start_offset;
        result.size = header->image_size;
        result.confidence = confidence_medium;
        result.description =
            description() + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<dkbs_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "dkbs"; }
    static std::string description() { return "DKBS firmware header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return single_magic(dkbs_magic_bytes);
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "dkbs_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        if(offset < dkbs_magic_offset) {
            return std::nullopt;
        }
        const auto start_offset = offset - dkbs_magic_offset;

        const auto header = inspect_dkbs(data, start_offset);
        if(!header) {
            return std::nullopt;
        }

        const auto available_data = static_cast<std::uint64_t>(data.size() - start_offset);
        if(available_data < dkbs_header_size + header->data_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start_offset;
        result.size = dkbs_header_size;
        result.confidence = start_offset == 0 ? confidence_high : confidence_medium;
        result.description = description()
            + ", board ID: " + header->board_id
            + ", firmware version: " + header->version
            + ", boot device: " + header->boot_device
            + ", endianness: " + header->endianness
            + ", header size: " + std::to_string(dkbs_header_size) + " bytes"
            + ", data size: " + std::to_string(header->data_size);
        return result;
    }
};

template<>
struct format_traits<encfw_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "encfw"; }
    static std::string description() { return "Known encrypted firmware"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        std::vector<std::vector<std::uint8_t>> patterns;
        patterns.reserve(encfw_known_firmware().size());
        for(const auto& entry : encfw_known_firmware()) {
            patterns.push_back({entry.magic.begin(), entry.magic.end()});
        }
        return patterns;
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal, "encfw_built_in", &formats::encfw_decrypt,
            std::string{}, std::string{}, {}, {}, false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        for(const auto& entry : encfw_known_firmware()) {
            if(!bytes_equal(data, offset, entry.magic)) {
                continue;
            }
            signature_result result;
            result.offset = offset;
            result.confidence = offset == 0 ? confidence_medium : confidence_low;
            result.description = description() + ", " + entry.model;
            return result;
        }
        return std::nullopt;
    }
};

namespace formats {

std::vector<signature> b4_encrypted_signatures() {
    return make_signatures(type_list<
        arcadyan_format,
        openssl_format,
        autel_format,
        dlink_tlv_format,
        shrs_format,
        encrpted_img_format,
        dms_format,
        dkbs_format,
        encfw_format
    >{});
}

}
}
