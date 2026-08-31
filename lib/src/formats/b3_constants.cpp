#include "b3_constants.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/common.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct crc32_format {};
struct sha256_format {};
struct md5_format {};
struct aes_sbox_format {};
struct aes_forward_table_format {};
struct aes_reverse_table_format {};
struct aes_rcon_format {};
struct aes_acceleration_table_format {};
struct pkcs_der_hash_format {};
struct rsa_format {};
struct luks_format {};
struct dpapi_format {};

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

[[nodiscard]] std::optional<std::size_t> first_match(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& patterns
) noexcept {
    for(std::size_t index = 0; index < patterns.size(); ++index) {
        if(bytes_equal(data, offset, patterns[index])) {
            return index;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool advance(byte_view data, std::size_t& cursor, std::uint64_t amount) noexcept {
    if(cursor > data.size()) {
        return false;
    }
    if(amount > static_cast<std::uint64_t>(data.size() - cursor)) {
        return false;
    }
    cursor += static_cast<std::size_t>(amount);
    return true;
}

[[nodiscard]] std::string to_hex(std::uint64_t value, std::size_t digit_count) {
    static const char digits[] = "0123456789ABCDEF";
    std::string text = "0x";
    for(std::size_t index = digit_count; index > 0; --index) {
        const auto shift = (index - 1) * 4;
        text.push_back(digits[static_cast<std::size_t>((value >> shift) & 0xFU)]);
    }
    return text;
}

[[nodiscard]] std::string to_hex_bytes(byte_view data, std::size_t offset, std::size_t length) {
    static const char digits[] = "0123456789ABCDEF";
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

constexpr std::size_t hash_magic_length = 16;

[[nodiscard]] std::optional<signature_result> parse_hash_constants(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& magics,
    const char* label
) {
    const auto matched = first_match(data, offset, magics);
    if(!matched) {
        return std::nullopt;
    }

    signature_result result;
    result.offset = offset;
    result.size = hash_magic_length;
    result.confidence = confidence_low;
    result.description = label;
    result.description += (*matched == 0) ? ", big endian" : ", little endian";
    return result;
}

[[nodiscard]] std::optional<signature_result> parse_constant_table(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& magics,
    const char* description
) {
    if(!first_match(data, offset, magics)) {
        return std::nullopt;
    }

    signature_result result;
    result.offset = offset;
    result.confidence = confidence_low;
    result.description = description;
    return result;
}

struct der_hash_entry {
    const char* name;
    std::vector<std::uint8_t> bytes;
};

[[nodiscard]] std::vector<der_hash_entry> der_hash_table() {
    return {
        {"MD5", {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02,
                 0x05, 0x05, 0x00, 0x04, 0x10}},
        {"SHA1", {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                  0x04, 0x14}},
        {"SHA256", {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20}},
        {"SHA384", {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x05, 0x00, 0x04, 0x30}},

        {"SHA512", {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x05, 0x00, 0x04}}
    };
}

struct rsa_key_definition {
    std::vector<std::uint8_t> magic;
    std::size_t key_size;
    std::size_t keyid_offset;
    std::size_t usage_offset;
    std::size_t valid_bytes_offset;
    std::size_t terminator_offset;
};

[[nodiscard]] std::vector<rsa_key_definition> rsa_key_definitions() {
    return {
        {{0x84, 0x8C, 0x03}, 1024, 3, 11, 12, 142},
        {{0x85, 0x01, 0x0c, 0x03}, 2048, 4, 12, 13, 271},
        {{0x85, 0x01, 0x8c, 0x03}, 3072, 4, 12, 13, 399},
        {{0x85, 0x02, 0x0c, 0x03}, 4096, 4, 12, 13, 527},
        {{0x85, 0x04, 0x0c, 0x03}, 8192, 4, 12, 13, 1039}
    };
}

[[nodiscard]] bool rsa_length_bytes_valid(std::size_t key_size, std::uint16_t value) noexcept {
    for(std::size_t index = 0; index < 8; ++index) {
        if(static_cast<std::uint16_t>(key_size - index) == value) {
            return true;
        }
    }
    return false;
}

constexpr std::size_t luks_version_offset = 6;
constexpr std::size_t luks_header_size_offset = 8;
constexpr std::size_t luks_cipher_algorithm_offset = 8;
constexpr std::size_t luks_cipher_mode_offset = 40;
constexpr std::size_t luks_hash_function_offset = 72;
constexpr std::size_t luks_string_field_length = 32;

constexpr std::uint64_t luks2_minimum_header_size = 4032;

constexpr std::uint64_t dpapi_header_size = 84;

}

template<>
struct format_traits<crc32_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "crc32"; }
    static std::string description() { return "CRC32 polynomial table"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {
            {0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96,
             0xEE, 0x0E, 0x61, 0x2C, 0x99, 0x09, 0x51, 0xBA},
            {0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
             0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_hash_constants(data, offset, magic(), "CRC32 polynomial table");
    }
};

template<>
struct format_traits<sha256_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "sha256"; }
    static std::string description() { return "SHA256 hash constants"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {
            {0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
             0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5},
            {0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71,
             0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_hash_constants(data, offset, magic(), "SHA256 hash constants");
    }
};

template<>
struct format_traits<md5_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "md5"; }
    static std::string description() { return "MD5 hash constants"; }
    static std::vector<std::vector<std::uint8_t>> magic() {

        return {
            {0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
             0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee},
            {0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8,
             0xdb, 0x70, 0x20, 0x24, 0xee, 0xce, 0xbd, 0xc1}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_hash_constants(data, offset, magic(), "MD5 hash constants");
    }
};

template<>
struct format_traits<aes_sbox_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "aes_sbox"; }
    static std::string description() { return "AES S-Box"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5},
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_constant_table(data, offset, magic(), "AES S-Box");
    }
};

template<>
struct format_traits<aes_forward_table_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "aes_forward_table"; }
    static std::string description() { return "AES Forward Table"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0xC6, 0x63, 0x63, 0xA5, 0xF8, 0x7C, 0x7C, 0x84,
                 0xEE, 0x77, 0x77, 0x99, 0xF6, 0x7B, 0x7B, 0x8D}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_constant_table(data, offset, magic(), "AES Forward Table");
    }
};

template<>
struct format_traits<aes_reverse_table_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "aes_reverse_table"; }
    static std::string description() { return "AES Reverse Table"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x51, 0xF4, 0xA7, 0x50, 0x7E, 0x41, 0x65, 0x53,
                 0x1A, 0x17, 0xA4, 0xC3, 0x3A, 0x27, 0x5E, 0x96}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_constant_table(data, offset, magic(), "AES Reverse Table");
    }
};

template<>
struct format_traits<aes_rcon_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "aes_rcon"; }
    static std::string description() { return "AES RCON"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {

            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36},

            {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
             0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
             0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00,
             0x00, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_constant_table(data, offset, magic(), "AES RCON");
    }
};

template<>
struct format_traits<aes_acceleration_table_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "aes_acceleration_table"; }
    static std::string description() { return "AES Acceleration Table"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {

            {0xA5, 0x84, 0x99, 0x8D, 0x0D, 0xBD, 0xB1, 0x54,
             0x50, 0x03, 0xA9, 0x7D, 0x19, 0x62, 0xE6, 0x9A},

            {0xC6, 0xF8, 0xEE, 0xF6, 0xFF, 0xD6, 0xDE, 0x91,
             0x60, 0x02, 0xCE, 0x56, 0xE7, 0xB5, 0x4D, 0xEC},

            {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
             0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e},
            {0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
             0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39},
            {0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
             0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf},
            {0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45,
             0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81},
            {0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f,
             0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3},
            {0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62,
             0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca}
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        return parse_constant_table(data, offset, magic(), "AES Acceleration Table");
    }
};

template<>
struct format_traits<pkcs_der_hash_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pkcs_der_hash"; }
    static std::string description() { return "PKCS DER hash"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        std::vector<std::vector<std::uint8_t>> patterns;
        for(auto& entry : der_hash_table()) {
            patterns.push_back(std::move(entry.bytes));
        }
        return patterns;
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        for(const auto& entry : der_hash_table()) {
            if(!bytes_equal(data, offset, entry.bytes)) {
                continue;
            }
            signature_result result;
            result.offset = offset;
            result.size = entry.bytes.size();
            result.confidence = confidence_medium;
            result.description = "PKCS DER hash, ";
            result.description += entry.name;
            return result;
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<rsa_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "rsa"; }
    static std::string description() { return "RSA encrypted session key"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        std::vector<std::vector<std::uint8_t>> patterns;
        for(auto& definition : rsa_key_definitions()) {
            patterns.push_back(std::move(definition.magic));
        }
        return patterns;
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::uint8_t terminator_byte = 0xD2;
        constexpr std::uint8_t sign_and_encrypt = 1;
        constexpr std::uint8_t encrypt_only = 2;

        for(const auto& definition : rsa_key_definitions()) {
            if(!bytes_equal(data, offset, definition.magic)) {
                continue;
            }

            const auto key_data_length = definition.terminator_offset + 1;
            if(!data.contains(offset, key_data_length)) {
                return std::nullopt;
            }
            if(data[offset + definition.terminator_offset] != terminator_byte) {
                return std::nullopt;
            }

            binary_reader<byte_order::big> reader(data);
            const auto key_id = reader.read<std::uint64_t>(offset + definition.keyid_offset);
            const auto length_bytes =
                reader.read<std::uint16_t>(offset + definition.valid_bytes_offset);
            if(!key_id || !length_bytes) {
                return std::nullopt;
            }

            const auto usage = data[offset + definition.usage_offset];
            const bool can_sign = usage == sign_and_encrypt;

            const bool can_encrypt = can_sign || usage == encrypt_only;
            if(!can_sign && !can_encrypt) {
                return std::nullopt;
            }
            if(!rsa_length_bytes_valid(definition.key_size, *length_bytes)) {
                return std::nullopt;
            }

            signature_result result;
            result.offset = offset;
            result.size = key_data_length;
            result.confidence = confidence_medium;
            result.description = "RSA encrypted session key, "
                + std::to_string(definition.key_size) + " bits, can sign: "
                + (can_sign ? "true" : "false") + ", can encrypt: "
                + (can_encrypt ? "true" : "false") + ", key ID: " + to_hex(*key_id, 16);
            return result;
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<luks_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "luks"; }
    static std::string description() { return "LUKS header"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'L', 'U', 'K', 'S', 0xBA, 0xBE}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {

        static const std::vector<std::uint8_t> luks_magic{'L', 'U', 'K', 'S', 0xBA, 0xBE};
        if(!bytes_equal(data, offset, luks_magic)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        const auto version = reader.read<std::uint16_t>(offset + luks_version_offset);

        const auto header_size = reader.read<std::uint64_t>(offset + luks_header_size_offset);
        if(!version || !header_size) {
            return std::nullopt;
        }

        const auto hash_function =
            get_cstring(data, offset + luks_hash_function_offset, luks_string_field_length);
        if(hash_function.empty()) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_medium;

        if(*version == 1) {
            const auto cipher_algorithm =
                get_cstring(data, offset + luks_cipher_algorithm_offset, luks_string_field_length);
            const auto cipher_mode =
                get_cstring(data, offset + luks_cipher_mode_offset, luks_string_field_length);
            if(cipher_algorithm.empty() || cipher_mode.empty()) {
                return std::nullopt;
            }
            result.description = "LUKS header, version: 1, cipher algorithm: " + cipher_algorithm
                + ", cipher mode: " + cipher_mode + ", hash fn: " + hash_function;
            return result;
        }

        if(*version == 2) {
            const auto available = static_cast<std::uint64_t>(data.size() - offset);
            if(*header_size <= luks2_minimum_header_size || *header_size >= available) {
                return std::nullopt;
            }
            result.description = "LUKS header, version: 2, header size: "
                + std::to_string(*header_size) + " bytes, hash fn: " + hash_function;
            return result;
        }

        return std::nullopt;
    }
};

template<>
struct format_traits<dpapi_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = true;

    static std::string name() { return "dpapi"; }
    static std::string description() { return "DPAPI blob data"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x01, 0x00, 0x00, 0x00, 0xD0, 0x8c, 0x9d, 0xdf, 0x01, 0x15,
                 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static const std::vector<std::uint8_t> blob_magic{
            0x01, 0x00, 0x00, 0x00, 0xD0, 0x8c, 0x9d, 0xdf, 0x01, 0x15,
            0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb
        };
        if(!bytes_equal(data, offset, blob_magic)) {
            return std::nullopt;
        }

        constexpr std::size_t provider_id_offset = 4;
        constexpr std::size_t master_key_version_offset = 20;
        constexpr std::size_t master_key_id_offset = 24;
        constexpr std::size_t flags_offset = 40;
        constexpr std::size_t description_length_offset = 44;
        constexpr std::size_t fixed_prefix_length = 48;
        constexpr std::size_t guid_length = 16;

        binary_reader<byte_order::little> reader(data);
        const auto version = reader.read<std::uint32_t>(offset);
        const auto master_key_version = reader.read<std::uint32_t>(offset + master_key_version_offset);
        const auto flags = reader.read<std::uint32_t>(offset + flags_offset);
        const auto description_length =
            reader.read<std::uint32_t>(offset + description_length_offset);
        if(!version || !master_key_version || !flags || !description_length) {
            return std::nullopt;
        }

        if((*description_length % 2) != 0) {
            return std::nullopt;
        }

        std::size_t cursor = offset;
        if(!advance(data, cursor, fixed_prefix_length)
            || !advance(data, cursor, *description_length)) {
            return std::nullopt;
        }

        const auto crypto_algorithm = reader.read<std::uint32_t>(cursor);
        const auto crypto_algorithm_length = reader.read<std::uint32_t>(cursor + 4);
        const auto salt_length = reader.read<std::uint32_t>(cursor + 8);
        if(!crypto_algorithm || !crypto_algorithm_length || !salt_length) {
            return std::nullopt;
        }
        if(!advance(data, cursor, 12U) || !advance(data, cursor, *salt_length)) {
            return std::nullopt;
        }

        const auto hmac_key_length = reader.read<std::uint32_t>(cursor);
        if(!hmac_key_length) {
            return std::nullopt;
        }
        if(!advance(data, cursor, 4U) || !advance(data, cursor, *hmac_key_length)) {
            return std::nullopt;
        }

        const auto hash_algorithm = reader.read<std::uint32_t>(cursor);
        const auto hash_algorithm_length = reader.read<std::uint32_t>(cursor + 4);
        const auto hmac2_key_length = reader.read<std::uint32_t>(cursor + 8);
        if(!hash_algorithm || !hash_algorithm_length || !hmac2_key_length) {
            return std::nullopt;
        }
        if(!advance(data, cursor, 12U) || !advance(data, cursor, *hmac2_key_length)) {
            return std::nullopt;
        }

        const auto data_length = reader.read<std::uint32_t>(cursor);
        if(!data_length) {
            return std::nullopt;
        }
        if(!advance(data, cursor, 4U) || !advance(data, cursor, *data_length)) {
            return std::nullopt;
        }

        const auto signature_length = reader.read<std::uint32_t>(cursor);
        if(!signature_length) {
            return std::nullopt;
        }
        if(!advance(data, cursor, 4U) || !advance(data, cursor, *signature_length)) {
            return std::nullopt;
        }

        const auto blob_size = static_cast<std::uint64_t>(cursor - offset);

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_medium;
        result.description = "DPAPI blob data, header size: " + std::to_string(dpapi_header_size)
            + " bytes, blob size: " + std::to_string(blob_size)
            + " bytes, version: " + std::to_string(*version)
            + ", provider ID: " + to_hex_bytes(data, offset + provider_id_offset, guid_length)
            + ", master key version: " + std::to_string(*master_key_version)
            + ", master key ID: " + to_hex_bytes(data, offset + master_key_id_offset, guid_length)
            + ", flags: " + std::to_string(*flags)
            + ", description length: " + std::to_string(*description_length)
            + ", crypto algorithm: " + to_hex(*crypto_algorithm, 8)
            + ", crypto algorithm length: " + std::to_string(*crypto_algorithm_length)
            + ", salt length: " + std::to_string(*salt_length)
            + ", HMAC key length: " + std::to_string(*hmac_key_length)
            + ", hash algorithm: " + to_hex(*hash_algorithm, 8)
            + ", hash algorithm length: " + std::to_string(*hash_algorithm_length)
            + ", HMAC2 key length: " + std::to_string(*hmac2_key_length)
            + ", data length: " + std::to_string(*data_length)
            + ", signature length: " + std::to_string(*signature_length);
        return result;
    }
};

namespace formats {

std::vector<signature> b3_constants_signatures() {
    return make_signatures(type_list<
        crc32_format,
        sha256_format,
        md5_format,
        aes_sbox_format,
        aes_forward_table_format,
        aes_reverse_table_format,
        aes_rcon_format,
        aes_acceleration_table_format,
        pkcs_der_hash_format,
        rsa_format,
        luks_format,
        dpapi_format
    >{});
}

}
}
