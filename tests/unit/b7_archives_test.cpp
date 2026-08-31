
#include "../../lib/src/formats/b7_archives.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
namespace {

using bytes = std::vector<std::uint8_t>;

const std::vector<binwalk::signature>& batch() {
    static const std::vector<binwalk::signature> signatures =
        binwalk::formats::b7_archives_signatures();
    return signatures;
}

const binwalk::signature* signature_named(const std::string& name) {
    for(const auto& value : batch()) {
        if(value.name == name) {
            return &value;
        }
    }
    return nullptr;
}

const std::vector<std::string>& batch_names() {
    static const std::vector<std::string> names{
        "deb", "tarball", "cpio", "arj", "iso9660", "cab", "rar",
        "matter_ota", "srecord", "srecord_generic", "7zip", "zip"
    };
    return names;
}

const std::vector<std::string>& upstream_registration_order() {
    static const std::vector<std::string> names{
        "gzip", "deb", "7zip", "xz", "tarball", "squashfs", "dlob", "lzma",
        "bmp", "bzip2", "uimage", "packimg", "crc32", "sha256", "cpio",
        "iso9660", "linux_kernel", "linux_boot_image", "linux_arm_zimage",
        "zstd", "zip", "pchrom", "uefi_pi_volume", "uefi_capsule", "pdf",
        "elf", "cramfs", "qnx_ifs", "romfs", "ext", "cab", "jffs2", "yaffs",
        "lz4", "lzop", "pe", "zlib", "gpg_signed", "pem_certificate",
        "pem_public_key", "pem_private_key", "chk", "trx", "srecord",
        "srecord_generic", "android_sparse", "dtb", "ubi", "ubifs", "cfe",
        "seama", "compressd", "rar", "png", "jpeg", "arcadyan", "copyright",
        "wind_kernel", "vxworks_symtab", "ecos", "dmg", "riff", "openssl",
        "lzfse", "mbr", "tplink", "pjl", "jboot_arm", "jboot_stag",
        "jboot_sch2", "pcapng", "rsa", "gif", "svg", "linux_arm64_boot_image",
        "fat", "efigpt", "rtk", "aes_sbox", "aes_forward_table",
        "aes_reverse_table", "aes_rcon", "aes_acceleration_table", "luks",
        "tplink_rtos", "binhdr", "autel", "ntfs", "apfs", "btrfs", "wince",
        "dahua_zip", "mh01", "csman", "dxbc", "dlink_tlv", "dlke", "shrs",
        "pkcs_der_hash", "logfs", "encrpted_img", "android_bootimg", "uboot",
        "dms", "dkbs", "encfw", "matter_ota", "dpapi", "qcow", "arj", "md5"
    };
    return names;
}

void put_bytes(bytes& out, std::initializer_list<std::uint8_t> values) {
    out.insert(out.end(), values.begin(), values.end());
}

void put_ascii(bytes& out, std::string_view text) {
    for(const char character : text) {
        out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
}

void put_u16_le(bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU));
}

void put_u32_le(bytes& out, std::uint32_t value) {
    for(unsigned index = 0; index < 4U; ++index) {
        out.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU));
    }
}

void put_u64_le(bytes& out, std::uint64_t value) {
    for(unsigned index = 0; index < 8U; ++index) {
        out.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU));
    }
}

void put_ascii_hex8(bytes& out, std::uint32_t value) {
    static const char digits[] = "0123456789ABCDEF";
    for(int shift = 28; shift >= 0; shift -= 4) {
        const auto nibble = static_cast<std::size_t>(
            (value >> static_cast<unsigned>(shift)) & 0xFU
        );
        out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(digits[nibble])));
    }
}

bytes junk(std::size_t length, std::uint8_t fill = 0xA5) {
    return bytes(length, fill);
}

std::size_t absurd_offset() {
    return ((std::numeric_limits<std::size_t>::max)() / 2U) + 1U;
}

void append(bytes& out, const bytes& tail) {
    out.insert(out.end(), tail.begin(), tail.end());
}

bytes registered_magic(const std::string& name, std::size_t index = 0) {
    const auto* value = signature_named(name);
    if(value == nullptr || value->magic.size() <= index) {
        return {};
    }
    return value->magic[index];
}

bytes magic_then_junk(const std::string& name, std::size_t junk_length, std::size_t index = 0) {
    bytes data = registered_magic(name, index);
    append(data, junk(junk_length));
    return data;
}

binwalk::byte_view view(const bytes& data) {
    return binwalk::byte_view(data.data(), data.size());
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

void expect_rejected(
    const std::string& name,
    const bytes& data,
    std::size_t offset,
    std::string_view why
) {
    SCOPED_TRACE(name + " @ offset " + std::to_string(offset) + ": " + std::string(why));
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b7_archives_signatures()";
    ASSERT_NE(value->parser, nullptr) << name << " has a null parser";

    const auto result = value->parser(view(data), offset);
    EXPECT_FALSE(result.has_value())
        << name << " accepted a malformed buffer (" << why << "). Contract §5 makes a "
        << "required rejection as strict as a required detection.";
}

std::optional<binwalk::signature_result> parse_at(
    const std::string& name,
    const bytes& data,
    std::size_t offset
) {
    const auto* value = signature_named(name);
    if(value == nullptr || value->parser == nullptr) {
        return std::nullopt;
    }
    return value->parser(view(data), offset);
}

const binwalk::scanner& batch_scanner() {
    static const binwalk::scanner value(binwalk::formats::b7_archives_signatures());
    return value;
}

std::optional<binwalk::signature_result> scan_for(const std::string& name, const bytes& data) {
    for(const auto& result : batch_scanner().scan(view(data))) {
        if(result.name == name) {
            return result;
        }
    }
    return std::nullopt;
}

bytes zip_local_entry(std::string_view file_name, const bytes& payload) {
    bytes out;
    put_bytes(out, {'P', 'K', 0x03, 0x04});
    put_u16_le(out, 20);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0x0021);
    put_u32_le(out, 0);
    put_u32_le(out, static_cast<std::uint32_t>(payload.size()));
    put_u32_le(out, static_cast<std::uint32_t>(payload.size()));
    put_u16_le(out, static_cast<std::uint16_t>(file_name.size()));
    put_u16_le(out, 0);
    put_ascii(out, file_name);
    append(out, payload);
    return out;
}

bytes zip_central_directory_entry(std::string_view file_name, const bytes& payload) {
    bytes out;
    put_bytes(out, {'P', 'K', 0x01, 0x02});
    put_u16_le(out, 20);
    put_u16_le(out, 20);
    put_u16_le(out, 0x000A);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0x0021);
    put_u32_le(out, 0);
    put_u32_le(out, static_cast<std::uint32_t>(payload.size()));
    put_u32_le(out, static_cast<std::uint32_t>(payload.size()));
    put_u16_le(out, static_cast<std::uint16_t>(file_name.size()));
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u32_le(out, 0);
    put_u32_le(out, 0);
    put_ascii(out, file_name);
    return out;
}

bytes zip_without_eocd(std::size_t& chain_end) {
    const bytes payload_a{'h', 'e', 'l', 'l', 'o', '\n'};
    const bytes payload_b{'w', 'o', 'r', 'l', 'd', '!', '\n'};

    bytes out;
    append(out, zip_local_entry("a.txt", payload_a));
    append(out, zip_local_entry("b.txt", payload_b));
    chain_end = out.size();

    append(out, zip_central_directory_entry("a.txt", payload_a));

    return out;
}

bytes cab_header(std::uint16_t flags, std::uint32_t cabinet_size) {
    bytes out;
    put_bytes(out, {'M', 'S', 'C', 'F'});
    put_u32_le(out, 0);
    put_u32_le(out, cabinet_size);
    put_u32_le(out, 0);
    put_u32_le(out, 36);
    put_u32_le(out, 0);
    out.push_back(3);
    out.push_back(1);
    put_u16_le(out, 1);
    put_u16_le(out, 1);
    put_u16_le(out, flags);
    put_u16_le(out, 0x1234);
    put_u16_le(out, 0);
    return out;
}

bytes cpio_newc_header(
    std::string_view magic,
    std::uint32_t name_size,
    std::uint32_t file_size,
    std::string_view name
) {
    bytes out;
    put_ascii(out, magic);
    put_ascii_hex8(out, 1);
    put_ascii_hex8(out, 0x000081A4);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, 1);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, file_size);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, 0);
    put_ascii_hex8(out, name_size);
    put_ascii_hex8(out, 0);
    put_ascii(out, name);
    return out;
}

bytes matter_ota_fixed_header(std::uint64_t total_size, std::uint32_t header_size) {
    bytes out;
    put_bytes(out, {0x1E, 0xF1, 0xEE, 0x1B});
    put_u64_le(out, total_size);
    put_u32_le(out, header_size);
    return out;
}

bytes matter_ota_tlv(
    std::uint16_t vendor_id,
    std::uint16_t product_id,
    std::uint32_t software_version,
    std::string_view version_string,
    std::uint64_t payload_size,
    std::uint8_t digest_type,
    const bytes& digest
) {
    bytes out;
    out.push_back(0x15);
    put_bytes(out, {0x25, 0x00}); put_u16_le(out, vendor_id);
    put_bytes(out, {0x25, 0x01}); put_u16_le(out, product_id);
    put_bytes(out, {0x26, 0x02}); put_u32_le(out, software_version);
    put_bytes(out, {0x2C, 0x03});
    out.push_back(static_cast<std::uint8_t>(version_string.size()));
    put_ascii(out, version_string);
    put_bytes(out, {0x27, 0x04}); put_u64_le(out, payload_size);
    put_bytes(out, {0x24, 0x08}); out.push_back(digest_type);
    put_bytes(out, {0x30, 0x09});
    out.push_back(static_cast<std::uint8_t>(digest.size()));
    append(out, digest);
    out.push_back(0x18);
    return out;
}

bytes matter_ota_image(const bytes& tlv, const bytes& payload) {
    bytes out;
    put_bytes(out, {0x1E, 0xF1, 0xEE, 0x1B});
    put_u64_le(
        out,
        static_cast<std::uint64_t>(16U + tlv.size() + payload.size())
    );
    put_u32_le(out, static_cast<std::uint32_t>(tlv.size()));
    append(out, tlv);
    append(out, payload);
    return out;
}

const bytes& matter_ota_test_payload() {
    static const bytes payload{'P', 'A', 'Y', 'L', 'O', 'A', 'D', '!'};
    return payload;
}

bytes matter_ota_test_digest() {
    bytes digest;
    for(unsigned index = 1; index <= 32U; ++index) {
        digest.push_back(static_cast<std::uint8_t>(index));
    }
    return digest;
}

std::string to_lowercase_hex(const bytes& data) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for(const std::uint8_t value : data) {
        out.push_back(digits[static_cast<std::size_t>(value >> 4U)]);
        out.push_back(digits[static_cast<std::size_t>(value & 0x0FU)]);
    }
    return out;
}

void write_arj_header(
    bytes& out,
    std::size_t start,
    std::uint8_t first_hdr_size,
    std::uint8_t archiver_version,
    std::uint8_t minimum_version,
    std::uint8_t host_os,
    std::uint8_t internal_flags,
    std::uint8_t compression_method,
    std::uint8_t file_type,
    std::uint32_t datetime,
    std::uint32_t compressed_size,
    std::uint32_t original_size,
    std::string_view original_name
) {
    bytes record;
    put_bytes(record, {0x60, 0xEA});
    put_u16_le(record, first_hdr_size);
    record.push_back(first_hdr_size);
    record.push_back(archiver_version);
    record.push_back(minimum_version);
    record.push_back(host_os);
    record.push_back(internal_flags);
    record.push_back(compression_method);
    record.push_back(file_type);
    record.push_back(0);
    put_u32_le(record, datetime);
    put_u32_le(record, compressed_size);
    put_u32_le(record, original_size);

    std::copy(record.begin(), record.end(), out.begin() + static_cast<std::ptrdiff_t>(start));

    const std::size_t name_offset = start + first_hdr_size + 4U;
    for(std::size_t index = 0; index < original_name.size(); ++index) {
        out[name_offset + index] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(original_name[index]));
    }
    out[name_offset + original_name.size()] = 0x00;
}

bytes arj_two_header_image() {
    bytes out(160, 0x00);
    write_arj_header(out, 0, 34, 11, 1, 2, 0x10, 0, 2, 1740322142U, 1740322564U, 0,
                     "example.arj");
    write_arj_header(out, 70, 46, 11, 1, 2, 0x10, 1, 0, 1740322561U, 54U, 60U,
                     "secret.txt");
    return out;
}

void write_ascii_at(bytes& out, std::size_t at, std::string_view text) {
    for(std::size_t index = 0; index < text.size(); ++index) {
        out[at + index] = static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    }
}

void write_u16_le_at(bytes& out, std::size_t at, std::uint16_t value) {
    out[at] = static_cast<std::uint8_t>(value & 0xFFU);
    out[at + 1] = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU);
}

void write_u16_be_at(bytes& out, std::size_t at, std::uint16_t value) {
    out[at] = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU);
    out[at + 1] = static_cast<std::uint8_t>(value & 0xFFU);
}

void write_u32_le_at(bytes& out, std::size_t at, std::uint32_t value) {
    for(unsigned index = 0; index < 4U; ++index) {
        out[at + index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
}

void write_u32_be_at(bytes& out, std::size_t at, std::uint32_t value) {
    for(unsigned index = 0; index < 4U; ++index) {
        out[at + index] =
            static_cast<std::uint8_t>((value >> ((3U - index) * 8U)) & 0xFFU);
    }
}

void put_space_padded(bytes& out, std::string_view text, std::size_t width) {
    put_ascii(out, text);
    for(std::size_t index = text.size(); index < width; ++index) {
        out.push_back(0x20);
    }
}

bytes ar_member_header(std::string_view name, std::string_view size_text) {
    bytes out;
    put_space_padded(out, name, 16);
    put_space_padded(out, "0", 12);
    put_space_padded(out, "0", 6);
    put_space_padded(out, "0", 6);
    put_space_padded(out, "100644", 8);
    put_space_padded(out, size_text, 10);
    put_bytes(out, {0x60, 0x0A});
    return out;
}

bytes deb_image() {
    bytes out;
    put_ascii(out, "!<arch>\n");
    append(out, ar_member_header("debian-binary", "4"));
    put_ascii(out, "2.0\n");
    append(out, ar_member_header("control.tar.gz", "8"));
    for(std::uint8_t value = 1; value <= 8; ++value) {
        out.push_back(value);
    }
    append(out, ar_member_header("data.tar.gz", "8"));
    for(std::uint8_t value = 9; value <= 16; ++value) {
        out.push_back(value);
    }
    return out;
}

bytes tar_header_block(std::string_view name) {
    bytes block(512, 0x00);
    write_ascii_at(block, 0, name);
    write_ascii_at(block, 100, "0000644");
    write_ascii_at(block, 108, "0000000");
    write_ascii_at(block, 116, "0000000");
    write_ascii_at(block, 124, "00000000012");
    write_ascii_at(block, 136, "00000000000");
    for(std::size_t index = 148; index < 156; ++index) {
        block[index] = 0x20;
    }
    block[156] = static_cast<std::uint8_t>('0');
    write_ascii_at(block, 257, "ustar");
    write_ascii_at(block, 263, "00");
    write_ascii_at(block, 265, "root");
    write_ascii_at(block, 297, "root");

    unsigned checksum = 0;
    for(const std::uint8_t value : block) {
        checksum += value;
    }
    for(int digit = 5; digit >= 0; --digit) {
        block[148U + static_cast<std::size_t>(digit)] =
            static_cast<std::uint8_t>(static_cast<unsigned char>('0' + (checksum & 7U)));
        checksum >>= 3U;
    }
    block[154] = 0x00;
    block[155] = 0x20;
    return block;
}

bytes tar_image(std::size_t entry_count) {
    bytes out;
    for(std::size_t index = 0; index < entry_count; ++index) {
        append(out, tar_header_block("file" + std::to_string(index) + ".txt"));
        bytes data(512, 0x00);
        write_ascii_at(data, 0, "hello tar!");
        append(out, data);
    }
    append(out, junk(1024, 0x00));
    return out;
}

bytes cpio_newc_entry(std::string_view magic, std::string_view name, const bytes& data) {
    bytes out = cpio_newc_header(
        magic,
        static_cast<std::uint32_t>(name.size() + 1U),
        static_cast<std::uint32_t>(data.size()),
        name
    );
    out.push_back(0x00);
    while(out.size() % 4U != 0U) {
        out.push_back(0x00);
    }
    append(out, data);
    while(out.size() % 4U != 0U) {
        out.push_back(0x00);
    }
    return out;
}

bytes cpio_image() {
    bytes out = cpio_newc_entry("070701", "hello.txt", bytes{'w', 'o', 'r', 'l', 'd'});
    append(out, cpio_newc_entry("070701", "TRAILER!!!", bytes{}));
    return out;
}

bytes iso9660_image() {
    constexpr std::size_t pvd = 32768;
    constexpr std::uint32_t volume_blocks = 17;
    constexpr std::uint16_t block_size = 2048;

    bytes out(static_cast<std::size_t>(volume_blocks) * block_size, 0x00);
    out[pvd] = 0x01;
    write_ascii_at(out, pvd + 1, "CD001");
    out[pvd + 6] = 0x01;
    out[pvd + 7] = 0x00;
    for(std::size_t index = pvd + 8; index < pvd + 72; ++index) {
        out[index] = 0x20;
    }
    write_u32_le_at(out, pvd + 80, volume_blocks);
    write_u32_be_at(out, pvd + 84, volume_blocks);
    write_u16_le_at(out, pvd + 120, 1);
    write_u16_be_at(out, pvd + 122, 1);
    write_u16_le_at(out, pvd + 124, 1);
    write_u16_be_at(out, pvd + 126, 1);
    write_u16_le_at(out, pvd + 128, block_size);
    write_u16_be_at(out, pvd + 130, block_size);
    write_u32_le_at(out, pvd + 132, 10);
    write_u32_be_at(out, pvd + 136, 10);
    return out;
}

bytes cab_image() {
    bytes out(64, 0x00);
    write_ascii_at(out, 0, "MSCF");
    write_u32_le_at(out, 8, 64);
    write_u32_le_at(out, 16, 44);
    out[24] = 3;
    out[25] = 1;
    write_u16_le_at(out, 26, 1);
    write_u16_le_at(out, 28, 1);
    write_u16_le_at(out, 30, 0);
    write_u16_le_at(out, 32, 0x1234);
    return out;
}

const bytes& rar_v5_end_marker() {
    static const bytes marker{0x1D, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00};
    return marker;
}

const bytes& rar_v4_end_marker() {
    static const bytes marker{0xC4, 0x3D, 0x7B, 0x00, 0x40, 0x07, 0x00};
    return marker;
}

bytes rar_image(std::uint8_t version_byte, const bytes& end_marker) {
    bytes out;
    put_bytes(out, {'R', 'a', 'r', '!', 0x1A, 0x07});
    out.push_back(version_byte);
    append(out, junk(16, 0x00));
    append(out, end_marker);
    return out;
}

bytes seven_zip_image() {
    const bytes next_header{'A', 'B', 'C', 'D'};

    bytes start_header;
    put_u64_le(start_header, 0);
    put_u64_le(start_header, next_header.size());
    put_u32_le(start_header, binwalk::crc32(binwalk::byte_view(next_header)));

    bytes out;
    put_bytes(out, {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C});
    out.push_back(0);
    out.push_back(4);
    put_u32_le(out, binwalk::crc32(binwalk::byte_view(start_header)));
    append(out, start_header);
    append(out, next_header);
    return out;
}

bytes zip_reference_local_entry() {
    bytes out;
    put_bytes(out, {'P', 'K', 0x03, 0x04});
    put_u16_le(out, 10);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0x2821);
    put_u32_le(out, 0x3610A686U);
    put_u32_le(out, 5);
    put_u32_le(out, 5);
    put_u16_le(out, 5);
    put_u16_le(out, 0);
    put_ascii(out, "a.txt");
    put_ascii(out, "hello");
    return out;
}

bytes zip_reference_central_directory() {
    bytes out;
    put_bytes(out, {'P', 'K', 0x01, 0x02});
    put_u16_le(out, 20);
    put_u16_le(out, 10);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0x2821);
    put_u32_le(out, 0x3610A686U);
    put_u32_le(out, 5);
    put_u32_le(out, 5);
    put_u16_le(out, 5);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u32_le(out, 0);
    put_u32_le(out, 0);
    put_ascii(out, "a.txt");
    return out;
}

bytes zip_reference_eocd() {
    bytes out;
    put_bytes(out, {'P', 'K', 0x05, 0x06});
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 1);
    put_u16_le(out, 1);
    put_u32_le(out, 51);
    put_u32_le(out, 40);
    put_u16_le(out, 0);
    return out;
}

std::optional<bytes> read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return std::nullopt;
    }
    const std::string text(
        (std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>()
    );
    bytes out;
    out.reserve(text.size());
    for(const char character : text) {
        out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    return out;
}

std::optional<std::filesystem::path> find_file_named(
    const std::filesystem::path& directory,
    std::string_view file_name
) {
    std::error_code error;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        if(iterator->path().filename().string() == file_name) {
            return iterator->path();
        }
    }
    return std::nullopt;
}

std::size_t count_entries(const std::filesystem::path& directory) {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        ++count;
    }
    return count;
}

bool stray_extraction_output_in_working_directory() {
    std::error_code error;
    const auto here = std::filesystem::current_path(error);
    if(error) {
        return false;
    }
    for(const char* const name : {"matter_payload.bin", "matter_ota.bin"}) {
        std::error_code probe;
        if(std::filesystem::exists(here / name, probe)) {
            return true;
        }
    }
    return false;
}

bytes arj_basic_header(std::uint8_t archiver_version) {
    bytes out;
    put_bytes(out, {0x60, 0xEA});
    put_u16_le(out, 34);
    out.push_back(34);
    out.push_back(archiver_version);
    out.push_back(1);
    out.push_back(2);
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    put_u32_le(out, 0);
    put_u32_le(out, 0);
    put_u32_le(out, 0);
    put_u32_le(out, 0);
    put_u16_le(out, 0);
    put_u16_le(out, 0);
    out.push_back(0);
    out.push_back(0);
    return out;
}

void expect_seven_zip_definition(const std::string& name, const std::string& extension) {
    SCOPED_TRACE("sevenzip_extractor() for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b7_archives_signatures()";
    ASSERT_TRUE(value->extractor_definition.has_value())
        << name << " declares NO extractor. Upstream magic.rs gives it sevenzip_extractor(); "
        << "without it the format is detected and then never extracted, which is exactly the "
        << "gap this batch exists to close.";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr)
        << "an external definition must not carry an internal function pointer";
    EXPECT_EQ(definition.command, "7zz");
    EXPECT_EQ(definition.extension, extension);
    EXPECT_EQ(definition.arguments, (std::vector<std::string>{"x", "-y", "-o.", "-p''", "%e"}));
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0, 2}));
    EXPECT_FALSE(definition.do_not_recurse);
}

void expect_srec_cat_definition(const std::string& name) {
    SCOPED_TRACE("srec_cat extractor for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b7_archives_signatures()";
    ASSERT_TRUE(value->extractor_definition.has_value()) << name << " declares no extractor";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr);
    EXPECT_EQ(definition.command, "srec_cat");
    EXPECT_EQ(definition.extension, "hex");
    EXPECT_EQ(
        definition.arguments,
        (std::vector<std::string>{"-output", "s-record.bin", "-binary", "%e"})
    );
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0}));
}

}

TEST(B7ArchivesRegistry, DeclaresExactlyTheTwelveExpectedNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "b7_archives registers \"" << value.name << "\" more than once";
    }
    const std::set<std::string> expected(batch_names().begin(), batch_names().end());

    for(const auto& name : expected) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b7_archives does not register \"" << name << "\"";
    }
    for(const auto& name : produced) {
        EXPECT_EQ(expected.count(name), std::size_t{1})
            << "b7_archives registers \"" << name << "\", which is not one of this batch's "
            << "twelve formats. Either the name is misspelled or the signature belongs to "
            << "another batch.";
    }
    EXPECT_EQ(batch().size(), std::size_t{12});
}

TEST(B7ArchivesRegistry, EveryNameIsInTheFrozenUpstreamOrderTable) {
    const auto& table = upstream_registration_order();
    ASSERT_EQ(table.size(), std::size_t{111})
        << "the transcribed magic.rs order table is not 111 entries long";
    const std::set<std::string> unique(table.begin(), table.end());
    ASSERT_EQ(unique.size(), table.size()) << "the transcribed table has a duplicate";

    for(const auto& value : batch()) {
        EXPECT_NE(std::find(table.begin(), table.end(), value.name), table.end())
            << "signature name \"" << value.name << "\" produced by b7_archives is NOT in "
            << "upstream magic.rs's 111-entry registry order table. It would sort silently "
            << "to the end of the registry and drop out of --include/--exclude and out of "
            << "every oracle diff. Fix the name in b7_archives; do NOT extend the table.";
    }
}

TEST(B7ArchivesRegistry, TheTwelveExpectedNamesAreThemselvesInTheOrderTable) {
    const auto& table = upstream_registration_order();
    for(const auto& name : batch_names()) {
        EXPECT_NE(std::find(table.begin(), table.end(), name), table.end())
            << "this test file's own spelling of \"" << name << "\" is not in the frozen "
            << "table, so the expectation itself is wrong";
    }
}

TEST(B7ArchivesRegistry, EverySignatureHasAParserMagicAndDescription) {
    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_NE(value.parser, nullptr) << value.name << " has a null parser";
        EXPECT_FALSE(value.magic.empty()) << value.name << " declares no magic pattern";
        for(std::size_t index = 0; index < value.magic.size(); ++index) {
            EXPECT_FALSE(value.magic[index].empty())
                << value.name << " magic pattern " << index << " is empty, which would match "
                << "at every offset in every file";
        }
        EXPECT_FALSE(value.description.empty()) << value.name << " has an empty description";
    }
}

TEST(B7ArchivesRegistry, EveryNameReachesTheAggregatedRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [&name](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "\"" << name << "\" is produced by b7_archives_signatures() but does not "
            << "appear in binwalk::builtin_signatures(); the aggregator dropped it";
    }
}

TEST(B7ArchivesMetadata, ShortSignatureAndAlwaysDisplayFlagsMatchUpstream) {
    struct expectation {
        const char* name;
        bool short_signature;
        bool always_display;
        std::size_t magic_offset;
    };

    const expectation expectations[] = {
        {"deb",             false, false, 0},
        {"tarball",         false, false, 0},
        {"cpio",            false, false, 0},
        {"arj",             false, false, 0},
        {"iso9660",         false, false, 0},
        {"cab",             false, false, 0},
        {"rar",             false, false, 0},
        {"matter_ota",      true,  false, 0},
        {"srecord",         false, false, 0},
        {"srecord_generic", true,  false, 0},
        {"7zip",            false, false, 0},
        {"zip",             false, false, 0}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name << " is not registered";
        EXPECT_EQ(value->short_signature, expected.short_signature)
            << expected.name << ": short_signature disagrees with magic.rs";
        EXPECT_EQ(value->always_display, expected.always_display)
            << expected.name << ": always_display disagrees with magic.rs";
        EXPECT_EQ(value->magic_offset, expected.magic_offset)
            << expected.name << ": magic_offset disagrees with magic.rs";
    }
}

TEST(B7ArchivesMetadata, SrecordGenericAndMatterOtaAreTheOnlyShortSignatures) {
    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        const bool expected = value.name == "srecord_generic" || value.name == "matter_ota";
        EXPECT_EQ(value.short_signature, expected)
            << value.name << ": short_signature gates the scanner's short-pattern handling. "
            << "`S0` is two bytes and matter_ota's magic is four, so those two are short and "
            << "the other ten are not.";
    }
}

TEST(B7ArchivesMetadata, NoSignatureInThisBatchSetsAlwaysDisplay) {

    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_FALSE(value.always_display)
            << value.name << " sets always_display, but no entry in this batch does in "
            << "upstream magic.rs";
    }
}

TEST(B7ArchivesMagic, SingleMagicPatternsMatchUpstream) {
    struct expectation {
        const char* name;
        bytes magic;
    };
    const std::vector<expectation> expectations{

        {"deb", bytes{
            '!', '<', 'a', 'r', 'c', 'h', '>', 0x0A,
            'd', 'e', 'b', 'i', 'a', 'n', '-', 'b', 'i', 'n', 'a', 'r', 'y',
            0x20, 0x20, 0x20
        }},
        {"7zip", bytes{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}},
        {"iso9660", bytes{0x01, 'C', 'D', '0', '0', '1', 0x01, 0x00}},
        {"zip", bytes{'P', 'K', 0x03, 0x04}},
        {"cab", bytes{'M', 'S', 'C', 'F', 0x00, 0x00, 0x00, 0x00}},
        {"srecord", bytes{
            'S', '0', '0', '6', '0', '0', '0', '0', '4', '8', '4', '4', '5', '2', '1', 'B'
        }},
        {"srecord_generic", bytes{'S', '0'}},
        {"rar", bytes{'R', 'a', 'r', '!', 0x1A, 0x07}},
        {"matter_ota", bytes{0x1E, 0xF1, 0xEE, 0x1B}},
        {"arj", bytes{0x60, 0xEA}}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name << " is not registered";
        ASSERT_EQ(value->magic.size(), std::size_t{1})
            << expected.name << " must declare exactly one magic pattern";
        EXPECT_EQ(value->magic[0], expected.magic)
            << expected.name << ": magic bytes disagree with upstream magic.rs";
    }
}

TEST(B7ArchivesMagic, TarballDeclaresBothUstarVariants) {
    const auto* value = signature_named("tarball");
    ASSERT_NE(value, nullptr);
    ASSERT_EQ(value->magic.size(), std::size_t{2})
        << "tarball must declare both the POSIX and the old GNU ustar variants";

    const bytes posix{'u', 's', 't', 'a', 'r', 0x00};
    const bytes gnu{'u', 's', 't', 'a', 'r', 0x20, 0x20, 0x00};
    EXPECT_NE(std::find(value->magic.begin(), value->magic.end(), posix), value->magic.end())
        << R"(tarball is missing the "ustar\x00" pattern)";
    EXPECT_NE(std::find(value->magic.begin(), value->magic.end(), gnu), value->magic.end())
        << R"(tarball is missing the "ustar\x20\x20\x00" pattern)";
}

TEST(B7ArchivesMagic, CpioDeclaresBothNewAsciiVariants) {
    const auto* value = signature_named("cpio");
    ASSERT_NE(value, nullptr);
    ASSERT_EQ(value->magic.size(), std::size_t{2})
        << "cpio must declare both 070701 (newc) and 070702 (newc with CRC)";

    const bytes newc{'0', '7', '0', '7', '0', '1'};
    const bytes newc_crc{'0', '7', '0', '7', '0', '2'};
    EXPECT_NE(std::find(value->magic.begin(), value->magic.end(), newc), value->magic.end())
        << "cpio is missing the 070701 pattern";
    EXPECT_NE(std::find(value->magic.begin(), value->magic.end(), newc_crc), value->magic.end())
        << "cpio is missing the 070702 pattern";
}

TEST(B7ArchivesExtractors, SevenZipAndZipDeclareTheSevenZipExtractor) {

    expect_seven_zip_definition("7zip", "bin");
    expect_seven_zip_definition("zip", "bin");
}

TEST(B7ArchivesExtractors, CpioAndArjAlsoShareTheSevenZipExtractor) {
    expect_seven_zip_definition("cpio", "bin");
    expect_seven_zip_definition("arj", "bin");
}

TEST(B7ArchivesExtractors, Iso9660UsesTheSevenZipExtractorWithAnIsoExtension) {

    expect_seven_zip_definition("iso9660", "iso");
}

TEST(B7ArchivesExtractors, TheFiveSevenZipDeclarersAgreeOnEveryFieldButExtension) {
    const char* const names[] = {"7zip", "zip", "cpio", "arj", "iso9660"};
    const binwalk::extractor* reference = nullptr;
    for(const char* const name : names) {
        SCOPED_TRACE(name);
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value());
        const auto& definition = *value->extractor_definition;
        if(reference == nullptr) {
            reference = &definition;
            continue;
        }
        EXPECT_EQ(definition.type, reference->type);
        EXPECT_EQ(definition.command, reference->command);
        EXPECT_EQ(definition.arguments, reference->arguments);
        EXPECT_EQ(definition.exit_codes, reference->exit_codes);
        EXPECT_EQ(definition.do_not_recurse, reference->do_not_recurse);
        EXPECT_EQ(definition.internal, reference->internal);
    }
}

TEST(B7ArchivesExtractors, CabUsesCabextract) {
    const auto* value = signature_named("cab");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value()) << "cab declares no extractor";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr);
    EXPECT_EQ(definition.command, "cabextract");
    EXPECT_EQ(definition.extension, "cab");
    EXPECT_EQ(definition.arguments, (std::vector<std::string>{"%e"}));
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0}));
    EXPECT_FALSE(definition.do_not_recurse);
}

TEST(B7ArchivesExtractors, TarballUsesTar) {
    const auto* value = signature_named("tarball");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value()) << "tarball declares no extractor";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr);
    EXPECT_EQ(definition.command, "tar");
    EXPECT_EQ(definition.extension, "tar");
    EXPECT_EQ(definition.arguments, (std::vector<std::string>{"-x", "-f", "%e"}));
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0, 2}));
    EXPECT_FALSE(definition.do_not_recurse);
}

TEST(B7ArchivesExtractors, BothSrecordSignaturesUseSrecCat) {
    expect_srec_cat_definition("srecord");
    expect_srec_cat_definition("srecord_generic");
}

TEST(B7ArchivesExtractors, DebDeclaresNoExtractor) {
    const auto* value = signature_named("deb");
    ASSERT_NE(value, nullptr);
    EXPECT_FALSE(value->extractor_definition.has_value())
        << "upstream magic.rs declares None for deb; inventing an extractor here would "
        << "diverge from the oracle in the extraction-success column, which is STRICT "
        << "under contract §5.";
}

TEST(B7ArchivesExtractors, RarDeclaresTheExternalUnrarExtractor) {

    const auto* value = signature_named("rar");
    ASSERT_NE(value, nullptr);
    EXPECT_NE(value->parser, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "rar must declare the external unrar extractor (contract §7b). Removing it costs "
        << "full extraction parity on every machine that HAS unrar installed.";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr)
        << "unrar is a subprocess; nothing about RAR is implemented natively here";
    EXPECT_TRUE(definition.name.empty());
    EXPECT_EQ(definition.command, "unrar");
    EXPECT_EQ(definition.extension, "rar");
    EXPECT_EQ(definition.arguments, (std::vector<std::string>{"x", "-y", "-ppassword", "%e"}));
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0}));
    EXPECT_FALSE(definition.do_not_recurse);
}

TEST(B7ArchivesExtractors, RarExtractionWithoutUnrarReportsUtilityNotFound) {
    const auto* value = signature_named("rar");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;

    if(binwalk::external_utility_available(definition)) {
        GTEST_SKIP() << "unrar IS installed here, so the absent-utility path cannot be "
                     << "exercised; this test targets the machine without it";
    }

    const bytes data = rar_image(1, rar_v5_end_marker());
    const auto signature = parse_at("rar", data, 0);
    ASSERT_TRUE(signature.has_value());

    std::error_code error;
    auto base = std::filesystem::temp_directory_path(error);
    if(error) {
        base = std::filesystem::path(".");
    }
    const auto output_root = base / "binwalk_b7_rar_missing_utility";
    std::filesystem::remove_all(output_root, error);

    const auto result = binwalk::execute_extractor(
        view(data), "rar.bin", *signature, definition, output_root.string()
    );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::utility_not_found)
        << "a missing utility must be distinguishable from a utility that ran and rejected "
        << "the data (utility_failed) and from one that produced nothing (no_output). "
        << "Actual failure code: " << static_cast<int>(result.failure);

    std::filesystem::remove_all(output_root, error);
}

TEST(B7ArchivesExtractors, MatterOtaDeclaresTheInternalBuiltInExtractor) {
    const auto* value = signature_named("matter_ota");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "matter_ota must declare its internal extractor; upstream's is internal and the "
        << "signature parser dry-runs it as its validator (contract §1 rule 3)";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
    EXPECT_EQ(definition.name, "matter_ota_built_in");
    EXPECT_NE(definition.internal, nullptr)
        << "an internal extractor with a null function pointer can only ever report "
        << "extraction_failure::unsupported";
    EXPECT_TRUE(definition.command.empty())
        << "an internal extractor spawns nothing, so it must name no command";
    EXPECT_TRUE(definition.extension.empty());
    EXPECT_TRUE(definition.arguments.empty());
    EXPECT_TRUE(definition.exit_codes.empty());
    EXPECT_FALSE(definition.do_not_recurse);
}

TEST(B7ArchivesExtractors, PlaceholderIsAlwaysItsOwnWholeArgument) {

    const std::string placeholder = "%e";
    for(const auto& value : batch()) {
        if(!value.extractor_definition.has_value()) {
            continue;
        }
        SCOPED_TRACE(value.name);
        const auto& definition = *value.extractor_definition;
        std::size_t placeholder_count = 0;
        for(const auto& argument : definition.arguments) {
            if(argument == placeholder) {
                ++placeholder_count;
                continue;
            }
            EXPECT_EQ(argument.find(placeholder), std::string::npos)
                << value.name << ": argument \"" << argument << "\" embeds %e inside a longer "
                << "string. Substitution is whole-argument only, so this would never be "
                << "replaced and the utility would be handed a literal %e.";
        }
        if(definition.type == binwalk::extractor_type::external) {
            EXPECT_EQ(placeholder_count, std::size_t{1})
                << value.name << ": an external extractor must name its source file exactly "
                << "once, as a standalone %e argument";
        }
    }
}

TEST(B7ArchivesExtractors, EveryExternalDefinitionIsWellFormed) {
    for(const auto& value : batch()) {
        if(!value.extractor_definition.has_value()) {
            continue;
        }
        SCOPED_TRACE(value.name);
        const auto& definition = *value.extractor_definition;
        if(definition.type != binwalk::extractor_type::external) {
            continue;
        }
        EXPECT_FALSE(definition.command.empty())
            << value.name << ": an external extractor with no command can never run";
        EXPECT_EQ(definition.internal, nullptr)
            << value.name << ": an external extractor must not carry an internal pointer";
        EXPECT_FALSE(definition.extension.empty())
            << value.name << ": the carved file needs an extension (contract §2 rule 1)";
        EXPECT_FALSE(definition.exit_codes.empty())
            << value.name << ": an empty exit_codes list would reject every exit status";
        EXPECT_NE(
            std::find(definition.exit_codes.begin(), definition.exit_codes.end(), 0),
            definition.exit_codes.end()
        ) << value.name << ": all 25 upstream extractor definitions accept exit code 0";
    }
}

TEST(B7ArchivesExtractors, UtilityPresenceIsProbedButNeverRequired) {
    for(const auto& value : batch()) {
        if(!value.extractor_definition.has_value()) {
            continue;
        }
        const auto& definition = *value.extractor_definition;
        if(definition.type != binwalk::extractor_type::external) {
            continue;
        }
        const bool available = binwalk::external_utility_available(definition);
        SUCCEED() << value.name << ": external utility \"" << definition.command << "\" is "
                  << (available ? "present" : "absent")
                  << " on this machine; no assertion depends on that.";
    }
}

namespace {

bytes zip_with_eocd() {
    bytes out = zip_reference_local_entry();
    append(out, zip_reference_central_directory());
    append(out, zip_reference_eocd());
    return out;
}

bytes zip_no_eocd() {
    bytes out = zip_reference_local_entry();
    append(out, junk(32, 0xFF));
    return out;
}

bytes zip_cd_trap() {
    bytes out = zip_reference_local_entry();
    append(out, zip_reference_central_directory());
    append(out, junk(32, 0xFF));
    return out;
}

}

TEST(B7ArchivesZip, WithEocdSizeEndsAtTheEocdRecord) {
    const bytes data = zip_with_eocd();
    ASSERT_EQ(data.size(), std::size_t{113});

    const auto result = parse_at("zip", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{113});
}

TEST(B7ArchivesZip, WithEocdSizeIgnoresTrailingBytes) {
    bytes data = zip_with_eocd();
    append(data, junk(32, 0xFF));
    ASSERT_EQ(data.size(), std::size_t{145});

    const auto result = parse_at("zip", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{113})
        << "size must stop at the end of the 22-byte EOCD record. 145 would mean it ran to "
        << "EOF and would swallow whatever follows the archive.";
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
}

TEST(B7ArchivesZip, NoEocdIsDetectedAndSaysSoInTheDescription) {
    const bytes data = zip_no_eocd();
    ASSERT_EQ(data.size(), std::size_t{72});

    const auto result = parse_at("zip", data, 0);
    ASSERT_TRUE(result.has_value())
        << "a ZIP with local file headers but no end-of-central-directory record must still "
        << "be detected; upstream detects this one too";

    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{40})
        << "size is the end of the local-header chain: the 40-byte entry, not the 32 bytes "
        << "of 0xFF behind it";

    EXPECT_TRUE(contains(result->description, "missing end-of-central-directory header"))
        << "the description must say WHY the size came from a chain walk rather than from an "
        << "EOCD record. Actual description: " << result->description;
}

TEST(B7ArchivesZip, D1_ChainStopsAtACentralDirectoryRecordThatUpstreamWouldSwallow) {
    const bytes data = zip_cd_trap();
    ASSERT_EQ(data.size(), std::size_t{123});

    ASSERT_EQ(data[40], std::uint8_t{'P'});
    ASSERT_EQ(data[41], std::uint8_t{'K'});
    ASSERT_EQ(data[42], std::uint8_t{0x01});
    ASSERT_EQ(data[43], std::uint8_t{0x02});

    const auto result = parse_at("zip", data, 0);
    ASSERT_TRUE(result.has_value())
        << "upstream loses this detection entirely (D1). Ours must keep it.";

    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{40})
        << "size must stop at the end of the LOCAL header chain. A larger size means the "
        << "PK\\x03\\x04 magic is not being validated and the PK\\x01\\x02 central directory "
        << "record at offset 40 was walked as if it were a local file entry -- D1.";
    EXPECT_LT(result->size, static_cast<std::uint64_t>(data.size()));
    EXPECT_TRUE(contains(result->description, "missing end-of-central-directory header"))
        << "Actual description: " << result->description;
}

TEST(B7ArchivesZip, D1_ChainWalksEveryLocalEntryBeforeTheCentralDirectory) {
    std::size_t chain_end = 0;
    const bytes data = zip_without_eocd(chain_end);
    ASSERT_GT(chain_end, std::size_t{0});
    ASSERT_GT(data.size(), chain_end) << "the fixture must carry a central directory record";
    ASSERT_EQ(data[chain_end + 2], std::uint8_t{0x01});
    ASSERT_EQ(data[chain_end + 3], std::uint8_t{0x02});

    const auto result = parse_at("zip", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, static_cast<std::uint64_t>(chain_end))
        << "both local entries must be walked, and the central directory record must not be";
    EXPECT_LT(result->size, static_cast<std::uint64_t>(data.size()));
}

TEST(B7ArchivesZip, D5_NoEocdZipIsDetectedAtANonZeroOffset) {
    constexpr std::size_t zip_start = 64;

    bytes data = junk(zip_start, 0xAA);
    append(data, zip_no_eocd());
    ASSERT_EQ(data.size(), std::size_t{136});

    EXPECT_FALSE(parse_at("zip", data, 0).has_value())
        << "the junk prefix must not itself be detected as a ZIP";

    const auto result = parse_at("zip", data, zip_start);
    ASSERT_TRUE(result.has_value())
        << "a no-EOCD ZIP at a non-zero offset must be detected. Upstream misses this "
        << "entirely (D5/X10: it compares a relative available_data against an absolute "
        << "offset), which is precisely why we do not copy that arithmetic.";

    EXPECT_EQ(result->offset, std::uint64_t{64})
        << "offset must be the ZIP's real start, not the start of the buffer";
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{40})
        << "size is a LENGTH, so it is identical to the offset-0 case and must not absorb "
        << "the 64-byte prefix";
    EXPECT_LE(
        result->offset + result->size,
        static_cast<std::uint64_t>(data.size())
    ) << "the reported byte range must fit inside the buffer";
}

TEST(B7ArchivesRejects, EveryParserRejectsAnEmptyBuffer) {
    const bytes empty;
    for(const auto& name : batch_names()) {
        expect_rejected(name, empty, 0, "an empty buffer");
    }
}

TEST(B7ArchivesRejects, EveryParserRejectsASingleByteBuffer) {
    const bytes single{0x00};
    const bytes single_high{0xFF};
    for(const auto& name : batch_names()) {
        expect_rejected(name, single, 0, "a one-byte buffer");
        expect_rejected(name, single_high, 0, "a one-byte 0xFF buffer");
    }
}

TEST(B7ArchivesRejects, EveryParserRejectsABufferThatIsOnlyItsMagic) {
    for(const auto& name : batch_names()) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name << " is not registered";
        for(std::size_t index = 0; index < value->magic.size(); ++index) {
            const bytes data = registered_magic(name, index);
            ASSERT_FALSE(data.empty()) << name << " magic pattern " << index << " is empty";
            expect_rejected(
                name, data, 0,
                "a buffer that is exactly magic pattern " + std::to_string(index)
                    + " and nothing else"
            );
        }
    }
}

TEST(B7ArchivesRejects, EveryParserRejectsAnOffsetAtOrPastTheEndOfTheBuffer) {
    const bytes data = junk(256);
    for(const auto& name : batch_names()) {
        expect_rejected(name, data, data.size(), "an offset exactly at end-of-buffer");
        expect_rejected(name, data, data.size() + 1, "an offset one past end-of-buffer");
        expect_rejected(name, data, data.size() + 4096, "an offset far past end-of-buffer");

        expect_rejected(name, data, absurd_offset(), "an absurd offset");
    }
}

TEST(B7ArchivesRejects, EveryParserRejectsMagicFollowedOnlyByJunk) {
    for(const auto& name : batch_names()) {

        expect_rejected(name, magic_then_junk(name, 512), 0, "magic followed by 512 junk bytes");
    }
}

TEST(B7ArchivesRejects, TarballRejectsAMatchBelowTheTwoFiveSevenRewind) {
    bytes data = junk(1024);
    const bytes ustar{'u', 's', 't', 'a', 'r', 0x00};

    for(const std::size_t offset : {std::size_t{0}, std::size_t{1}, std::size_t{100},
                                    std::size_t{256}}) {
        std::copy(ustar.begin(), ustar.end(), data.begin() + static_cast<std::ptrdiff_t>(offset));
        expect_rejected(
            "tarball", data, offset,
            "a ustar match below offset 257, where the rewind would underflow"
        );
        std::fill(
            data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + ustar.size()),
            std::uint8_t{0xA5}
        );
    }
}

TEST(B7ArchivesRejects, Iso9660RejectsAMatchBelowTheThirtyTwoSevenSixEightRewind) {
    const bytes descriptor{0x01, 'C', 'D', '0', '0', '1', 0x01, 0x00};

    for(const std::size_t offset : {std::size_t{0}, std::size_t{1}, std::size_t{2048},
                                    std::size_t{32767}}) {
        bytes data = junk(offset + 4096);
        std::copy(
            descriptor.begin(), descriptor.end(),
            data.begin() + static_cast<std::ptrdiff_t>(offset)
        );
        expect_rejected(
            "iso9660", data, offset,
            "a CD001 match below offset 32768, where the rewind would underflow"
        );
    }
}

TEST(B7ArchivesRejects, Iso9660RejectsATruncatedVolumeDescriptorAtAValidOffset) {
    constexpr std::size_t descriptor_offset = 32768;
    const bytes descriptor{0x01, 'C', 'D', '0', '0', '1', 0x01, 0x00};

    bytes data = junk(descriptor_offset, 0x00);
    append(data, descriptor);
    expect_rejected(
        "iso9660", data, descriptor_offset,
        "a primary volume descriptor magic with no descriptor body behind it"
    );
}

TEST(B7ArchivesRejects, CpioRejectsAZeroLengthFileName) {

    for(const std::string_view magic : {std::string_view{"070701"}, std::string_view{"070702"}}) {
        bytes data = cpio_newc_header(magic, 0, 0, "");
        append(data, junk(256));
        expect_rejected("cpio", data, 0, "a cpio entry declaring a file-name length of 0");
    }
}

TEST(B7ArchivesRejects, CpioRejectsAnAbsurdDeclaredDataSize) {
    const std::string_view name = "hello";

    bytes data = cpio_newc_header("070701", static_cast<std::uint32_t>(name.size() + 1),
                                  0xFFFFFFF0U, name);
    data.push_back(0x00);
    append(data, junk(256));
    expect_rejected("cpio", data, 0, "a cpio entry declaring a ~4 GiB file in a 400-byte buffer");

    bytes maxed = cpio_newc_header("070702", 0xFFFFFFFFU, 0xFFFFFFFFU, name);
    append(maxed, junk(256));
    expect_rejected("cpio", maxed, 0, "a cpio entry with every length field saturated");
}

TEST(B7ArchivesRejects, MatterOtaRejectsAHeaderSizeLargerThanTheBuffer) {

    bytes data = matter_ota_fixed_header(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFF0U);
    append(data, junk(256));
    expect_rejected("matter_ota", data, 0, "a TLV header size of ~4 GiB in a 272-byte buffer");

    bytes moderate = matter_ota_fixed_header(4096, 100000U);
    append(moderate, junk(256));
    expect_rejected("matter_ota", moderate, 0, "a header size of 100000 in a 272-byte buffer");

    bytes undersized = matter_ota_fixed_header(4, 0);
    append(undersized, junk(256));
    expect_rejected("matter_ota", undersized, 0, "a total size smaller than the fixed header");
}

TEST(B7ArchivesRejects, CabRejectsATruncatedHeader) {

    bytes data = cab_header(0x0000, 4096);
    append(data, junk(4));
    ASSERT_EQ(data.size(), std::size_t{40});
    expect_rejected("cab", data, 0, "a 40-byte cabinet declaring a 4096-byte cbCabinet");

    for(const std::size_t length : {std::size_t{8}, std::size_t{16}, std::size_t{24},
                                    std::size_t{35}}) {
        bytes truncated = cab_header(0x0000, 4096);
        truncated.resize(length);
        expect_rejected(
            "cab", truncated, 0,
            "a CFHEADER truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, CabRejectsTheReservePresentFlagWithNoReserveHeader) {

    bytes data = cab_header(0x0004, 36);
    ASSERT_EQ(data.size(), std::size_t{36});
    expect_rejected("cab", data, 0, "cfhdrRESERVE_PRESENT set with no reserve header present");

    bytes partial = cab_header(0x0004, 65536);
    put_u16_le(partial, 60000);
    partial.push_back(0);
    partial.push_back(0);
    expect_rejected("cab", partial, 0, "a 60000-byte abReserve block in a 40-byte buffer");
}

TEST(B7ArchivesRejects, ArjRejectsAVersionOutsideOneThroughSixteen) {
    for(const std::uint8_t version : {std::uint8_t{0}, std::uint8_t{17}, std::uint8_t{100},
                                      std::uint8_t{255}}) {
        bytes data = arj_basic_header(version);
        append(data, junk(256));
        expect_rejected(
            "arj", data, 0,
            "an ARJ archiver version of " + std::to_string(static_cast<unsigned>(version))
                + ", outside the valid 1..=16 range"
        );
    }
}

TEST(B7ArchivesRejects, SrecordRejectsAFooterLineThatNeverTerminates) {

    bytes data = registered_magic("srecord");
    ASSERT_FALSE(data.empty());
    put_ascii(data, "\n");
    put_ascii(data, "S9030000FC");
    expect_rejected("srecord", data, 0, "an S9 footer line that never terminates before EOF");

    bytes bare = registered_magic("srecord");
    put_ascii(bare, "\nS804000000FB");
    expect_rejected("srecord", bare, 0, "an S8 footer line that never terminates before EOF");

    bytes headless = registered_magic("srecord");
    put_ascii(headless, "\n");
    for(int line = 0; line < 8; ++line) {
        put_ascii(headless, "S1130000000000000000000000000000000000EB\n");
    }
    expect_rejected("srecord", headless, 0, "an S-record stream with no S7/S8/S9 terminator");
}

TEST(B7ArchivesRejects, SrecordGenericRejectsATruncatedS0Record) {

    bytes data{'S', '0', 'F', 'F'};
    expect_rejected("srecord_generic", data, 0, "an S0 record declaring 0xFF bytes with none");

    bytes not_hex{'S', '0', 'Z', 'Z', 'Z', 'Z'};
    expect_rejected("srecord_generic", not_hex, 0, "an S0 record whose length is not hex");

    bytes truncated{'S', '0', '0', '6', '0', '0'};
    expect_rejected("srecord_generic", truncated, 0, "an S0 record cut off mid-payload");
}

TEST(B7ArchivesRejects, DebRejectsATruncatedArHeader) {

    for(const std::size_t extra : {std::size_t{0}, std::size_t{1}, std::size_t{16},
                                   std::size_t{35}}) {
        bytes data = registered_magic("deb");
        append(data, junk(extra, 0x20));
        expect_rejected(
            "deb", data, 0,
            "a deb magic followed by only " + std::to_string(extra)
                + " bytes of ar member header"
        );
    }

    bytes malformed = registered_magic("deb");
    append(malformed, junk(60 - malformed.size(), 0x5A));
    append(malformed, junk(64));
    expect_rejected("deb", malformed, 0, "a deb ar member header with a non-numeric size field");
}

TEST(B7ArchivesRejects, SevenZipRejectsATruncatedSignatureHeader) {

    for(const std::size_t extra : {std::size_t{0}, std::size_t{1}, std::size_t{2},
                                   std::size_t{16}, std::size_t{25}}) {
        expect_rejected(
            "7zip", magic_then_junk("7zip", extra), 0,
            "a 7z signature truncated to " + std::to_string(6 + extra) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, ZipRejectsATruncatedLocalFileHeader) {

    for(const std::size_t extra : {std::size_t{0}, std::size_t{1}, std::size_t{10},
                                   std::size_t{25}}) {
        expect_rejected(
            "zip", magic_then_junk("zip", extra), 0,
            "a local file header truncated to " + std::to_string(4 + extra) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, ZipRejectsALocalFileHeaderDeclaringMoreThanTheBufferHolds) {
    bytes data;
    put_bytes(data, {'P', 'K', 0x03, 0x04});
    put_u16_le(data, 20);
    put_u16_le(data, 0);
    put_u16_le(data, 0);
    put_u16_le(data, 0);
    put_u16_le(data, 0x0021);
    put_u32_le(data, 0);
    put_u32_le(data, 0xFFFFFFF0U);
    put_u32_le(data, 0xFFFFFFF0U);
    put_u16_le(data, 0xFFF0U);
    put_u16_le(data, 0xFFF0U);
    append(data, junk(64));
    expect_rejected(
        "zip", data, 0,
        "a local file header whose declared name, extra and payload lengths overflow the buffer"
    );
}

TEST(B7ArchivesRejects, RarRejectsATruncatedArchiveHeader) {

    for(const std::size_t extra : {std::size_t{0}, std::size_t{1}, std::size_t{2},
                                   std::size_t{6}}) {
        expect_rejected(
            "rar", magic_then_junk("rar", extra), 0,
            "a RAR marker truncated to " + std::to_string(6 + extra) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, MatterOtaRejectsATruncatedFixedHeader) {
    for(const std::size_t length : {std::size_t{4}, std::size_t{8}, std::size_t{12},
                                    std::size_t{15}}) {
        bytes data = matter_ota_fixed_header(4096, 8);
        data.resize(length);
        expect_rejected(
            "matter_ota", data, 0,
            "a Matter OTA fixed header truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, ArjRejectsATruncatedBasicHeader) {
    for(const std::size_t length : {std::size_t{2}, std::size_t{4}, std::size_t{8},
                                    std::size_t{16}}) {
        bytes data = arj_basic_header(11);
        data.resize(length);
        expect_rejected(
            "arj", data, 0,
            "an ARJ basic header truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, CpioRejectsATruncatedNewcHeader) {

    for(const std::size_t length : {std::size_t{6}, std::size_t{20}, std::size_t{64},
                                    std::size_t{109}}) {
        bytes data = cpio_newc_header("070701", 6, 0, "hello");
        data.resize(length);
        expect_rejected(
            "cpio", data, 0,
            "a cpio newc header truncated to " + std::to_string(length) + " bytes"
        );
    }
}

TEST(B7ArchivesRejects, TarballRejectsAnAllZeroHeaderAtAValidRewindOffset) {

    constexpr std::size_t magic_offset = 257;
    bytes data(1024, 0x00);
    const bytes ustar{'u', 's', 't', 'a', 'r', 0x00};
    std::copy(
        ustar.begin(), ustar.end(),
        data.begin() + static_cast<std::ptrdiff_t>(magic_offset)
    );
    expect_rejected(
        "tarball", data, magic_offset,
        "an all-zero tar header block with a valid ustar magic and an invalid checksum"
    );
}

TEST(B7ArchivesRejects, NoParserAcceptsAnotherFormatsMagic) {

    const auto related = [](const std::string& left, const std::string& right) {
        const bool left_is_srecord = left == "srecord" || left == "srecord_generic";
        const bool right_is_srecord = right == "srecord" || right == "srecord_generic";
        return left_is_srecord && right_is_srecord;
    };

    for(const auto& owner : batch_names()) {
        for(const auto& other : batch_names()) {
            if(owner == other || related(owner, other)) {
                continue;
            }
            const auto* value = signature_named(other);
            ASSERT_NE(value, nullptr);
            for(std::size_t index = 0; index < value->magic.size(); ++index) {
                bytes data = registered_magic(other, index);
                append(data, junk(512));
                expect_rejected(
                    owner, data, 0,
                    "a buffer whose magic belongs to \"" + other + "\""
                );
            }
        }
    }
}

namespace {

struct matter_ota_fixture {
    bytes image;
    bytes payload;
    bytes digest;
    std::size_t tlv_size = 0;
    std::size_t payload_offset = 0;
    std::uint64_t total_size = 0;
};

matter_ota_fixture build_matter_ota() {
    matter_ota_fixture fixture;
    fixture.payload = matter_ota_test_payload();
    fixture.digest = matter_ota_test_digest();

    const bytes tlv = matter_ota_tlv(
        0x1234,
        0x5678,
        1,
        "1.2.3.4",
        static_cast<std::uint64_t>(fixture.payload.size()),
        1,
        fixture.digest
    );

    fixture.tlv_size = tlv.size();
    fixture.image = matter_ota_image(tlv, fixture.payload);
    fixture.payload_offset = binwalk::formats::matter_ota_fixed_header_size + tlv.size();
    fixture.total_size = static_cast<std::uint64_t>(fixture.image.size());
    return fixture;
}

class b7_matter_ota_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b7_archives_";
        const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
        if(information != nullptr) {
            name += information->name();
        }
        root_ = base / name;

        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
        ASSERT_EQ(count_entries(root_), std::size_t{0});
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    std::filesystem::path root_;
};

}

TEST(B7ArchivesMatterOta, InspectorAcceptsAWellFormedImage) {
    const auto fixture = build_matter_ota();

    const auto header = binwalk::formats::inspect_matter_ota(view(fixture.image), 0);
    ASSERT_TRUE(header.has_value())
        << "inspect_matter_ota rejected a self-consistent image of " << fixture.image.size()
        << " bytes (16-byte fixed header + " << fixture.tlv_size << "-byte TLV header + "
        << fixture.payload.size() << "-byte payload)";

    EXPECT_EQ(fixture.image.size(), std::size_t{98}) << "the fixture itself drifted";
    EXPECT_EQ(fixture.tlv_size, std::size_t{74}) << "the TLV body drifted";

    EXPECT_EQ(header->total_size, std::uint64_t{98});
    EXPECT_EQ(header->header_size, std::uint64_t{74})
        << "header_size is the TLV header length ONLY, not the whole image";
    EXPECT_EQ(header->payload_size, std::uint64_t{8});
    EXPECT_EQ(header->total_size, fixture.total_size);
    EXPECT_EQ(header->header_size, static_cast<std::uint64_t>(fixture.tlv_size));
    EXPECT_EQ(header->payload_size, static_cast<std::uint64_t>(fixture.payload.size()));

    EXPECT_EQ(
        header->payload_size + binwalk::formats::matter_ota_fixed_header_size
            + header->header_size,
        header->total_size
    ) << "payload_size + 16 + header_size == total_size must hold for any header that "
      << "validates; an image where it does not must be rejected instead";

    EXPECT_EQ(header->vendor_id, std::uint64_t{0x1234});
    EXPECT_EQ(header->product_id, std::uint64_t{0x5678});
    EXPECT_EQ(header->image_digest_type, std::uint64_t{1});
    EXPECT_FALSE(header->version.empty())
        << "version feeds the description, whose wording is FREE under §5, but it must "
        << "carry the fact";

    EXPECT_EQ(header->image_digest, to_lowercase_hex(fixture.digest))
        << "image_digest must be lowercase hex, two characters per byte, with no "
        << "separators and no 0x prefix";
    EXPECT_EQ(
        header->image_digest,
        std::string("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    );
}

TEST(B7ArchivesMatterOta, PayloadLivesAtSixteenPlusHeaderSize) {
    const auto fixture = build_matter_ota();
    const auto header = binwalk::formats::inspect_matter_ota(view(fixture.image), 0);
    ASSERT_TRUE(header.has_value());

    const auto start = binwalk::formats::matter_ota_fixed_header_size
        + static_cast<std::size_t>(header->header_size);
    const auto length = static_cast<std::size_t>(header->payload_size);
    ASSERT_EQ(start, fixture.payload_offset);
    ASSERT_LE(start + length, fixture.image.size());

    const bytes recovered(
        fixture.image.begin() + static_cast<std::ptrdiff_t>(start),
        fixture.image.begin() + static_cast<std::ptrdiff_t>(start + length)
    );
    EXPECT_EQ(recovered, fixture.payload)
        << "the payload range computed from the header does not contain the payload bytes";
}

TEST(B7ArchivesMatterOta, InspectorWorksAtANonZeroOffset) {
    const auto fixture = build_matter_ota();
    constexpr std::size_t start = 137;

    bytes data = junk(start, 0x5A);
    append(data, fixture.image);

    const auto header = binwalk::formats::inspect_matter_ota(view(data), start);
    ASSERT_TRUE(header.has_value()) << "inspect_matter_ota must honour its offset argument";
    EXPECT_EQ(header->total_size, fixture.total_size);
    EXPECT_EQ(header->header_size, static_cast<std::uint64_t>(fixture.tlv_size));
    EXPECT_EQ(header->payload_size, static_cast<std::uint64_t>(fixture.payload.size()));

    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(data), 0).has_value())
        << "the junk prefix must not be mistaken for a Matter OTA image";
}

TEST(B7ArchivesMatterOta, InspectorRejectsMalformedAndOutOfRangeInput) {
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(binwalk::byte_view{}, 0).has_value());

    const bytes single{0x1E};
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(single), 0).has_value());

    const bytes magic_only = registered_magic("matter_ota");
    ASSERT_FALSE(magic_only.empty());
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(magic_only), 0).has_value());

    bytes oversized = matter_ota_fixed_header(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFF0U);
    append(oversized, junk(256));
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(oversized), 0).has_value())
        << "a TLV header size larger than the buffer must be rejected, not trusted";

    const auto fixture = build_matter_ota();
    bytes inconsistent = fixture.image;
    inconsistent[4] = static_cast<std::uint8_t>(inconsistent[4] ^ 0x7FU);
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(inconsistent), 0).has_value())
        << "payload_size + 16 + header_size != total_size must be a rejection";

    const bytes data = junk(256);
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(data), data.size()).has_value());
    EXPECT_FALSE(
        binwalk::formats::inspect_matter_ota(view(data), data.size() + 4096).has_value()
    );
    EXPECT_FALSE(binwalk::formats::inspect_matter_ota(view(data), absurd_offset()).has_value());
}

TEST(B7ArchivesMatterOta, SignatureSizeIsTheTlvHeaderLengthNotTheWholeImage) {
    const auto fixture = build_matter_ota();

    const auto result = parse_at("matter_ota", fixture.image, 0);
    ASSERT_TRUE(result.has_value()) << "a well-formed Matter OTA image must be detected";

    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{74})
        << "the signature size is the TLV header length -- 74 for this 98-byte image, and "
        << "72 for the 96-byte image in tests/golden/matter_ota.json. The whole-image size "
        << "belongs to the extraction result and the two are never reconciled.";
    EXPECT_EQ(result->size, static_cast<std::uint64_t>(fixture.tlv_size));
    EXPECT_LT(result->size, fixture.total_size);
    EXPECT_FALSE(result->extraction_declined)
        << "a valid Matter OTA image is extracted, not declined (contract §5: "
        << "extraction_declined is STRICT)";
}

TEST(B7ArchivesMatterOta, DetectedAtANonZeroOffsetWithTheSameSize) {
    const auto fixture = build_matter_ota();
    constexpr std::size_t start = 137;

    bytes data = junk(start, 0x5A);
    append(data, fixture.image);

    const auto result = parse_at("matter_ota", data, start);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, static_cast<std::uint64_t>(start));
    EXPECT_EQ(result->size, static_cast<std::uint64_t>(fixture.tlv_size))
        << "size is a length and must not absorb the prefix";
}

TEST(B7ArchivesMatterOta, DryRunValidatesReportsTheTotalSizeAndWritesNothing) {
    const auto fixture = build_matter_ota();

    const auto* value = signature_named("matter_ota");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto signature = parse_at("matter_ota", fixture.image, 0);
    ASSERT_TRUE(signature.has_value());

    ASSERT_FALSE(stray_extraction_output_in_working_directory())
        << "the working directory already holds extraction output before the dry run";

    const auto through_definition = binwalk::dry_run_extractor(
        *value->extractor_definition, view(fixture.image), *signature
    );
    EXPECT_TRUE(through_definition.success)
        << "the dry run failed with extraction_failure "
        << static_cast<int>(through_definition.failure);
    ASSERT_TRUE(through_definition.size.has_value())
        << "callers take `size` from a dry run (contract §1 rule 2)";
    EXPECT_EQ(*through_definition.size, std::uint64_t{98})
        << "a dry run reports the TRUE TOTAL size -- the whole image, not the TLV header "
        << "length the signature reports (74 here, 72/96 in the golden)";
    EXPECT_EQ(*through_definition.size, fixture.total_size);

    const auto direct = binwalk::formats::extract_matter_ota(
        view(fixture.image), *signature, nullptr
    );
    EXPECT_TRUE(direct.success);
    ASSERT_TRUE(direct.size.has_value());
    EXPECT_EQ(*direct.size, fixture.total_size);

    EXPECT_FALSE(stray_extraction_output_in_working_directory())
        << "a dry run wrote to disk. Contract §1 rule 1: a dry run that writes a file is a "
        << "bug, and the parser dry-runs its own extractor during a plain scan, so this is "
        << "reachable without -e.";
}

TEST(B7ArchivesMatterOta, DryRunOfAMalformedImageFailsAndStillWritesNothing) {
    const auto fixture = build_matter_ota();

    bytes broken = fixture.image;
    ASSERT_GT(broken.size(), std::size_t{16});
    broken[12] = 0xFF;
    broken[13] = 0xFF;
    broken[14] = 0xFF;
    broken[15] = 0x0F;

    const auto* value = signature_named("matter_ota");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    EXPECT_FALSE(parse_at("matter_ota", broken, 0).has_value());

    binwalk::signature_result signature;
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(broken.size());
    signature.name = "matter_ota";
    signature.id = "matter_ota_malformed_probe";
    signature.confidence = binwalk::confidence_medium;

    ASSERT_FALSE(stray_extraction_output_in_working_directory());

    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, view(broken), signature
    );
    EXPECT_FALSE(result.success)
        << "a dry run must validate; accepting a header_size of ~256 MiB in a "
        << broken.size() << "-byte buffer is exactly the §5b failure mode";

    EXPECT_FALSE(stray_extraction_output_in_working_directory())
        << "a failed dry run wrote to disk";
}

TEST_F(b7_matter_ota_extraction_test, RealExtractionWritesThePayloadBytes) {
    const auto fixture = build_matter_ota();

    const auto* value = signature_named("matter_ota");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto signature = parse_at("matter_ota", fixture.image, 0);
    ASSERT_TRUE(signature.has_value());

    const auto output_root = root_ / "out";
    const auto result = binwalk::execute_extractor(
        view(fixture.image), "matter_ota.bin", *signature, *value->extractor_definition,
        output_root.string()
    );

    ASSERT_TRUE(result.success)
        << "internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{98})
        << "the extraction reports total_size, not the 74-byte signature size";
    EXPECT_EQ(*result.size, fixture.total_size);

    const auto written = find_file_named(output_root, "matter_payload.bin");
    ASSERT_TRUE(written.has_value())
        << "no matter_payload.bin under " << output_root.string();

    const auto contents = read_file(*written);
    ASSERT_TRUE(contents.has_value());
    EXPECT_EQ(contents->size(), std::size_t{8});
    EXPECT_EQ(*contents, fixture.payload)
        << "extracted content is STRICT under contract §5: the written bytes must be the "
        << "image's payload range, not the whole image and not the header";
}

TEST(B7ArchivesArj, CommentHeaderIsDetectedAndIsNotDeclined) {
    const bytes data = arj_two_header_image();
    ASSERT_EQ(data.size(), std::size_t{160});

    const auto result = parse_at("arj", data, 0);
    ASSERT_TRUE(result.has_value()) << "the ARJ main header at offset 0 must be detected";

    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_EQ(result->size, std::uint64_t{34})
        << "size is the u8 at +4 (first header size), NOT the u16 at +2. Upstream parses "
        << "the u16 and then never uses it.";
    EXPECT_FALSE(result->extraction_declined)
        << "upstream declines extraction for every ARJ record EXCEPT the comment header, "
        << "and the golden's offset-13 comment header has extraction_declined=false";

    EXPECT_TRUE(contains(result->description, "comment header"))
        << "the description must name the file type, because it is what decides "
        << "extraction_declined. Actual: " << result->description;
    EXPECT_TRUE(contains(result->description, "example.arj"))
        << "the original name is read at offset + first_hdr_size + 4, so a wrong "
        << "first_hdr_size shows up here first. Actual: " << result->description;
}

TEST(B7ArchivesArj, ABinaryFileHeaderAtOffsetSeventyDeclinesExtraction) {
    const bytes data = arj_two_header_image();

    const auto result = parse_at("arj", data, 70);
    ASSERT_TRUE(result.has_value()) << "the ARJ file header at offset 70 must be detected";

    EXPECT_EQ(result->offset, std::uint64_t{70})
        << "offset is the record's real start, not the start of the buffer";
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_EQ(result->size, std::uint64_t{46})
        << "size is a LENGTH -- the +4 byte of THIS record -- and must not absorb the "
        << "70 bytes in front of it";
    EXPECT_TRUE(result->extraction_declined)
        << "every ARJ record whose file type is not \"comment header\" declines extraction; "
        << "the golden's offset-70 binary record has extraction_declined=true";

    EXPECT_TRUE(contains(result->description, "binary")) << "Actual: " << result->description;
    EXPECT_TRUE(contains(result->description, "secret.txt"))
        << "Actual: " << result->description;
}

TEST(B7ArchivesArj, TheTwoRecordsDisagreeOnExtractionDeclined) {

    const bytes data = arj_two_header_image();

    const auto comment_header = parse_at("arj", data, 0);
    const auto file_header = parse_at("arj", data, 70);
    ASSERT_TRUE(comment_header.has_value());
    ASSERT_TRUE(file_header.has_value());

    EXPECT_NE(comment_header->extraction_declined, file_header->extraction_declined)
        << "extraction_declined must be derived from the file type, not fixed";
    EXPECT_NE(comment_header->size, file_header->size)
        << "the two records declare different first-header sizes (34 and 46)";
}

TEST(B7ArchivesPositive, Deb) {
    const bytes data = deb_image();
    ASSERT_EQ(data.size(), std::size_t{208}) << "the fixture itself drifted";

    const auto result = parse_at("deb", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{208})
        << "size runs to the end of the data.tar.gz member: its size field ends at 198, "
        << "plus the 2-byte end marker, plus the 8-byte member body";
}

TEST(B7ArchivesPositive, TarballWithTwoEntriesIsMediumConfidence) {
    const bytes data = tar_image(2);
    ASSERT_EQ(data.size(), std::size_t{3072});
    ASSERT_EQ(data[257], std::uint8_t{'u'}) << "the ustar magic is not where it should be";

    const auto result = parse_at("tarball", data, 257);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0})
        << "the parser rewinds 257 bytes from the magic to the start of the header block";
    EXPECT_EQ(result->confidence, binwalk::confidence_medium)
        << "2 valid headers is below upstream's promote-to-high threshold of 10";
    EXPECT_EQ(result->size, std::uint64_t{2048})
        << "size is 2 entries x (512-byte header + 512-byte data). The 1024 trailing zero "
        << "bytes are the end-of-archive blocks: they fail the checksum, which is what "
        << "stops the walk, and they are not counted.";
}

TEST(B7ArchivesPositive, TarballWithTwelveEntriesIsHighConfidence) {
    const bytes data = tar_image(12);
    ASSERT_EQ(data.size(), std::size_t{13312});

    const auto result = parse_at("tarball", data, 257);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high)
        << "12 valid headers is at or above upstream's threshold of 10. The TIER is STRICT "
        << "under §5 because the overlap filter branches on >= confidence_medium.";
    EXPECT_EQ(result->size, std::uint64_t{12288});
}

TEST(B7ArchivesPositive, Cpio) {
    const bytes data = cpio_image();
    ASSERT_EQ(data.size(), std::size_t{252}) << "the fixture itself drifted";

    const auto result = parse_at("cpio", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{252})
        << "size covers the 128-byte hello.txt entry and the 124-byte TRAILER!!! entry";
}

TEST(B7ArchivesPositive, CpioRejectsAnArchiveThatIsOnlyTheTrailerEntry) {
    const bytes data = cpio_newc_entry("070701", "TRAILER!!!", bytes{});
    ASSERT_EQ(data.size(), std::size_t{124});
    expect_rejected(
        "cpio", data, 0,
        "an archive consisting of nothing but the TRAILER!!! entry (header_count == 1)"
    );
}

TEST(B7ArchivesPositive, Iso9660) {
    const bytes data = iso9660_image();
    ASSERT_EQ(data.size(), std::size_t{34816}) << "the fixture itself drifted";
    ASSERT_EQ(data[32768], std::uint8_t{0x01});

    const auto result = parse_at("iso9660", data, 32768);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0})
        << "the parser rewinds the whole 32 KiB system area from the descriptor magic";
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{34816})
        << "size is volume_blocks * block_size == 17 * 2048";
}

TEST(B7ArchivesPositive, Cab) {
    const bytes data = cab_image();
    ASSERT_EQ(data.size(), std::size_t{64}) << "the fixture itself drifted";

    const auto result = parse_at("cab", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_EQ(result->size, std::uint64_t{64}) << "size is cbCabinet, read from the header";
}

TEST(B7ArchivesPositive, RarVersionFive) {
    const bytes data = rar_image(1, rar_v5_end_marker());
    ASSERT_EQ(data.size(), std::size_t{31}) << "the fixture itself drifted";

    const auto result = parse_at("rar", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_EQ(result->size, std::uint64_t{31})
        << "size is the end-of-archive marker's offset plus its 8-byte length";
}

TEST(B7ArchivesPositive, RarVersionFour) {
    const bytes data = rar_image(0, rar_v4_end_marker());
    ASSERT_EQ(data.size(), std::size_t{30}) << "the fixture itself drifted";

    const auto result = parse_at("rar", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_EQ(result->size, std::uint64_t{30})
        << "the v4 marker is 7 bytes, one shorter than the v5 marker";
}

TEST(B7ArchivesPositive, RarWithNoEndMarkerIsLowConfidenceWithZeroSize) {
    const bytes data = rar_image(1, bytes{});
    ASSERT_EQ(data.size(), std::size_t{23}) << "the fixture itself drifted";

    const auto result = parse_at("rar", data, 0);
    ASSERT_TRUE(result.has_value())
        << "a RAR archive with no end-of-archive marker is still a detection, just a "
        << "low-confidence one";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_low);
    EXPECT_EQ(result->size, std::uint64_t{0})
        << "the PARSER reports 0. The 23 in the oracle's JSON is the scanner filling a "
        << "zero-size result with next_offset - offset, which is not this code path.";
}

TEST(B7ArchivesPositive, RarRejectsAVersionByteThatIsNeitherZeroNorOne) {
    for(const std::uint8_t version : {std::uint8_t{2}, std::uint8_t{3}, std::uint8_t{0xFF}}) {
        bytes data = rar_image(version, rar_v5_end_marker());
        expect_rejected(
            "rar", data, 0,
            "a RAR version byte of " + std::to_string(static_cast<unsigned>(version))
                + "; only 0 (v4) and 1 (v5) exist"
        );
    }
}

TEST(B7ArchivesPositive, EveryRarDetectionRoutesToTheUnrarExtractor) {
    const auto* value = signature_named("rar");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "contract §7b: extraction is an opt-in external process, invoked if present and "
        << "never linked. A subprocess is not a derived work, so the licence restriction "
        << "does not reach it. Only a NATIVE RAR3+RAR5 decoder is out of scope.";
    EXPECT_EQ(value->extractor_definition->command, "unrar");

    for(const bytes& data : {rar_image(1, rar_v5_end_marker()),
                             rar_image(0, rar_v4_end_marker()),
                             rar_image(1, bytes{})}) {
        EXPECT_TRUE(parse_at("rar", data, 0).has_value())
            << "detection must not depend on whether the utility is installed";
    }
}

TEST(B7ArchivesPositive, SrecordWithUnixLineEndings) {
    bytes data;
    put_ascii(data, "S00600004844521B\nS9030000FC\n");
    ASSERT_EQ(data.size(), std::size_t{28});

    const auto result = parse_at("srecord", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{28})
        << "size includes the terminator line's final LF";
    EXPECT_TRUE(contains(result->description, "Unix")) << "Actual: " << result->description;
}

TEST(B7ArchivesPositive, SrecordWithWindowsLineEndings) {
    bytes data;
    put_ascii(data, "S00600004844521B\r\nS9030000FC\r\n");
    ASSERT_EQ(data.size(), std::size_t{30});

    const auto result = parse_at("srecord", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{30})
        << "the two CRLFs are two bytes longer than the two LFs, and size must follow";
    EXPECT_TRUE(contains(result->description, "Windows")) << "Actual: " << result->description;
}

TEST(B7ArchivesPositive, SrecordGeneric) {
    bytes data;
    put_ascii(data, "S0030000FC\nS9030000FC\n");
    ASSERT_EQ(data.size(), std::size_t{22});

    const auto result = parse_at("srecord_generic", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{22});
}

TEST(B7ArchivesPositive, TheTwoSrecordSignaturesShareOneParser) {
    const auto* strict = signature_named("srecord");
    const auto* generic = signature_named("srecord_generic");
    ASSERT_NE(strict, nullptr);
    ASSERT_NE(generic, nullptr);

    bytes data;
    put_ascii(data, "S00600004844521B\nS9030000FC\n");

    const auto as_srecord = parse_at("srecord", data, 0);
    const auto as_generic = parse_at("srecord_generic", data, 0);
    ASSERT_TRUE(as_srecord.has_value());
    ASSERT_TRUE(as_generic.has_value())
        << "the srecord fixture begins with a valid generic S0 record, so the shared parser "
        << "accepts it under both registrations";
    EXPECT_EQ(as_srecord->size, as_generic->size)
        << "one parser, one answer: only the signature NAME differs";
    EXPECT_EQ(as_generic->size, std::uint64_t{28});
}

TEST(B7ArchivesPositive, SevenZip) {
    const bytes data = seven_zip_image();
    ASSERT_EQ(data.size(), std::size_t{36}) << "the fixture itself drifted";

    const bytes next_header{'A', 'B', 'C', 'D'};
    ASSERT_EQ(binwalk::crc32(binwalk::byte_view(next_header)), std::uint32_t{0xDB1720A5U})
        << "binwalk::crc32 regressed; the 7z fixture's CRCs are computed with it";

    const auto result = parse_at("7zip", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_EQ(result->size, std::uint64_t{36})
        << "size is the 32-byte signature header plus the next header's offset (0) and "
        << "size (4)";
}

TEST(B7ArchivesPositive, SevenZipRejectsABadStartHeaderCrc) {
    bytes data = seven_zip_image();
    data[8] = static_cast<std::uint8_t>(data[8] ^ 0xFFU);
    expect_rejected("7zip", data, 0, "a corrupted start-header CRC");
}

TEST(B7ArchivesPositive, SevenZipRejectsABadNextHeaderCrc) {
    bytes data = seven_zip_image();
    data[35] = static_cast<std::uint8_t>(data[35] ^ 0xFFU);
    expect_rejected("7zip", data, 0, "a next header that does not match its recorded CRC");
}

namespace {

std::vector<binwalk::signature_result> scan_all_for(const std::string& name, const bytes& data) {
    std::vector<binwalk::signature_result> found;
    for(const auto& result : batch_scanner().scan(view(data))) {
        if(result.name == name) {
            found.push_back(result);
        }
    }
    return found;
}

struct scanner_case {
    const char* name;
    bytes data;
    std::uint64_t offset;
    std::uint64_t size;
    std::uint8_t confidence;
};

}

TEST(B7ArchivesScanner, PopulatesNameAndAgreesWithTheParserOnOffsetSizeAndTier) {

    const std::vector<scanner_case> cases{
        {"deb",        deb_image(),                       0, 208,   binwalk::confidence_high},
        {"tarball",    tar_image(2),                      0, 2048,  binwalk::confidence_medium},
        {"tarball",    tar_image(12),                     0, 12288, binwalk::confidence_high},
        {"cpio",       cpio_image(),                      0, 252,   binwalk::confidence_high},
        {"iso9660",    iso9660_image(),                   0, 34816, binwalk::confidence_high},
        {"cab",        cab_image(),                       0, 64,    binwalk::confidence_medium},
        {"rar",        rar_image(1, rar_v5_end_marker()), 0, 31,    binwalk::confidence_medium},
        {"rar",        rar_image(0, rar_v4_end_marker()), 0, 30,    binwalk::confidence_medium},
        {"7zip",       seven_zip_image(),                 0, 36,    binwalk::confidence_high},
        {"matter_ota", build_matter_ota().image,          0, 74,    binwalk::confidence_high},
        {"zip",        zip_with_eocd(),                   0, 113,   binwalk::confidence_high},
        {"zip",        zip_no_eocd(),                     0, 40,    binwalk::confidence_high}
    };

    for(const auto& expected : cases) {
        SCOPED_TRACE(
            std::string(expected.name) + " over " + std::to_string(expected.data.size())
            + " bytes"
        );
        const auto found = scan_for(expected.name, expected.data);
        ASSERT_TRUE(found.has_value())
            << "the scanner produced no result named \"" << expected.name << "\". The parser "
            << "accepts this buffer, so either the magic pattern does not match where the "
            << "parser expects it, or the overlap filter dropped the result.";

        EXPECT_EQ(found->name, expected.name)
            << "name is the --include/--exclude key and is STRICT under §5";
        EXPECT_EQ(found->offset, expected.offset);
        EXPECT_EQ(found->size, expected.size)
            << "the scanner must report the same size the parser computed";
        EXPECT_EQ(found->confidence, expected.confidence);
        EXPECT_FALSE(found->id.empty()) << "populate() must assign an id";
        EXPECT_FALSE(found->always_display)
            << "no signature in this batch sets always_display, so no result may carry it";
    }
}

TEST(B7ArchivesScanner, AgreesWithTheRawParserOnEveryFieldTheParserSets) {
    const bytes data = zip_with_eocd();

    const auto raw = parse_at("zip", data, 0);
    const auto scanned = scan_for("zip", data);
    ASSERT_TRUE(raw.has_value());
    ASSERT_TRUE(scanned.has_value());

    EXPECT_EQ(scanned->offset, raw->offset);
    EXPECT_EQ(scanned->size, raw->size);
    EXPECT_EQ(scanned->confidence, raw->confidence);
    EXPECT_EQ(scanned->extraction_declined, raw->extraction_declined);
    EXPECT_EQ(scanned->description, raw->description);

    EXPECT_TRUE(raw->name.empty())
        << "the parser has started setting `name` itself. If that is intended, the "
        << "parser-level tests here should assert it and this expectation should go.";
    EXPECT_EQ(scanned->name, "zip");
    EXPECT_TRUE(raw->id.empty());
    EXPECT_FALSE(scanned->id.empty());
}

TEST(B7ArchivesScanner, D1_CentralDirectoryTrapStillDetectsThroughTheScanner) {
    const bytes data = zip_cd_trap();
    const auto found = scan_for("zip", data);
    ASSERT_TRUE(found.has_value())
        << "upstream loses this detection entirely (D1: it never validates the PK\\x03\\x04 "
        << "magic, walks the central directory record as a local entry, runs past EOF and "
        << "returns Err). Ours must keep it.";
    EXPECT_EQ(found->name, "zip");
    EXPECT_EQ(found->offset, std::uint64_t{0});
    EXPECT_EQ(found->size, std::uint64_t{40});
    EXPECT_EQ(found->confidence, binwalk::confidence_high);
}

TEST(B7ArchivesScanner, D5_NoEocdZipAtANonZeroOffsetStillDetectsThroughTheScanner) {
    bytes data = junk(64, 0xAA);
    append(data, zip_no_eocd());

    const auto found = scan_for("zip", data);
    ASSERT_TRUE(found.has_value())
        << "upstream reports no detection at all for a no-EOCD ZIP anywhere but offset 0 "
        << "(D5/X10: a relative available_data compared against an absolute offset)";
    EXPECT_EQ(found->name, "zip");
    EXPECT_EQ(found->offset, std::uint64_t{64});
    EXPECT_EQ(found->size, std::uint64_t{40});
    EXPECT_EQ(found->confidence, binwalk::confidence_high);
}

TEST(B7ArchivesScanner, ArjReportsBothRecordsWithTheirOwnDeclinedFlags) {
    const bytes data = arj_two_header_image();
    const auto found = scan_all_for("arj", data);

    ASSERT_EQ(found.size(), std::size_t{2})
        << "the scanner must report BOTH ARJ records: the comment header at 0 and the file "
        << "header at 70";

    EXPECT_EQ(found[0].offset, std::uint64_t{0});
    EXPECT_EQ(found[0].size, std::uint64_t{34});
    EXPECT_FALSE(found[0].extraction_declined) << "the comment header is the one that extracts";

    EXPECT_EQ(found[1].offset, std::uint64_t{70});
    EXPECT_EQ(found[1].size, std::uint64_t{46});
    EXPECT_TRUE(found[1].extraction_declined) << "every non-comment-header record declines";

    EXPECT_NE(found[0].id, found[1].id) << "populate() must give each result its own id";
}

TEST(B7ArchivesScanner, RarWithNoEndMarkerIsZeroFromTheParserAndFilledByTheScanner) {
    const bytes data = rar_image(1, bytes{});
    ASSERT_EQ(data.size(), std::size_t{23});

    const auto raw = parse_at("rar", data, 0);
    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(raw->size, std::uint64_t{0}) << "the parser reports 0";
    EXPECT_EQ(raw->confidence, binwalk::confidence_low);

    const auto scanned = scan_for("rar", data);
    ASSERT_TRUE(scanned.has_value());
    EXPECT_EQ(scanned->name, "rar");
    EXPECT_EQ(scanned->offset, std::uint64_t{0});
    EXPECT_EQ(scanned->confidence, binwalk::confidence_low)
        << "filling in the size must not promote the confidence";
    EXPECT_EQ(scanned->size, std::uint64_t{23})
        << "the zero-size result is widened to EOF, which is the 23 the oracle's JSON shows";
}

TEST(B7ArchivesScanner, TheSrecordPairCollapsesToOneResultAtOffsetZero) {
    bytes data;
    put_ascii(data, "S00600004844521B\nS9030000FC\n");
    ASSERT_EQ(data.size(), std::size_t{28});

    const auto results = batch_scanner().scan(view(data));
    ASSERT_EQ(results.size(), std::size_t{1})
        << "both srecord registrations match at offset 0; the overlap filter must keep one";

    const auto& only = results.front();
    EXPECT_EQ(only.name, "srecord_generic")
        << "the short-signature pre-pass makes srecord_generic the incumbent, and an equal "
        << "HIGH confidence does not displace it. The oracle agrees. If this now reports "
        << "\"srecord\", the tie-break has changed and that is a divergence from upstream, "
        << "not an improvement -- read the comment above before touching it.";
    EXPECT_EQ(only.offset, std::uint64_t{0});
    EXPECT_EQ(only.size, std::uint64_t{28})
        << "both registrations share one parser, so the size is the same 28 either way -- "
        << "only the name distinguishes them, which is why the name is what this test pins";
    EXPECT_EQ(only.confidence, binwalk::confidence_high);
    EXPECT_FALSE(only.id.empty());
}

TEST(B7ArchivesScanner, SrecordGenericIsNamedWhenItIsTheOnlyMatch) {
    bytes data;
    put_ascii(data, "S0030000FC\nS9030000FC\n");
    ASSERT_EQ(data.size(), std::size_t{22});

    const auto found = scan_for("srecord_generic", data);
    ASSERT_TRUE(found.has_value())
        << "srecord_generic is a SHORT signature, so the scanner only tests it at "
        << "magic_offset 0 unless search_all is set -- which is exactly where it is here";
    EXPECT_EQ(found->name, "srecord_generic");
    EXPECT_EQ(found->offset, std::uint64_t{0});
    EXPECT_EQ(found->size, std::uint64_t{22});
    EXPECT_EQ(found->confidence, binwalk::confidence_high);

    EXPECT_FALSE(scan_for("srecord", data).has_value())
        << "this buffer's S0 record is not the strict srecord magic, so the strict "
        << "registration must not claim it";
}
