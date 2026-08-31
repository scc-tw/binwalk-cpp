
#include "../../lib/src/formats/b10a_kernels.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/chroot.hpp>
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
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <vector>
namespace {

using bytes = std::vector<std::uint8_t>;

const std::vector<binwalk::signature>& batch() {
    static const std::vector<binwalk::signature> signatures =
        binwalk::formats::b10a_kernels_signatures();
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
        "elf", "uimage", "linux_kernel", "linux_boot_image", "linux_arm_zimage",
        "linux_arm64_boot_image", "wind_kernel", "vxworks_symtab", "ecos"
    };
    return names;
}

const std::vector<std::string>& upstream_registration_order() {
    static const std::vector<std::string> names{
        "gzip", "deb", "7zip", "xz", "tarball", "squashfs", "dlob", "lzma", "bmp",
        "bzip2", "uimage", "packimg", "crc32", "sha256", "cpio", "iso9660",
        "linux_kernel", "linux_boot_image", "linux_arm_zimage", "zstd", "zip",
        "pchrom", "uefi_pi_volume", "uefi_capsule", "pdf", "elf", "cramfs",
        "qnx_ifs", "romfs", "ext", "cab", "jffs2", "yaffs", "lz4", "lzop", "pe",
        "zlib", "gpg_signed", "pem_certificate", "pem_public_key",
        "pem_private_key", "chk", "trx", "srecord", "srecord_generic",
        "android_sparse", "dtb", "ubi", "ubifs", "cfe", "seama", "compressd",
        "rar", "png", "jpeg", "arcadyan", "copyright", "wind_kernel",
        "vxworks_symtab", "ecos", "dmg", "riff", "openssl", "lzfse", "mbr",
        "tplink", "pjl", "jboot_arm", "jboot_stag", "jboot_sch2", "pcapng", "rsa",
        "gif", "svg", "linux_arm64_boot_image", "fat", "efigpt", "rtk", "aes_sbox",
        "aes_forward_table", "aes_reverse_table", "aes_rcon",
        "aes_acceleration_table", "luks", "tplink_rtos", "binhdr", "autel", "ntfs",
        "apfs", "btrfs", "wince", "dahua_zip", "mh01", "csman", "dxbc",
        "dlink_tlv", "dlke", "shrs", "pkcs_der_hash", "logfs", "encrpted_img",
        "android_bootimg", "uboot", "dms", "dkbs", "encfw", "matter_ota", "dpapi",
        "qcow", "arj", "md5"
    };
    return names;
}

enum class confidence_tier { low, medium, high };

void expect_confidence_tier(std::uint8_t confidence, confidence_tier expected) {
    switch(expected) {
        case confidence_tier::low:
            EXPECT_LT(confidence, binwalk::confidence_medium)
                << "expected LOW tier; a higher tier changes overlap resolution";
            break;
        case confidence_tier::medium:
            EXPECT_GE(confidence, binwalk::confidence_medium) << "expected at least MEDIUM tier";
            EXPECT_LT(confidence, binwalk::confidence_high) << "expected MEDIUM, not HIGH";
            break;
        case confidence_tier::high:
            EXPECT_GE(confidence, binwalk::confidence_high) << "expected HIGH tier";
            break;
    }
}

binwalk::byte_view view(const bytes& data) {
    return binwalk::byte_view(data);
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

void write_u32_be_at(bytes& out, std::size_t at, std::uint32_t value) {
    out[at] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
    out[at + 1] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[at + 2] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[at + 3] = static_cast<std::uint8_t>(value & 0xFFU);
}

void write_u32_le_at(bytes& out, std::size_t at, std::uint32_t value) {
    out[at] = static_cast<std::uint8_t>(value & 0xFFU);
    out[at + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    out[at + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    out[at + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

void write_u64_le_at(bytes& out, std::size_t at, std::uint64_t value) {
    for(unsigned index = 0; index < 8U; ++index) {
        out[at + index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
}

using poke = std::pair<std::size_t, std::uint8_t>;

constexpr poke at(std::size_t offset, int value) noexcept {
    return poke(offset, static_cast<std::uint8_t>(value));
}

bytes build_input(bytes base, const std::vector<poke>& pokes, std::size_t truncate_to) {
    for(const auto& entry : pokes) {
        if(entry.first < base.size()) {
            base[entry.first] = entry.second;
        }
    }
    if(truncate_to != 0 && truncate_to < base.size()) {
        base.resize(truncate_to);
    }
    return base;
}

void expect_in_bounds(const binwalk::signature_result& result, std::size_t data_size) {
    const auto limit = static_cast<std::uint64_t>(data_size);
    EXPECT_LE(result.offset, limit) << "result offset is past the end of the buffer";
    if(result.offset <= limit) {
        EXPECT_LE(result.size, limit - result.offset)
            << "reported size runs past the end of the buffer";
    }
}

std::optional<binwalk::signature_result> parse_at(
    const std::string& name, const bytes& data, std::size_t offset
) {
    const auto* value = signature_named(name);
    if(value == nullptr || value->parser == nullptr) {
        return std::nullopt;
    }
    return value->parser(view(data), offset);
}

const binwalk::scanner& batch_scanner() {
    static const binwalk::scanner value(binwalk::formats::b10a_kernels_signatures());
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

std::filesystem::path temp_dir(const std::string& label) {
    std::error_code error;
    auto base = std::filesystem::temp_directory_path(error);
    if(error) {
        base = std::filesystem::path(".");
    }
    auto dir = base / ("binwalk_b10a_kernels_" + label);
    std::filesystem::remove_all(dir, error);
    return dir;
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

bytes read_file_bytes(const std::string& path) {
    bytes out;
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return out;
    }
    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if(size <= 0) {
        return out;
    }
    out.resize(static_cast<std::size_t>(size));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return out;
}

bytes elf_image() {
    bytes out(256, 0x00);
    out[0] = 0x7F; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
    out[4] = 1;
    out[5] = 1;
    out[6] = 1;
    out[7] = 0;
    out[8] = 0;

    write_u32_le_at(out, 16, 0);
    out[16] = 2; out[17] = 0;
    out[18] = 0x28; out[19] = 0;
    write_u32_le_at(out, 20, 1);
    return out;
}

bytes uimage_image(std::uint32_t magic, const std::string& name, bool corrupt_header_crc) {
    bytes out(64 + 256, 0x00);
    write_u32_be_at(out, 0, magic);

    write_u32_be_at(out, 8, 0x65500000U);
    write_u32_be_at(out, 12, 256);
    write_u32_be_at(out, 16, 0x80000000U);
    write_u32_be_at(out, 20, 0x80000000U);

    out[28] = 5;
    out[29] = 5;
    out[30] = 2;
    out[31] = 1;
    std::copy(name.begin(), name.end(), out.begin() + 32);

    for(std::size_t index = 64; index < out.size(); ++index) {
        out[index] = 0x42;
    }
    const auto payload_view = binwalk::byte_view(out.data() + 64, 256);
    write_u32_be_at(out, 24, binwalk::crc32(payload_view));

    const auto header_crc = binwalk::crc32(binwalk::byte_view(out.data(), 64));
    write_u32_be_at(out, 4, corrupt_header_crc ? (header_crc ^ 0xA5A5A5A5U) : header_crc);
    return out;
}

bytes uimage_good_image() {
    return uimage_image(0x27051956U, "MIPS OpenWrt Linux-5.10", false);
}

bytes linux_kernel_image(bool with_symtab) {
    static const std::string version =
        "Linux version 4.9.241 (root@server2) (gcc version 10.0.1 "
        "(OpenWrt GCC 10.0.1 r12423-0493d57e04) ) #755 SMP Wed Nov 4 03:59:02 +03 2020\n";
    bytes out;
    out.reserve(124253);
    out.insert(out.end(), 4096, static_cast<std::uint8_t>('A'));
    out.insert(out.end(), version.begin(), version.end());
    out.push_back(0x00);
    if(with_symtab) {
        out.insert(out.end(), 60000, static_cast<std::uint8_t>('A'));
        static const bytes marker{
            0x00, 0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00, 0x34, 0x00,
            0x35, 0x00, 0x36, 0x00, 0x37, 0x00, 0x38, 0x00, 0x39, 0x00
        };
        out.insert(out.end(), marker.begin(), marker.end());
        out.insert(out.end(), 60000, static_cast<std::uint8_t>('A'));
    } else {
        out.insert(out.end(), 120000, static_cast<std::uint8_t>('A'));
    }
    return out;
}

bytes linux_boot_image_image() {
    bytes out;
    out.insert(out.end(), 64, static_cast<std::uint8_t>('A'));
    static const bytes magic{
        0xb8, 0xc0, 0x07, 0x8e, 0xd8, 0xb8, 0x00, 0x90,
        0x8e, 0xc0, 0xb9, 0x00, 0x01, 0x29, 0xf6, 0x29
    };
    out.insert(out.end(), magic.begin(), magic.end());
    out.insert(out.end(), 498, std::uint8_t{0x00});
    static const std::string hdrs = "!HdrS";
    out.insert(out.end(), hdrs.begin(), hdrs.end());
    out.insert(out.end(), 64, std::uint8_t{0x00});
    return out;
}

bytes linux_arm_zimage_image(bool big_endian) {
    bytes out;
    out.insert(out.end(), 64, static_cast<std::uint8_t>('A'));
    static const bytes nop_le{0x00, 0x00, 0xA0, 0xE1};
    static const bytes nop_be{0xE1, 0xA0, 0x00, 0x00};
    const auto& nop = big_endian ? nop_be : nop_le;
    for(int index = 0; index < 8; ++index) {
        out.insert(out.end(), nop.begin(), nop.end());
    }
    out.insert(out.end(), {0xEF, 0xBE, 0xAD, 0xDE});
    if(big_endian) {
        out.insert(out.end(), {0x01, 0x6F, 0x28, 0x18});
    } else {
        out.insert(out.end(), {0x18, 0x28, 0x6F, 0x01});
    }
    out.insert(out.end(), 128, static_cast<std::uint8_t>('A'));
    return out;
}

bytes linux_arm64_boot_image_image() {
    bytes out;
    out.insert(out.end(), 128, static_cast<std::uint8_t>('A'));

    bytes header(64, 0x00);
    write_u32_le_at(header, 0, 0x91005A4DU);
    write_u32_le_at(header, 4, 0x14000000U);

    write_u64_le_at(header, 16, 0x01000000U);
    write_u64_le_at(header, 24, 0x0AU);

    header[56] = 'A'; header[57] = 'R'; header[58] = 'M'; header[59] = 'd';
    write_u32_le_at(header, 60, 64);

    out.insert(out.end(), header.begin(), header.end());
    out.push_back('P'); out.push_back('E');
    out.insert(out.end(), 126, static_cast<std::uint8_t>('A'));
    return out;
}

bytes wind_kernel_image() {
    bytes out;
    out.insert(out.end(), 32, static_cast<std::uint8_t>('A'));
    static const std::string text = "WIND version 2.11";
    out.insert(out.end(), text.begin(), text.end());
    out.push_back(0x00);
    out.insert(out.end(), 64, static_cast<std::uint8_t>('A'));
    return out;
}

bytes vxworks_symtab_image(bool big_endian) {
    bytes out;
    out.insert(out.end(), 16, static_cast<std::uint8_t>('A'));
    for(std::uint32_t index = 0; index < 250; ++index) {
        const auto name_ptr = 0x11111111U + index;
        const auto value_ptr = 0x22222222U + index;
        const std::uint32_t type = (index % 3 == 0) ? 0x500U : (index % 3 == 1) ? 0x700U : 0x900U;
        bytes entry(16, 0x00);
        if(big_endian) {
            write_u32_be_at(entry, 0, name_ptr);
            write_u32_be_at(entry, 4, value_ptr);
            write_u32_be_at(entry, 8, type);
            write_u32_be_at(entry, 12, 0);
        } else {
            write_u32_le_at(entry, 0, name_ptr);
            write_u32_le_at(entry, 4, value_ptr);
            write_u32_le_at(entry, 8, type);
            write_u32_le_at(entry, 12, 0);
        }
        out.insert(out.end(), entry.begin(), entry.end());
    }
    out.insert(out.end(), 16, static_cast<std::uint8_t>('A'));
    return out;
}

bytes ecos_image(bool big_endian) {
    bytes out;
    out.insert(out.end(), 32, static_cast<std::uint8_t>('A'));
    if(big_endian) {
        out.insert(out.end(), {0x40, 0x1A, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x33, 0x5A, 0x00, 0x7F});
    } else {
        out.insert(out.end(), {0x00, 0x68, 0x1A, 0x40, 0x00, 0x00, 0x00, 0x00,
                               0x7F, 0x00, 0x5A, 0x33});
    }
    out.insert(out.end(), 64, static_cast<std::uint8_t>('A'));
    return out;
}

}

struct batch_entry {
    const char* name;
    bool always_display;
    std::size_t magic_count;
};

const std::vector<batch_entry>& batch_entries() {
    static const std::vector<batch_entry> entries{
        {"elf", false, 1},
        {"uimage", false, 2},
        {"linux_kernel", true, 1},
        {"linux_boot_image", false, 1},
        {"linux_arm_zimage", false, 2},
        {"linux_arm64_boot_image", false, 1},
        {"wind_kernel", true, 1},
        {"vxworks_symtab", true, 6},
        {"ecos", true, 4},
    };
    return entries;
}

TEST(B10aKernelsRegistry, DeclaresExactlyTheNineExpectedNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "b10a_kernels registers \"" << value.name << "\" more than once";
    }
    const std::set<std::string> expected(batch_names().begin(), batch_names().end());
    for(const auto& name : expected) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b10a_kernels does not register \"" << name << "\"";
    }
    for(const auto& name : produced) {
        EXPECT_EQ(expected.count(name), std::size_t{1})
            << "b10a_kernels registers \"" << name << "\", which is not one of this batch's "
            << "nine formats";
    }
    EXPECT_EQ(batch().size(), std::size_t{9});
}

TEST(B10aKernelsRegistry, EveryNameIsInTheFrozenUpstreamOrderTable) {
    const auto& table = upstream_registration_order();
    ASSERT_EQ(table.size(), std::size_t{111});
    const std::set<std::string> unique(table.begin(), table.end());
    ASSERT_EQ(unique.size(), table.size()) << "the transcribed table has a duplicate";

    for(const auto& value : batch()) {
        EXPECT_NE(std::find(table.begin(), table.end(), value.name), table.end())
            << "signature name \"" << value.name << "\" is NOT in upstream magic.rs's "
            << "111-entry registry order table. It would sort silently to the end of the "
            << "registry and drop out of --include/--exclude and out of every oracle diff. "
            << "Fix the name; do NOT extend the table.";
    }
    for(const auto& name : batch_names()) {
        EXPECT_NE(std::find(table.begin(), table.end(), name), table.end())
            << "this test file's own spelling of \"" << name << "\" is not in the frozen table";
    }
}

TEST(B10aKernelsRegistry, EveryNameReachesTheAggregatedRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [&name](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "\"" << name << "\" is produced by b10a_kernels_signatures() but does not "
            << "appear in binwalk::builtin_signatures(); the aggregator dropped it";
    }
}

TEST(B10aKernelsRegistry, EverySignatureHasAParserMagicAndDescription) {
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

TEST(B10aKernelsRegistry, ShortSignatureIsFalseAndMagicOffsetIsZeroForEveryEntry) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = signature_named(entry.name);
        ASSERT_NE(registered, nullptr) << entry.name << " is not registered";
        EXPECT_FALSE(registered->short_signature)
            << entry.name << ": upstream magic.rs gives every entry in this batch short: false";
        EXPECT_EQ(registered->magic_offset, 0U)
            << entry.name << ": upstream magic.rs gives every entry in this batch magic_offset 0";
    }
}

TEST(B10aKernelsRegistry, AlwaysDisplayMatchesUpstreamMagicTable) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = signature_named(entry.name);
        ASSERT_NE(registered, nullptr) << entry.name << " is not registered";
        EXPECT_EQ(registered->always_display, entry.always_display)
            << "always_display for \"" << entry.name << "\" disagrees with upstream magic.rs";
    }
}

TEST(B10aKernelsRegistry, MagicPatternCountsMatchUpstream) {

    for(const auto& entry : batch_entries()) {
        const auto* registered = signature_named(entry.name);
        ASSERT_NE(registered, nullptr) << entry.name << " is not registered";
        EXPECT_EQ(registered->magic.size(), entry.magic_count)
            << "\"" << entry.name << "\" declares " << registered->magic.size()
            << " magic patterns, upstream declares " << entry.magic_count;
    }
}

TEST(B10aKernelsRegistry, ExtractorDefinitionsMatchUpstream) {

    {
        const auto* value = signature_named("uimage");
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value()) << "uimage declares no extractor";
        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
        EXPECT_NE(definition.internal, nullptr);
        EXPECT_FALSE(definition.do_not_recurse);
    }

    {
        const auto* value = signature_named("vxworks_symtab");
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value())
            << "vxworks_symtab declares no extractor";
        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
        EXPECT_NE(definition.internal, nullptr);
        EXPECT_TRUE(definition.do_not_recurse)
            << "upstream's vxworks_symtab_extractor() sets do_not_recurse: true";
    }

    {
        const auto* value = signature_named("linux_kernel");
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value())
            << "linux_kernel declares no extractor";
        const auto& definition = *value->extractor_definition;
        EXPECT_NE(definition.type, binwalk::extractor_type::external)
            << "linux_kernel's documented capability gap (§7b) must be a native stub, not an "
            << "external command -- an external definition here would mean shelling out to a "
            << "Python tool, which contract §7 forbids even as a subprocess";
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
        EXPECT_NE(definition.internal, nullptr);
        EXPECT_TRUE(definition.do_not_recurse)
            << "upstream's linux_kernel_extractor() sets do_not_recurse: true";
    }

    for(const char* name : {"elf", "linux_boot_image", "linux_arm_zimage",
                            "linux_arm64_boot_image", "wind_kernel", "ecos"}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        EXPECT_FALSE(value->extractor_definition.has_value())
            << name << " declares an extractor; upstream magic.rs declares extractor: None";
    }
}

TEST(B10aKernelsRegistry, NoMagicPatternIsAPrefixOfAnother) {

    struct flat_pattern {
        std::string signature;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<flat_pattern> patterns;
    for(const auto& value : batch()) {
        for(const auto& pattern : value.magic) {
            patterns.push_back({value.name, pattern});
        }
    }

    for(std::size_t first = 0; first < patterns.size(); ++first) {
        for(std::size_t second = 0; second < patterns.size(); ++second) {
            if(first == second) {
                continue;
            }
            const bool first_is_shorter = patterns[first].bytes.size() <= patterns[second].bytes.size();
            const auto& shorter = first_is_shorter ? patterns[first] : patterns[second];
            const auto& longer = first_is_shorter ? patterns[second] : patterns[first];
            if(shorter.bytes.empty()) {
                continue;
            }
            const bool is_prefix =
                std::equal(shorter.bytes.begin(), shorter.bytes.end(), longer.bytes.begin());
            EXPECT_FALSE(is_prefix)
                << "\"" << shorter.signature << "\"'s pattern is a byte-prefix of \""
                << longer.signature << "\"'s -- they could both match at the same offset, "
                << "which silently changes overlap resolution";
        }
    }
}

namespace {

struct positive_row {
    const char* label;
    const char* signature;
    std::function<bytes()> build;
    std::size_t prefix;
    std::size_t argument_offset;
    std::uint64_t expected_offset;
    std::uint64_t expected_size;
    confidence_tier tier;
    bool extraction_declined;
    std::vector<std::string> facts;
    std::vector<std::string> absent_facts;
};

const std::vector<positive_row>& positive_rows() {
    static const std::vector<positive_row> rows{
        {"elf", "elf", [] { return elf_image(); }, 0, 0, 0, 0,
         confidence_tier::medium, false,
         {"32-bit executable", "ARM for System-V (Unix)", "little endian"}, {}},

        {"elf_at_nonzero_offset", "elf", [] { return elf_image(); }, 37, 0, 0, 0,
         confidence_tier::medium, false, {"ARM for System-V (Unix)"}, {}},

        {"uimage_good", "uimage", [] { return uimage_good_image(); }, 0, 0, 0, 320,
         confidence_tier::high, false,
         {"header size: 64 bytes", "data size: 256 bytes", "compression: gzip",
          "CPU: MIPS32", "OS: Linux", "image type: OS Kernel Image",
          "load address: 0x80000000", "image name: \"MIPS OpenWrt Linux-5.10\""},
         {"invalid checksum"}},
        {"uimage_at_nonzero_offset", "uimage", [] { return uimage_good_image(); }, 41, 0, 0, 320,
         confidence_tier::high, false, {"image name: \"MIPS OpenWrt Linux-5.10\""}, {}},
        {"uimage_okli", "uimage",
         [] { return uimage_image(0x4F4B4C49U, "OKLI kernel", false); }, 0, 0, 0, 320,
         confidence_tier::high, false, {"image name: \"OKLI kernel\""}, {}},
        {"uimage_badcrc", "uimage",
         [] { return uimage_image(0x27051956U, "MIPS OpenWrt Linux-5.10", true); }, 0, 0, 0, 320,
         confidence_tier::medium, true, {"invalid checksum"}, {}},

        {"linux_kernel_no_symtab", "linux_kernel", [] { return linux_kernel_image(false); },
         0, 4096, 4096, 135, confidence_tier::low, true,
         {"4.9.241", "has symbol table: false"}, {"has symbol table: true"}},
        {"linux_kernel_with_symtab", "linux_kernel", [] { return linux_kernel_image(true); },
         0, 4096, 0, 124253, confidence_tier::low, false,
         {"4.9.241", "has symbol table: true"}, {"has symbol table: false"}},

        {"linux_boot_image", "linux_boot_image", [] { return linux_boot_image_image(); },
         0, 64, 64, 0, confidence_tier::low, false, {"Linux kernel boot image"}, {}},

        {"linux_arm_zimage_le", "linux_arm_zimage",
         [] { return linux_arm_zimage_image(false); }, 0, 100, 64, 0,
         confidence_tier::medium, false, {"little endian"}, {"big endian"}},
        {"linux_arm_zimage_be", "linux_arm_zimage",
         [] { return linux_arm_zimage_image(true); }, 0, 100, 64, 0,
         confidence_tier::medium, false, {"big endian"}, {"little endian"}},

        {"linux_arm64_boot_image", "linux_arm64_boot_image",
         [] { return linux_arm64_boot_image_image(); }, 0, 176, 128, 64,
         confidence_tier::medium, false, {"little endian", "16777216 bytes"}, {}},

        {"wind_kernel", "wind_kernel", [] { return wind_kernel_image(); }, 0, 32, 32, 17,
         confidence_tier::low, false, {"2.11"}, {}},

        {"vxworks_symtab_be", "vxworks_symtab", [] { return vxworks_symtab_image(true); },
         0, 24, 16, 4000, confidence_tier::high, false, {"4000 bytes"}, {}},
        {"vxworks_symtab_le", "vxworks_symtab", [] { return vxworks_symtab_image(false); },
         0, 24, 16, 4000, confidence_tier::high, false, {"4000 bytes"}, {}},

        {"ecos_le", "ecos", [] { return ecos_image(false); }, 0, 32, 32, 0,
         confidence_tier::low, false, {"MIPS little endian"}, {"big"}},
        {"ecos_be", "ecos", [] { return ecos_image(true); }, 0, 32, 32, 0,
         confidence_tier::low, false, {"MIPS big endian"}, {"little"}},
    };
    return rows;
}

struct row_name {
    template<typename ParamType>
    std::string operator()(const testing::TestParamInfo<ParamType>& info) const {
        return info.param.label;
    }
};

class B10aKernelsPositiveFixtures : public testing::TestWithParam<positive_row> {};

}

TEST_P(B10aKernelsPositiveFixtures, ParserMatchesTheOracle) {
    const auto& row = GetParam();
    bytes data(row.prefix, 0x00);
    const auto body = row.build();
    data.insert(data.end(), body.begin(), body.end());
    const auto call_offset = row.prefix + row.argument_offset;

    const auto result = parse_at(row.signature, data, call_offset);
    ASSERT_TRUE(result.has_value())
        << "expected a " << row.signature << " match calling the parser at offset "
        << call_offset;

    EXPECT_EQ(result->offset, static_cast<std::uint64_t>(row.prefix) + row.expected_offset);
    EXPECT_EQ(result->size, row.expected_size);
    expect_confidence_tier(result->confidence, row.tier);
    EXPECT_EQ(result->extraction_declined, row.extraction_declined);

    EXPECT_TRUE(result->name.empty());
    EXPECT_TRUE(result->id.empty());
    EXPECT_FALSE(result->always_display);

    for(const auto& fact : row.facts) {
        EXPECT_TRUE(contains(result->description, fact))
            << "description \"" << result->description << "\" is missing \"" << fact << "\"";
    }
    for(const auto& fact : row.absent_facts) {
        EXPECT_FALSE(contains(result->description, fact))
            << "description \"" << result->description << "\" carries \"" << fact
            << "\", which it should not for this input";
    }
    expect_in_bounds(*result, data.size());
}

INSTANTIATE_TEST_SUITE_P(
    OracleFixtures, B10aKernelsPositiveFixtures, testing::ValuesIn(positive_rows()), row_name()
);

TEST(B10aKernelsBackOffsets, UnderflowGuardsRejectRatherThanWrapping) {
    const bytes data(512, 0x00);

    EXPECT_FALSE(parse_at("linux_arm_zimage", data, 4).has_value())
        << "offset 4 < back-offset 36 must be rejected, not underflowed";
    EXPECT_FALSE(parse_at("linux_arm_zimage", data, 35).has_value())
        << "offset 35 < back-offset 36 (one short) must be rejected";

    EXPECT_FALSE(parse_at("linux_arm64_boot_image", data, 20).has_value())
        << "offset 20 < back-offset 0x30 (48) must be rejected, not underflowed";
    EXPECT_FALSE(parse_at("linux_arm64_boot_image", data, 47).has_value())
        << "offset 47 < back-offset 0x30 (one short) must be rejected";

    EXPECT_FALSE(parse_at("vxworks_symtab", data, 0).has_value())
        << "offset 0 < back-offset 8 must be rejected, not underflowed";
    EXPECT_FALSE(parse_at("vxworks_symtab", data, 7).has_value())
        << "offset 7 < back-offset 8 (one short) must be rejected";
}

namespace {

struct rejection_row {
    const char* label;
    const char* signature;
    std::function<bytes()> build;
    std::vector<poke> pokes;
    std::size_t truncate_to;
    std::size_t call_offset;
};

const std::vector<rejection_row>& rejection_rows() {
    static const std::vector<rejection_row> rows{

        {"elf_magic_only", "elf", [] { return elf_image(); }, {}, 4, 0},
        {"elf_truncated_before_info", "elf", [] { return elf_image(); }, {}, 20, 0},
        {"elf_bad_version_byte", "elf", [] { return elf_image(); }, {at(6, 0)}, 0, 0},
        {"elf_bad_class", "elf", [] { return elf_image(); }, {at(4, 3)}, 0, 0},
        {"elf_bad_endianness", "elf", [] { return elf_image(); }, {at(5, 0)}, 0, 0},
        {"elf_bad_osabi", "elf", [] { return elf_image(); }, {at(7, 0xF0)}, 0, 0},
        {"elf_bad_info_version", "elf", [] { return elf_image(); }, {at(20, 2)}, 0, 0},
        {"elf_bad_info_type", "elf", [] { return elf_image(); }, {at(16, 9), at(17, 0)}, 0, 0},

        {"elf_shared_padding_byte_nonzero", "elf", [] { return elf_image(); },
         {at(13, 1)}, 0, 0},

        {"uimage_magic_corrupted", "uimage", [] { return uimage_good_image(); },
         {at(0, 0x00)}, 0, 0},
        {"uimage_truncated_to_200", "uimage", [] { return uimage_good_image(); }, {}, 200, 0},
        {"uimage_bad_os_type", "uimage", [] { return uimage_good_image(); },
         {at(28, 0xFF)}, 0, 0},
        {"uimage_bad_cpu_type", "uimage", [] { return uimage_good_image(); },
         {at(29, 0xFF)}, 0, 0},
        {"uimage_bad_image_type", "uimage", [] { return uimage_good_image(); },
         {at(30, 0xFF)}, 0, 0},
        {"uimage_bad_compression_type", "uimage", [] { return uimage_good_image(); },
         {at(31, 0xFF)}, 0, 0},

        {"uimage_data_truncated_one_short", "uimage", [] { return uimage_good_image(); },
         {}, 319, 0},

        {"linux_kernel_file_too_small", "linux_kernel", [] { return linux_kernel_image(false); },
         {}, 4296, 4096},
        {"linux_kernel_bad_first_period", "linux_kernel",
         [] { return linux_kernel_image(false); }, {at(4111, 'X')}, 0, 4096},
        {"linux_kernel_missing_at_sign", "linux_kernel",
         [] { return linux_kernel_image(false); }, {at(4123, 'X')}, 0, 4096},
        {"linux_kernel_missing_gcc_token", "linux_kernel",
         [] { return linux_kernel_image(false); }, {at(4134, 'X')}, 0, 4096},
        {"linux_kernel_missing_trailing_newline", "linux_kernel",
         [] { return linux_kernel_image(false); }, {at(4230, ' ')}, 0, 4096},

        {"linux_boot_image_bad_hdrs", "linux_boot_image",
         [] { return linux_boot_image_image(); }, {at(578, 'X')}, 0, 64},
        {"linux_boot_image_truncated_before_hdrs", "linux_boot_image",
         [] { return linux_boot_image_image(); }, {}, 578, 64},

        {"linux_arm_zimage_nop_mismatch", "linux_arm_zimage",
         [] { return linux_arm_zimage_image(false); }, {at(70, 0x55)}, 0, 100},

        {"linux_arm64_reserved1_nonzero", "linux_arm64_boot_image",
         [] { return linux_arm64_boot_image_image(); }, {at(160, 0x01)}, 0, 176},
        {"linux_arm64_pe_signature_missing", "linux_arm64_boot_image",
         [] { return linux_arm64_boot_image_image(); }, {at(192, 'X')}, 0, 176},

        {"linux_arm64_flags_reserved_bit_set", "linux_arm64_boot_image",
         [] { return linux_arm64_boot_image_image(); }, {at(153, 0x01)}, 0, 176},

        {"vxworks_symtab_one_entry_short", "vxworks_symtab",
         [] { return vxworks_symtab_image(true); }, {}, 4000, 24},

        {"vxworks_symtab_middle_entry_invalid", "vxworks_symtab",
         [] { return vxworks_symtab_image(true); },
         {at(1616, 0x00), at(1617, 0x00), at(1618, 0x00), at(1619, 0x00)}, 0, 24},
    };
    return rows;
}

class B10aKernelsRejections : public testing::TestWithParam<rejection_row> {};

}

TEST_P(B10aKernelsRejections, IsRejected) {
    const auto& row = GetParam();
    const auto data = build_input(row.build(), row.pokes, row.truncate_to);
    const auto result = parse_at(row.signature, data, row.call_offset);
    EXPECT_FALSE(result.has_value())
        << "the " << row.signature << " parser accepted a malformed buffer at offset "
        << row.call_offset << " (" << data.size() << " bytes)";
}

INSTANTIATE_TEST_SUITE_P(
    MalformedInputs, B10aKernelsRejections, testing::ValuesIn(rejection_rows()), row_name()
);

TEST(B10aKernelsEcos, EachOfTheFourMagicPatternsSucceedsStandingAlone) {
    const std::vector<std::pair<bytes, const char*>> cases{
        {{0x00, 0x68, 0x1A, 0x40, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x5A, 0x33}, "little"},
        {{0x00, 0x68, 0x1A, 0x40, 0x7F, 0x00, 0x5A, 0x33}, "little"},
        {{0x40, 0x1A, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x5A, 0x00, 0x7F}, "big"},
        {{0x40, 0x1A, 0x68, 0x00, 0x33, 0x5A, 0x00, 0x7F}, "big"},
    };
    for(const auto& entry : cases) {
        SCOPED_TRACE(entry.second);
        const auto result = parse_at("ecos", entry.first, 0);
        ASSERT_TRUE(result.has_value())
            << "upstream's exception_handler_parser unconditionally succeeds once its magic "
            << "matches -- it never fails, even on the shortest 8-byte variant";
        EXPECT_EQ(result->offset, 0U);
        EXPECT_EQ(result->size, 0U);
        EXPECT_TRUE(contains(result->description, entry.second));
    }
}

namespace {

bytes elf_header_only(std::uint8_t abiversion, std::uint8_t padding2_tail) {
    bytes out(24, 0x00);
    out[0] = 0x7F; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
    out[4] = 1; out[5] = 1; out[6] = 1; out[7] = 0;
    out[8] = abiversion;

    out[15] = padding2_tail;
    out[16] = 2; out[17] = 0;
    out[18] = 0x28; out[19] = 0;
    out[20] = 1; out[21] = 0; out[22] = 0; out[23] = 0;
    return out;
}

}

TEST(B10aKernelsKnownBugs, ElfAbiversionIsNotValidatedByUpstream) {
    const auto data = elf_header_only(5, 0);
    const auto result = parse_at("elf", data, 0);
    EXPECT_TRUE(result.has_value())
        << "upstream never validates e_ident's abiversion byte -- a nonzero abiversion must "
        << "still be detected (oracle: offset 0, size 24, detects). See section 6's comment "
        << "for the fix.";
}

TEST(B10aKernelsKnownBugs, ElfRejectsNonzeroPaddingTailByte) {
    const auto data = elf_header_only(0, 7);
    const auto result = parse_at("elf", data, 0);
    EXPECT_FALSE(result.has_value())
        << "upstream requires e_ident's padding_2 (offset+13..16) to be all zero, and the true "
        << "tail byte is offset+15 -- oracle rejects this input outright. See section 6's "
        << "comment for the fix.";
}

namespace {

struct safety_fixture {
    const char* signature;
    std::function<bytes()> build;
    std::size_t argument_offset;
};

const std::vector<safety_fixture>& safety_fixtures() {
    static const std::vector<safety_fixture> items{
        {"elf", [] { return elf_image(); }, 0},
        {"uimage", [] { return uimage_good_image(); }, 0},
        {"linux_kernel", [] { return linux_kernel_image(true); }, 4096},
        {"linux_boot_image", [] { return linux_boot_image_image(); }, 64},
        {"linux_arm_zimage", [] { return linux_arm_zimage_image(false); }, 100},
        {"linux_arm64_boot_image", [] { return linux_arm64_boot_image_image(); }, 176},
        {"wind_kernel", [] { return wind_kernel_image(); }, 32},
        {"vxworks_symtab", [] { return vxworks_symtab_image(true); }, 24},
        {"ecos", [] { return ecos_image(false); }, 32},
    };
    return items;
}

}

TEST(B10aKernelsSafety, EveryPrefixOfEveryFixtureParsesInBoundsAtSeveralOffsets) {
    for(const auto& item : safety_fixtures()) {
        SCOPED_TRACE(item.signature);
        const auto full = item.build();

        std::vector<std::size_t> cuts{
            0, 1, item.argument_offset / 2, item.argument_offset, item.argument_offset + 1,
            full.size() / 2, full.size() > 0 ? full.size() - 1 : 0, full.size()
        };
        std::sort(cuts.begin(), cuts.end());
        cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());

        for(const auto cut : cuts) {
            if(cut > full.size()) {
                continue;
            }
            const bytes prefix(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
            const std::vector<std::size_t> offsets{
                0,
                item.argument_offset,
                item.argument_offset > 0 ? item.argument_offset - 1 : 0,
                prefix.size()
            };
            for(const auto offset : offsets) {
                const auto result = parse_at(item.signature, prefix, offset);
                if(result) {
                    expect_in_bounds(*result, prefix.size());
                }
            }
        }
    }
}

TEST(B10aKernelsSafety, DegenerateBuffersNeverProduceAnOutOfBoundsResult) {
    const std::vector<std::size_t> lengths{0, 1, 2, 3, 7, 15, 16, 17, 63, 64, 256, 1024};
    for(const auto& name : batch_names()) {
        for(const auto length : lengths) {
            for(const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xFF},
                                           static_cast<std::uint8_t>('A')}) {
                const bytes data(length, fill);
                const std::vector<std::size_t> offsets{0, length / 2, length};
                for(const auto offset : offsets) {
                    const auto result = parse_at(name, data, offset);
                    if(result) {
                        expect_in_bounds(*result, data.size());
                    }
                }
            }
        }
    }
}

TEST(B10aKernelsSafety, AnAbsurdOffsetIsRangeCheckedNeverTurnedIntoAWildRead) {
    const auto absurd = (std::numeric_limits<std::size_t>::max)() / 2U + 1U;
    const bytes data(64, 0xA5);
    for(const auto& name : batch_names()) {
        EXPECT_FALSE(parse_at(name, data, absurd).has_value()) << name;
        EXPECT_FALSE(parse_at(name, data, data.size()).has_value()) << name;
        EXPECT_FALSE(parse_at(name, data, data.size() + 1).has_value()) << name;
    }
}

TEST(B10aKernelsExtractors, UimageDryRunValidatesFullyAndWritesNothing) {
    const auto data = uimage_good_image();
    const auto* value = signature_named("uimage");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto parsed = value->parser(view(data), 0);
    ASSERT_TRUE(parsed.has_value());

    const auto dry = binwalk::dry_run_extractor(*value->extractor_definition, view(data), *parsed);
    EXPECT_TRUE(dry.success);
    ASSERT_TRUE(dry.size.has_value());
    EXPECT_EQ(*dry.size, 320U);

    const auto scratch = temp_dir("uimage_dry_run");
    std::error_code error;
    std::filesystem::create_directories(scratch, error);
    ASSERT_NE(value->extractor_definition->internal, nullptr);
    const auto direct = value->extractor_definition->internal(view(data), *parsed, nullptr);
    EXPECT_TRUE(direct.success);
    EXPECT_EQ(count_entries(scratch), 0U);
    std::filesystem::remove_all(scratch, error);
}

TEST(B10aKernelsExtractors, UimageRealExtractionCarvesTheDataPayload) {
    const auto data = uimage_good_image();
    const auto* value = signature_named("uimage");
    ASSERT_NE(value, nullptr);
    const auto parsed = value->parser(view(data), 0);
    ASSERT_TRUE(parsed.has_value());

    const auto output_root = temp_dir("uimage_extract");
    const auto result = binwalk::execute_extractor(
        view(data), "uimage.bin", *parsed, *value->extractor_definition, output_root.string()
    );
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::none);

    const auto files = binwalk::chroot::extracted_files(output_root.string());
    ASSERT_EQ(files.size(), 1U)
        << "uimage carves exactly one payload file; file naming is FREE under contract §5";
    const auto content = read_file_bytes(files.front());
    EXPECT_EQ(content.size(), 256U);
    EXPECT_TRUE(std::all_of(
        content.begin(), content.end(), [](std::uint8_t value_) { return value_ == 0x42U; }
    )) << "extracted content is STRICT under contract §5";

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, UimageOkliRealExtractionAlsoSucceeds) {
    const auto data = uimage_image(0x4F4B4C49U, "OKLI kernel", false);
    const auto* value = signature_named("uimage");
    const auto parsed = value->parser(view(data), 0);
    ASSERT_TRUE(parsed.has_value());

    const auto output_root = temp_dir("uimage_okli_extract");
    const auto result = binwalk::execute_extractor(
        view(data), "uimage_okli.bin", *parsed, *value->extractor_definition, output_root.string()
    );
    EXPECT_TRUE(result.success);
    const auto files = binwalk::chroot::extracted_files(output_root.string());
    ASSERT_EQ(files.size(), 1U);
    EXPECT_EQ(read_file_bytes(files.front()).size(), 256U);

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, UimageBadCrcIsDeclinedAndNeverReachesTheExtractor) {
    const auto data = uimage_image(0x27051956U, "MIPS OpenWrt Linux-5.10", true);
    const auto results = batch_scanner().scan(view(data));
    ASSERT_EQ(results.size(), 1U);
    EXPECT_TRUE(results.front().extraction_declined);

    const auto output_root = temp_dir("uimage_badcrc_extract");
    const auto extractions =
        batch_scanner().extract(view(data), "uimage_badcrc.bin", results, output_root.string());
    EXPECT_TRUE(extractions.empty())
        << "scanner::extract skips every declined result outright (`if(identified."
        << "extraction_declined) continue;` in lib/src/scanner.cpp) -- there must be NO entry "
        << "at all, not a failed one";

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, VxworksSymtabDryRunValidatesFullyAndWritesNothing) {
    const auto data = vxworks_symtab_image(true);
    const auto* value = signature_named("vxworks_symtab");
    ASSERT_NE(value, nullptr);
    const auto parsed = value->parser(view(data), 24);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->offset, 16U);
    ASSERT_EQ(parsed->size, 4000U);

    const auto dry = binwalk::dry_run_extractor(*value->extractor_definition, view(data), *parsed);
    EXPECT_TRUE(dry.success);
    ASSERT_TRUE(dry.size.has_value());
    EXPECT_EQ(*dry.size, 4000U);

    const auto scratch = temp_dir("vxworks_symtab_dry_run");
    std::error_code error;
    std::filesystem::create_directories(scratch, error);
    EXPECT_EQ(count_entries(scratch), 0U);
    std::filesystem::remove_all(scratch, error);
}

TEST(B10aKernelsExtractors, VxworksSymtabRealExtractionWritesTheFullJsonArray) {
    const auto data = vxworks_symtab_image(true);
    const auto* value = signature_named("vxworks_symtab");
    const auto parsed = value->parser(view(data), 24);
    ASSERT_TRUE(parsed.has_value());

    const auto output_root = temp_dir("vxworks_symtab_extract");
    const auto result = binwalk::execute_extractor(
        view(data), "vxworks_symtab.bin", *parsed, *value->extractor_definition,
        output_root.string()
    );
    EXPECT_TRUE(result.success);

    const auto files = binwalk::chroot::extracted_files(output_root.string());
    ASSERT_EQ(files.size(), 1U);
    const auto content = read_file_bytes(files.front());

    EXPECT_EQ(content.size(), 25996U);

    const std::string text(content.begin(), content.end());
    static const std::string expected_prefix =
        "[\n  {\n    \"size\": 16,\n    \"name\": 286331153,\n    \"value\": 572662306,\n"
        "    \"symtype\": \"function\"\n  },\n  {";
    ASSERT_GE(text.size(), expected_prefix.size());
    EXPECT_EQ(text.substr(0, expected_prefix.size()), expected_prefix)
        << "extracted content is STRICT under contract §5 (nlohmann_json is not linked into "
        << "binwalk::core, so this is a plain text comparison, not a JSON-library parse). "
        << "Actual prefix: " << text.substr(0, expected_prefix.size());
    ASSERT_FALSE(text.empty());
    EXPECT_EQ(text.back(), ']') << "no trailing newline, matching serde_json::to_string_pretty";

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, LinuxKernelExtractionIsADocumentedCapabilityGapNotABug) {

    const auto data = linux_kernel_image(true);
    const auto* value = signature_named("linux_kernel");
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto parsed = value->parser(view(data), 4096);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_FALSE(parsed->extraction_declined)
        << "this input HAS a symbol table, so extraction is attempted rather than declined -- "
        << "the gap has to be observed through an actual extraction attempt, not through the "
        << "(different) declined-skip path exercised below";

    const auto dry = binwalk::dry_run_extractor(*value->extractor_definition, view(data), *parsed);
    EXPECT_FALSE(dry.success);
    EXPECT_EQ(dry.failure, binwalk::extraction_failure::unsupported);

    const auto output_root = temp_dir("linux_kernel_gap");
    const auto real = binwalk::execute_extractor(
        view(data), "linux_kernel_symtab.bin", *parsed, *value->extractor_definition,
        output_root.string()
    );
    EXPECT_FALSE(real.success);
    EXPECT_EQ(real.failure, binwalk::extraction_failure::unsupported);

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, LinuxKernelGapIsVisibleThroughTheFullScannerPipeline) {
    const auto data = linux_kernel_image(true);
    const auto output_root = temp_dir("linux_kernel_gap_scanner");
    const auto analysis =
        batch_scanner().analyze(view(data), "linux_kernel_symtab.bin", true, output_root.string());
    ASSERT_EQ(analysis.file_map.size(), 1U);
    EXPECT_EQ(analysis.file_map.front().name, "linux_kernel");
    ASSERT_EQ(analysis.extractions.size(), 1U)
        << "extraction_declined is false here, so scanner::extract does not skip it -- an "
        << "entry must exist, reporting the gap rather than being silently absent";
    const auto& extraction = analysis.extractions.at(analysis.file_map.front().id);
    EXPECT_FALSE(extraction.success);
    EXPECT_EQ(extraction.failure, binwalk::extraction_failure::unsupported);

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

TEST(B10aKernelsExtractors, LinuxKernelWithoutASymbolTableIsDeclinedNotAttempted) {

    const auto data = linux_kernel_image(false);
    const auto output_root = temp_dir("linux_kernel_declined_scanner");
    const auto analysis =
        batch_scanner().analyze(view(data), "linux_kernel.bin", true, output_root.string());
    ASSERT_EQ(analysis.file_map.size(), 1U);
    EXPECT_TRUE(analysis.file_map.front().extraction_declined);
    EXPECT_TRUE(analysis.extractions.empty());

    std::error_code error;
    std::filesystem::remove_all(output_root, error);
}

namespace {

struct scanner_row {
    const char* label;
    const char* signature;
    std::function<bytes()> build;
    std::uint64_t expected_offset;
    std::uint64_t expected_size;
    confidence_tier tier;
    bool always_display;
    bool extraction_declined;
};

const std::vector<scanner_row>& scanner_rows() {
    static const std::vector<scanner_row> rows{
        {"elf", "elf", [] { return elf_image(); }, 0, 256, confidence_tier::medium, false, false},
        {"uimage_good", "uimage", [] { return uimage_good_image(); }, 0, 320,
         confidence_tier::high, false, false},
        {"uimage_okli", "uimage",
         [] { return uimage_image(0x4F4B4C49U, "OKLI kernel", false); }, 0, 320,
         confidence_tier::high, false, false},
        {"uimage_badcrc", "uimage",
         [] { return uimage_image(0x27051956U, "MIPS OpenWrt Linux-5.10", true); }, 0, 320,
         confidence_tier::medium, false, true},
        {"linux_kernel_no_symtab", "linux_kernel", [] { return linux_kernel_image(false); },
         4096, 135, confidence_tier::low, true, true},
        {"linux_kernel_with_symtab", "linux_kernel", [] { return linux_kernel_image(true); },
         0, 124253, confidence_tier::low, true, false},
        {"linux_boot_image", "linux_boot_image", [] { return linux_boot_image_image(); },
         64, 583, confidence_tier::low, false, false},
        {"linux_arm_zimage_le", "linux_arm_zimage",
         [] { return linux_arm_zimage_image(false); }, 64, 168, confidence_tier::medium,
         false, false},
        {"linux_arm_zimage_be", "linux_arm_zimage",
         [] { return linux_arm_zimage_image(true); }, 64, 168, confidence_tier::medium,
         false, false},
        {"linux_arm64_boot_image", "linux_arm64_boot_image",
         [] { return linux_arm64_boot_image_image(); }, 128, 64, confidence_tier::medium,
         false, false},
        {"wind_kernel", "wind_kernel", [] { return wind_kernel_image(); }, 32, 17,
         confidence_tier::low, true, false},
        {"vxworks_symtab_be", "vxworks_symtab", [] { return vxworks_symtab_image(true); },
         16, 4000, confidence_tier::high, true, false},
        {"vxworks_symtab_le", "vxworks_symtab", [] { return vxworks_symtab_image(false); },
         16, 4000, confidence_tier::high, true, false},
        {"ecos_le", "ecos", [] { return ecos_image(false); }, 32, 76, confidence_tier::low,
         true, false},
        {"ecos_be", "ecos", [] { return ecos_image(true); }, 32, 76, confidence_tier::low,
         true, false},
    };
    return rows;
}

class B10aKernelsScannerPositive : public testing::TestWithParam<scanner_row> {};

}

TEST_P(B10aKernelsScannerPositive, MatchesTheFullPipeline) {
    const auto& row = GetParam();
    const auto data = row.build();
    const auto found = scan_for(row.signature, data);
    ASSERT_TRUE(found.has_value())
        << "the scanner produced no result named \"" << row.signature << "\"";

    EXPECT_EQ(found->name, row.signature)
        << "name is the --include/--exclude key and is STRICT under contract §5";
    EXPECT_EQ(found->offset, row.expected_offset);
    EXPECT_EQ(found->size, row.expected_size);
    expect_confidence_tier(found->confidence, row.tier);
    EXPECT_EQ(found->always_display, row.always_display);
    EXPECT_EQ(found->extraction_declined, row.extraction_declined);
    EXPECT_FALSE(found->id.empty()) << "populate() must assign an id";
}

INSTANTIATE_TEST_SUITE_P(
    OracleFixtures, B10aKernelsScannerPositive, testing::ValuesIn(scanner_rows()), row_name()
);

TEST(B10aKernelsScanner, ZeroSizeParserResultIsFilledToTheNextBoundaryByTheScanner) {

    {
        const auto data = elf_image();
        const auto raw = parse_at("elf", data, 0);
        ASSERT_TRUE(raw.has_value());
        EXPECT_EQ(raw->size, 0U) << "the parser reports 0";

        const auto scanned = scan_for("elf", data);
        ASSERT_TRUE(scanned.has_value());
        EXPECT_EQ(scanned->size, static_cast<std::uint64_t>(data.size()))
            << "filled to EOF -- nothing else is in this buffer";
        EXPECT_EQ(scanned->confidence, raw->confidence)
            << "filling in the size must not promote the confidence";
    }
    {
        const auto data = linux_boot_image_image();
        const auto raw = parse_at("linux_boot_image", data, 64);
        ASSERT_TRUE(raw.has_value());
        EXPECT_EQ(raw->size, 0U);

        const auto scanned = scan_for("linux_boot_image", data);
        ASSERT_TRUE(scanned.has_value());
        EXPECT_EQ(scanned->offset, 64U);
        EXPECT_EQ(scanned->size, static_cast<std::uint64_t>(data.size()) - 64U)
            << "filled from offset 64 to EOF";
    }
}

TEST(B10aKernelsScanner, AgreesWithTheRawParserOnEveryFieldTheParserSets) {
    const auto data = uimage_good_image();
    const auto raw = parse_at("uimage", data, 0);
    const auto scanned = scan_for("uimage", data);
    ASSERT_TRUE(raw.has_value());
    ASSERT_TRUE(scanned.has_value());

    EXPECT_EQ(scanned->offset, raw->offset);
    EXPECT_EQ(scanned->size, raw->size);
    EXPECT_EQ(scanned->confidence, raw->confidence);
    EXPECT_EQ(scanned->extraction_declined, raw->extraction_declined);
    EXPECT_EQ(scanned->description, raw->description);

    EXPECT_TRUE(raw->name.empty())
        << "if the parser has started setting `name` itself, this expectation (and this "
        << "file's rationale for not asserting `name` on a raw parser result) should go";
    EXPECT_EQ(scanned->name, "uimage");
    EXPECT_TRUE(raw->id.empty());
    EXPECT_FALSE(scanned->id.empty());
}

TEST(B10aKernelsScanner, OverlapFilterKeepsTheHigherPrioritySpanAndDropsTheEmbeddedMatch) {

    bytes header(64, 0x00);
    write_u32_be_at(header, 0, 0x27051956U);

    write_u32_be_at(header, 8, 0);
    write_u32_be_at(header, 12, 0);
    write_u32_be_at(header, 16, 0);
    write_u32_be_at(header, 20, 0);
    write_u32_be_at(header, 24, 0);
    header[28] = 5; header[29] = 5; header[30] = 2; header[31] = 0;

    static const std::string wind_text = "WIND version 1.0";
    std::copy(wind_text.begin(), wind_text.end(), header.begin() + 32);
    header[32 + wind_text.size()] = 0x00;

    const auto header_crc = binwalk::crc32(binwalk::byte_view(header.data(), 64));
    write_u32_be_at(header, 4, header_crc);

    ASSERT_EQ(header.size(), std::size_t{64});
    ASSERT_TRUE(parse_at("uimage", header, 0).has_value()) << "sanity: the header must be valid";
    ASSERT_TRUE(parse_at("wind_kernel", header, 32).has_value())
        << "sanity: the embedded text must independently parse as wind_kernel";

    binwalk::scan_options options;
    options.search_all = true;
    const binwalk::scanner scanner(batch(), options);
    const auto results = scanner.scan(view(header));

    ASSERT_EQ(results.size(), 1U)
        << "expected exactly one surviving result (uimage); wind_kernel's embedded match "
        << "should have been dropped by the overlap filter -- see this test's comment for the "
        << "exact mechanism";
    EXPECT_EQ(results.front().name, "uimage");
    EXPECT_EQ(results.front().offset, 0U);
    EXPECT_EQ(results.front().size, 64U);
}
