
#include "../../lib/src/formats/b4_encrypted.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/codec.hpp>
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
        binwalk::formats::b4_encrypted_signatures();
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
        "arcadyan", "openssl", "autel", "dlink_tlv", "shrs",
        "encrpted_img", "dms", "dkbs", "encfw"
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

void write_ascii_at(bytes& out, std::size_t at, std::string_view text) {
    for(std::size_t index = 0; index < text.size(); ++index) {
        out[at + index] = static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    }
}

void zeros_to(bytes& out, std::size_t length) {
    while(out.size() < length) {
        out.push_back(0x00);
    }
}

std::uint8_t filler_byte(std::size_t index) {
    return static_cast<std::uint8_t>(
        0x80U + ((37U * static_cast<unsigned>(index) + 8U) % 121U)
    );
}

void pad_with_filler_to(bytes& out, std::size_t length) {
    while(out.size() < length) {
        out.push_back(filler_byte(out.size()));
    }
}

bytes from_hex(std::string_view hex) {
    const auto nibble = [](char character) -> std::uint8_t {
        if(character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        return static_cast<std::uint8_t>(character - 'a' + 10);
    };
    bytes out;
    out.reserve(hex.size() / 2U);
    for(std::size_t index = 0; index + 1U < hex.size(); index += 2U) {
        out.push_back(static_cast<std::uint8_t>(
            (nibble(hex[index]) << 4U) | nibble(hex[index + 1U])
        ));
    }
    return out;
}

bytes truncate_to(bytes data, std::size_t length) {
    if(data.size() > length) {
        data.resize(length);
    }
    return data;
}

bytes at_offset(const bytes& data, std::size_t prefix_length) {
    bytes out(prefix_length, 0x00);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

binwalk::byte_view view(const bytes& data) {
    return binwalk::byte_view(data.data(), data.size());
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

std::size_t absurd_offset() {
    return ((std::numeric_limits<std::size_t>::max)() / 2U) + 1U;
}

bytes registered_magic(const std::string& name, std::size_t index = 0) {
    const auto* value = signature_named(name);
    if(value == nullptr || value->magic.size() <= index) {
        return {};
    }
    return value->magic[index];
}

bool lzma_alone_available() {
    return binwalk::codec_available(binwalk::codec_id::lzma_alone);
}

bool row_is_unavailable_without_lzma(std::string_view name) {
    return name == "arcadyan" && !lzma_alone_available();
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

void expect_rejected(
    const std::string& name,
    const bytes& data,
    std::size_t offset,
    std::string_view why
) {
    SCOPED_TRACE(name + " @ offset " + std::to_string(offset) + ": " + std::string(why));
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b4_encrypted_signatures()";
    ASSERT_NE(value->parser, nullptr) << name << " has a null parser";

    const auto result = value->parser(view(data), offset);
    EXPECT_FALSE(result.has_value())
        << name << " accepted a malformed buffer (" << why << "). Policy makes a "
        << "required rejection exactly as strict as a required detection.";
}

const binwalk::scanner& batch_scanner() {
    static const binwalk::scanner value(binwalk::formats::b4_encrypted_signatures());
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

bytes openssl_image() {
    bytes out;
    put_ascii(out, "Salted__");
    put_bytes(out, {0x01, 0x02, 0x03, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD});
    pad_with_filler_to(out, 256);
    return out;
}

bytes openssl_header_only_image() {
    return truncate_to(openssl_image(), 16);
}

bytes openssl_printable_salt_image() {
    bytes out;
    put_ascii(out, "Salted__");
    put_ascii(out, "ABCDEFGH");
    pad_with_filler_to(out, 256);
    return out;
}

bytes encfw_image(const bytes& magic) {
    bytes out = magic;
    pad_with_filler_to(out, 256);
    return out;
}

bytes encrpted_img_image() {
    bytes out;
    put_ascii(out, "encrpted_img");
    pad_with_filler_to(out, 256);
    return out;
}

bytes shrs_image() {
    bytes out;
    put_ascii(out, "SHRS");
    put_bytes(out, {0x00, 0x00, 0x00, 0x01});
    put_bytes(out, {0x00, 0x00, 0x01, 0x00});
    for(unsigned value = 0xA0; value <= 0xAF; ++value) {
        out.push_back(static_cast<std::uint8_t>(value));
    }
    pad_with_filler_to(out, 2012);
    return out;
}

bytes dms_image() {
    bytes out;
    put_bytes(out, {0x4D, 0x47, 0x12, 0x34});
    put_ascii(out, "0><1");
    put_bytes(out, {0x00, 0x00, 0x00, 0x00});
    put_bytes(out, {0x01, 0x00, 0x00, 0x00});
    pad_with_filler_to(out, 256);
    return out;
}

bytes dkbs_image() {
    bytes out;
    put_ascii(out, "DKBS007_dkbs_BOARD");
    zeros_to(out, 40);
    put_ascii(out, "1.02.03");
    zeros_to(out, 104);
    put_bytes(out, {0x00, 0x00, 0x01, 0x00});
    zeros_to(out, 112);
    put_ascii(out, "nand0");
    zeros_to(out, 160);
    pad_with_filler_to(out, 416);
    return out;
}

bytes autel_image() {
    bytes out;
    put_ascii(out, "ECC0101");
    out.push_back(0x00);
    put_bytes(out, {0x00, 0x01, 0x00, 0x00});
    put_bytes(out, {0x20, 0x00, 0x00, 0x00});
    put_ascii(out, "Copyright Autel");
    out.push_back(0x00);
    pad_with_filler_to(out, 288);
    return out;
}

bytes dlink_tlv_image(std::string_view md5_text) {
    bytes out(116, 0x00);
    out[0] = 0x64;
    out[1] = 0x80;
    out[2] = 0x19;
    out[3] = 0x40;
    write_ascii_at(out, 4, "DIR-878");
    write_ascii_at(out, 36, "AP_BOARD_A1");
    if(!md5_text.empty()) {
        write_ascii_at(out, 76, md5_text);
    }
    out[108] = 0x01;
    out[113] = 0x01;
    pad_with_filler_to(out, 372);
    return out;
}

std::string_view dlink_tlv_good_md5() {
    return "60fe5fcaf850277ec9ba364561eb59be";
}

std::string_view dlink_tlv_bad_md5() {
    return "01fe5fcaf850277ec9ba364561eb59be";
}

bytes arcadyan_image() {
    return from_hex(
        "deadbeefbe8d03d60cbe64bbafc84504"
        "539731b9b5acedec163b7930bc22c654"
        "cfe95e3062b0212714f9b1958a586021"
        "7a2cace77798df4586b188dff8f7052d"
        "d535f17afa80adbbe5d1b2bac38aaae4"
        "11317be16bce4effa1382bb99b2ac670"
        "70a5632c9ff0100e00d50800ff00ffff"
        "ffffffff00ff200075f08620876c8dec"
        "09f0be6edd6b07f149059dcb5dbf0b24"
        "72499b7a8188934d9f69433f0fe5d535"
        "fa9631b362d62d487ae32820b916ac46"
        "87d07ea5e6405c4bc8eae4e6e92e13a3"
        "152a6c471c365857f60397c804653ced"
        "87bba35ee5cb2900631fa57181f7b3e3"
        "ae272c298de2cdcc2b42eb7bc7ff3a1a"
        "d0a893e5d7c2f4e72ed04cc98a910462"
        "68550ab528f953f737fadf6c950300d3"
        "14a17d0a5030eb3fb9a2ad3520d8dbb2"
        "92af6726ffcc2ad2787066d7d4503f82"
        "c0dfaf96d7eb2164f65adecf258fb72c"
        "80fffe1e7500"
    );
}

std::vector<bytes> encfw_magics() {
    const auto* value = signature_named("encfw");
    if(value == nullptr) {
        return {};
    }
    return value->magic;
}

struct positive_case {
    const char* name;
    bytes data;
    std::size_t magic_offset;
    std::uint64_t reported_offset;
    std::uint64_t parser_size;
    std::uint64_t scanner_size;
    std::uint8_t confidence;
    bool always_display;
};

const std::vector<positive_case>& positive_cases() {
    static const std::vector<positive_case> cases{
        {"openssl",      openssl_image(),                       0,   0,    0,  256, binwalk::confidence_medium, true},
        {"openssl",      openssl_header_only_image(),           0,   0,    0,   16, binwalk::confidence_medium, true},
        {"encfw",        encfw_image({0xDF, 0x8C, 0x39, 0x0D}), 0,   0,    0,  256, binwalk::confidence_medium, true},
        {"encrpted_img", encrpted_img_image(),                  0,   0,    0,  256, binwalk::confidence_medium, false},
        {"shrs",         shrs_image(),                          0,   0, 2012, 2012, binwalk::confidence_medium, false},
        {"dkbs",         dkbs_image(),                          7,   0,  160,  160, binwalk::confidence_high,   false},
        {"autel",        autel_image(),                         0,   0,  288,  288, binwalk::confidence_medium, false},
        {"dms",          dms_image(),                           4,   0,  256,  256, binwalk::confidence_medium, false},
        {"dlink_tlv",    dlink_tlv_image(dlink_tlv_good_md5()), 0,   0,  372,  372, binwalk::confidence_high,   false},
        {"dlink_tlv",    dlink_tlv_image({}),                   0,   0,  372,  372, binwalk::confidence_high,   false},
        {"arcadyan",     arcadyan_image(),                    104,   0,    0,  326, binwalk::confidence_high,   false}
    };
    return cases;
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

std::size_t count_regular_files(const std::filesystem::path& directory) {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        std::error_code probe;
        if(std::filesystem::is_regular_file(iterator->path(), probe)) {
            ++count;
        }
    }
    return count;
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
    for(const char* const name : {"autel.decoded", "swapped.bin", "decompressed.bin"}) {
        std::error_code probe;
        if(std::filesystem::exists(here / name, probe)) {
            return true;
        }
    }
    return false;
}

class b4_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b4_encrypted_";
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

TEST(B4EncryptedRegistry, DeclaresExactlyTheNineExpectedNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "b4_encrypted registers \"" << value.name << "\" more than once";
    }
    const std::set<std::string> expected(batch_names().begin(), batch_names().end());

    for(const auto& name : expected) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b4_encrypted does not register \"" << name << "\"";
    }
    for(const auto& name : produced) {
        EXPECT_EQ(expected.count(name), std::size_t{1})
            << "b4_encrypted registers \"" << name << "\", which is not one of this batch's "
            << "nine formats. Either the name is misspelled or the signature belongs to "
            << "another batch.";
    }
    EXPECT_EQ(batch().size(), std::size_t{9});
}

TEST(B4EncryptedRegistry, EveryNameIsInTheFrozenUpstreamOrderTable) {
    const auto& table = upstream_registration_order();
    ASSERT_EQ(table.size(), std::size_t{111})
        << "the transcribed magic.rs order table is not 111 entries long";
    const std::set<std::string> unique(table.begin(), table.end());
    ASSERT_EQ(unique.size(), table.size()) << "the transcribed table has a duplicate";

    for(const auto& value : batch()) {
        EXPECT_NE(std::find(table.begin(), table.end(), value.name), table.end())
            << "signature name \"" << value.name << "\" produced by b4_encrypted is NOT in "
            << "upstream magic.rs's 111-entry registry order table. It would sort silently "
            << "to the end of the registry and drop out of --include/--exclude and out of "
            << "every oracle diff. Fix the name in b4_encrypted; do NOT extend the table.";
    }
}

TEST(B4EncryptedRegistry, TheNineExpectedNamesAreThemselvesInTheOrderTable) {
    const auto& table = upstream_registration_order();
    for(const auto& name : batch_names()) {
        EXPECT_NE(std::find(table.begin(), table.end(), name), table.end())
            << "this test file's own spelling of \"" << name << "\" is not in the frozen "
            << "table, so the expectation itself is wrong";
    }
}

TEST(B4EncryptedRegistry, EveryNameReachesTheAggregatedRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [&name](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "\"" << name << "\" is produced by b4_encrypted_signatures() but does not "
            << "appear in binwalk::builtin_signatures(); the aggregator dropped it, so "
            << "--include=" << name << " selects nothing";
    }
}

TEST(B4EncryptedRegistry, EverySignatureHasAParserMagicAndDescription) {
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

TEST(B4EncryptedMetadata, ShortSignatureAlwaysDisplayAndMagicOffsetMatchUpstream) {
    struct expectation {
        const char* name;
        bool short_signature;
        bool always_display;
        std::size_t magic_offset;
        std::size_t magic_count;
    };

    const expectation expectations[] = {
        {"arcadyan",     false, false, 0, 1},
        {"openssl",      false, true,  0, 1},
        {"autel",        false, false, 0, 1},
        {"dlink_tlv",    false, false, 0, 1},
        {"shrs",         false, false, 0, 1},
        {"encrpted_img", true,  false, 0, 1},
        {"dms",          false, false, 0, 1},
        {"dkbs",         false, false, 0, 1},
        {"encfw",        true,  true,  0, 5}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name << " is not registered";
        EXPECT_EQ(value->short_signature, expected.short_signature)
            << "short_signature decides whether the scanner probes this format only at "
            << "magic_offset or everywhere, which is detection presence/absence and STRICT";
        EXPECT_EQ(value->always_display, expected.always_display);
        EXPECT_EQ(value->magic_offset, expected.magic_offset);
        EXPECT_EQ(value->magic.size(), expected.magic_count);
    }
}

TEST(B4EncryptedMetadata, AllNineDeclareAnInternalExtractorNamedAfterTheSignature) {
    for(const auto& name : batch_names()) {
        SCOPED_TRACE(name);
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value())
            << name << " declares NO extractor; upstream magic.rs gives all nine one";

        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
        EXPECT_NE(definition.internal, nullptr)
            << "an internal definition must carry a function pointer";
        EXPECT_EQ(definition.name, name + std::string("_built_in"));
        EXPECT_TRUE(definition.command.empty())
            << "an internal extractor must not name a command; this batch spawns no processes";
        EXPECT_TRUE(definition.arguments.empty());
        EXPECT_TRUE(definition.exit_codes.empty());
    }
}

TEST(B4EncryptedMetadata, EachSignaturePointsAtTheExpectedExtractorFunction) {
    struct expectation {
        const char* name;
        binwalk::internal_extractor function;
    };
    const expectation expectations[] = {
        {"arcadyan",     &binwalk::formats::extract_obfuscated_lzma},
        {"autel",        &binwalk::formats::autel_deobfuscate},
        {"dms",          &binwalk::formats::extract_swapped_u16},

        {"openssl",      &binwalk::formats::encfw_decrypt},
        {"dlink_tlv",    &binwalk::formats::encfw_decrypt},
        {"shrs",         &binwalk::formats::encfw_decrypt},
        {"encrpted_img", &binwalk::formats::encfw_decrypt},
        {"dkbs",         &binwalk::formats::encfw_decrypt},
        {"encfw",        &binwalk::formats::encfw_decrypt}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value());
        EXPECT_EQ(value->extractor_definition->internal, expected.function)
            << expected.name << " points at the wrong extractor function";
    }
}

TEST(B4EncryptedMagics, NoRegisteredPatternIsAPrefixOfAnother) {
    struct pattern {
        std::string owner;
        bytes value;
    };
    std::vector<pattern> patterns;
    for(const auto& value : batch()) {
        for(const auto& magic : value.magic) {
            patterns.push_back({value.name, magic});
        }
    }
    ASSERT_EQ(patterns.size(), std::size_t{13})
        << "this batch is expected to register 13 magic patterns in total (five for encfw, "
        << "one each for the other eight)";

    for(std::size_t left = 0; left < patterns.size(); ++left) {
        for(std::size_t right = 0; right < patterns.size(); ++right) {
            if(left == right) {
                continue;
            }
            const auto& shorter = patterns[left].value;
            const auto& longer = patterns[right].value;
            if(shorter.size() > longer.size()) {
                continue;
            }
            EXPECT_FALSE(std::equal(shorter.begin(), shorter.end(), longer.begin()))
                << "magic pattern " << left << " (owned by " << patterns[left].owner
                << ") is a prefix of pattern " << right << " (owned by "
                << patterns[right].owner << "). Two signatures in this batch can now match "
                << "at the same magic offset, which changes overlap resolution. Measure the "
                << "new winner and pin it before changing this test.";
        }
    }
}

TEST(B4EncryptedPositives, EveryOracleVerifiedFixtureParsesWithTheExpectedOffsetSizeAndTier) {
    std::size_t exercised = 0;
    for(const auto& expected : positive_cases()) {

        if(row_is_unavailable_without_lzma(expected.name)) {
            continue;
        }
        ++exercised;
        SCOPED_TRACE(
            std::string(expected.name) + " over " + std::to_string(expected.data.size())
            + " bytes, magic at " + std::to_string(expected.magic_offset)
        );
        const auto result = parse_at(expected.name, expected.data, expected.magic_offset);
        ASSERT_TRUE(result.has_value())
            << expected.name << " rejected an oracle-verified fixture. Detection presence is "
            << "STRICT under policy.";

        EXPECT_EQ(result->offset, expected.reported_offset)
            << "offset is STRICT; for dkbs, dms and arcadyan it is the magic offset MINUS the "
            << "rewind distance, not the magic offset";
        EXPECT_EQ(result->size, expected.parser_size)
            << "the parser's own size. For openssl, encfw, encrpted_img and arcadyan this is "
            << "0 by design and the scanner fills it in -- see section 10.";
        EXPECT_EQ(result->confidence, expected.confidence)
            << "only the confidence TIER is strict, and this is the tier";
        EXPECT_FALSE(result->extraction_declined)
            << "extraction_declined is STRICT under policy; none of this batch's "
            << "positive fixtures declines";
        EXPECT_FALSE(result->description.empty());
    }

    EXPECT_EQ(exercised, positive_cases().size() - (lzma_alone_available() ? 0U : 1U));
    ASSERT_GE(exercised, std::size_t{10})
        << "every positive row except arcadyan must still be exercised with the LZMA codec "
        << "compiled out; only " << exercised << " were";
}

TEST(B4EncryptedPositives, FourParsersDeliberatelyReportZeroSize) {
    struct expectation {
        const char* name;
        bytes data;
        std::size_t magic_offset;
    };
    const expectation expectations[] = {
        {"openssl",      openssl_image(),                       0},
        {"encfw",        encfw_image({0xDF, 0x8C, 0x39, 0x0D}), 0},
        {"encrpted_img", encrpted_img_image(),                  0},
        {"arcadyan",     arcadyan_image(),                    104}
    };
    std::size_t exercised = 0;
    for(const auto& expected : expectations) {

        if(row_is_unavailable_without_lzma(expected.name)) {
            continue;
        }
        ++exercised;
        SCOPED_TRACE(expected.name);
        const auto result = parse_at(expected.name, expected.data, expected.magic_offset);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->size, std::uint64_t{0})
            << expected.name << " must leave its span to the scanner's zero-size fill";
    }

    EXPECT_EQ(exercised, std::size(expectations) - (lzma_alone_available() ? 0U : 1U));
    ASSERT_GE(exercised, std::size_t{3})
        << "openssl, encfw and encrpted_img do not need any codec and must still be "
        << "asserted; only " << exercised << " rows were exercised";
}

TEST(B4EncryptedPositives, DkbsReportsTheHeaderLengthNotTheFileLength) {
    const bytes data = dkbs_image();
    ASSERT_EQ(data.size(), std::size_t{416});

    const auto result = parse_at("dkbs", data, 7);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, std::uint64_t{160})
        << "dkbs reports its 160-byte header, not the 416-byte file. The payload length in "
        << "the header (256) is validated against what remains but is not added to `size`.";
    EXPECT_EQ(result->confidence, binwalk::confidence_high);
    EXPECT_TRUE(contains(result->description, "DKBS007_dkbs_BOARD"));
    EXPECT_TRUE(contains(result->description, "1.02.03"));
    EXPECT_TRUE(contains(result->description, "nand0"));
}

TEST(B4EncryptedPositives, DkbsReadsThePayloadLengthLittleEndianWhenTheTopByteIsSet) {
    bytes data = dkbs_image();
    data[104] = 0x01;
    data[105] = 0x00;
    data[106] = 0x00;
    data[107] = 0x00;

    const auto result = parse_at("dkbs", data, 7);
    ASSERT_TRUE(result.has_value())
        << "the little-endian arm of the payload-length read must still produce a detection";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{160})
        << "dkbs reports its header length whichever way the payload length was read";
    EXPECT_EQ(result->confidence, binwalk::confidence_high);

    EXPECT_TRUE(contains(result->description, "little"))
        << "the description does not report little-endian, so the big-endian arm was taken "
        << "and this test is no longer exercising the branch it exists for. Description was: "
        << result->description;
}

TEST(B4EncryptedPositives, ShrsReportsHeaderPlusCiphertext) {
    const bytes data = shrs_image();
    ASSERT_EQ(data.size(), std::size_t{2012});

    const auto result = parse_at("shrs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, std::uint64_t{2012})
        << "1756-byte header plus the 256-byte ciphertext declared at +8";
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
    EXPECT_TRUE(contains(result->description, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
        << "the description should carry the IV the header declares";
}

TEST(B4EncryptedPositives, DlinkTlvAcceptsBothARecordedAndAnAbsentMd5) {
    for(const auto& md5 : {dlink_tlv_good_md5(), std::string_view{}}) {
        SCOPED_TRACE(md5.empty() ? "absent md5" : "recorded md5");
        const bytes data = dlink_tlv_image(md5);
        ASSERT_EQ(data.size(), std::size_t{372});

        const auto result = parse_at("dlink_tlv", data, 0);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->offset, std::uint64_t{0});
        EXPECT_EQ(result->size, std::uint64_t{372})
            << "116-byte header plus the 256-byte payload declared at +112";
        EXPECT_EQ(result->confidence, binwalk::confidence_high);
        EXPECT_TRUE(contains(result->description, "DIR-878"));
        EXPECT_TRUE(contains(result->description, "AP_BOARD_A1"));
    }
}

TEST(B4EncryptedPositives, AllFiveEncfwMagicsAreDetected) {
    const auto magics = encfw_magics();
    ASSERT_EQ(magics.size(), std::size_t{5});

    std::set<std::string> descriptions;
    for(std::size_t index = 0; index < magics.size(); ++index) {
        SCOPED_TRACE("encfw magic " + std::to_string(index));
        ASSERT_EQ(magics[index].size(), std::size_t{4}) << "every encfw magic is four bytes";

        const bytes data = encfw_image(magics[index]);
        const auto result = parse_at("encfw", data, 0);
        ASSERT_TRUE(result.has_value())
            << "encfw magic " << index << " is registered but its parser rejects it, so the "
            << "pattern can never produce a detection";
        EXPECT_EQ(result->offset, std::uint64_t{0});
        EXPECT_EQ(result->size, std::uint64_t{0});
        EXPECT_EQ(result->confidence, binwalk::confidence_medium);
        descriptions.insert(result->description);
    }
    EXPECT_EQ(descriptions.size(), std::size_t{5})
        << "each encfw fingerprint identifies a different device family, so each should "
        << "describe itself differently; identical descriptions mean the lookup collapsed";
}

TEST(B4EncryptedPositives, EncfwRejectsAFourByteValueOutsideItsTable) {
    expect_rejected("encfw", encfw_image({0xDE, 0xAD, 0xBE, 0xEF}), 0,
                    "0xDEADBEEF is not one of the five known firmware fingerprints");
}

TEST(B4EncryptedOffsets, FourFormatsDropToLowConfidenceAwayFromOffsetZero) {
    struct expectation {
        const char* name;
        bytes data;
        std::size_t magic_offset;
    };

    const expectation expectations[] = {
        {"openssl",      openssl_image(),                       0},
        {"encfw",        encfw_image({0xDF, 0x8C, 0x39, 0x0D}), 0},
        {"encrpted_img", encrpted_img_image(),                  0},
        {"shrs",         shrs_image(),                          0}
    };
    constexpr std::size_t prefix = 64;

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);

        const auto at_zero = parse_at(expected.name, expected.data, expected.magic_offset);
        ASSERT_TRUE(at_zero.has_value());
        EXPECT_EQ(at_zero->confidence, binwalk::confidence_medium);

        const bytes moved = at_offset(expected.data, prefix);
        const auto moved_result =
            parse_at(expected.name, moved, expected.magic_offset + prefix);
        ASSERT_TRUE(moved_result.has_value())
            << expected.name << " must still be DETECTED away from offset 0 -- only its "
            << "confidence drops. Losing the detection would be a presence/absence "
            << "divergence, which is STRICT.";
        EXPECT_EQ(moved_result->confidence, binwalk::confidence_low)
            << "upstream promotes to MEDIUM only when the magic is the first bytes of the "
            << "file; away from 0 the tier must be LOW";
        EXPECT_EQ(moved_result->offset, static_cast<std::uint64_t>(prefix));
    }
}

TEST(B4EncryptedOffsets, FourOtherFormatsKeepTheirTierAwayFromOffsetZero) {
    struct expectation {
        const char* name;
        bytes data;
        std::size_t magic_offset;
        std::uint8_t confidence;
    };
    const expectation expectations[] = {
        {"autel",     autel_image(),                           0, binwalk::confidence_medium},
        {"dlink_tlv", dlink_tlv_image(dlink_tlv_good_md5()),   0, binwalk::confidence_high},
        {"dms",       dms_image(),                             4, binwalk::confidence_medium},
        {"arcadyan",  arcadyan_image(),                      104, binwalk::confidence_high}
    };
    constexpr std::size_t prefix = 64;

    std::size_t exercised = 0;
    for(const auto& expected : expectations) {

        if(row_is_unavailable_without_lzma(expected.name)) {
            continue;
        }
        ++exercised;
        SCOPED_TRACE(expected.name);
        const bytes moved = at_offset(expected.data, prefix);
        const auto result = parse_at(expected.name, moved, expected.magic_offset + prefix);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->offset, static_cast<std::uint64_t>(prefix))
            << "the reported offset is still magic offset minus rewind distance; `size` is a "
            << "length and must not absorb the prefix";
        EXPECT_EQ(result->confidence, expected.confidence);
    }

    EXPECT_EQ(exercised, std::size(expectations) - (lzma_alone_available() ? 0U : 1U));
    ASSERT_GE(exercised, std::size_t{3})
        << "autel, dlink_tlv and dms need no codec and must still be asserted; only "
        << exercised << " rows were exercised";
}

TEST(B4EncryptedOffsets, DkbsDropsFromHighToMediumAwayFromOffsetZero) {
    const bytes data = dkbs_image();
    const auto at_zero = parse_at("dkbs", data, 7);
    ASSERT_TRUE(at_zero.has_value());
    EXPECT_EQ(at_zero->confidence, binwalk::confidence_high);

    constexpr std::size_t prefix = 64;
    const bytes moved = at_offset(data, prefix);
    const auto moved_result = parse_at("dkbs", moved, prefix + 7);
    ASSERT_TRUE(moved_result.has_value());
    EXPECT_EQ(moved_result->offset, std::uint64_t{prefix});
    EXPECT_EQ(moved_result->size, std::uint64_t{160});
    EXPECT_EQ(moved_result->confidence, binwalk::confidence_medium)
        << "dkbs is HIGH only at offset 0 and MEDIUM elsewhere -- still >= MEDIUM, so it "
        << "still participates in skip_contents and the overlap filter";
}

TEST(B4EncryptedRejections, OpensslRejectsAnEntirelyPrintableSalt) {
    expect_rejected("openssl", openssl_printable_salt_image(), 0,
                    "every salt byte is printable ASCII, so it is text and not entropy");
}

TEST(B4EncryptedRejections, OpensslAcceptsASaltWithASingleNonPrintableByte) {
    bytes data = openssl_image();
    write_ascii_at(data, 8, "ABCDEFG");
    data[15] = 0x01;

    const auto result = parse_at("openssl", data, 0);
    ASSERT_TRUE(result.has_value())
        << "one non-printable byte is enough entropy to keep the detection";
    EXPECT_EQ(result->confidence, binwalk::confidence_medium);
}

TEST(B4EncryptedRejections, OpensslRejectsAnAllZeroSalt) {
    bytes data = openssl_image();
    for(std::size_t index = 8; index < 16; ++index) {
        data[index] = 0x00;
    }
    expect_rejected("openssl", data, 0, "an all-NUL salt is not entropy either");
}

TEST(B4EncryptedRejections, DlinkTlvRejectsACorruptedMd5) {
    const bytes data = dlink_tlv_image(dlink_tlv_bad_md5());
    ASSERT_EQ(data.size(), std::size_t{372});
    expect_rejected("dlink_tlv", data, 0,
                    "the stored MD5 no longer matches the header it covers");
}

TEST(B4EncryptedRejections, RewindingParsersDoNotUnderflowWhenTheMagicIsAtOffsetZero) {
    {
        bytes data;
        put_ascii(data, "_dkbs_");
        data.resize(data.size() + 512, 0x00);
        expect_rejected("dkbs", data, 0, "magic at 0 with a -7 rewind must not wrap");
    }
    {
        bytes data;
        put_ascii(data, "0><1");
        data.resize(data.size() + 512, 0x00);
        expect_rejected("dms", data, 0, "magic at 0 with a -4 rewind must not wrap");
    }
    {
        bytes data;
        put_bytes(data, {0x00, 0xD5, 0x08, 0x00});
        data.resize(data.size() + 512, 0x00);
        expect_rejected("arcadyan", data, 0, "magic at 0 with a -0x68 rewind must not wrap");
    }
}

TEST(B4EncryptedRejections, RewindingParsersRejectEveryOffsetBelowTheirRewindDistance) {
    struct expectation {
        const char* name;
        bytes magic;
        std::size_t rewind;
    };
    const expectation expectations[] = {
        {"dkbs",     registered_magic("dkbs"),     7},
        {"dms",      registered_magic("dms"),      4},
        {"arcadyan", registered_magic("arcadyan"), 0x68}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        ASSERT_FALSE(expected.magic.empty()) << expected.name << " registers no magic";

        for(std::size_t offset = 0; offset < expected.rewind; ++offset) {
            bytes data(offset, 0x00);
            data.insert(data.end(), expected.magic.begin(), expected.magic.end());
            data.resize(data.size() + 512, 0x00);

            const auto result = parse_at(expected.name, data, offset);
            EXPECT_FALSE(result.has_value())
                << expected.name << " accepted a magic at offset " << offset
                << ", which is closer to the buffer start than its rewind distance of "
                << expected.rewind << ". The subtraction would underflow.";
        }
    }
}

TEST(B4EncryptedRobustness, EveryPositiveFixtureTruncatedToSixteenBytesIsSafe) {
    for(const auto& expected : positive_cases()) {
        SCOPED_TRACE(
            std::string(expected.name) + " truncated to 16 bytes, parsed at "
            + std::to_string(expected.magic_offset)
        );
        const bytes data = truncate_to(expected.data, 16);

        const auto result = parse_at(expected.name, data, expected.magic_offset);
        if(!result.has_value()) {
            continue;
        }
        EXPECT_LE(result->offset, static_cast<std::uint64_t>(data.size()))
            << "a result whose offset is past the end of the buffer it came from is not "
            << "well-formed";
        EXPECT_TRUE(
            result->confidence == binwalk::confidence_low
            || result->confidence == binwalk::confidence_medium
            || result->confidence == binwalk::confidence_high
        ) << "confidence must be one of the three defined tiers";
    }
}

TEST(B4EncryptedRobustness, HeaderTruncationBoundariesRejectRatherThanOverread) {
    struct expectation {
        const char* name;
        bytes data;
        std::size_t magic_offset;
        std::size_t too_short;
        std::size_t just_enough;
    };
    const expectation expectations[] = {

        {"openssl",      openssl_image(),      0,  15,  16},

        {"encrpted_img", encrpted_img_image(), 0,  11,  12},

        {"shrs",         shrs_image(),         0,  27,  28},

        {"dms",          dms_image(),          4, 0xFF, 0x100}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        expect_rejected(
            expected.name, truncate_to(expected.data, expected.too_short),
            expected.magic_offset, "one byte short of the smallest valid header"
        );
        const auto result = parse_at(
            expected.name, truncate_to(expected.data, expected.just_enough),
            expected.magic_offset
        );
        EXPECT_TRUE(result.has_value())
            << expected.name << " rejects at exactly " << expected.just_enough
            << " bytes, so the boundary this test pins has moved. If that is intended, "
            << "re-measure both sides; if not, the header minimum is now one byte too large "
            << "and real files are being dropped.";
    }
}

TEST(B4EncryptedRobustness, DkbsRejectsATruncatedHeaderAndAHeaderWithNoPayload) {
    expect_rejected("dkbs", truncate_to(dkbs_image(), 0x9F), 7,
                    "one byte short of the 160-byte header");
    expect_rejected("dkbs", truncate_to(dkbs_image(), 0xA0), 7,
                    "the full header but none of the 256 payload bytes it declares");
}

TEST(B4EncryptedRobustness, DkbsValidatesItsDeclaredPayloadLengthAgainstWhatRemains) {
    const auto with_payload_length = [](std::uint32_t length) {
        bytes data = dkbs_image();
        data[104] = static_cast<std::uint8_t>((length >> 24U) & 0xFFU);
        data[105] = static_cast<std::uint8_t>((length >> 16U) & 0xFFU);
        data[106] = static_cast<std::uint8_t>((length >> 8U) & 0xFFU);
        data[107] = static_cast<std::uint8_t>(length & 0xFFU);
        return data;
    };

    const auto exact = parse_at("dkbs", with_payload_length(256), 7);
    ASSERT_TRUE(exact.has_value()) << "a payload that exactly fills the file must be accepted";
    EXPECT_EQ(exact->size, std::uint64_t{160});

    expect_rejected("dkbs", with_payload_length(257), 7,
                    "one byte more payload than the file actually contains");
    expect_rejected("dkbs", with_payload_length(4096), 7,
                    "a declared payload far larger than what remains");
    expect_rejected("dkbs", with_payload_length(0), 7,
                    "a zero-length payload is not a firmware image");
}

TEST(B4EncryptedRobustness, DegenerateBuffersAndOutOfRangeOffsetsAreRefusedNotCrashed) {
    const bytes empty;
    const bytes one_byte{0x53};
    const bytes filler(256, 0xA5);

    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        ASSERT_NE(value.parser, nullptr);

        EXPECT_FALSE(value.parser(view(empty), 0).has_value());
        EXPECT_FALSE(value.parser(view(empty), 1).has_value());
        EXPECT_FALSE(value.parser(view(one_byte), 0).has_value());
        EXPECT_FALSE(value.parser(view(one_byte), 1).has_value());
        EXPECT_FALSE(value.parser(view(one_byte), 5).has_value());
        EXPECT_FALSE(value.parser(view(filler), filler.size()).has_value());
        EXPECT_FALSE(value.parser(view(filler), filler.size() + 4096).has_value());
        EXPECT_FALSE(value.parser(view(filler), absurd_offset()).has_value())
            << value.name << " must range-check an offset before turning it into a pointer";
    }
}

TEST(B4EncryptedRobustness, AMagicOnlyBufferIsAcceptedByTheParserByDesign) {
    for(const char* const name : {"encrpted_img", "encfw"}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->short_signature)
            << name << " is no longer a short signature, so the binwalk.rs:287 pre-pass "
            << "rule this test documents no longer applies to it";

        for(std::size_t index = 0; index < value->magic.size(); ++index) {
            SCOPED_TRACE(std::string(name) + " magic " + std::to_string(index));
            const bytes data = registered_magic(name, index);
            ASSERT_FALSE(data.empty());
            EXPECT_TRUE(value->parser(view(data), 0).has_value())
                << name << "'s parser rejected a buffer that is exactly its magic. Upstream's "
                << "accepts it -- the EOF rule lives in the short-signature pre-pass, not in "
                << "the parser. Do not tighten the parser to make a magic-only file reject; "
                << "read the comment above this test.";
        }
    }
}

TEST(B4EncryptedRejections, AutelRejectsAWrongHeaderSizeOrACorruptedCopyright) {
    {
        bytes data = autel_image();
        data[12] = 0x21;
        expect_rejected("autel", data, 0, "the header size is fixed at 0x20");
    }
    {
        bytes data = autel_image();
        data[16] = static_cast<std::uint8_t>('X');
        expect_rejected("autel", data, 0, "the copyright string is part of the format check");
    }
}

TEST(B4EncryptedRejections, DmsRejectsACorruptedPreamble) {
    bytes data = dms_image();
    data[0] = 0x00;
    expect_rejected("dms", data, 4,
                    "the four preamble bytes the -4 rewind lands on are validated");
}

TEST(B4EncryptedRejections, DkbsRejectsAnyEmptyStringField) {
    struct expectation {
        std::size_t offset;
        const char* what;
    };
    const expectation expectations[] = {
        {0,   "board ID"},
        {40,  "firmware version"},
        {112, "boot device"}
    };
    for(const auto& expected : expectations) {
        bytes data = dkbs_image();
        data[expected.offset] = 0x00;
        expect_rejected("dkbs", data, 7,
                        std::string("an empty ") + expected.what + " is not a valid header");
    }
}

TEST(B4EncryptedRejections, DlinkTlvRejectsAWrongTypeOrAnEmptyNameField) {
    {
        bytes data = dlink_tlv_image(dlink_tlv_good_md5());
        data[108] = 0x02;
        expect_rejected("dlink_tlv", data, 0, "only TLV type 1 is a firmware image");
    }
    {
        bytes data = dlink_tlv_image(dlink_tlv_good_md5());
        data[4] = 0x00;
        expect_rejected("dlink_tlv", data, 0, "an empty model name is not a valid header");
    }
    {
        bytes data = dlink_tlv_image(dlink_tlv_good_md5());
        data[36] = 0x00;
        expect_rejected("dlink_tlv", data, 0, "an empty board ID is not a valid header");
    }
}

TEST(B4EncryptedRejections, ArcadyanRejectsAStreamThatDoesNotDecode) {
    {
        bytes data = arcadyan_image();
        for(std::size_t index = 200; index < 240; ++index) {
            data[index] = static_cast<std::uint8_t>(data[index] ^ 0xFFU);
        }
        expect_rejected("arcadyan", data, 104,
                        "40 bytes of the LZMA stream inverted, so the dry run fails");
    }

    expect_rejected("arcadyan", truncate_to(arcadyan_image(), 0x100), 104,
                    "exactly the minimum length, which a strict > rejects");
}

TEST(B4EncryptedExtraction, AutelDryRunValidatesReportsTheSizeAndWritesNothing) {
    const bytes data = autel_image();
    const auto* value = signature_named("autel");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto signature = parse_at("autel", data, 0);
    ASSERT_TRUE(signature.has_value());
    ASSERT_FALSE(stray_extraction_output_in_working_directory())
        << "the working directory already holds extraction output before the dry run";

    const auto through_definition = binwalk::dry_run_extractor(
        *value->extractor_definition, view(data), *signature
    );
    EXPECT_TRUE(through_definition.success)
        << "the dry run failed with extraction_failure "
        << static_cast<int>(through_definition.failure);
    ASSERT_TRUE(through_definition.size.has_value())
        << "callers take `size` from a dry run (policy rule 2)";
    EXPECT_EQ(*through_definition.size, std::uint64_t{256})
        << "the extractor reports the PAYLOAD length, not the 288-byte image size the "
        << "signature reports; the two are different quantities and are never reconciled";

    const auto direct = binwalk::dry_run_extractor(
        &binwalk::formats::autel_deobfuscate, view(data), *signature
    );
    EXPECT_TRUE(direct.success);
    ASSERT_TRUE(direct.size.has_value());
    EXPECT_EQ(*direct.size, std::uint64_t{256});

    EXPECT_FALSE(stray_extraction_output_in_working_directory())
        << "a dry run wrote to disk";
}

TEST_F(b4_extraction_test, AutelDryRunLeavesAnEmptyDirectoryEmpty) {
    const bytes data = autel_image();
    const auto* value = signature_named("autel");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto signature = parse_at("autel", data, 0);
    ASSERT_TRUE(signature.has_value());

    ASSERT_EQ(count_entries(root_), std::size_t{0});
    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, view(data), *signature
    );
    EXPECT_TRUE(result.success);
    EXPECT_EQ(count_entries(root_), std::size_t{0})
        << "a dry run must not create anything anywhere -- policy rule 1";
}

TEST_F(b4_extraction_test, AutelRealRunWritesTheDecodedPayload) {
    const bytes data = autel_image();
    const auto* value = signature_named("autel");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto signature = parse_at("autel", data, 0);
    ASSERT_TRUE(signature.has_value());

    const auto result = binwalk::execute_extractor(
        view(data), "autel.bin", *signature, *value->extractor_definition, root_.string()
    );
    ASSERT_TRUE(result.success)
        << "internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{256})
        << "the real run must report the same size the dry run did";

    const auto written = find_file_named(root_, "autel.decoded");
    ASSERT_TRUE(written.has_value()) << "no autel.decoded under " << root_.string();
    const auto contents = read_file(*written);
    ASSERT_TRUE(contents.has_value());
    EXPECT_EQ(contents->size(), std::size_t{256});

    const bytes raw_payload(data.begin() + 32, data.end());
    ASSERT_EQ(raw_payload.size(), std::size_t{256});
    EXPECT_NE(*contents, raw_payload)
        << "autel.decoded is byte-identical to the raw payload, so the deobfuscation did "
        << "nothing";

    EXPECT_EQ(count_regular_files(root_), std::size_t{1})
        << "the autel extractor writes exactly one file";
}

TEST(B4EncryptedExtraction, DmsDryRunValidatesReportsTheSizeAndWritesNothing) {
    const bytes data = dms_image();
    const auto* value = signature_named("dms");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto signature = parse_at("dms", data, 4);
    ASSERT_TRUE(signature.has_value());
    ASSERT_FALSE(stray_extraction_output_in_working_directory());

    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, view(data), *signature
    );
    EXPECT_TRUE(result.success)
        << "dry run failed with extraction_failure " << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{256})
        << "the input length from the signature offset to EOF, rounded DOWN to a multiple "
        << "of four -- here already a multiple of four";

    EXPECT_FALSE(stray_extraction_output_in_working_directory());
}

TEST_F(b4_extraction_test, DmsRealRunWritesTheHalfwordSwappedImage) {
    const bytes data = dms_image();
    const auto* value = signature_named("dms");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto signature = parse_at("dms", data, 4);
    ASSERT_TRUE(signature.has_value());
    ASSERT_EQ(signature->offset, std::uint64_t{0});

    const auto result = binwalk::execute_extractor(
        view(data), "dms.bin", *signature, *value->extractor_definition, root_.string()
    );
    ASSERT_TRUE(result.success)
        << "internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{256});

    const auto written = find_file_named(root_, "swapped.bin");
    ASSERT_TRUE(written.has_value()) << "no swapped.bin under " << root_.string();
    const auto contents = read_file(*written);
    ASSERT_TRUE(contents.has_value());

    bytes expected;
    expected.reserve(data.size());
    for(std::size_t index = 0; index + 3U < data.size(); index += 4U) {
        expected.push_back(data[index + 2U]);
        expected.push_back(data[index + 3U]);
        expected.push_back(data[index]);
        expected.push_back(data[index + 1U]);
    }
    EXPECT_EQ(contents->size(), std::size_t{256});
    EXPECT_EQ(*contents, expected)
        << "swapped.bin is not the halfword-swapped input";

    EXPECT_EQ(count_regular_files(root_), std::size_t{1});
}

TEST(B4EncryptedExtraction, ArcadyanDryRunReportsTheCompressedLengthAndWritesNothing) {
    if(!lzma_alone_available()) {
        GTEST_SKIP() << "BINWALK_WITH_LZMA=OFF: extract_obfuscated_lzma cannot decode, and "
                     << "arcadyan detects nothing without it. Ruled correct by main; this "
                     << "test has no codec-independent half to keep asserting.";
    }
    const bytes data = arcadyan_image();
    const auto* value = signature_named("arcadyan");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto signature = parse_at("arcadyan", data, 104);
    ASSERT_TRUE(signature.has_value());
    ASSERT_FALSE(stray_extraction_output_in_working_directory());

    const auto result = binwalk::dry_run_extractor(
        *value->extractor_definition, view(data), *signature
    );
    EXPECT_TRUE(result.success)
        << "dry run failed with extraction_failure " << static_cast<int>(result.failure)
        << ". The skip above already excluded the codec-compiled-out case, so "
        << static_cast<int>(binwalk::extraction_failure::unsupported)
        << " (unsupported) here would mean codec_available() and the codec disagree.";
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{322})
        << "`size` is the number of COMPRESSED bytes consumed from four bytes into the "
        << "326-byte image, not the length of the decompressed output (16384). The two are "
        << "different quantities and neither is a typo for the other.";

    EXPECT_FALSE(stray_extraction_output_in_working_directory());
}

TEST_F(b4_extraction_test, ArcadyanRealRunWritesTheDecompressedStream) {
    if(!lzma_alone_available()) {
        GTEST_SKIP() << "BINWALK_WITH_LZMA=OFF: there is no decompressed output to write, "
                     << "and arcadyan produces no signature to extract from.";
    }
    const bytes data = arcadyan_image();
    const auto* value = signature_named("arcadyan");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto signature = parse_at("arcadyan", data, 104);
    ASSERT_TRUE(signature.has_value());

    const auto result = binwalk::execute_extractor(
        view(data), "arcadyan.bin", *signature, *value->extractor_definition, root_.string()
    );
    ASSERT_TRUE(result.success)
        << "internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure);
    ASSERT_TRUE(result.size.has_value());
    EXPECT_EQ(*result.size, std::uint64_t{322})
        << "the real run reports the same compressed length the dry run did";

    const auto written = find_file_named(root_, "decompressed.bin");
    ASSERT_TRUE(written.has_value()) << "no decompressed.bin under " << root_.string();
    const auto contents = read_file(*written);
    ASSERT_TRUE(contents.has_value());
    EXPECT_EQ(contents->size(), std::size_t{16384})
        << "16384 decompressed bytes out of 322 compressed ones";

    ASSERT_GE(contents->size(), std::size_t{16});
    const bytes expected_head{
        0x00, 0x07, 0x0E, 0x15, 0x1C, 0x23, 0x2A, 0x31,
        0x38, 0x3F, 0x46, 0x4D, 0x54, 0x5B, 0x62, 0x69
    };
    const bytes expected_tail{
        0xC5, 0xCC, 0xD3, 0xDA, 0xE1, 0xE8, 0xEF, 0xF6,
        0x02, 0x09, 0x10, 0x17, 0x1E, 0x25, 0x2C, 0x33
    };
    EXPECT_EQ(bytes(contents->begin(), contents->begin() + 16), expected_head);
    EXPECT_EQ(bytes(contents->end() - 16, contents->end()), expected_tail);

    EXPECT_EQ(count_regular_files(root_), std::size_t{1});
}

TEST(B4EncryptedExtraction, EncfwDecryptIsUnsupportedInBothModesForAllSixSignatures) {
    struct expectation {
        const char* name;
        bytes data;
        std::size_t magic_offset;
    };
    const expectation expectations[] = {
        {"openssl",      openssl_image(),                       0},
        {"dlink_tlv",    dlink_tlv_image(dlink_tlv_good_md5()), 0},
        {"shrs",         shrs_image(),                          0},
        {"encrpted_img", encrpted_img_image(),                  0},
        {"dkbs",         dkbs_image(),                          7},
        {"encfw",        encfw_image({0xDF, 0x8C, 0x39, 0x0D}), 0}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->extractor_definition.has_value());
        ASSERT_EQ(value->extractor_definition->internal, &binwalk::formats::encfw_decrypt);

        const auto signature = parse_at(expected.name, expected.data, expected.magic_offset);
        ASSERT_TRUE(signature.has_value());

        const auto dry = binwalk::dry_run_extractor(
            *value->extractor_definition, view(expected.data), *signature
        );
        EXPECT_FALSE(dry.success)
            << "encfw_decrypt must not claim success: the D-Link decryptor is not ported";
        EXPECT_EQ(dry.failure, binwalk::extraction_failure::unsupported)
            << "the failure must be `unsupported` -- \"this build cannot do it at all\" -- "
            << "and not invalid_data, which would say the input was bad";
    }
}

TEST_F(b4_extraction_test, EncfwDecryptWritesNothingOnARealRun) {
    const bytes data = encfw_image({0xDF, 0x8C, 0x39, 0x0D});
    const auto* value = signature_named("encfw");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto signature = parse_at("encfw", data, 0);
    ASSERT_TRUE(signature.has_value());

    const auto result = binwalk::execute_extractor(
        view(data), "encfw.bin", *signature, *value->extractor_definition, root_.string()
    );
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported);

    EXPECT_EQ(count_regular_files(root_), std::size_t{0})
        << "the unsupported extractor wrote a file; it must write nothing at all";
}

TEST(B4EncryptedScanner, PopulatesNameIdAndAlwaysDisplayForEveryPositiveFixture) {
    std::size_t exercised = 0;
    for(const auto& expected : positive_cases()) {

        if(row_is_unavailable_without_lzma(expected.name)) {
            continue;
        }
        ++exercised;
        SCOPED_TRACE(
            std::string(expected.name) + " over " + std::to_string(expected.data.size())
            + " bytes"
        );
        const auto found = scan_for(expected.name, expected.data);
        ASSERT_TRUE(found.has_value())
            << "the scanner produced no result named \"" << expected.name << "\". The parser "
            << "accepts this buffer, so either the magic does not match where the parser "
            << "expects it, or the overlap filter dropped the result.";

        EXPECT_EQ(found->name, expected.name)
            << "name is the --include/--exclude key and is STRICT under policy";
        EXPECT_FALSE(found->id.empty()) << "populate() must assign an id";
        EXPECT_EQ(found->always_display, expected.always_display)
            << "always_display comes from the registry and is stamped in by populate(); "
            << "openssl and encfw carry it, the other seven do not";
        EXPECT_EQ(found->offset, expected.reported_offset);
        EXPECT_EQ(found->confidence, expected.confidence);
        EXPECT_FALSE(found->extraction_declined);
    }

    EXPECT_EQ(exercised, positive_cases().size() - (lzma_alone_available() ? 0U : 1U));
    ASSERT_GE(exercised, std::size_t{10})
        << "only " << exercised << " rows were exercised";
}

TEST(B4EncryptedScanner, FillsInTheSizeOfTheFourZeroSizeParsers) {
    std::size_t exercised = 0;
    for(const auto& expected : positive_cases()) {

        if(row_is_unavailable_without_lzma(expected.name)) {
            continue;
        }
        ++exercised;
        SCOPED_TRACE(
            std::string(expected.name) + " over " + std::to_string(expected.data.size())
            + " bytes"
        );
        const auto found = scan_for(expected.name, expected.data);
        ASSERT_TRUE(found.has_value());
        EXPECT_EQ(found->size, expected.scanner_size)
            << "for openssl, encfw, encrpted_img and arcadyan the parser reports 0 and the "
            << "scanner extends the result to the next medium-or-better result or to EOF; "
            << "for the other five the scanner must report exactly what the parser computed";
    }

    EXPECT_EQ(exercised, positive_cases().size() - (lzma_alone_available() ? 0U : 1U));
    ASSERT_GE(exercised, std::size_t{10})
        << "only " << exercised << " rows were exercised";
}

TEST(B4EncryptedScanner, AgreesWithTheRawParserOnEveryFieldTheParserSets) {
    const bytes data = dlink_tlv_image(dlink_tlv_good_md5());

    const auto raw = parse_at("dlink_tlv", data, 0);
    const auto scanned = scan_for("dlink_tlv", data);
    ASSERT_TRUE(raw.has_value());
    ASSERT_TRUE(scanned.has_value());

    EXPECT_EQ(scanned->offset, raw->offset);
    EXPECT_EQ(scanned->size, raw->size);
    EXPECT_EQ(scanned->confidence, raw->confidence);
    EXPECT_EQ(scanned->extraction_declined, raw->extraction_declined);
    EXPECT_EQ(scanned->description, raw->description);

    EXPECT_TRUE(raw->name.empty())
        << "the parser has started setting `name` itself. If that is intended, the "
        << "parser-level tests here should assert it and this expectation should go -- but "
        << "do not simply delete the `name` assertions, which would drop all coverage of "
        << "the --include/--exclude key.";
    EXPECT_EQ(scanned->name, "dlink_tlv");
    EXPECT_TRUE(raw->id.empty());
    EXPECT_FALSE(scanned->id.empty());
    EXPECT_FALSE(raw->always_display)
        << "always_display is a registry property, not a parser one";
}

TEST(B4EncryptedScanner, TheTwoRequiredRejectionsProduceNoResultAtAll) {
    EXPECT_TRUE(batch_scanner().scan(view(openssl_printable_salt_image())).empty())
        << "openssl_printable_salt.bin must produce zero results; the oracle reports 0 hits";
    EXPECT_TRUE(batch_scanner().scan(view(dlink_tlv_image(dlink_tlv_bad_md5()))).empty())
        << "dlink_tlv_badmd5.bin must produce zero results; the oracle reports 0 hits";
}

TEST(B4EncryptedScanner, TheZeroSizeFillSkipsALowConfidenceNeighbourAndRunsToEof) {
    bytes data = openssl_image();
    const bytes tail = shrs_image();
    data.insert(data.end(), tail.begin(), tail.end());
    ASSERT_EQ(data.size(), std::size_t{2268});

    const auto openssl_result = scan_for("openssl", data);
    ASSERT_TRUE(openssl_result.has_value());
    EXPECT_EQ(openssl_result->offset, std::uint64_t{0});
    EXPECT_EQ(openssl_result->size, std::uint64_t{2268})
        << "the fill runs to EOF, not to the shrs result at 256, because that result is LOW "
        << "confidence and only a medium-or-better result stops the fill";

    const auto shrs_result = scan_for("shrs", data);
    ASSERT_TRUE(shrs_result.has_value());
    EXPECT_EQ(shrs_result->offset, std::uint64_t{256});
    EXPECT_EQ(shrs_result->confidence, binwalk::confidence_low)
        << "this is the fact the assertion above depends on; if shrs stops being demoted "
        << "away from offset 0 the expected openssl size becomes 256";
}

TEST(B4EncryptedScanner, ArcadyanDisplacesEncfwAtTheSameReportedOffset) {
    if(!lzma_alone_available()) {
        GTEST_SKIP() << "BINWALK_WITH_LZMA=OFF: arcadyan cannot match, so the two-result "
                     << "collision this test constructs does not exist to be resolved.";
    }
    bytes data = arcadyan_image();
    const bytes encfw_magic = registered_magic("encfw");
    ASSERT_EQ(encfw_magic.size(), std::size_t{4});
    std::copy(encfw_magic.begin(), encfw_magic.end(), data.begin());

    const auto arcadyan_raw = parse_at("arcadyan", data, 104);
    const auto encfw_raw = parse_at("encfw", data, 0);
    ASSERT_TRUE(arcadyan_raw.has_value())
        << "arcadyan must still parse: it does not read bytes 0..3, which is what makes "
        << "this collision constructible at all";
    ASSERT_TRUE(encfw_raw.has_value());
    ASSERT_EQ(arcadyan_raw->offset, std::uint64_t{0});
    ASSERT_EQ(encfw_raw->offset, std::uint64_t{0});
    ASSERT_GT(arcadyan_raw->confidence, encfw_raw->confidence)
        << "the whole mechanism below depends on arcadyan carrying strictly more confidence";

    const auto results = batch_scanner().scan(view(data));
    ASSERT_EQ(results.size(), std::size_t{1})
        << "both signatures report offset 0, so the overlap filter must keep exactly one";
    EXPECT_EQ(results.front().name, "arcadyan")
        << "arcadyan (HIGH) must displace encfw (MEDIUM) at the same reported offset. If "
        << "this now says \"encfw\", the filter has stopped honouring the confidence clause "
        << "and is deciding on order instead -- read the comment above before changing it.";
    EXPECT_EQ(results.front().offset, std::uint64_t{0});
    EXPECT_EQ(results.front().size, std::uint64_t{326});
    EXPECT_EQ(results.front().confidence, binwalk::confidence_high);
    EXPECT_FALSE(results.front().always_display)
        << "the surviving result carries arcadyan's always_display, not encfw's";
}

TEST(B4EncryptedScanner, EncfwWinsTheSameOffsetOnceArcadyanCanNoLongerMatch) {
    bytes data = arcadyan_image();
    const bytes encfw_magic = registered_magic("encfw");
    ASSERT_EQ(encfw_magic.size(), std::size_t{4});
    std::copy(encfw_magic.begin(), encfw_magic.end(), data.begin());
    for(std::size_t index = 104; index < 108; ++index) {
        data[index] = 0x00;
    }

    const auto results = batch_scanner().scan(view(data));
    ASSERT_EQ(results.size(), std::size_t{1})
        << "encfw really does match this buffer at offset 0; if it did not, the collision "
        << "test above would be asserting nothing";
    EXPECT_EQ(results.front().name, "encfw");
    EXPECT_EQ(results.front().offset, std::uint64_t{0});
    EXPECT_EQ(results.front().size, std::uint64_t{326})
        << "encfw's parser reports 0 and the fill extends it to EOF";
    EXPECT_EQ(results.front().confidence, binwalk::confidence_medium);
    EXPECT_TRUE(results.front().always_display)
        << "encfw is one of the two always_display signatures in this batch";
}

TEST(B4EncryptedScanner, ShortSignaturesAreNotFoundAwayFromOffsetZero) {
    for(const char* const name : {"encrpted_img", "encfw"}) {
        SCOPED_TRACE(name);
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr);
        ASSERT_TRUE(value->short_signature);

        const bytes image = (std::string(name) == "encfw")
            ? encfw_image({0xDF, 0x8C, 0x39, 0x0D})
            : encrpted_img_image();
        const bytes moved = at_offset(image, 64);

        ASSERT_TRUE(parse_at(name, moved, 64).has_value());
        EXPECT_FALSE(scan_for(name, moved).has_value())
            << name << " is a short signature, so the scanner's pre-pass only probes it at "
            << "magic_offset 0; finding it at 64 would mean short_signature was dropped";
    }
}
