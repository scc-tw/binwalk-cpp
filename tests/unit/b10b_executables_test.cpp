
#include "../../lib/src/formats/b10b_executables.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
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
        binwalk::formats::b10b_executables_signatures();
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
        "pchrom", "uefi_pi_volume", "uefi_capsule", "pe",
        "copyright", "dmg", "pjl", "qcow"
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

std::string normalized(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    for(const char character : text) {
        const auto value = static_cast<unsigned char>(character);
        if(std::isalnum(value) != 0) {
            result.push_back(static_cast<char>(std::tolower(value)));
        }
    }
    return result;
}

bool mentions(const std::string& description, const std::string& fact) {
    return normalized(description).find(fact) != std::string::npos;
}

enum class confidence_tier { low, medium, high };

void expect_confidence_tier(std::uint8_t confidence, confidence_tier expected) {
    switch(expected) {
    case confidence_tier::low:
        EXPECT_LT(confidence, binwalk::confidence_medium)
            << "the oracle reports this result in the LOW confidence tier; a higher "
            << "tier would change which overlapping results survive and would make "
            << "the scanner skip past this result's own contents";
        break;
    case confidence_tier::medium:
        EXPECT_GE(confidence, binwalk::confidence_medium)
            << "the oracle reports this result in the MEDIUM confidence tier";
        EXPECT_LT(confidence, binwalk::confidence_high)
            << "the oracle reports MEDIUM, not HIGH";
        break;
    case confidence_tier::high:
        EXPECT_GE(confidence, binwalk::confidence_high)
            << "the oracle reports this result in the HIGH confidence tier";
        break;
    }
}

struct fixture_location {
    std::filesystem::path directory;
    std::string searched;
};

fixture_location locate_fixtures() {
    fixture_location location;
    std::vector<std::filesystem::path> starting_points;

    const std::filesystem::path source_file(__FILE__);
    if(source_file.is_absolute()) {
        starting_points.push_back(source_file.parent_path());
    }

    std::error_code error;
    const auto working_directory = std::filesystem::current_path(error);
    if(!error) {
        starting_points.push_back(working_directory);
    }

    for(const auto& starting_point : starting_points) {
        std::filesystem::path directory = starting_point;
        for(int level = 0; level < 12; ++level) {
            for(const char* relative : {"fixtures", "tests/fixtures"}) {
                const auto candidate = directory / relative;
                location.searched += candidate.string();
                location.searched += "\n";
                if(std::filesystem::exists(candidate / "qcow.bin", error)) {
                    location.directory = candidate;
                    return location;
                }
            }
            const auto parent = directory.parent_path();
            if(parent.empty() || parent == directory) {
                break;
            }
            directory = parent;
        }
    }
    return location;
}

const fixture_location& fixtures() {
    static const fixture_location location = locate_fixtures();
    return location;
}

bytes read_fixture(const std::string& name) {
    if(fixtures().directory.empty()) {
        return {};
    }
    const auto path = fixtures().directory / name;

    std::error_code error;
    const auto file_size = std::filesystem::file_size(path, error);
    if(error) {
        return {};
    }

    bytes buffer(static_cast<std::size_t>(file_size));
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    if(!buffer.empty()) {
        stream.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size())
        );
        if(!stream) {
            return {};
        }
    }
    return buffer;
}

bytes require_fixture(const std::string& name, std::size_t expected_size) {
    auto data = read_fixture(name);
    EXPECT_EQ(data.size(), expected_size)
        << "fixture " << name << " is missing or the wrong size. Searched:\n"
        << fixtures().searched;
    return data;
}

std::string read_golden_text(const std::string& name) {
    if(fixtures().directory.empty()) {
        return {};
    }
    const auto path = fixtures().directory.parent_path() / "golden" / name;
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    return std::string(
        (std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>()
    );
}

std::string golden_value(const std::string& document, const std::string& key) {
    const auto quoted = "\"" + key + "\"";
    auto position = document.find(quoted);
    if(position == std::string::npos) {
        return {};
    }
    position = document.find(':', position + quoted.size());
    if(position == std::string::npos) {
        return {};
    }
    ++position;
    while(position < document.size()
          && std::isspace(static_cast<unsigned char>(document[position])) != 0) {
        ++position;
    }
    if(position >= document.size()) {
        return {};
    }
    if(document[position] == '"') {
        ++position;
        std::string value;
        while(position < document.size() && document[position] != '"') {
            value.push_back(document[position]);
            ++position;
        }
        return value;
    }
    std::string value;
    while(position < document.size() && document[position] != ','
          && document[position] != '\n' && document[position] != '}') {
        value.push_back(document[position]);
        ++position;
    }
    while(!value.empty()
          && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.pop_back();
    }
    return value;
}

std::optional<binwalk::signature_result> parse_at(
    const std::string& signature_name, const bytes& data, std::size_t magic_offset
) {
    const auto* value = signature_named(signature_name);
    if(value == nullptr || value->parser == nullptr) {
        ADD_FAILURE() << signature_name << " has no registered parser";
        return std::nullopt;
    }
    return value->parser(binwalk::byte_view(data.data(), data.size()), magic_offset);
}

std::vector<binwalk::signature_result> batch_scan(
    const bytes& data, bool search_all = false
) {
    binwalk::scan_options options;
    options.search_all = search_all;
    const binwalk::scanner scanner(batch(), options);
    return scanner.scan(binwalk::byte_view(data.data(), data.size()));
}

void put_ascii_at(bytes& buffer, std::size_t offset, std::string_view text) {
    for(std::size_t index = 0; index < text.size(); ++index) {
        buffer[offset + index] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    }
}

void put_u16_le_at(bytes& buffer, std::size_t offset, std::uint16_t value) {
    buffer[offset] = static_cast<std::uint8_t>(value & 0xFFU);
    buffer[offset + 1] = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU);
}

void put_u64_le_at(bytes& buffer, std::size_t offset, std::uint64_t value) {
    for(unsigned index = 0; index < 8U; ++index) {
        buffer[offset + index] =
            static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU);
    }
}

const bytes& pchrom_image() {
    static const bytes image = [] {
        bytes buffer(16777232, 0);
        const std::uint8_t header[] = {0x5A, 0xA5, 0xF0, 0x0F, 0x03, 0x00, 0x04, 0x00};
        for(std::size_t index = 0; index < sizeof(header); ++index) {
            buffer[16 + index] = header[index];
        }
        return buffer;
    }();
    return image;
}

void put_uefi_volume_header(bytes& buffer, std::size_t volume_start, std::uint64_t volume_size) {
    put_u64_le_at(buffer, volume_start + 32, volume_size);
    put_ascii_at(buffer, volume_start + 40, "_FVH");
    buffer[volume_start + 44] = 0xFE;
    buffer[volume_start + 45] = 0xFF;
    buffer[volume_start + 46] = 0x04;
    buffer[volume_start + 47] = 0x00;
    put_u16_le_at(buffer, volume_start + 48, 72);
    put_u16_le_at(buffer, volume_start + 50, 0x1234);
    put_u16_le_at(buffer, volume_start + 52, 0);
    buffer[volume_start + 54] = 0;
    buffer[volume_start + 55] = 2;
}

class scratch_directory {
public:
    explicit scratch_directory(const std::string& label) {
        std::error_code error;
        path_ = std::filesystem::temp_directory_path(error) / ("binwalk_b10b_" + label);
        std::filesystem::remove_all(path_, error);
        std::filesystem::create_directories(path_, error);
    }
    scratch_directory(const scratch_directory&) = delete;
    scratch_directory& operator=(const scratch_directory&) = delete;
    ~scratch_directory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    [[nodiscard]] std::string string() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

void expect_uefi_stub_definition(const std::string& name) {
    SCOPED_TRACE("internal UEFI stub extractor for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b10b_executables_signatures()";
    ASSERT_TRUE(value->extractor_definition.has_value())
        << name << " declares NO extractor. Upstream magic.rs gives it "
        << "extractors::uefi::uefi_extractor(); dropping the definition entirely "
        << "would hide the documented capability gap instead of reporting it.";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::internal)
        << "the replacement for a Python extractor must be internal: contract §7 "
        << "forbids invoking Python as a subprocess, so external is not available";
    EXPECT_NE(definition.internal, nullptr)
        << "an internal definition must carry a function pointer, otherwise a dry "
        << "run cannot even report why it failed";
    EXPECT_TRUE(definition.command.empty());
    EXPECT_TRUE(definition.arguments.empty());
    EXPECT_TRUE(definition.exit_codes.empty());
    EXPECT_TRUE(definition.do_not_recurse)
        << "upstream's uefi_extractor sets do_not_recurse";
}

void expect_no_extractor(const std::string& name) {
    SCOPED_TRACE("no extractor for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b10b_executables_signatures()";
    EXPECT_FALSE(value->extractor_definition.has_value())
        << name << " declares an extractor, but upstream src/magic.rs declares "
        << "`extractor: None` for it. An invented extractor would be attempted "
        << "during extraction and would report a failure upstream never reports.";
}

void expect_stub_extraction_unsupported(const std::string& name, const bytes& data) {
    SCOPED_TRACE("stub extraction for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    binwalk::signature_result identified;
    identified.offset = 0;
    identified.size = data.size();
    identified.name = name;

    const binwalk::byte_view view(data.data(), data.size());

    const auto dry = binwalk::dry_run_extractor(*value->extractor_definition, view, identified);
    EXPECT_FALSE(dry.success)
        << "a dry run of the stub must not claim success -- contract §7b";
    EXPECT_EQ(dry.failure, binwalk::extraction_failure::unsupported)
        << "`unsupported` is reserved for \"this build cannot do it at all\", which "
        << "is exactly the situation: the upstream extractor is Python and §7 "
        << "forbids both linking and spawning it";

    const scratch_directory output("stub_" + name);
    const auto real = binwalk::execute_extractor(
        view, "b10b_executables_test", identified, *value->extractor_definition, output.string()
    );
    EXPECT_FALSE(real.success)
        << "a real run must fail the same way a dry run does; a stub that 'succeeds' "
        << "with an empty output directory would hide the gap";
    EXPECT_EQ(real.failure, binwalk::extraction_failure::unsupported);
}

}

TEST(B10bExecutablesRegistry, BatchProducesExactlyTheEightExpectedNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "duplicate signature name: " << value.name;
    }
    const std::set<std::string> expected(batch_names().begin(), batch_names().end());
    EXPECT_EQ(produced, expected);
    EXPECT_EQ(batch().size(), std::size_t{8});
}

TEST(B10bExecutablesRegistry, EveryNameAppearsInTheFrozenUpstreamOrderTable) {

    const auto& order = upstream_registration_order();
    ASSERT_EQ(order.size(), std::size_t{111})
        << "the transcription of upstream src/magic.rs is the wrong length";
    for(const auto& value : batch()) {
        EXPECT_NE(std::find(order.begin(), order.end(), value.name), order.end())
            << "signature '" << value.name << "' is NOT in the frozen order table";
    }
}

TEST(B10bExecutablesRegistry, EveryNameSurvivesIntoTheAssembledRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [&](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "'" << name << "' is produced by the batch but is absent from "
            << "builtin_signatures(); --include=" << name << " would match nothing";
    }
}

TEST(B10bExecutablesRegistry, RelativeOrderInTheRegistryMatchesUpstream) {

    const auto registry = binwalk::builtin_signatures();
    const auto& order = upstream_registration_order();

    std::vector<std::size_t> registry_positions;
    std::vector<std::size_t> upstream_positions;
    for(const auto& name : batch_names()) {
        for(std::size_t index = 0; index < registry.size(); ++index) {
            if(registry[index].name == name) {
                registry_positions.push_back(index);
                break;
            }
        }
        const auto found = std::find(order.begin(), order.end(), name);
        ASSERT_NE(found, order.end());
        upstream_positions.push_back(
            static_cast<std::size_t>(std::distance(order.begin(), found))
        );
    }
    ASSERT_EQ(registry_positions.size(), batch_names().size());

    for(std::size_t left = 0; left < registry_positions.size(); ++left) {
        for(std::size_t right = left + 1; right < registry_positions.size(); ++right) {
            EXPECT_EQ(
                registry_positions[left] < registry_positions[right],
                upstream_positions[left] < upstream_positions[right]
            ) << batch_names()[left] << " vs " << batch_names()[right]
              << ": relative registry order disagrees with upstream magic.rs";
        }
    }
}

TEST(B10bExecutablesRegistry, EveryEntryHasAParserAndANonEmptyDescription) {
    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_NE(value.parser, nullptr);
        EXPECT_FALSE(value.description.empty());
        EXPECT_FALSE(value.magic.empty());
        for(const auto& pattern : value.magic) {
            EXPECT_FALSE(pattern.empty()) << "an empty magic matches everywhere";
        }
    }
}

TEST(B10bExecutablesRegistry, QcowIsTheOnlyShortSignature) {

    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_EQ(value.short_signature, value.name == "qcow");
    }
}

TEST(B10bExecutablesRegistry, QcowIsTheOnlyAlwaysDisplayEntry) {

    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_EQ(value.always_display, value.name == "qcow");
    }
}

TEST(B10bExecutablesRegistry, EveryEntryUsesMagicOffsetZero) {

    for(const auto& value : batch()) {
        SCOPED_TRACE(value.name);
        EXPECT_EQ(value.magic_offset, std::size_t{0});
    }
}

TEST(B10bExecutablesRegistry, MagicPatternsMatchUpstream) {

    struct expectation {
        const char* name;
        std::vector<bytes> magic;
    };
    const std::vector<expectation> expected{
        {"pchrom", {{0x5A, 0xA5, 0xF0, 0x0F}}},
        {"uefi_pi_volume", {{'_', 'F', 'V', 'H'}}},
        {"uefi_capsule", {
            {0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40,
             0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0},
            {0x8B, 0xA6, 0x3C, 0x4A, 0x23, 0x77, 0xFB, 0x48,
             0x80, 0x3D, 0x57, 0x8C, 0xC1, 0xFE, 0xC4, 0x4D},
            {0xB9, 0x82, 0x91, 0x53, 0xB5, 0xAB, 0x91, 0x43,
             0xB6, 0x9A, 0xE3, 0xA9, 0x43, 0xF7, 0x2F, 0xCC},
        }},
        {"pe", {
            {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
             0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
            {0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        }},
        {"copyright", {
            {'c', 'o', 'p', 'y', 'r', 'i', 'g', 'h', 't'},
            {'C', 'o', 'p', 'y', 'r', 'i', 'g', 'h', 't'},
            {'C', 'O', 'P', 'Y', 'R', 'I', 'G', 'H', 'T'},
        }},
        {"dmg", {{'k', 'o', 'l', 'y', 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00}}},
        {"pjl", {{0x1B, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L'}}},
        {"qcow", {{'Q', 'F', 'I', 0xFB}}},
    };

    for(const auto& item : expected) {
        SCOPED_TRACE(item.name);
        const auto* value = signature_named(item.name);
        ASSERT_NE(value, nullptr);
        EXPECT_EQ(value->magic, item.magic);
    }
}

TEST(B10bExecutablesRegistry, NoMagicIsAPrefixOfAnotherSignaturesMagic) {

    for(const auto& left : batch()) {
        for(const auto& right : batch()) {
            if(left.name == right.name) {
                continue;
            }
            for(const auto& left_pattern : left.magic) {
                for(const auto& right_pattern : right.magic) {
                    const bool is_prefix =
                        left_pattern.size() <= right_pattern.size()
                        && std::equal(
                            left_pattern.begin(), left_pattern.end(), right_pattern.begin()
                        );
                    EXPECT_FALSE(is_prefix)
                        << "a magic of '" << left.name << "' is a prefix of a magic of '"
                        << right.name << "'; the two can now collide at the same offset "
                        << "and the tie-break in section 12 no longer describes reality";
                }
            }
        }
    }
}

TEST(B10bPchrom, ParsesTheSixteenMegabyteImageBuiltInMemory) {
    const auto& image = pchrom_image();
    const auto result = parse_at("pchrom", image, 16);
    ASSERT_TRUE(result.has_value())
        << "the magic sits at file offset 16, exactly the rewind distance, so the "
        << "-16 back-offset resolves to a volume start of 0";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{16777232})
        << "header_size (16) + data_size (0x01000000), derived from flash region "
        << "entry 4, which is the magic itself";
    expect_confidence_tier(result->confidence, confidence_tier::low);
    EXPECT_FALSE(result->extraction_declined);
}

TEST(B10bPchrom, RejectsWhenTheMagicSitsBelowTheRewindDistance) {

    const auto data = require_fixture("pchrom_underflow.bin", 48);
    EXPECT_FALSE(parse_at("pchrom", data, 8).has_value());
}

TEST(B10bPchrom, RejectsAMagicAtOffsetZero) {

    const auto data = require_fixture("pchrom_underflow.bin", 48);
    EXPECT_FALSE(parse_at("pchrom", data, 0).has_value());
}

TEST(B10bPchrom, RejectsWrongFlashComponentBaseAddress) {

    const auto data = require_fixture("pchrom_bad_fcba.bin", 56);
    EXPECT_FALSE(parse_at("pchrom", data, 16).has_value());
}

TEST(B10bPchrom, RejectsWrongFlashRegionBaseAddress) {

    const auto data = require_fixture("pchrom_bad_frba.bin", 56);
    EXPECT_FALSE(parse_at("pchrom", data, 16).has_value());
}

TEST(B10bPchrom, RejectsAnOutOfRangeComponentCount) {

    const auto data = require_fixture("pchrom_bad_nc.bin", 56);
    EXPECT_FALSE(parse_at("pchrom", data, 16).has_value());
}

TEST(B10bPchrom, DescribesTheFormat) {
    const auto result = parse_at("pchrom", pchrom_image(), 16);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(mentions(result->description, "pch"))
        << "description was: " << result->description;
}

TEST(B10bUefiCapsule, ParsesTheEfiCapsuleGuid) {
    const auto data = require_fixture("uefi_capsule.bin", 1024);
    const auto result = parse_at("uefi_capsule", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{1024});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bUefiCapsule, ParsesTheEfi2CapsuleGuid) {
    const auto data = require_fixture("uefi_capsule_efi2.bin", 1024);
    const auto result = parse_at("uefi_capsule", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{1024});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bUefiCapsule, ParsesTheUefiCapsuleGuid) {
    const auto data = require_fixture("uefi_capsule_uefi.bin", 1024);
    const auto result = parse_at("uefi_capsule", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{1024});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bUefiCapsule, DescriptionCarriesTheHeaderAndTotalSizes) {
    const auto data = require_fixture("uefi_capsule.bin", 1024);
    const auto result = parse_at("uefi_capsule", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(mentions(result->description, "headersize28"))
        << "description was: " << result->description;
    EXPECT_TRUE(mentions(result->description, "totalsize1024"))
        << "description was: " << result->description;
}

TEST(B10bUefiCapsule, RejectsAHeaderLargerThanTheCapsule) {

    const auto data = require_fixture("uefi_capsule_bad_sizes.bin", 1024);
    EXPECT_FALSE(parse_at("uefi_capsule", data, 0).has_value());
}

TEST(B10bUefiCapsule, DetectsACapsuleEmbeddedAtANonZeroOffset) {

    const auto data = require_fixture("uefi_capsule_at_offset.bin", 3072);
    const auto result = parse_at("uefi_capsule", data, 1024);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{1024});
    EXPECT_EQ(result->size, std::uint64_t{1024});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bUefiPiVolume, ParsesAVolumeWhoseMagicSitsFortyBytesIn) {

    const auto data = require_fixture("uefi_pi_volume.bin", 4096);
    const auto result = parse_at("uefi_pi_volume", data, 40);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{4096});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bUefiPiVolume, DescriptionCarriesTheCrcAndBothSizes) {
    const auto data = require_fixture("uefi_pi_volume.bin", 4096);
    const auto result = parse_at("uefi_pi_volume", data, 40);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(mentions(result->description, "0x1234"))
        << "description was: " << result->description;
    EXPECT_TRUE(mentions(result->description, "headersize72"))
        << "description was: " << result->description;
    EXPECT_TRUE(mentions(result->description, "totalsize4096"))
        << "description was: " << result->description;
}

TEST(B10bUefiPiVolume, RejectsAnUnknownRevision) {

    const auto data = require_fixture("uefi_pi_volume_bad_revision.bin", 4096);
    EXPECT_FALSE(parse_at("uefi_pi_volume", data, 40).has_value());
}

TEST(B10bUefiPiVolume, RejectsWhenTheMagicSitsBelowTheRewindDistance) {

    const auto data = require_fixture("uefi_pi_volume_underflow.bin", 76);
    EXPECT_FALSE(parse_at("uefi_pi_volume", data, 8).has_value());
}

TEST(B10bUefiPiVolume, RejectsAMagicAtOffsetZero) {
    const auto data = require_fixture("uefi_pi_volume_underflow.bin", 76);
    EXPECT_FALSE(parse_at("uefi_pi_volume", data, 0).has_value());
}

TEST(B10bUefiPiVolume, DetectsASpecCorrectFirmwareVolumeHeader) {

    const auto data = require_fixture("uefi_pi_volume_real.bin", 4096);
    const auto result = parse_at("uefi_pi_volume", data, 40);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{4096});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
}

TEST(B10bPe, ParsesTheNinetyByteDosStubVariant) {
    const auto data = require_fixture("pe.bin", 3504);
    const auto result = parse_at("pe", data, 1024);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{1024});
    EXPECT_EQ(result->size, std::uint64_t{0})
        << "upstream's pe_parser never assigns result.size; the scanner fills it";
    expect_confidence_tier(result->confidence, confidence_tier::medium);
    EXPECT_TRUE(mentions(result->description, "intelx8664"))
        << "description was: " << result->description;
}

TEST(B10bPe, ParsesTheZeroFilledDosStubVariant) {
    const auto data = require_fixture("pe.bin", 3504);
    const auto result = parse_at("pe", data, 2264);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{2264});
    EXPECT_EQ(result->size, std::uint64_t{0});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
    EXPECT_TRUE(mentions(result->description, "arm"))
        << "description was: " << result->description;
}

TEST(B10bPe, RejectsAnUnknownMachineType) {

    const auto data = require_fixture("pe_bad_machine.bin", 2264);
    EXPECT_FALSE(parse_at("pe", data, 1024).has_value());
}

TEST(B10bPe, RejectsANonZeroReservedDosField) {

    const auto data = require_fixture("pe_nonzero_reserved.bin", 2264);
    EXPECT_FALSE(parse_at("pe", data, 1024).has_value());
}

TEST(B10bPe, RejectsAnOutOfBoundsLfanew) {

    const auto data = require_fixture("pe_lfanew_oob.bin", 2264);
    EXPECT_FALSE(parse_at("pe", data, 1024).has_value());
}

TEST(B10bPe, DeclaresNoExtractor) {
    expect_no_extractor("pe");
}

TEST(B10bCopyright, ParsesALowercaseCopyrightString) {
    const auto data = require_fixture("copyright.bin", 4210);
    const auto result = parse_at("copyright", data, 1024);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{1024});
    EXPECT_EQ(result->size, std::uint64_t{29});
    expect_confidence_tier(result->confidence, confidence_tier::high);
    EXPECT_TRUE(mentions(result->description, "copyright2024examplevendor"))
        << "description was: " << result->description;
}

TEST(B10bCopyright, ParsesACapitalisedCopyrightString) {
    const auto data = require_fixture("copyright.bin", 4210);
    const auto result = parse_at("copyright", data, 2078);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{2078});
    EXPECT_EQ(result->size, std::uint64_t{45});
    expect_confidence_tier(result->confidence, confidence_tier::high);
}

TEST(B10bCopyright, ParsesAnUppercaseCopyrightString) {
    const auto data = require_fixture("copyright.bin", 4210);
    const auto result = parse_at("copyright", data, 3148);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{3148});
    EXPECT_EQ(result->size, std::uint64_t{37});
    expect_confidence_tier(result->confidence, confidence_tier::high);
}

TEST(B10bCopyright, SizeIsTheNulTerminatedStringLength) {

    const auto data = require_fixture("copyright.bin", 4210);
    ASSERT_EQ(data.size(), std::size_t{4210});
    for(const std::size_t offset : {std::size_t{1024}, std::size_t{2078}, std::size_t{3148}}) {
        SCOPED_TRACE(offset);
        const auto result = parse_at("copyright", data, offset);
        ASSERT_TRUE(result.has_value());
        std::size_t length = 0;
        while(offset + length < data.size() && data[offset + length] != 0) {
            ++length;
        }
        EXPECT_EQ(result->size, static_cast<std::uint64_t>(length));
        EXPECT_GT(result->size, std::uint64_t{9})
            << "upstream requires strictly more than the 9-byte magic";
    }
}

TEST(B10bCopyright, RejectsAStringThatIsOnlyTheBareMagic) {

    const auto data = require_fixture("copyright_bare.bin", 2058);
    EXPECT_FALSE(parse_at("copyright", data, 1024).has_value());
}

TEST(B10bCopyright, DeclaresNoExtractor) {
    expect_no_extractor("copyright");
}

TEST(B10bDmg, ParsesTheUdifFooter) {

    const auto data = require_fixture("dmg.bin", 3760);
    const auto result = parse_at("dmg", data, 3248);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{3760});
    expect_confidence_tier(result->confidence, confidence_tier::high);
    EXPECT_TRUE(mentions(result->description, "totalsize3760"))
        << "description was: " << result->description;
}

TEST(B10bDmg, OutranksEveryOtherSignatureInThisBatch) {

    const auto dmg_data = require_fixture("dmg.bin", 3760);
    const auto dmg_result = parse_at("dmg", dmg_data, 3248);
    ASSERT_TRUE(dmg_result.has_value());

    const auto copyright_data = require_fixture("copyright.bin", 4210);
    const auto copyright_result = parse_at("copyright", copyright_data, 1024);
    ASSERT_TRUE(copyright_result.has_value());

    EXPECT_GT(dmg_result->confidence, copyright_result->confidence)
        << "dmg must outrank the highest-confidence signature in this batch, or a "
        << "colliding result would displace it at the same offset";
    EXPECT_GT(dmg_result->confidence, binwalk::confidence_high);
}

TEST(B10bDmg, RejectsAFooterWhoseHeaderSizeIsWrong) {

    const auto data = require_fixture("dmg_bad_header_size.bin", 3760);
    EXPECT_FALSE(parse_at("dmg", data, 3248).has_value());
}

TEST(B10bDmg, RejectsAnImageWithNoBlkxPropertyList) {

    const auto data = require_fixture("dmg_no_xml.bin", 3760);
    EXPECT_FALSE(parse_at("dmg", data, 3248).has_value());
}

TEST(B10bDmg, DetectsADmgEmbeddedAtANonZeroOffset) {

    const auto data = require_fixture("dmg_at_offset.bin", 4784);
    const auto result = parse_at("dmg", data, 4272);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{1024});
    EXPECT_EQ(result->size, std::uint64_t{3760})
        << "size must be the DMG's LENGTH, not its absolute end offset";
    expect_confidence_tier(result->confidence, confidence_tier::high);
}

TEST(B10bPjl, ParsesThePjlCommandText) {
    const auto data = require_fixture("pjl.bin", 2100);
    const auto result = parse_at("pjl", data, 1024);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{1024});
    EXPECT_EQ(result->size, std::uint64_t{42});
    expect_confidence_tier(result->confidence, confidence_tier::low);
    EXPECT_TRUE(mentions(result->description, "pjlsetcopies1"))
        << "description was: " << result->description;
    EXPECT_TRUE(mentions(result->description, "pjlenterlanguagepcl"))
        << "description was: " << result->description;
}

TEST(B10bPjl, SizeCountsOnlyTheCommandTextAndIsNineBytesShortOfTheData) {

    const auto data = require_fixture("pjl.bin", 2100);
    const auto result = parse_at("pjl", data, 1024);
    ASSERT_TRUE(result.has_value());

    std::size_t text_length = 0;
    while(1024 + 9 + text_length < data.size() && data[1024 + 9 + text_length] != 0) {
        ++text_length;
    }
    EXPECT_EQ(result->size, static_cast<std::uint64_t>(text_length));
    EXPECT_EQ(result->offset + result->size + 9, std::uint64_t{1024 + 9 + text_length});
}

TEST(B10bPjl, RejectsEmptyCommandText) {

    const auto data = require_fixture("pjl_empty.bin", 2058);
    EXPECT_FALSE(parse_at("pjl", data, 1024).has_value());
}

TEST(B10bPjl, DeclaresNoExtractor) {
    expect_no_extractor("pjl");
}

TEST(B10bQcow, ParsesAVersionThreeImage) {
    const auto data = require_fixture("qcow.bin", 512);
    const auto result = parse_at("qcow", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{0})
        << "upstream's qcow_parser never assigns result.size";
    expect_confidence_tier(result->confidence, confidence_tier::medium);
    EXPECT_EQ(
        result->description,
        "QEMU QCOW Image, version: 3, storage media size: 0x400 bytes, "
        "cluster block size: 0x10000 bytes, encryption method: None"
    ) << "qcow's description is the one in this batch that must match "
      << "character-for-character: it is pinned by tests/golden/qcow.json";
}

TEST(B10bQcow, ParsesAVersionOneImage) {
    const auto data = require_fixture("qcow_v1.bin", 512);
    const auto result = parse_at("qcow", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{0});
    expect_confidence_tier(result->confidence, confidence_tier::medium);
    EXPECT_TRUE(mentions(result->description, "version1"))
        << "description was: " << result->description;
}

TEST(B10bQcow, RejectsOutOfRangeClusterBits) {

    const auto data = require_fixture("qcow_bad_cluster_bits.bin", 512);
    EXPECT_FALSE(parse_at("qcow", data, 0).has_value());
}

TEST(B10bQcow, RejectsAnUnknownEncryptionMethod) {

    const auto data = require_fixture("qcow_bad_encryption.bin", 512);
    EXPECT_FALSE(parse_at("qcow", data, 0).has_value());
}

TEST(B10bQcow, RejectsAnUnalignedLevelOneTableOffset) {

    const auto data = require_fixture("qcow_unaligned_l1.bin", 512);
    EXPECT_FALSE(parse_at("qcow", data, 0).has_value());
}

TEST(B10bQcow, RejectsAnUnknownVersion) {

    const auto data = require_fixture("qcow_bad_version.bin", 512);
    EXPECT_FALSE(parse_at("qcow", data, 0).has_value());
}

TEST(B10bQcow, DeclaresNoExtractor) {
    expect_no_extractor("qcow");
}

TEST(B10bExtractors, PchromUsesTheInternalUefiStub) {
    expect_uefi_stub_definition("pchrom");
}

TEST(B10bExtractors, UefiPiVolumeUsesTheInternalUefiStub) {
    expect_uefi_stub_definition("uefi_pi_volume");
}

TEST(B10bExtractors, UefiCapsuleUsesTheInternalUefiStub) {
    expect_uefi_stub_definition("uefi_capsule");
}

TEST(B10bExtractors, PchromStubReportsUnsupportedInBothModes) {
    expect_stub_extraction_unsupported("pchrom", require_fixture("uefi_capsule.bin", 1024));
}

TEST(B10bExtractors, UefiPiVolumeStubReportsUnsupportedInBothModes) {
    expect_stub_extraction_unsupported("uefi_pi_volume", require_fixture("uefi_pi_volume.bin", 4096));
}

TEST(B10bExtractors, UefiCapsuleStubReportsUnsupportedInBothModes) {
    expect_stub_extraction_unsupported("uefi_capsule", require_fixture("uefi_capsule.bin", 1024));
}

TEST(B10bExtractors, DmgDeclaresTheExternalDmg2imgUtility) {

    const auto* value = signature_named("dmg");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr)
        << "an external definition must not carry an internal function pointer";
    EXPECT_EQ(definition.command, "dmg2img");
    EXPECT_EQ(definition.extension, "dmg");
    EXPECT_EQ(
        definition.arguments,
        (std::vector<std::string>{"-i", "%e", "-o", "mbr.img"})
    ) << "contract §2 rule 2: the placeholder is the literal two-character "
      << "string \"%e\", substituted per-argument and whole-argument";
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0, 1}));
    EXPECT_FALSE(definition.do_not_recurse);
}

TEST(B10bExtractors, DmgExtractionRunsWhenDmg2imgIsInstalled) {

    const auto* value = signature_named("dmg");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;

    if(!binwalk::external_utility_available(definition)) {
        GTEST_SKIP() << "dmg2img is not installed; contract §2 rule 5 requires the "
                     << "suite to pass without it. This is the ONE deliberate skip "
                     << "in this file.";
    }

    const auto data = require_fixture("dmg.bin", 3760);
    binwalk::signature_result identified;
    identified.offset = 0;
    identified.size = data.size();
    identified.name = "dmg";

    const scratch_directory output("dmg");
    const auto result = binwalk::execute_extractor(
        binwalk::byte_view(data.data(), data.size()),
        "b10b_executables_test", identified, definition, output.string()
    );

    EXPECT_NE(result.failure, binwalk::extraction_failure::utility_not_found);
    EXPECT_NE(result.failure, binwalk::extraction_failure::unsupported);
}

TEST(B10bGolden, QcowScanReproducesTheCommittedGolden) {
    const auto document = read_golden_text("qcow.json");
    ASSERT_FALSE(document.empty())
        << "tests/golden/qcow.json is missing; searched beside " << fixtures().directory;

    const auto data = require_fixture("qcow.bin", 512);
    const auto results = batch_scan(data);
    ASSERT_EQ(results.size(), std::size_t{1});
    const auto& result = results.front();

    EXPECT_EQ(std::to_string(result.offset), golden_value(document, "offset"));
    EXPECT_EQ(std::to_string(result.size), golden_value(document, "size"));
    EXPECT_EQ(result.name, golden_value(document, "name"));
    EXPECT_EQ(
        std::to_string(static_cast<unsigned>(result.confidence)),
        golden_value(document, "confidence")
    );
    EXPECT_EQ(result.description, golden_value(document, "description"));
    EXPECT_EQ(result.always_display ? "true" : "false", golden_value(document, "always_display"));
    EXPECT_EQ(
        result.extraction_declined ? "true" : "false",
        golden_value(document, "extraction_declined")
    );
}

TEST(B10bGolden, TheGoldenKeySetDoesNotLeakInternalFields) {

    const auto document = read_golden_text("qcow.json");
    ASSERT_FALSE(document.empty());
    EXPECT_EQ(document.find("failure"), std::string::npos)
        << "`extraction_failure` must be surfaced in human-readable stdout only";
    EXPECT_EQ(document.find("preferred_extractor"), std::string::npos);
}

TEST(B10bScanner, StampsTheSignatureNameOnEveryResult) {

    struct expectation { const char* fixture; std::size_t size; const char* name; };
    const std::vector<expectation> cases{
        {"pe.bin", 3504, "pe"},
        {"copyright.bin", 4210, "copyright"},
        {"pjl.bin", 2100, "pjl"},
        {"uefi_capsule.bin", 1024, "uefi_capsule"},
        {"uefi_pi_volume.bin", 4096, "uefi_pi_volume"},
        {"dmg.bin", 3760, "dmg"},
        {"qcow.bin", 512, "qcow"},
    };
    for(const auto& item : cases) {
        SCOPED_TRACE(item.fixture);
        const auto data = require_fixture(item.fixture, item.size);
        const auto results = batch_scan(data);
        ASSERT_FALSE(results.empty());
        for(const auto& result : results) {
            EXPECT_EQ(result.name, item.name);
        }
    }
}

TEST(B10bScanner, ParserLeavesNameAndIdEmptyAndAlwaysDisplayFalse) {

    const auto data = require_fixture("qcow.bin", 512);
    const auto parsed = parse_at("qcow", data, 0);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->name.empty());
    EXPECT_TRUE(parsed->id.empty());
    EXPECT_FALSE(parsed->always_display);
}

TEST(B10bScanner, StampsANonEmptyUniqueIdOnEveryResult) {
    const auto data = require_fixture("copyright.bin", 4210);
    const auto results = batch_scan(data);
    ASSERT_EQ(results.size(), std::size_t{3});
    std::set<std::string> identifiers;
    for(const auto& result : results) {
        EXPECT_FALSE(result.id.empty());
        EXPECT_TRUE(identifiers.insert(result.id).second) << "duplicate id " << result.id;
    }
}

TEST(B10bScanner, StampsAlwaysDisplayForQcowAndForNothingElse) {

    const auto qcow = require_fixture("qcow.bin", 512);
    const auto qcow_results = batch_scan(qcow);
    ASSERT_EQ(qcow_results.size(), std::size_t{1});
    EXPECT_TRUE(qcow_results.front().always_display);

    struct expectation { const char* fixture; std::size_t size; };
    const std::vector<expectation> others{
        {"pe.bin", 3504}, {"copyright.bin", 4210}, {"pjl.bin", 2100},
        {"uefi_capsule.bin", 1024}, {"uefi_pi_volume.bin", 4096}, {"dmg.bin", 3760},
    };
    for(const auto& item : others) {
        SCOPED_TRACE(item.fixture);
        const auto data = require_fixture(item.fixture, item.size);
        for(const auto& result : batch_scan(data)) {
            EXPECT_FALSE(result.always_display);
        }
    }
}

TEST(B10bScanner, FillsAZeroSizePeResultToTheNextResultThenToEof) {

    const auto data = require_fixture("pe.bin", 3504);
    const auto results = batch_scan(data);
    ASSERT_EQ(results.size(), std::size_t{2});

    EXPECT_EQ(results[0].offset, std::uint64_t{1024});
    EXPECT_EQ(results[0].size, std::uint64_t{1240});
    EXPECT_TRUE(mentions(results[0].description, "intelx8664"));

    EXPECT_EQ(results[1].offset, std::uint64_t{2264});
    EXPECT_EQ(results[1].size, std::uint64_t{1240});
    EXPECT_TRUE(mentions(results[1].description, "arm"));

    EXPECT_EQ(results[1].offset + results[1].size, std::uint64_t{data.size()});
}

TEST(B10bScanner, FillsAZeroSizeQcowResultToEof) {
    const auto data = require_fixture("qcow.bin", 512);
    const auto parsed = parse_at("qcow", data, 0);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size, std::uint64_t{0});

    const auto results = batch_scan(data);
    ASSERT_EQ(results.size(), std::size_t{1});
    EXPECT_EQ(results.front().offset, std::uint64_t{0});
    EXPECT_EQ(results.front().size, std::uint64_t{512});
}

TEST(B10bScanner, DropsAPchromResultThatWouldRunPastEof) {

    const auto& image = pchrom_image();
    const auto full = batch_scan(image);
    ASSERT_EQ(full.size(), std::size_t{1});
    EXPECT_EQ(full.front().name, "pchrom");
    EXPECT_EQ(full.front().offset, std::uint64_t{0});
    EXPECT_EQ(full.front().size, std::uint64_t{16777232});

    const bytes one_byte_short(image.begin(), image.end() - 1);
    EXPECT_TRUE(batch_scan(one_byte_short).empty())
        << "a result claiming to extend one byte past EOF must be discarded";
}

TEST(B10bScanner, SameOffsetFilterLetsHigherConfidenceDisplaceTheIncumbent) {

    bytes buffer(4096, 0);
    put_ascii_at(buffer, 0, "\x1B%-12345X@PJL SET COPIES=1");
    buffer[26] = 0;
    put_uefi_volume_header(buffer, 0, 4096);

    const auto standalone_pjl = parse_at("pjl", buffer, 0);
    ASSERT_TRUE(standalone_pjl.has_value())
        << "the low-confidence result must really be produced, or this test would "
        << "pass for the wrong reason";
    expect_confidence_tier(standalone_pjl->confidence, confidence_tier::low);
    EXPECT_EQ(standalone_pjl->offset, std::uint64_t{0});

    const auto standalone_volume = parse_at("uefi_pi_volume", buffer, 40);
    ASSERT_TRUE(standalone_volume.has_value());
    EXPECT_EQ(standalone_volume->offset, std::uint64_t{0});

    for(const bool search_all : {false, true}) {
        SCOPED_TRACE(search_all ? "search_all=true" : "search_all=false");
        const auto results = batch_scan(buffer, search_all);
        ASSERT_EQ(results.size(), std::size_t{1});
        EXPECT_EQ(results.front().name, "uefi_pi_volume")
            << "the strictly higher confidence must displace the incumbent";
        EXPECT_EQ(results.front().offset, std::uint64_t{0});
        EXPECT_EQ(results.front().size, std::uint64_t{4096});
    }
}

TEST(B10bScanner, SameOffsetFilterKeepsTheIncumbentOnEqualConfidence) {

    bytes buffer(4096, 0);
    const std::uint8_t efi_capsule_guid[] = {
        0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40,
        0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0
    };
    for(std::size_t index = 0; index < sizeof(efi_capsule_guid); ++index) {
        buffer[index] = efi_capsule_guid[index];
    }
    buffer[16] = 28;
    buffer[22] = 0x01;
    buffer[25] = 0x10;
    put_uefi_volume_header(buffer, 0, 4096);

    const auto standalone_capsule = parse_at("uefi_capsule", buffer, 0);
    ASSERT_TRUE(standalone_capsule.has_value());
    const auto standalone_volume = parse_at("uefi_pi_volume", buffer, 40);
    ASSERT_TRUE(standalone_volume.has_value());
    ASSERT_EQ(standalone_capsule->offset, standalone_volume->offset);
    ASSERT_EQ(standalone_capsule->confidence, standalone_volume->confidence)
        << "this test is only meaningful while the two tie on confidence";

    const auto results = batch_scan(buffer, true);
    ASSERT_EQ(results.size(), std::size_t{1});
    EXPECT_EQ(results.front().name, "uefi_capsule")
        << "equal confidence keeps the incumbent, and the incumbent is whichever "
        << "Aho-Corasick match was reported first";
    EXPECT_EQ(results.front().offset, std::uint64_t{0});
}

TEST(B10bScanner, AHighConfidenceResultSuppressesAMagicInsideItsOwnSpan) {

    bytes overlapping(1024, 0xA7);
    for(const char character : std::string("Copyright ACME\x1B%-12345X@PJL SET COPIES=1")) {
        overlapping.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    overlapping.push_back(0);
    overlapping.resize(2100, 0xA7);

    for(const bool search_all : {false, true}) {
        SCOPED_TRACE(search_all ? "search_all=true" : "search_all=false");
        const auto results = batch_scan(overlapping, search_all);
        ASSERT_EQ(results.size(), std::size_t{1});
        EXPECT_EQ(results.front().name, "copyright");
        EXPECT_EQ(results.front().offset, std::uint64_t{1024});
        EXPECT_EQ(results.front().size, std::uint64_t{40});
    }

    bytes disjoint(1024, 0xA7);
    for(const char character : std::string("Copyright ACME")) {
        disjoint.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    disjoint.push_back(0);
    disjoint.resize(1100, 0xA7);
    for(const char character : std::string("\x1B%-12345X@PJL SET COPIES=1")) {
        disjoint.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(character)));
    }
    disjoint.push_back(0);
    disjoint.resize(2100, 0xA7);

    const auto disjoint_results = batch_scan(disjoint);
    ASSERT_EQ(disjoint_results.size(), std::size_t{2});
    EXPECT_EQ(disjoint_results[0].name, "copyright");
    EXPECT_EQ(disjoint_results[0].offset, std::uint64_t{1024});
    EXPECT_EQ(disjoint_results[0].size, std::uint64_t{14});
    EXPECT_EQ(disjoint_results[1].name, "pjl");
    EXPECT_EQ(disjoint_results[1].offset, std::uint64_t{1100});
    EXPECT_EQ(disjoint_results[1].size, std::uint64_t{17});
}

TEST(B10bScanner, ScansOfTheNegativeFixturesFindWhatTheOracleFinds) {

    struct expectation { const char* fixture; std::size_t size; };
    const std::vector<expectation> empty_scans{
        {"pe_bad_machine.bin", 2264},
        {"pe_nonzero_reserved.bin", 2264},
        {"pe_lfanew_oob.bin", 2264},
        {"copyright_bare.bin", 2058},
        {"pjl_empty.bin", 2058},
        {"pchrom_bad_fcba.bin", 56},
        {"pchrom_bad_frba.bin", 56},
        {"pchrom_bad_nc.bin", 56},
        {"pchrom_underflow.bin", 48},
        {"uefi_capsule_bad_sizes.bin", 1024},
        {"uefi_pi_volume_bad_revision.bin", 4096},
        {"uefi_pi_volume_underflow.bin", 76},
        {"dmg_bad_header_size.bin", 3760},
        {"dmg_no_xml.bin", 3760},
        {"qcow_bad_cluster_bits.bin", 512},
        {"qcow_bad_encryption.bin", 512},
        {"qcow_unaligned_l1.bin", 512},
        {"qcow_bad_version.bin", 512},
    };
    for(const auto& item : empty_scans) {
        SCOPED_TRACE(item.fixture);
        const auto data = require_fixture(item.fixture, item.size);
        const auto results = batch_scan(data);
        if(!results.empty()) {
            ADD_FAILURE() << "expected no detection, got " << results.size()
                          << " (first: " << results.front().name
                          << " @" << results.front().offset << ")";
        }
    }
}

TEST(B10bScanner, ScansOfTheDivergenceFixturesStillReportTheDetection) {

    struct expectation {
        const char* fixture;
        std::size_t file_size;
        const char* name;
        std::uint64_t offset;
        std::uint64_t size;
    };
    const std::vector<expectation> cases{
        {"uefi_pi_volume_real.bin", 4096, "uefi_pi_volume", 0, 4096},
        {"uefi_capsule_at_offset.bin", 3072, "uefi_capsule", 1024, 1024},
        {"dmg_at_offset.bin", 4784, "dmg", 1024, 3760},
    };
    for(const auto& item : cases) {
        SCOPED_TRACE(item.fixture);
        const auto data = require_fixture(item.fixture, item.file_size);
        const auto results = batch_scan(data);
        ASSERT_EQ(results.size(), std::size_t{1});
        EXPECT_EQ(results.front().name, item.name);
        EXPECT_EQ(results.front().offset, item.offset);
        EXPECT_EQ(results.front().size, item.size);
    }
}

TEST(B10bScanner, PositiveFixturesScanToTheOracleReportedExtents) {

    struct expectation {
        const char* fixture;
        std::size_t file_size;
        const char* name;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> extents;
    };
    const std::vector<expectation> cases{
        {"copyright.bin", 4210, "copyright", {{1024, 29}, {2078, 45}, {3148, 37}}},
        {"pjl.bin", 2100, "pjl", {{1024, 42}}},
        {"uefi_capsule.bin", 1024, "uefi_capsule", {{0, 1024}}},
        {"uefi_capsule_efi2.bin", 1024, "uefi_capsule", {{0, 1024}}},
        {"uefi_capsule_uefi.bin", 1024, "uefi_capsule", {{0, 1024}}},
        {"uefi_pi_volume.bin", 4096, "uefi_pi_volume", {{0, 4096}}},
        {"dmg.bin", 3760, "dmg", {{0, 3760}}},
        {"qcow_v1.bin", 512, "qcow", {{0, 512}}},
    };
    for(const auto& item : cases) {
        SCOPED_TRACE(item.fixture);
        const auto data = require_fixture(item.fixture, item.file_size);
        const auto results = batch_scan(data);
        ASSERT_EQ(results.size(), item.extents.size());
        for(std::size_t index = 0; index < item.extents.size(); ++index) {
            EXPECT_EQ(results[index].name, item.name);
            EXPECT_EQ(results[index].offset, item.extents[index].first);
            EXPECT_EQ(results[index].size, item.extents[index].second);
            EXPECT_FALSE(results[index].extraction_declined);
        }
    }
}
