
#include "../../lib/src/formats/b8b_volumes.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
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
        binwalk::formats::b8b_volumes_signatures();
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
        "ext", "mbr", "fat", "efigpt", "ntfs", "apfs", "btrfs"
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

constexpr std::size_t ext_rewind = 1080;
constexpr std::size_t mbr_rewind = 0x1FE;
constexpr std::size_t fat_rewind = 0x1FE;
constexpr std::size_t efigpt_rewind = 0x1FE;
constexpr std::size_t apfs_rewind = 0x20;
constexpr std::size_t btrfs_rewind = 0x10040;

std::optional<std::filesystem::path> find_fixtures_dir() {
    std::error_code error;
    std::filesystem::path dir = std::filesystem::current_path(error);
    if(error) {
        return std::nullopt;
    }
    for(int depth = 0; depth < 10; ++depth) {
        std::error_code probe;
        const auto candidate = dir / "tests" / "fixtures";
        if(std::filesystem::is_directory(candidate, probe)) {
            return candidate;
        }
        const auto parent = dir.parent_path();
        if(parent.empty() || parent == dir) {
            break;
        }
        dir = parent;
    }
    return std::nullopt;
}

bytes read_fixture(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
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

void write_u8_at(bytes& out, std::size_t at, std::uint8_t value) {
    out.at(at) = value;
}

void write_u16_le_at(bytes& out, std::size_t at, std::uint16_t value) {
    out.at(at) = static_cast<std::uint8_t>(value & 0xFFU);
    out.at(at + 1U) = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU);
}

void write_u32_le_at(bytes& out, std::size_t at, std::uint32_t value) {
    for(unsigned index = 0; index < 4U; ++index) {
        out.at(at + index) = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
}

void write_u64_le_at(bytes& out, std::size_t at, std::uint64_t value) {
    for(unsigned index = 0; index < 8U; ++index) {
        out.at(at + index) = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xFFU);
    }
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

bytes with_zero_prefix(const bytes& data, std::size_t prefix_length) {
    bytes out(prefix_length, 0x00);
    out.insert(out.end(), data.begin(), data.end());
    return out;
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
    ASSERT_NE(value, nullptr) << name << " is not registered by b8b_volumes_signatures()";
    ASSERT_NE(value->parser, nullptr) << name << " has a null parser";

    const auto result = value->parser(view(data), offset);
    EXPECT_FALSE(result.has_value())
        << name << " accepted data it must reject (" << why << "). Contract §5 makes a "
        << "required rejection as strict as a required detection.";
}

const binwalk::scanner& batch_scanner() {
    static const binwalk::scanner value(binwalk::formats::b8b_volumes_signatures(), {});
    return value;
}

std::vector<binwalk::signature_result> scan_all(const bytes& data) {
    return batch_scanner().scan(view(data));
}

std::optional<binwalk::signature_result> scan_for(const std::string& name, const bytes& data) {
    for(const auto& result : scan_all(data)) {
        if(result.name == name) {
            return result;
        }
    }
    return std::nullopt;
}

std::size_t count_named(const std::vector<binwalk::signature_result>& results,
                        const std::string& name) {
    std::size_t count = 0;
    for(const auto& result : results) {
        if(result.name == name) {
            ++count;
        }
    }
    return count;
}

struct mbr_partition_entry {
    std::uint8_t status = 0x00;
    std::uint8_t os_type = 0x00;
    std::uint32_t lba_start = 0;
    std::uint32_t lba_size = 0;
};

bytes mbr_image(const std::vector<mbr_partition_entry>& partitions, std::size_t total_bytes) {
    bytes out(total_bytes, 0x00);
    const std::size_t entry_count =
        (partitions.size() < std::size_t{4}) ? partitions.size() : std::size_t{4};
    for(std::size_t index = 0; index < entry_count; ++index) {
        const std::size_t base = 446U + (index * 16U);
        write_u8_at(out, base, partitions[index].status);
        write_u8_at(out, base + 4U, partitions[index].os_type);
        write_u32_le_at(out, base + 8U, partitions[index].lba_start);
        write_u32_le_at(out, base + 12U, partitions[index].lba_size);
    }
    write_u8_at(out, 0x1FE, 0x55);
    write_u8_at(out, 0x1FF, 0xAA);
    return out;
}

bytes golden_equivalent_mbr_image() {
    mbr_partition_entry linux_partition;
    linux_partition.status = 0x00;
    linux_partition.os_type = 0x83;
    linux_partition.lba_start = 1;
    linux_partition.lba_size = 9;
    return mbr_image({linux_partition}, 5120);
}

void expect_tsk_recover_definition(const std::string& name) {
    SCOPED_TRACE("tsk_recover extractor for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b8b_volumes_signatures()";
    ASSERT_TRUE(value->extractor_definition.has_value())
        << name << " declares NO extractor. Upstream magic.rs gives it the tsk_recover "
        << "extractor; without it the format is detected and then never extracted.";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr)
        << "an external definition must not carry an internal function pointer";
    EXPECT_EQ(definition.command, "tsk_recover");
    EXPECT_EQ(definition.extension, "img");
    EXPECT_EQ(
        definition.arguments,
        (std::vector<std::string>{"-i", "raw", "-a", "%e", "rootfs"})
    );
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0}));
    EXPECT_FALSE(definition.do_not_recurse);
}

void expect_seven_zz_definition(const std::string& name) {
    SCOPED_TRACE("7zz extractor for " + name);
    const auto* value = signature_named(name);
    ASSERT_NE(value, nullptr) << name << " is not registered by b8b_volumes_signatures()";
    ASSERT_TRUE(value->extractor_definition.has_value())
        << name << " declares NO extractor. Upstream magic.rs gives it sevenzip_extractor().";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::external);
    EXPECT_EQ(definition.internal, nullptr);
    EXPECT_EQ(definition.command, "7zz");
    EXPECT_EQ(definition.extension, "bin");
    EXPECT_EQ(
        definition.arguments,
        (std::vector<std::string>{"x", "-y", "-o.", "-p''", "%e"})
    );
    EXPECT_EQ(definition.exit_codes, (std::vector<std::int32_t>{0, 2}));
    EXPECT_FALSE(definition.do_not_recurse);
}

}

#define B8B_REQUIRE_FIXTURES_DIR(var)                                                     \
    const auto var = find_fixtures_dir();                                                 \
    if(!(var).has_value()) {                                                              \
        GTEST_SKIP() << "tests/fixtures directory not found upward from the test "        \
                        "binary's working directory; the fixture-driven assertions "      \
                        "cannot run without it";                                          \
    }                                                                                     \
    static_cast<void>(0)

#define B8B_LOAD_FIXTURE(var, file)                                                       \
    const auto var = read_fixture(*fixtures_dir / (file));                                \
    ASSERT_FALSE((var).empty()) << "fixture failed to load: " << (file)

TEST(B8bVolumesRegistry, DeclaresExactlyTheSevenExpectedNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "b8b_volumes registers \"" << value.name << "\" more than once";
    }
    const std::set<std::string> expected(batch_names().begin(), batch_names().end());

    for(const auto& name : expected) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b8b_volumes does not register \"" << name << "\"";
    }
    for(const auto& name : produced) {
        EXPECT_EQ(expected.count(name), std::size_t{1})
            << "b8b_volumes registers \"" << name << "\", which is not one of this batch's "
            << "seven formats. Either the name is misspelled or the signature belongs to "
            << "another batch.";
    }
    EXPECT_EQ(batch().size(), std::size_t{7});
}

TEST(B8bVolumesRegistry, EveryNameIsInTheFrozenUpstreamOrderTable) {
    const auto& table = upstream_registration_order();
    ASSERT_EQ(table.size(), std::size_t{111})
        << "the transcribed magic.rs order table is not 111 entries long";
    const std::set<std::string> unique(table.begin(), table.end());
    ASSERT_EQ(unique.size(), table.size()) << "the transcribed table has a duplicate";

    for(const auto& value : batch()) {
        EXPECT_NE(std::find(table.begin(), table.end(), value.name), table.end())
            << "signature name \"" << value.name << "\" produced by b8b_volumes is NOT in "
            << "upstream magic.rs's 111-entry registry order table. It would sort silently "
            << "to the end of the registry and drop out of --include/--exclude and out of "
            << "every oracle diff. Fix the name in b8b_volumes; do NOT extend the table.";
    }
}

TEST(B8bVolumesRegistry, TheSevenExpectedNamesAreThemselvesInTheOrderTable) {
    const auto& table = upstream_registration_order();
    for(const auto& name : batch_names()) {
        EXPECT_NE(std::find(table.begin(), table.end(), name), table.end())
            << "this test file's own spelling of \"" << name << "\" is not in the frozen "
            << "table, so the expectation itself is wrong";
    }
}

TEST(B8bVolumesRegistry, EverySignatureHasAParserMagicAndDescription) {
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

TEST(B8bVolumesRegistry, EveryNameReachesTheAggregatedRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const auto& name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [&name](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "\"" << name << "\" is produced by b8b_volumes_signatures() but does not "
            << "appear in binwalk::builtin_signatures(); the aggregator dropped it";
    }
}

TEST(B8bVolumesMetadata, ShortSignatureMagicOffsetAndAlwaysDisplayMatchUpstream) {
    struct expectation {
        const char* name;
        bool short_signature;
        std::size_t magic_offset;
        bool always_display;
    };

    const expectation expectations[] = {
        {"ext",    false, 0,     false},
        {"mbr",    true,  0x1FE, true },
        {"fat",    true,  0x1FE, false},
        {"efigpt", false, 0,     false},
        {"ntfs",   false, 0,     false},
        {"apfs",   false, 0,     false},
        {"btrfs",  false, 0,     true }
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.name);
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name << " is not registered";
        EXPECT_EQ(value->short_signature, expected.short_signature);
        EXPECT_EQ(value->magic_offset, expected.magic_offset);
        EXPECT_EQ(value->always_display, expected.always_display);
    }
}

TEST(B8bVolumesMetadata, MbrFatAndEfigptMagicsOverlapAsAStrictPrefix) {
    const auto* mbr = signature_named("mbr");
    const auto* fat = signature_named("fat");
    const auto* efigpt = signature_named("efigpt");
    ASSERT_NE(mbr, nullptr);
    ASSERT_NE(fat, nullptr);
    ASSERT_NE(efigpt, nullptr);
    ASSERT_FALSE(mbr->magic.empty());
    ASSERT_FALSE(fat->magic.empty());
    ASSERT_FALSE(efigpt->magic.empty());

    const bytes boot_signature{0x55, 0xAA};
    EXPECT_EQ(mbr->magic[0], boot_signature);
    EXPECT_EQ(fat->magic[0], boot_signature);

    const bytes gpt_magic{0x55, 0xAA, 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
    EXPECT_EQ(efigpt->magic[0], gpt_magic);
    ASSERT_GE(efigpt->magic[0].size(), boot_signature.size());
    EXPECT_TRUE(std::equal(
        boot_signature.begin(), boot_signature.end(), efigpt->magic[0].begin()
    )) << "efigpt's magic must begin with the same two bytes mbr and fat declare";

    EXPECT_FALSE(efigpt->short_signature);
    EXPECT_EQ(efigpt->magic_offset, std::size_t{0});
}

TEST(B8bVolumesExtractors, ExtFatAndNtfsDeclareTskRecover) {
    expect_tsk_recover_definition("ext");
    expect_tsk_recover_definition("fat");
    expect_tsk_recover_definition("ntfs");
}

TEST(B8bVolumesExtractors, EfigptAndApfsDeclareSevenZz) {
    expect_seven_zz_definition("efigpt");
    expect_seven_zz_definition("apfs");
}

TEST(B8bVolumesExtractors, MbrDeclaresTheInternalBuiltInExtractor) {
    const auto* value = signature_named("mbr");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value())
        << "mbr must declare the internal MBR extractor; tests/golden/mbr.json pins an "
        << "extraction under the key \"offset:0\" with extractor \"mbr_built_in\"";

    const auto& definition = *value->extractor_definition;
    EXPECT_EQ(definition.type, binwalk::extractor_type::internal);
    EXPECT_NE(definition.internal, nullptr)
        << "an internal definition must carry a function pointer";
    EXPECT_TRUE(definition.command.empty())
        << "an internal extractor spawns nothing, so it must not name a command";
    EXPECT_FALSE(definition.name.empty());

}

TEST(B8bVolumesExtractors, BtrfsDeclaresNoExtractorAtAll) {
    const auto* value = signature_named("btrfs");
    ASSERT_NE(value, nullptr);
    EXPECT_FALSE(value->extractor_definition.has_value())
        << "btrfs must declare NO extractor (upstream magic.rs: `extractor: None`)";
}

TEST(B8bVolumesExtractors, FileTokenIsAlwaysItsOwnWholeArgument) {
    for(const auto& value : batch()) {
        if(!value.extractor_definition.has_value()) {
            continue;
        }
        const auto& definition = *value.extractor_definition;
        if(definition.type != binwalk::extractor_type::external) {
            continue;
        }
        SCOPED_TRACE(value.name);
        std::size_t token_count = 0;
        for(const auto& argument : definition.arguments) {
            if(argument == "%e") {
                ++token_count;
                continue;
            }
            EXPECT_EQ(argument.find("%e"), std::string::npos)
                << "argument \"" << argument << "\" embeds the %e token in a longer string; "
                << "substitution is whole-argument only";
        }
        EXPECT_EQ(token_count, std::size_t{1})
            << value.name << " must pass the carved file as exactly one \"%e\" argument";
    }
}

TEST(B8bVolumesExt, AtFileStartMatchesOracle) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "ext.bin");
    ASSERT_EQ(data.size(), std::size_t{8192});

    ASSERT_EQ(data[ext_rewind], 0x53U);
    ASSERT_EQ(data[ext_rewind + 1U], 0xEFU);

    const auto result = parse_at("ext", data, ext_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects ext in ext.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{8192});
    EXPECT_GE(static_cast<unsigned>(result->confidence),
              static_cast<unsigned>(binwalk::confidence_medium));
    EXPECT_TRUE(contains(result->description, "Linux"))
        << "oracle reports creator OS \"Linux\" (s_creator_os == 0); got: "
        << result->description;
}

TEST(B8bVolumesExt, AtNonZeroOffsetPinsTheTenEightyByteRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "ext_at_offset.bin");
    ASSERT_EQ(data.size(), std::size_t{12288});
    ASSERT_EQ(data[4096U + ext_rewind], 0x53U);
    ASSERT_EQ(data[4096U + ext_rewind + 1U], 0xEFU);

    const auto result = parse_at("ext", data, 4096U + ext_rewind);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{4096});
    EXPECT_EQ(result->size, std::uint64_t{8192});
    EXPECT_TRUE(contains(result->description, "FreeBSD"))
        << "oracle reports creator OS \"FreeBSD\" (s_creator_os == 3); got: "
        << result->description;
}

TEST(B8bVolumesExt, UnderflowGuardRejectsEveryOffsetBelowTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "ext.bin");

    for(std::size_t offset = 0; offset < ext_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("ext", data, offset).has_value())
            << "ext accepted a magic below its 1080-byte rewind; the subtraction underflowed";
    }
}

TEST(B8bVolumesExt, RejectsOutOfRangeLogBlockSize) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "ext.bin");
    auto data = base;
    write_u32_le_at(data, 1024U + 24U, 3U);

    expect_rejected("ext", data, ext_rewind, "log_block_size 3 is out of range");
}

TEST(B8bVolumesExt, RejectsSuperblockTruncatedAtTheMagic) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "ext.bin");
    auto data = base;
    data.resize(ext_rewind + 2U);

    expect_rejected("ext", data, ext_rewind, "superblock body truncated");
}

TEST(B8bVolumesFat, Fat12Or16MatchesOracle) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "fat.bin");
    ASSERT_EQ(data.size(), std::size_t{8192});
    ASSERT_EQ(data[0], 0xEBU) << "fat.bin exercises the 0xEB short-jump opcode";

    const auto result = parse_at("fat", data, fat_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects fat in fat.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{8192});
    EXPECT_TRUE(contains(result->description, "FAT12") || contains(result->description, "FAT16"))
        << "oracle reports a FAT12/16 volume; got: " << result->description;
}

TEST(B8bVolumesFat, Fat32MatchesOracle) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "fat32.bin");
    ASSERT_EQ(data.size(), std::size_t{16384});
    ASSERT_EQ(data[0], 0xE9U) << "fat32.bin exercises the 0xE9 near-jump opcode";

    const auto result = parse_at("fat", data, fat_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects fat in fat32.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{16384});
    EXPECT_TRUE(contains(result->description, "FAT32"))
        << "oracle reports a FAT32 volume; got: " << result->description;
}

TEST(B8bVolumesFat, ParserRewindIsGreaterOrEqualNotEquality) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "fat.bin");

    for(const std::size_t prefix : {std::size_t{512}, std::size_t{4096}}) {
        SCOPED_TRACE(prefix);
        const auto data = with_zero_prefix(base, prefix);
        const auto result = parse_at("fat", data, prefix + fat_rewind);
        ASSERT_TRUE(result.has_value())
            << "fat's parser must accept a boot sector that is not at file offset 0";
        EXPECT_EQ(result->offset, static_cast<std::uint64_t>(prefix));
        EXPECT_EQ(result->size, std::uint64_t{8192});
    }
}

TEST(B8bVolumesFat, UnderflowGuardRejectsEveryOffsetBelowTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "fat.bin");

    for(std::size_t offset = 0; offset < fat_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("fat", data, offset).has_value())
            << "fat accepted a magic below its 0x1FE rewind; the subtraction underflowed";
    }
}

TEST(B8bVolumesFat, RejectsUnknownFirstOpcode) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "fat.bin");
    auto data = base;
    write_u8_at(data, 0, 0x90U);

    expect_rejected("fat", data, fat_rewind, "first opcode is neither 0xEB nor 0xE9");
}

TEST(B8bVolumesFat, RejectsFatCountOtherThanTwo) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "fat.bin");

    for(const std::uint8_t fat_count : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{3}}) {
        auto data = base;
        write_u8_at(data, 16U, fat_count);
        expect_rejected("fat", data, fat_rewind, "fat_count is not 2");
    }
}

TEST(B8bVolumesEfigpt, AtFileStartIsHighConfidence) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "efigpt.bin");
    ASSERT_EQ(data.size(), std::size_t{24576});

    const auto result = parse_at("efigpt", data, efigpt_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects efigpt in efigpt.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{20480});

    EXPECT_GE(static_cast<unsigned>(result->confidence),
              static_cast<unsigned>(binwalk::confidence_high));
}

TEST(B8bVolumesEfigpt, AtNonZeroOffsetPinsTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "efigpt_at_offset.bin");
    ASSERT_EQ(data.size(), std::size_t{28672});

    const auto result = parse_at("efigpt", data, 4096U + efigpt_rewind);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{4096});
    EXPECT_EQ(result->size, std::uint64_t{20480});
}

TEST(B8bVolumesEfigpt, UnderflowGuardRejectsEveryOffsetBelowTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "efigpt.bin");

    for(std::size_t offset = 0; offset < efigpt_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("efigpt", data, offset).has_value())
            << "efigpt accepted a magic below its 0x1FE rewind; the subtraction underflowed";
    }
}

TEST(B8bVolumesEfigpt, RejectsBadPartitionEntryCrc) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "efigpt_bad_crc.bin");
    ASSERT_EQ(data.size(), std::size_t{24576});

    expect_rejected("efigpt", data, efigpt_rewind, "partition-entry CRC-32 does not match");

    EXPECT_FALSE(scan_for("efigpt", data).has_value());
}

TEST(B8bVolumesNtfs, ReportsTheMatchOffsetWithoutRewinding) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "ntfs.bin");
    ASSERT_EQ(data.size(), std::size_t{10240});
    ASSERT_EQ(data[2048], 0xEBU);

    const auto result = parse_at("ntfs", data, 2048);
    ASSERT_TRUE(result.has_value()) << "oracle detects ntfs in ntfs.bin";
    EXPECT_EQ(result->offset, std::uint64_t{2048})
        << "ntfs must report the match offset unchanged; a rewind would report something "
        << "lower and silently disagree with the oracle";

    EXPECT_EQ(result->size, std::uint64_t{8192});
}

TEST(B8bVolumesNtfs, AcceptsTheSameBootSectorAtFileOffsetZero) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "ntfs.bin");
    const bytes data(base.begin() + 2048, base.end());
    ASSERT_EQ(data.size(), std::size_t{8192});

    const auto result = parse_at("ntfs", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{8192});
}

TEST(B8bVolumesNtfs, RejectsNonZeroUnusedField) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "ntfs.bin");
    auto data = base;
    write_u16_le_at(data, 2048U + 14U, 1U);

    expect_rejected("ntfs", data, 2048, "unused1 (u16 @ magic+14) is non-zero");
}

TEST(B8bVolumesNtfs, RejectsZeroSectorCount) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "ntfs.bin");
    auto data = base;
    write_u64_le_at(data, 2048U + 40U, 0U);

    expect_rejected("ntfs", data, 2048, "sector_count 0 yields size == one sector");
}

TEST(B8bVolumesApfs, PinsTheThirtyTwoByteRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "apfs.bin");
    ASSERT_EQ(data.size(), std::size_t{12288});
    ASSERT_EQ(data[4128], static_cast<std::uint8_t>('N'));
    ASSERT_EQ(data[4129], static_cast<std::uint8_t>('X'));
    ASSERT_EQ(data[4130], static_cast<std::uint8_t>('S'));
    ASSERT_EQ(data[4131], static_cast<std::uint8_t>('B'));

    const auto result = parse_at("apfs", data, 4096U + apfs_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects apfs in apfs.bin";
    EXPECT_EQ(result->offset, std::uint64_t{4096});

    EXPECT_EQ(result->size, std::uint64_t{8192});
}

TEST(B8bVolumesApfs, UnderflowGuardRejectsEveryOffsetBelowTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "apfs.bin");

    for(std::size_t offset = 0; offset < apfs_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("apfs", data, offset).has_value())
            << "apfs accepted a magic below its 0x20 rewind; the subtraction underflowed";
    }
}

TEST(B8bVolumesApfs, RejectsSuperblockTruncatedInsideTheBlockCount) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "apfs.bin");
    auto data = base;
    data.resize(4128U + 12U);

    expect_rejected("apfs", data, 4096U + apfs_rewind, "block_count field is truncated");
}

TEST(B8bVolumesBtrfs, PinsTheSixtyFiveThousandSixHundredByteRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "btrfs.bin");
    ASSERT_EQ(data.size(), std::size_t{73728});
    ASSERT_EQ(data[69696], static_cast<std::uint8_t>('_'));
    ASSERT_EQ(data[69697], static_cast<std::uint8_t>('B'));

    const auto result = parse_at("btrfs", data, 4096U + btrfs_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects btrfs in btrfs.bin";
    EXPECT_EQ(result->offset, std::uint64_t{4096});
    EXPECT_EQ(result->size, std::uint64_t{69632});
}

TEST(B8bVolumesBtrfs, UnderflowGuardRejectsEveryOffsetBelowTheRewind) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "btrfs.bin");
    ASSERT_GT(data.size(), btrfs_rewind);

    for(std::size_t offset = 0; offset < btrfs_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("btrfs", data, offset).has_value())
            << "btrfs accepted a magic below its 0x10040 rewind; the subtraction underflowed";
    }
}

TEST(B8bVolumesBtrfs, RejectsBadSuperblockCrc) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "btrfs_bad_crc.bin");
    ASSERT_EQ(data.size(), std::size_t{73728});

    expect_rejected("btrfs", data, 4096U + btrfs_rewind, "superblock crc32c does not match");

    EXPECT_FALSE(scan_for("btrfs", data).has_value());
}

TEST(B8bVolumesBtrfs, RejectsSuperblockTruncatedAtTheMagic) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "btrfs.bin");
    auto data = base;
    data.resize(69696U + 8U);

    expect_rejected("btrfs", data, 4096U + btrfs_rewind, "superblock body truncated");
}

TEST(B8bVolumesMbr, Lba0PartitionIsNotNamedButStillSizesTheImage) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "mbr_lba0.bin");
    ASSERT_EQ(data.size(), std::size_t{20480});

    const auto result = parse_at("mbr", data, mbr_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects mbr in mbr_lba0.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{20480})
        << "the LBA-0 entry ends at 20480 and must count toward image_size even though it "
        << "is never named. Dropping it would report 4608, the second entry's end.";

    EXPECT_TRUE(contains(result->description, "FAT32"))
        << "the second entry starts at LBA 1 and must be named; got: " << result->description;
    EXPECT_FALSE(contains(result->description, "Linux"))
        << "upstream structures/mbr.rs does `if this_partition.start != 0 { push }`, so the "
        << "LBA-0 Linux entry must NOT be named. Oracle description names FAT32 only. Got: "
        << result->description;
}

TEST(B8bVolumesMbr, ZeroSizePartitionIsNamedAndStillSizesTheImage) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "mbr_zero_size.bin");
    ASSERT_EQ(data.size(), std::size_t{20480});

    const auto result = parse_at("mbr", data, mbr_rewind);
    ASSERT_TRUE(result.has_value()) << "oracle detects mbr in mbr_zero_size.bin";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{20480})
        << "the zero-length entry still ends at 20480 and must size the image. Dropping "
        << "zero-length entries would report 4608, the second entry's end.";

    const auto linux_at = result->description.find("Linux");
    const auto fat32_at = result->description.find("FAT32");
    EXPECT_NE(linux_at, std::string::npos)
        << "the zero-length Linux entry starts at LBA 40 (!= 0) and must still be named; "
        << "got: " << result->description;
    EXPECT_NE(fat32_at, std::string::npos) << "got: " << result->description;
    if(linux_at != std::string::npos && fat32_at != std::string::npos) {
        EXPECT_LT(linux_at, fat32_at)
            << "oracle lists the partitions in partition-table order: Linux (entry 0) then "
            << "FAT32 (entry 1); got: " << result->description;
    }
}

TEST(B8bVolumesMbr, ExtractionDeclinedIsAlwaysFalse) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    for(const char* file : {"mbr_lba0.bin", "mbr_zero_size.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(*fixtures_dir / file);
        ASSERT_FALSE(data.empty()) << "fixture failed to load: " << file;
        const auto result = parse_at("mbr", data, mbr_rewind);
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->extraction_declined);
    }

    const auto reconstructed = golden_equivalent_mbr_image();
    const auto result = parse_at("mbr", reconstructed, mbr_rewind);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->extraction_declined);
}

TEST(B8bVolumesMbr, RejectsImageSizeAtTheMinimumBoundary) {
    mbr_partition_entry entry;
    entry.status = 0x00;
    entry.os_type = 0x83;
    entry.lba_start = 1;
    entry.lba_size = 1;
    const auto data = mbr_image({entry}, 20480);

    expect_rejected("mbr", data, mbr_rewind, "image_size 1024 is not greater than MIN_IMAGE_SIZE");
}

TEST(B8bVolumesMbr, AcceptsImageSizeJustAboveTheMinimumBoundary) {
    mbr_partition_entry entry;
    entry.status = 0x00;
    entry.os_type = 0x83;
    entry.lba_start = 1;
    entry.lba_size = 2;
    const auto data = mbr_image({entry}, 20480);

    const auto result = parse_at("mbr", data, mbr_rewind);
    ASSERT_TRUE(result.has_value())
        << "1536 is above MIN_IMAGE_SIZE (1024) and must be accepted; rejecting it would "
        << "make the boundary off by one block";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{1536});
    EXPECT_TRUE(contains(result->description, "Linux")) << result->description;
}

TEST(B8bVolumesMbr, ParserFiresOnlyAtTheFixedMagicOffset) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(data, "mbr_lba0.bin");

    ASSERT_TRUE(parse_at("mbr", data, mbr_rewind).has_value());
    for(std::size_t offset = 0; offset < mbr_rewind; ++offset) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("mbr", data, offset).has_value())
            << "mbr accepted an offset below 0x1FE";
    }
    for(const std::size_t offset : {mbr_rewind + 1U, std::size_t{1024}, std::size_t{4096}}) {
        SCOPED_TRACE(offset);
        EXPECT_FALSE(parse_at("mbr", data, offset).has_value())
            << "mbr accepted an offset above 0x1FE; the comparison must be equality, so "
            << "result.offset is always 0";
    }
}

TEST(B8bVolumesMbr, ReconstructedGoldenImageReproducesTheGoldenResult) {
    const auto data = golden_equivalent_mbr_image();
    ASSERT_EQ(data.size(), std::size_t{5120});

    const auto result = parse_at("mbr", data, mbr_rewind);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{5120});
    EXPECT_EQ(static_cast<unsigned>(result->confidence),
              static_cast<unsigned>(binwalk::confidence_medium))
        << "golden mbr.json pins confidence 128 / tier \"medium\"";
    EXPECT_EQ(result->description, "DOS Master Boot Record, partition: Linux, "
                                   "image size: 5120 bytes")
        << "golden mbr.json pins this exact description text";
    EXPECT_FALSE(result->extraction_declined);
}

TEST(B8bVolumesMbr, InternalExtractorDryRunReportsTheImageSize) {
    const auto data = golden_equivalent_mbr_image();
    const auto* value = signature_named("mbr");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());

    const auto result = parse_at("mbr", data, mbr_rewind);
    ASSERT_TRUE(result.has_value());

    const auto dry_run =
        binwalk::dry_run_extractor(*value->extractor_definition, view(data), *result);
    EXPECT_TRUE(dry_run.success)
        << "golden mbr.json records a successful mbr_built_in extraction";
    ASSERT_TRUE(dry_run.size.has_value());
    EXPECT_EQ(*dry_run.size, std::uint64_t{5120});
    EXPECT_EQ(dry_run.failure, binwalk::extraction_failure::none);
}

TEST(B8bVolumesBounds, EveryRewindingParserRejectsTheOffsetJustBelowItsConstant) {
    struct entry {
        const char* name;
        std::size_t rewind;
    };
    const entry entries[] = {
        {"ext",    ext_rewind},
        {"mbr",    mbr_rewind},
        {"fat",    fat_rewind},
        {"efigpt", efigpt_rewind},
        {"apfs",   apfs_rewind},
        {"btrfs",  btrfs_rewind}
    };

    bytes data(131072, 0x00);
    for(std::size_t index = 0; index + 1U < data.size(); index += 512U) {
        data[index] = 0x55;
        data[index + 1U] = 0xAA;
    }

    for(const auto& value : entries) {
        SCOPED_TRACE(value.name);
        ASSERT_GT(value.rewind, std::size_t{0});
        EXPECT_FALSE(parse_at(value.name, data, value.rewind - 1U).has_value())
            << value.name << " accepted an offset one byte below its rewind constant";
    }
}

TEST(B8bVolumesBounds, EveryParserRejectsEveryOffsetInATinyBuffer) {
    std::vector<bytes> buffers;
    buffers.push_back(bytes{});
    buffers.push_back(bytes{0x55, 0xAA});
    buffers.push_back(bytes(64, 0x00));
    buffers.push_back(bytes(64, 0xFF));
    {
        bytes mixed(64, 0x00);
        mixed[0] = 0xEB;
        mixed[1] = 0x52;
        mixed[2] = 0x90;
        write_u16_le_at(mixed, 4U, 0xEF53U);
        mixed[16] = static_cast<std::uint8_t>('N');
        mixed[17] = static_cast<std::uint8_t>('X');
        mixed[18] = static_cast<std::uint8_t>('S');
        mixed[19] = static_cast<std::uint8_t>('B');
        mixed[32] = static_cast<std::uint8_t>('_');
        mixed[33] = static_cast<std::uint8_t>('B');
        mixed[34] = static_cast<std::uint8_t>('H');
        mixed[35] = static_cast<std::uint8_t>('R');
        mixed[62] = 0x55;
        mixed[63] = 0xAA;
        buffers.push_back(std::move(mixed));
    }

    for(const auto& data : buffers) {
        for(const auto& name : batch_names()) {
            for(std::size_t offset = 0; offset <= data.size(); ++offset) {
                SCOPED_TRACE(name + " @ " + std::to_string(offset)
                             + " in a " + std::to_string(data.size()) + "-byte buffer");
                EXPECT_FALSE(parse_at(name, data, offset).has_value())
                    << "no b8b_volumes structure fits in " << data.size() << " bytes";
            }
        }
    }
}

TEST(B8bVolumesBounds, AbsurdOffsetsAreRangeCheckedNotDereferenced) {
    const bytes data(4096, 0xA5);
    for(const auto& name : batch_names()) {
        SCOPED_TRACE(name);
        EXPECT_FALSE(parse_at(name, data, absurd_offset()).has_value());
        EXPECT_FALSE(parse_at(name, data, (std::numeric_limits<std::size_t>::max)()).has_value());
        EXPECT_FALSE(parse_at(name, data, data.size()).has_value());
    }
}

namespace {

struct fixture_expectation {
    const char* file;
    const char* name;
    std::uint64_t offset;
    std::uint64_t size;
};

const std::vector<fixture_expectation>& positive_fixtures() {
    static const std::vector<fixture_expectation> table{
        {"ext.bin",              "ext",    0,    8192},
        {"ext_at_offset.bin",    "ext",    4096, 8192},
        {"fat.bin",              "fat",    0,    8192},
        {"fat32.bin",            "fat",    0,    16384},
        {"ntfs.bin",             "ntfs",   2048, 8192},
        {"apfs.bin",             "apfs",   4096, 8192},
        {"btrfs.bin",            "btrfs",  4096, 69632},
        {"efigpt.bin",           "efigpt", 0,    20480},
        {"efigpt_at_offset.bin", "efigpt", 4096, 20480},
        {"mbr_lba0.bin",         "mbr",    0,    20480},
        {"mbr_zero_size.bin",    "mbr",    0,    20480}
    };
    return table;
}

}

TEST(B8bVolumesScanner, StampsTheNameOffsetAndSizeOnEveryPositiveFixture) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    for(const auto& expected : positive_fixtures()) {
        SCOPED_TRACE(expected.file);
        const auto data = read_fixture(*fixtures_dir / expected.file);
        ASSERT_FALSE(data.empty()) << "fixture failed to load: " << expected.file;

        const auto results = scan_all(data);
        ASSERT_EQ(count_named(results, expected.name), std::size_t{1})
            << "expected exactly one \"" << expected.name << "\" result";
        const auto found = scan_for(expected.name, data);
        ASSERT_TRUE(found.has_value());
        EXPECT_EQ(found->name, expected.name);
        EXPECT_EQ(found->offset, expected.offset);
        EXPECT_EQ(found->size, expected.size);
        EXPECT_FALSE(found->extraction_declined);
    }
}

TEST(B8bVolumesScanner, StampsANonEmptyIdOnEveryResult) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    for(const auto& expected : positive_fixtures()) {
        SCOPED_TRACE(expected.file);
        const auto data = read_fixture(*fixtures_dir / expected.file);
        ASSERT_FALSE(data.empty());
        const auto found = scan_for(expected.name, data);
        ASSERT_TRUE(found.has_value());
        EXPECT_FALSE(found->id.empty()) << "populate() must stamp a non-empty result id";
    }
}

TEST(B8bVolumesScanner, StampsAlwaysDisplayForMbrAndBtrfsOnly) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    for(const auto& expected : positive_fixtures()) {
        SCOPED_TRACE(expected.file);
        const auto data = read_fixture(*fixtures_dir / expected.file);
        ASSERT_FALSE(data.empty());
        const auto found = scan_for(expected.name, data);
        ASSERT_TRUE(found.has_value());

        const std::string name = expected.name;
        const bool expected_flag = (name == "mbr") || (name == "btrfs");
        EXPECT_EQ(found->always_display, expected_flag)
            << name << " must have always_display == " << (expected_flag ? "true" : "false");
    }
}

TEST(B8bVolumesScanner, NoResultDependsOnTheZeroSizeFill) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    struct probe {
        const char* file;
        const char* name;
        std::size_t magic_offset;
    };
    const probe probes[] = {
        {"ext.bin",              "ext",    ext_rewind},
        {"ext_at_offset.bin",    "ext",    4096U + ext_rewind},
        {"fat.bin",              "fat",    fat_rewind},
        {"fat32.bin",            "fat",    fat_rewind},
        {"ntfs.bin",             "ntfs",   2048U},
        {"apfs.bin",             "apfs",   4096U + apfs_rewind},
        {"btrfs.bin",            "btrfs",  4096U + btrfs_rewind},
        {"efigpt.bin",           "efigpt", efigpt_rewind},
        {"efigpt_at_offset.bin", "efigpt", 4096U + efigpt_rewind},
        {"mbr_lba0.bin",         "mbr",    mbr_rewind},
        {"mbr_zero_size.bin",    "mbr",    mbr_rewind}
    };

    for(const auto& value : probes) {
        SCOPED_TRACE(value.file);
        const auto data = read_fixture(*fixtures_dir / value.file);
        ASSERT_FALSE(data.empty());

        const auto direct = parse_at(value.name, data, value.magic_offset);
        ASSERT_TRUE(direct.has_value());
        EXPECT_NE(direct->size, std::uint64_t{0})
            << value.name << "'s parser must compute its own size";

        const auto scanned = scan_for(value.name, data);
        ASSERT_TRUE(scanned.has_value());
        EXPECT_EQ(scanned->size, direct->size)
            << "the scanner widened a size the parser had already computed";
    }
}

TEST(B8bVolumesScanner, EfigptDisplacesMbrAndFatAtTheSameOffsetOnConfidence) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(gpt, "efigpt.bin");
    B8B_LOAD_FIXTURE(fat, "fat.bin");
    ASSERT_GE(gpt.size(), std::size_t{512});
    ASSERT_GE(fat.size(), std::size_t{512});

    bytes data = gpt;
    std::copy(fat.begin(), fat.begin() + 446, data.begin());

    write_u8_at(data, 446U, 0x00);
    write_u8_at(data, 446U + 4U, 0x0B);
    write_u32_le_at(data, 446U + 8U, 1U);
    write_u32_le_at(data, 446U + 12U, 8U);
    ASSERT_EQ(data[0x1FE], 0x55U);
    ASSERT_EQ(data[0x1FF], 0xAAU);

    const auto mbr_direct = parse_at("mbr", data, mbr_rewind);
    const auto fat_direct = parse_at("fat", data, fat_rewind);
    const auto gpt_direct = parse_at("efigpt", data, efigpt_rewind);
    ASSERT_TRUE(mbr_direct.has_value()) << "the spliced buffer must be a valid MBR";
    ASSERT_TRUE(fat_direct.has_value()) << "the spliced buffer must be a valid FAT boot sector";
    ASSERT_TRUE(gpt_direct.has_value()) << "the spliced buffer must still be a valid GPT";
    ASSERT_EQ(mbr_direct->offset, std::uint64_t{0});
    ASSERT_EQ(fat_direct->offset, std::uint64_t{0});
    ASSERT_EQ(gpt_direct->offset, std::uint64_t{0});
    ASSERT_GT(static_cast<unsigned>(gpt_direct->confidence),
              static_cast<unsigned>(mbr_direct->confidence));
    ASSERT_GT(static_cast<unsigned>(gpt_direct->confidence),
              static_cast<unsigned>(fat_direct->confidence));

    const auto results = scan_all(data);
    ASSERT_EQ(results.size(), std::size_t{1})
        << "three signatures matched at offset 0; the overlap filter must keep exactly one";
    EXPECT_EQ(results[0].name, "efigpt")
        << "efigpt (250) must displace mbr and fat (128 each) at the shared offset";
    EXPECT_EQ(results[0].offset, std::uint64_t{0});
    EXPECT_EQ(results[0].size, std::uint64_t{20480});
    EXPECT_EQ(count_named(results, "mbr"), std::size_t{0});
    EXPECT_EQ(count_named(results, "fat"), std::size_t{0});
}

TEST(B8bVolumesScanner, NeverFindsFatAwayFromItsFixedMagicOffset) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "fat.bin");
    const auto data = with_zero_prefix(base, 4096);

    ASSERT_TRUE(parse_at("fat", data, 4096U + fat_rewind).has_value());

    EXPECT_FALSE(scan_for("fat", data).has_value())
        << "a short signature is probed only at its registered magic_offset";
}

TEST(B8bVolumesScanner, NeverFindsMbrAwayFromItsFixedMagicOffset) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    B8B_LOAD_FIXTURE(base, "mbr_lba0.bin");
    const auto data = with_zero_prefix(base, 4096);

    EXPECT_FALSE(scan_for("mbr", data).has_value())
        << "a short signature is probed only at its registered magic_offset";
}

TEST(B8bVolumesScanner, BadCrcFixturesProduceNoResultsAtAll) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    for(const char* file : {"efigpt_bad_crc.bin", "btrfs_bad_crc.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(*fixtures_dir / file);
        ASSERT_FALSE(data.empty()) << "fixture failed to load: " << file;
        EXPECT_TRUE(scan_all(data).empty())
            << "oracle reports an empty file_map for " << file;
    }
}

TEST(B8bVolumesExternalExtraction, ExtRunsTskRecoverOnlyWhenItIsInstalled) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto* value = signature_named("ext");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;

    if(!binwalk::external_utility_available(definition)) {

        GTEST_SKIP() << "external utility \"tsk_recover\" is not installed; "
                        "the extractor DEFINITION is asserted separately and does not skip";
    }

    B8B_LOAD_FIXTURE(data, "ext.bin");
    const auto result = parse_at("ext", data, ext_rewind);
    ASSERT_TRUE(result.has_value());

    std::error_code error;
    const auto output_root =
        std::filesystem::temp_directory_path(error) / "b8b_volumes_ext_extraction";
    ASSERT_FALSE(error);
    std::filesystem::create_directories(output_root, error);

    const auto extraction = binwalk::execute_extractor(
        view(data),
        (*fixtures_dir / "ext.bin").string(),
        *result,
        definition,
        output_root.string()
    );
    EXPECT_NE(extraction.failure, binwalk::extraction_failure::utility_not_found)
        << "the utility was reported available, so it must not come back as missing";

    std::error_code cleanup;
    std::filesystem::remove_all(output_root, cleanup);
}

TEST(B8bVolumesExternalExtraction, ApfsRunsSevenZzOnlyWhenItIsInstalled) {
    B8B_REQUIRE_FIXTURES_DIR(fixtures_dir);
    const auto* value = signature_named("apfs");
    ASSERT_NE(value, nullptr);
    ASSERT_TRUE(value->extractor_definition.has_value());
    const auto& definition = *value->extractor_definition;

    if(!binwalk::external_utility_available(definition)) {

        GTEST_SKIP() << "external utility \"7zz\" is not installed; "
                        "the extractor DEFINITION is asserted separately and does not skip";
    }

    B8B_LOAD_FIXTURE(data, "apfs.bin");
    const auto result = parse_at("apfs", data, 4096U + apfs_rewind);
    ASSERT_TRUE(result.has_value());

    std::error_code error;
    const auto output_root =
        std::filesystem::temp_directory_path(error) / "b8b_volumes_apfs_extraction";
    ASSERT_FALSE(error);
    std::filesystem::create_directories(output_root, error);

    const auto extraction = binwalk::execute_extractor(
        view(data),
        (*fixtures_dir / "apfs.bin").string(),
        *result,
        definition,
        output_root.string()
    );
    EXPECT_NE(extraction.failure, binwalk::extraction_failure::utility_not_found)
        << "the utility was reported available, so it must not come back as missing";

    std::error_code cleanup;
    std::filesystem::remove_all(output_root, cleanup);
}
