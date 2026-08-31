#include "../../lib/src/formats/b1_compression.hpp"

#include <binwalk/chroot.hpp>
#include <binwalk/codec.hpp>
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
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
namespace {

const std::vector<binwalk::signature>& batch() {
    static const std::vector<binwalk::signature> value =
        binwalk::formats::b1_compression_signatures();
    return value;
}

const binwalk::signature* signature_named(const std::string& name) {
    for(const auto& value : batch()) {
        if(value.name == name) {
            return &value;
        }
    }
    return nullptr;
}

const std::array<const char*, 11> batch_names{
    "gzip", "xz", "lzma", "bzip2", "zstd", "lz4",
    "lzop", "zlib", "gpg_signed", "compressd", "lzfse"
};

struct registry_fact {
    const char* name;
    bool short_signature;
    std::size_t magic_offset;
    bool always_display;
    std::size_t magic_count;
};

const std::array<registry_fact, 11>& registry_facts() {
    static const std::array<registry_fact, 11> facts{{

        {"gzip",         false, 0,            false,          1},
        {"xz",           false, 0,            false,          1},
        {"lzma",         false, 0,            false,          48},
        {"bzip2",        false, 0,            false,          9},
        {"zstd",         false, 0,            false,          1},
        {"lz4",          false, 0,            false,          1},
        {"lzop",         false, 0,            false,          1},
        {"zlib",         true,  0,            false,          3},
        {"gpg_signed",   true,  0,            false,          1},
        {"compressd",    true,  0,            false,          1},
        {"lzfse",        false, 0,            false,          4}
    }};
    return facts;
}

enum class tier { low, medium, high };

void expect_tier(std::uint8_t confidence, tier expected, const std::string& what) {
    switch(expected) {
    case tier::low:
        EXPECT_LT(confidence, binwalk::confidence_medium)
            << what << ": the oracle reports this in the LOW tier";
        break;
    case tier::medium:
        EXPECT_GE(confidence, binwalk::confidence_medium)
            << what << ": the oracle reports this at MEDIUM or above; below "
            << "medium the scanner would not skip past the result";
        EXPECT_LT(confidence, binwalk::confidence_high)
            << what << ": the oracle reports MEDIUM, not HIGH";
        break;
    case tier::high:
        EXPECT_GE(confidence, binwalk::confidence_high)
            << what << ": the oracle reports HIGH";
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
                if(std::filesystem::exists(candidate / "xz.bin", error)) {
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

std::vector<std::uint8_t> read_fixture(const std::string& name) {
    if(fixtures().directory.empty()) {
        return {};
    }
    const auto path = fixtures().directory / name;

    std::error_code error;
    const auto file_size = std::filesystem::file_size(path, error);
    if(error) {
        return {};
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
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

binwalk::byte_view view(const std::vector<std::uint8_t>& data) {
    return binwalk::byte_view(data.data(), data.size());
}

std::vector<binwalk::signature_result> scan_for(
    const std::string& name, const std::vector<std::uint8_t>& data
) {
    binwalk::scan_options options;
    options.include = {name};
    const binwalk::scanner scanner(options);
    return scanner.scan(view(data));
}

std::vector<binwalk::signature_result> scan_all_for(
    const std::string& name, const std::vector<std::uint8_t>& data
) {
    binwalk::scan_options options;
    options.include = {name};
    options.search_all = true;
    const binwalk::scanner scanner(options);
    return scanner.scan(view(data));
}

std::optional<binwalk::signature_result> parse_at(
    const std::string& name, const std::vector<std::uint8_t>& data, std::size_t offset
) {
    const auto* definition = signature_named(name);
    if(definition == nullptr || definition->parser == nullptr) {
        return std::nullopt;
    }
    return definition->parser(view(data), offset);
}

std::vector<std::uint8_t> with_prefix(const std::vector<std::uint8_t>& data, std::size_t bytes) {
    std::vector<std::uint8_t> result(bytes, 0x00);
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

std::vector<std::uint8_t> truncated(const std::vector<std::uint8_t>& data, std::size_t length) {
    if(length >= data.size()) {
        return data;
    }
    return std::vector<std::uint8_t>(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(length));
}

std::vector<std::uint8_t> drop_last(const std::vector<std::uint8_t>& data, std::size_t bytes) {
    if(bytes >= data.size()) {
        return {};
    }
    return truncated(data, data.size() - bytes);
}

std::vector<std::uint8_t> poked(
    const std::vector<std::uint8_t>& data, std::size_t offset, std::uint8_t value
) {
    std::vector<std::uint8_t> result = data;
    if(offset < result.size()) {
        result[offset] = value;
    }
    return result;
}

std::vector<std::uint8_t> flipped(
    const std::vector<std::uint8_t>& data, std::size_t first, std::size_t last
) {
    std::vector<std::uint8_t> result = data;
    for(std::size_t index = first; index < last && index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(result[index] ^ 0xFF);
    }
    return result;
}

bool zlib_family_available() {
    return binwalk::codec_available(binwalk::codec_id::deflate)
        && binwalk::codec_available(binwalk::codec_id::zlib_stream)
        && binwalk::codec_available(binwalk::codec_id::gzip);
}

}

TEST(B1CompressionRegistry, RegistersExactlyTheElevenUpstreamNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "signature name \"" << value.name << "\" is registered twice by this batch";
    }

    for(const char* name : batch_names) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b1_compression does not register \"" << name << "\". Upstream "
            << "src/magic.rs registers it, so the format would silently not exist.";
    }
    EXPECT_EQ(produced.size(), batch_names.size())
        << "b1_compression registers a name outside its own eleven; another "
        << "batch owns it and it would be a duplicate registration";
}

TEST(B1CompressionRegistry, FlagsAndMagicCountsMatchUpstreamMagicRs) {
    for(const auto& fact : registry_facts()) {
        const auto* value = signature_named(fact.name);
        ASSERT_NE(value, nullptr) << fact.name << " is not registered";

        EXPECT_EQ(value->short_signature, fact.short_signature)
            << fact.name << ": `short` decides whether the signature is only "
            << "matched at the start of the file; upstream magic.rs says "
            << (fact.short_signature ? "true" : "false");
        EXPECT_EQ(value->magic_offset, fact.magic_offset) << fact.name;
        EXPECT_EQ(value->always_display, fact.always_display) << fact.name;
        EXPECT_EQ(value->magic.size(), fact.magic_count)
            << fact.name << ": wrong number of magic patterns; a missing "
            << "pattern is a format variant that is never detected";
        for(const auto& pattern : value->magic) {
            EXPECT_FALSE(pattern.empty()) << fact.name << " has an empty magic pattern";
        }
    }
}

TEST(B1CompressionRegistry, EverySignatureHasAParser) {
    for(const auto& value : batch()) {
        EXPECT_NE(value.parser, nullptr)
            << value.name << " has a null parser; every magic match would be "
            << "accepted or dropped without validation";
    }
}

TEST(B1CompressionRegistry, EveryNameAppearsInTheFrozenOrderTable) {

    static const std::array<const char*, 111> upstream_order{
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

    for(const auto& value : batch()) {
        const auto found = std::find_if(
            upstream_order.begin(),
            upstream_order.end(),
            [&value](const char* entry) { return value.name == entry; }
        );
        EXPECT_NE(found, upstream_order.end())
            << "b1_compression produced signature name \"" << value.name
            << "\", which is NOT in upstream magic.rs's 111-entry order table. "
            << "builtin.cpp would sort it to the end of the registry and it "
            << "would vanish from --include/--exclude. Fix the name in the "
            << "batch; the table is frozen.";
    }
}

TEST(B1CompressionRegistry, LzmaGeneratesTheFullFortyEightPatternProduct) {
    const auto* value = signature_named("lzma");
    ASSERT_NE(value, nullptr);
    ASSERT_EQ(value->magic.size(), std::size_t{48})
        << "upstream lzma_magic() is the cross product of 4 property bytes and "
        << "12 dictionary sizes";

    static const std::array<std::uint8_t, 4> properties{0x5D, 0x6E, 0x6D, 0x6C};
    static const std::array<std::uint32_t, 12> dictionary_sizes{
        0x10000000u, 0x20000000u, 0x01000000u, 0x02000000u,
        0x04000000u, 0x00800000u, 0x00400000u, 0x00200000u,
        0x00100000u, 0x00080000u, 0x00020000u, 0x00010000u
    };

    std::set<std::vector<std::uint8_t>> expected;
    for(const auto property : properties) {
        for(const auto dictionary_size : dictionary_sizes) {
            expected.insert({
                property,
                static_cast<std::uint8_t>(dictionary_size & 0xFFu),
                static_cast<std::uint8_t>((dictionary_size >> 8) & 0xFFu),
                static_cast<std::uint8_t>((dictionary_size >> 16) & 0xFFu),
                static_cast<std::uint8_t>((dictionary_size >> 24) & 0xFFu)
            });
        }
    }
    ASSERT_EQ(expected.size(), std::size_t{48});

    std::set<std::vector<std::uint8_t>> produced;
    for(const auto& pattern : value->magic) {
        EXPECT_EQ(pattern.size(), std::size_t{5})
            << "every lzma magic is one property byte plus a 4-byte dictionary size";
        produced.insert(pattern);
    }

    EXPECT_EQ(produced, expected)
        << "the generated lzma magic set is not {properties} x {dictionary sizes}";
}

TEST(B1CompressionRegistry, NoMagicPatternIsAPrefixOfAnotherSignaturesMagic) {

    const auto to_hex = [](const std::vector<std::uint8_t>& pattern) {
        static const char digits[] = "0123456789ABCDEF";
        std::string text;
        for(const auto byte : pattern) {
            if(!text.empty()) {
                text.push_back(' ');
            }
            text.push_back(digits[(byte >> 4) & 0x0F]);
            text.push_back(digits[byte & 0x0F]);
        }
        return text;
    };

    std::size_t pattern_total = 0;
    for(const auto& value : batch()) {
        pattern_total += value.magic.size();
    }
    EXPECT_EQ(pattern_total, std::size_t{71})
        << "the batch no longer owns 71 magic patterns. That is not necessarily "
        << "wrong, but re-read the collision reasoning below before changing "
        << "this number.";

    for(const auto& left : batch()) {
        for(const auto& right : batch()) {
            if(left.name == right.name) {
                continue;
            }
            for(const auto& first : left.magic) {
                for(const auto& second : right.magic) {
                    if(first.empty() || second.empty() || first.size() > second.size()) {
                        continue;
                    }
                    const bool is_prefix =
                        std::equal(first.begin(), first.end(), second.begin());
                    EXPECT_FALSE(is_prefix)
                        << "magic collision: \"" << left.name << "\" pattern ["
                        << to_hex(first) << "] is a prefix of \"" << right.name
                        << "\" pattern [" << to_hex(second) << "]. Both signatures "
                        << "can now match at the same offset, which drops the "
                        << "result into the scanner's equal-offset overlap "
                        << "tie-break -- precedence by confidence, then by "
                        << "upstream registration order. That is scanner "
                        << "behaviour this batch does not control and cannot "
                        << "test, so the collision has to go rather than be "
                        << "accommodated.";
                }
            }
        }
    }
}

TEST(B1CompressionRegistry, MagicPatternsMatchUpstreamByteForByte) {
    struct expectation {
        const char* name;
        std::vector<std::vector<std::uint8_t>> magic;
    };

    const std::vector<expectation> expectations{
        {"gzip", {{0x1F, 0x8B, 0x08}}},
        {"xz", {{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}}},
        {"zstd", {{0x28, 0xB5, 0x2F, 0xFD}}},
        {"lz4", {{0x04, 0x22, 0x4D, 0x18}}},
        {"lzop", {{0x89, 'L', 'Z', 'O', 0x00, 0x0D, 0x0A, 0x1A, 0x0A}}},
        {"zlib", {{0x78, 0x9C}, {0x78, 0xDA}, {0x78, 0x5E}}},
        {"gpg_signed", {{0xA3, 0x01}}},
        {"compressd", {{0x1F, 0x9D, 0x90}}},
        {"lzfse", {{'b', 'v', 'x', '-'}, {'b', 'v', 'x', '1'},
                   {'b', 'v', 'x', '2'}, {'b', 'v', 'x', 'n'}}},
        {"bzip2", {{'B', 'Z', 'h', '9', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '8', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '7', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '6', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '5', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '4', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '3', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '2', '1', 'A', 'Y', '&', 'S', 'Y'},
                   {'B', 'Z', 'h', '1', '1', 'A', 'Y', '&', 'S', 'Y'}}}
    };

    for(const auto& expected : expectations) {
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name;
        const std::set<std::vector<std::uint8_t>> produced(
            value->magic.begin(), value->magic.end()
        );
        const std::set<std::vector<std::uint8_t>> wanted(
            expected.magic.begin(), expected.magic.end()
        );
        EXPECT_EQ(produced, wanted)
            << expected.name << ": magic byte patterns differ from upstream. A "
            << "wrong pattern means the format is either never found or found "
            << "at the wrong offsets.";
    }
}

TEST(B1CompressionExtractors, ExternalDefinitionsMatchUpstream) {
    struct external {
        const char* name;
        const char* command;
        const char* extension;
        std::vector<std::string> arguments;
        std::vector<std::int32_t> exit_codes;
    };

    const std::vector<external> expectations{
        {"zstd", "zstd", "zst", {"-k", "-f", "-d", "%e"}, {0}},
        {"lz4", "lz4", "lz4", {"-f", "-d", "%e", "decompressed.bin"}, {0}},
        {"lzop", "lzop", "lzo", {"-p", "-N", "-d", "%e"}, {0}},
        {"lzfse", "lzfse", "bin", {"-decode", "-i", "%e", "-o", "decompressed.bin"}, {0}},

        {"compressd", "7zz", "bin", {"x", "-y", "-o.", "-p''", "%e"}, {0, 2}}
    };

    for(const auto& expected : expectations) {
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name;
        ASSERT_TRUE(value->extractor_definition.has_value())
            << expected.name << " has no extractor; upstream gives it one";

        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::external) << expected.name;
        EXPECT_EQ(definition.command, expected.command) << expected.name;
        EXPECT_EQ(definition.extension, expected.extension)
            << expected.name << ": the extension decides the carved file name the "
            << "utility is pointed at (contract §2 rule 1)";
        EXPECT_EQ(definition.arguments, expected.arguments)
            << expected.name << ": argv must match, including the \"%e\" placeholder";
        EXPECT_EQ(definition.exit_codes, expected.exit_codes) << expected.name;
        EXPECT_EQ(definition.internal, nullptr)
            << expected.name << " is external and must not carry an internal function";

        const auto placeholder = std::find(
            definition.arguments.begin(), definition.arguments.end(), std::string("%e")
        );
        EXPECT_NE(placeholder, definition.arguments.end())
            << expected.name << ": without the %e placeholder the carved file is "
            << "never passed to the utility";
    }
}

TEST(B1CompressionExtractors, InternalDefinitionsAreInternalAndCallable) {

    for(const char* name : {"gzip", "zlib", "xz", "lzma", "bzip2", "gpg_signed"}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        ASSERT_TRUE(value->extractor_definition.has_value())
            << name << " has no extractor definition";

        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal) << name;
        EXPECT_NE(definition.internal, nullptr)
            << name << ": an internal extractor with a null function pointer "
            << "cannot dry-run, so the parser has no validator (§1 rule 3)";
        EXPECT_FALSE(definition.name.empty())
            << name << ": the extractor name is emitted in the --log JSON";
        EXPECT_TRUE(definition.command.empty())
            << name << " is internal and must not name an external command";
    }
}

TEST(B1CompressionExtractors, EverySignatureInTheBatchHasAnExtractor) {

    for(const auto& value : batch()) {
        EXPECT_TRUE(value.extractor_definition.has_value())
            << value.name << " has no extractor; upstream magic.rs gives every "
            << "entry in this batch one";
        if(value.extractor_definition.has_value()) {
            EXPECT_NE(value.extractor_definition->type, binwalk::extractor_type::none)
                << value.name;
        }
    }
}

namespace {

std::string fixture_diagnostic() {
    return "tests/fixtures was not found. Directories tried:\n" + fixtures().searched;
}

void expect_single_hit(
    const std::string& name,
    const std::vector<std::uint8_t>& data,
    std::uint64_t offset,
    std::uint64_t size,
    tier expected_tier
) {
    const auto results = scan_for(name, data);
    ASSERT_EQ(results.size(), std::size_t{1})
        << name << ": the oracle reports exactly one hit in this " << data.size()
        << "-byte input, we report " << results.size();
    EXPECT_EQ(results[0].name, name);
    EXPECT_EQ(results[0].offset, offset) << name << ": wrong offset";
    EXPECT_EQ(results[0].size, size)
        << name << ": wrong size; size drives carving bounds and the scanner's "
        << "skip-ahead, so a wrong size corrupts every downstream result";
    EXPECT_FALSE(results[0].extraction_declined) << name;
    expect_tier(results[0].confidence, expected_tier, name);

    EXPECT_LE(results[0].offset, static_cast<std::uint64_t>(data.size()));
    if(results[0].offset <= data.size()) {
        EXPECT_LE(results[0].size, static_cast<std::uint64_t>(data.size()) - results[0].offset)
            << name << ": carving this result would read past the end of the buffer";
    }
}

void expect_rejected(const std::string& name, const std::vector<std::uint8_t>& data) {
    const auto results = scan_for(name, data);
    EXPECT_TRUE(results.empty())
        << name << ": the oracle REJECTS this " << data.size() << "-byte input, "
        << "we report " << results.size() << " hit(s); the first at offset "
        << (results.empty() ? 0 : results[0].offset) << " size "
        << (results.empty() ? 0 : results[0].size);
}

const std::array<std::uint8_t, 57> zlib_body{
    0x4B, 0xCA, 0xCC, 0x2B, 0x4F, 0xCC, 0xC9, 0xD6, 0x4D, 0x2E, 0x28, 0x50,
    0x48, 0x32, 0x8C, 0x4F, 0xCE, 0xCF, 0x2D, 0x28, 0x4A, 0x2D, 0x2E, 0xCE,
    0xCC, 0xCF, 0x53, 0xA8, 0xCA, 0xC9, 0x4C, 0x52, 0x48, 0xCB, 0xAC, 0x28,
    0x29, 0x2D, 0x4A, 0x55, 0x28, 0x48, 0xAC, 0xCC, 0xC9, 0x4F, 0x4C, 0xE1,
    0x4A, 0x1A, 0x61, 0xEA, 0x01, 0x9C, 0xEF, 0x6C, 0xF1
};

std::vector<std::uint8_t> zlib_stream(std::uint8_t first, std::uint8_t second) {
    std::vector<std::uint8_t> data{first, second};
    data.insert(data.end(), zlib_body.begin(), zlib_body.end());
    return data;
}

std::vector<std::uint8_t> zlib_payload() {
    const std::string unit = "binwalk-cpp b1_compression zlib fixture payload\n";
    std::string text;
    for(int repeat = 0; repeat < 6; ++repeat) {
        text += unit;
    }
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

}

TEST(B1CompressionDetection, GzipWholeFixture) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "zlib/deflate/gzip codecs compiled out of this build";
    }
    const auto data = read_fixture("gzip_whole.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{490});
    expect_single_hit("gzip", data, 0, 490, tier::high);
}

TEST(B1CompressionDetection, GzipTruncatedIsRejected) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "zlib/deflate/gzip codecs compiled out of this build";
    }

    const auto data = read_fixture("gzip_truncated.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{485});
    expect_rejected("gzip", data);

    const auto whole = read_fixture("gzip_whole.bin");
    ASSERT_FALSE(whole.empty()) << fixture_diagnostic();
    expect_single_hit("gzip", whole, 0, 490, tier::high);
}

TEST(B1CompressionDetection, GzipIsFoundAwayFromTheStartOfTheFile) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "zlib/deflate/gzip codecs compiled out of this build";
    }
    const auto data = read_fixture("gzip_whole.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_single_hit("gzip", with_prefix(data, 32), 32, 490, tier::high);
}

TEST(B1CompressionDetection, XzWholeFixture) {
    if(!binwalk::codec_available(binwalk::codec_id::xz)) {

        GTEST_SKIP() << "the xz codec is compiled out of this build";
    }
    const auto data = read_fixture("xz.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{1916});
    expect_single_hit("xz", data, 0, 1916, tier::high);
    expect_single_hit("xz", with_prefix(data, 32), 32, 1916, tier::high);
}

TEST(B1CompressionDetection, XzBadHeaderCrcIsRejected) {

    const auto data = read_fixture("xz.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{12});
    expect_rejected("xz", poked(data, 8, static_cast<std::uint8_t>(data[8] ^ 0x01)));
}

TEST(B1CompressionDetection, XzValidHeaderWithMalformedStreamIsStillReported) {
    if(!binwalk::codec_available(binwalk::codec_id::xz)) {

        GTEST_SKIP() << "the xz codec is compiled out of this build";
    }
    const auto data = read_fixture("xz.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_single_hit("xz", truncated(data, 12), 0, 12, tier::high);

    expect_single_hit("xz", truncated(data, 20), 0, 20, tier::high);
}

TEST(B1CompressionDetection, XzMalformedStreamSetsSevenZipAsThePreferredExtractor) {
    if(!binwalk::codec_available(binwalk::codec_id::xz)) {

        GTEST_SKIP() << "the xz codec is compiled out of this build";
    }
    const auto data = read_fixture("xz.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{256});

    const auto malformed = poked(data, 200, 0x00);
    const auto broken = parse_at("xz", malformed, 0);
    ASSERT_TRUE(broken.has_value())
        << "a valid, CRC-checked xz stream header must still be reported even "
        << "when the stream behind it is unusable";
    EXPECT_EQ(broken->size, std::uint64_t{0})
        << "no xz stream decompressed, so the parser has no size of its own; "
        << "the 1916 the oracle prints comes from the scanner's zero-size "
        << "rewrite, not from here";

    ASSERT_TRUE(broken->preferred_extractor.has_value())
        << "section 1b: a valid header over a malformed stream must hand the "
        << "result to 7-Zip. Without the override this result would be given to "
        << "the built-in decompressor that has already failed on it, and the "
        << "recovery upstream performs would be lost.";
    const auto& preferred = *broken->preferred_extractor;
    EXPECT_EQ(preferred.type, binwalk::extractor_type::external);
    EXPECT_EQ(preferred.command, "7zz");
    EXPECT_EQ(preferred.extension, "bin");
    EXPECT_EQ(
        preferred.arguments,
        (std::vector<std::string>{"x", "-y", "-o.", "-p''", "%e"})
    );
    EXPECT_EQ(preferred.exit_codes, (std::vector<std::int32_t>{0, 2}))
        << "7zz exits 2 when there is trailing data after the archive, which "
        << "is the normal case for a carved range";
    EXPECT_EQ(preferred.internal, nullptr);

    const auto clean = parse_at("xz", data, 0);
    ASSERT_TRUE(clean.has_value());
    EXPECT_EQ(clean->size, std::uint64_t{1916});
    EXPECT_FALSE(clean->preferred_extractor.has_value())
        << "an xz stream that decompresses cleanly must use the signature's "
        << "own internal extractor, not the 7-Zip fallback";
}

TEST(B1CompressionDetection, LzmaWholeFixture) {
    if(!binwalk::codec_available(binwalk::codec_id::lzma_alone)) {

        GTEST_SKIP() << "the lzma_alone codec is compiled out of this build";
    }
    const auto data = read_fixture("lzma.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{1867});
    expect_single_hit("lzma", data, 0, 1867, tier::high);
}

TEST(B1CompressionDetection, LzmaRejectionsFromTheHeaderAndTheBody) {
    const auto data = read_fixture("lzma.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{64});

    expect_rejected("lzma", poked(data, 12, 0x01));

    auto small = data;
    for(std::size_t index = 5; index < 13; ++index) {
        small[index] = 0x00;
    }
    small[5] = 0x10;
    expect_rejected("lzma", small);

    expect_rejected("lzma", truncated(data, 13));
    expect_rejected("lzma", truncated(data, 32));
    expect_rejected("lzma", flipped(data, 13, 60));
}

TEST(B1CompressionDetection, Bzip2WholeFixture) {
    if(!binwalk::codec_available(binwalk::codec_id::bzip2)) {

        GTEST_SKIP() << "the bzip2 codec is compiled out of this build";
    }
    const auto data = read_fixture("bzip2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{5152});
    expect_single_hit("bzip2", data, 0, 5152, tier::high);
    expect_single_hit("bzip2", with_prefix(data, 32), 32, 5152, tier::high);
}

TEST(B1CompressionDetection, Bzip2RejectionsFromTruncationAndCorruption) {
    const auto data = read_fixture("bzip2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{64});

    expect_rejected("bzip2", truncated(data, 10));
    expect_rejected("bzip2", truncated(data, 14));

    expect_rejected("bzip2", flipped(data, 12, 40));
}

TEST(B1CompressionDetection, ZstdWholeFixture) {

    const auto data = read_fixture("zstd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{3347});
    expect_single_hit("zstd", data, 0, 3347, tier::high);
}

TEST(B1CompressionDetection, ZstdRejections) {
    const auto data = read_fixture("zstd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{8});

    expect_rejected("zstd", truncated(data, 4));

    expect_rejected("zstd", truncated(data, data.size() / 2));

    expect_rejected("zstd", poked(data, 4, static_cast<std::uint8_t>(data[4] | 0x18)));
}

TEST(B1CompressionDetection, Lz4WholeFixtureIsMediumConfidence) {

    const auto data = read_fixture("lz4.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{3966});

    expect_single_hit("lz4", data, 0, 3966, tier::medium);
}

TEST(B1CompressionDetection, Lz4Rejections) {
    const auto data = read_fixture("lz4.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{8});

    expect_rejected("lz4", truncated(data, 4));

    expect_rejected("lz4", poked(data, 4, static_cast<std::uint8_t>(data[4] | 0x02)));

    expect_rejected("lz4", poked(data, 6, static_cast<std::uint8_t>(data[6] ^ 0xFF)));

    expect_rejected("lz4", truncated(data, data.size() / 2));
}

TEST(B1CompressionDetection, LzopWholeFixture) {

    const auto data = read_fixture("lzop.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{90});
    expect_single_hit("lzop", data, 0, 90, tier::high);
}

TEST(B1CompressionDetection, LzopRejections) {
    const auto data = read_fixture("lzop.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{24});

    expect_rejected("lzop", poked(data, 15, 0x09));

    auto bad_version = data;
    bad_version[9] = 0x99;
    bad_version[10] = 0x99;
    expect_rejected("lzop", bad_version);

    expect_rejected("lzop", drop_last(data, 4));

    expect_rejected("lzop", truncated(data, 9));
}

TEST(B1CompressionDetection, LzfseWholeFixture) {

    const auto data = read_fixture("lzfse.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{6282});
    expect_single_hit("lzfse", data, 0, 6282, tier::high);
    expect_single_hit("lzfse", with_prefix(data, 32), 32, 6282, tier::high);
}

TEST(B1CompressionDetection, LzfseUncompressedBlockFixture) {

    const auto data = read_fixture("lzfse_raw.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{44});
    expect_single_hit("lzfse", data, 0, 44, tier::high);
}

TEST(B1CompressionDetection, LzfseRejections) {
    const auto data = read_fixture("lzfse.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{8});

    expect_rejected("lzfse", drop_last(data, 4));

    expect_rejected("lzfse", truncated(data, 4));
}

TEST(B1CompressionDetection, GpgSignedWholeFixture) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the deflate codec is compiled out of this build";
    }
    const auto data = read_fixture("gpg_signed.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{888});
    expect_single_hit("gpg_signed", data, 0, 888, tier::high);
}

#if defined(__GNUC__) && !defined(__clang__)
#    pragma GCC diagnostic push
// GCC 16 misdiagnoses this bounded std::vector fill insertion after inlining.
#    pragma GCC diagnostic ignored "-Warray-bounds"
#    pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
TEST(B1CompressionDetection, GpgSignedRejections) {
    const auto data = read_fixture("gpg_signed.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GT(data.size(), std::size_t{4});

    expect_rejected("gpg_signed", truncated(data, 2));

    std::vector<std::uint8_t> no_deflate{data[0], data[1]};
    no_deflate.insert(no_deflate.end(), 24, 0xFF);
    expect_rejected("gpg_signed", no_deflate);
}
#if defined(__GNUC__) && !defined(__clang__)
#    pragma GCC diagnostic pop
#endif

TEST(B1CompressionDetection, CompressdWholeFixture) {
    const auto data = read_fixture("compressd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{131});

    expect_single_hit("compressd", data, 0, 131, tier::medium);
}

TEST(B1CompressionDetection, CompressdAwayFromOffsetZeroIsLowConfidenceUnderSearchAll) {
    const auto data = read_fixture("compressd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    const auto shifted = with_prefix(data, 32);
    ASSERT_EQ(shifted.size(), std::size_t{163});

    EXPECT_TRUE(scan_for("compressd", shifted).empty())
        << "a default scan must not reach a short signature away from offset 0";

    const auto results = scan_all_for("compressd", shifted);
    ASSERT_EQ(results.size(), std::size_t{1})
        << "--search-all must find the compress'd magic at offset 32";
    EXPECT_EQ(results[0].name, "compressd");
    EXPECT_EQ(results[0].offset, std::uint64_t{32});
    EXPECT_EQ(results[0].size, std::uint64_t{131});
    expect_tier(results[0].confidence, tier::low, "compressd at offset 32 under --search-all");
}

TEST(B1CompressionDetection, CompressdParserItselfReportsNoSize) {
    const auto data = read_fixture("compressd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    const auto result = parse_at("compressd", data, 0);
    ASSERT_TRUE(result.has_value())
        << "compress'd carries no validatable structure beyond its magic, so a "
        << "buffer that starts with 1F 9D 90 must be accepted at offset 0";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{0})
        << "compressd carries no length field; the size a user sees comes from "
        << "the scanner's zero-size rewrite";
    EXPECT_FALSE(result->extraction_declined);
    expect_tier(result->confidence, tier::medium, "compressd parser at offset 0");
}

TEST(B1CompressionDetection, CompressdNeedsAtLeastOneByteBeyondItsMagic) {
    const auto data = read_fixture("compressd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_GE(data.size(), std::size_t{5});

    expect_rejected("compressd", truncated(data, 3));

    expect_single_hit("compressd", truncated(data, 4), 0, 4, tier::medium);
    expect_single_hit("compressd", truncated(data, 5), 0, 5, tier::medium);
}

TEST(B1CompressionDetection, ZlibIsDetectedForAllThreeMagicPatterns) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the zlib/deflate codecs are compiled out of this build";
    }

    const std::array<std::array<std::uint8_t, 2>, 3> headers{{
        {{std::uint8_t{0x78}, std::uint8_t{0x9C}}},
        {{std::uint8_t{0x78}, std::uint8_t{0xDA}}},
        {{std::uint8_t{0x78}, std::uint8_t{0x5E}}}
    }};
    for(const auto& header : headers) {
        const auto data = zlib_stream(header[0], header[1]);
        ASSERT_EQ(data.size(), std::size_t{59});
        expect_single_hit("zlib", data, 0, 59, tier::high);
    }
}

TEST(B1CompressionDetection, ZlibCommittedFixture) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the zlib/deflate codecs are compiled out of this build";
    }

    const auto data = read_fixture("zlib.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    ASSERT_EQ(data.size(), std::size_t{892});
    expect_single_hit("zlib", data, 0, 892, tier::high);
}

#if defined(__GNUC__) && !defined(__clang__)
#    pragma GCC diagnostic push
// GCC 16 misdiagnoses this bounded std::vector fill insertion after inlining.
#    pragma GCC diagnostic ignored "-Warray-bounds"
#    pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
TEST(B1CompressionDetection, ZlibRejections) {

    expect_rejected("zlib", std::vector<std::uint8_t>{0x78, 0xDA});
    std::vector<std::uint8_t> no_deflate{0x78, 0xDA};
    no_deflate.insert(no_deflate.end(), 24, 0xFF);
    expect_rejected("zlib", no_deflate);
}
#if defined(__GNUC__) && !defined(__clang__)
#    pragma GCC diagnostic pop
#endif

TEST(B1CompressionDetection, ShortSignaturesAreNeverReportedAwayFromOffsetZero) {

    for(const char* name : {"zlib", "gpg_signed", "compressd"}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        ASSERT_TRUE(value->short_signature) << name << " must be a short signature";
    }

    expect_rejected("zlib", with_prefix(zlib_stream(0x78, 0xDA), 32));

    const auto gpg = read_fixture("gpg_signed.bin");
    ASSERT_FALSE(gpg.empty()) << fixture_diagnostic();
    expect_rejected("gpg_signed", with_prefix(gpg, 32));

    const auto compressd = read_fixture("compressd.bin");
    ASSERT_FALSE(compressd.empty()) << fixture_diagnostic();
    expect_rejected("compressd", with_prefix(compressd, 32));
}

TEST(B1CompressionBounds, EveryParserSurvivesEmptyAndTinyBuffers) {
    const std::vector<std::vector<std::uint8_t>> inputs{
        {},
        {0x00},
        {0xFF},
        {0x1F, 0x8B},
        {0x78, 0xDA},
        {0xA3, 0x01},
        {0x1F, 0x9D, 0x90}
    };

    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        for(const auto& input : inputs) {
            const auto result = value.parser(view(input), 0);
            if(result.has_value()) {
                EXPECT_LE(result->offset, static_cast<std::uint64_t>(input.size()))
                    << value.name << " reported an offset past the end of a "
                    << input.size() << "-byte buffer";
                if(result->offset <= input.size()) {
                    EXPECT_LE(
                        result->size,
                        static_cast<std::uint64_t>(input.size()) - result->offset
                    ) << value.name << " reported a size that runs past the end of a "
                      << input.size() << "-byte buffer";
                }
            }
        }
    }
}

TEST(B1CompressionBounds, EveryParserSurvivesItsOwnMagicWithNothingAfterIt) {

    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        for(const auto& pattern : value.magic) {
            const auto result = value.parser(view(pattern), 0);
            if(result.has_value()) {
                EXPECT_LE(result->offset, static_cast<std::uint64_t>(pattern.size()))
                    << value.name;
                if(result->offset <= pattern.size()) {
                    EXPECT_LE(
                        result->size,
                        static_cast<std::uint64_t>(pattern.size()) - result->offset
                    ) << value.name << " reported a size past the end of a buffer "
                      << "that holds nothing but its own magic";
                }
            }

            if(pattern.size() > 1) {
                const std::vector<std::uint8_t> shorter(pattern.begin(), pattern.end() - 1);
                const auto short_result = value.parser(view(shorter), 0);
                if(short_result.has_value()) {
                    EXPECT_LE(short_result->size, static_cast<std::uint64_t>(shorter.size()))
                        << value.name;
                }
            }
        }
    }
}

TEST(B1CompressionBounds, EveryParserSurvivesAnOffsetAtOrPastTheEnd) {
    const std::vector<std::uint8_t> data(64, 0xA5);
    const std::array<std::size_t, 3> offsets{data.size(), data.size() + 1, data.size() * 4};
    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        for(const auto offset : offsets) {
            const auto result = value.parser(view(data), offset);

            if(result.has_value()) {
                EXPECT_EQ(result->size, std::uint64_t{0})
                    << value.name << " reported a non-zero size for a match at "
                    << "offset " << offset << " in a " << data.size() << "-byte buffer";
            }
        }
    }
}

TEST(B1CompressionBounds, ScanningMagicSoupNeverReportsOutOfBounds) {

    std::vector<std::uint8_t> data;
    std::uint32_t state = 0x1234567u;
    for(const auto& value : batch()) {
        for(const auto& pattern : value.magic) {
            data.insert(data.end(), pattern.begin(), pattern.end());
            for(int filler = 0; filler < 7; ++filler) {
                state = state * 1103515245u + 12345u;
                data.push_back(static_cast<std::uint8_t>((state >> 16) & 0xFFu));
            }
        }
    }
    ASSERT_FALSE(data.empty());

    const binwalk::scanner scanner(batch());
    const auto results = scanner.scan(view(data));
    for(const auto& result : results) {
        EXPECT_LE(result.offset, static_cast<std::uint64_t>(data.size()))
            << result.name << " offset past EOF";
        if(result.offset <= data.size()) {
            EXPECT_LE(result.size, static_cast<std::uint64_t>(data.size()) - result.offset)
                << result.name << " size runs past EOF";
        }
    }
}

namespace {

class b1_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b1_compression_";
        const auto* information = ::testing::UnitTest::GetInstance()->current_test_info();
        if(information != nullptr) {
            name += information->name();
        }
        root_ = base / name;

        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_, error);
        ASSERT_FALSE(static_cast<bool>(error)) << error.message();
    }

    void TearDown() override {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    std::filesystem::path root_;
};

std::vector<std::filesystem::path> files_under(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> found;
    std::error_code error;
    if(!std::filesystem::exists(directory, error)) {
        return found;
    }
    for(std::filesystem::recursive_directory_iterator iterator(directory, error), end;
        iterator != end;
        iterator.increment(error)) {
        if(error) {
            break;
        }
        if(iterator->is_regular_file(error)) {
            found.push_back(iterator->path());
        }
    }
    std::sort(found.begin(), found.end());
    return found;
}

std::string describe(const std::vector<std::filesystem::path>& files) {
    std::string text;
    for(const auto& file : files) {
        std::error_code error;
        text += "\n    " + file.filename().string() + " ("
            + std::to_string(std::filesystem::file_size(file, error)) + " bytes)";
    }
    return text.empty() ? "\n    <no files written>" : text;
}

std::vector<std::uint8_t> read_whole(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if(error) {
        return {};
    }
    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    if(!stream) {
        return {};
    }
    if(!buffer.empty()) {
        stream.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size())
        );
    }
    return buffer;
}

std::optional<binwalk::signature_result> scanned_result(
    const std::string& name, const std::vector<std::uint8_t>& data
) {
    const auto results = scan_for(name, data);
    if(results.size() != 1) {
        return std::nullopt;
    }
    return results[0];
}

binwalk::signature_result whole_buffer_result(
    const std::string& name, const std::vector<std::uint8_t>& data
) {
    binwalk::signature_result signature;
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());
    signature.name = name;
    signature.id = name + "_b1_probe";
    signature.confidence = binwalk::confidence_high;
    return signature;
}

void expect_internal_extraction(
    const std::filesystem::path& root,
    const std::string& name,
    const std::vector<std::uint8_t>& data,
    std::uint64_t expected_output_size,
    const std::vector<std::uint8_t>* expected_content
) {
    const auto* definition = signature_named(name);
    ASSERT_NE(definition, nullptr) << name;
    ASSERT_TRUE(definition->extractor_definition.has_value()) << name;

    const auto signature = scanned_result(name, data);
    ASSERT_TRUE(signature.has_value())
        << name << ": the scan that feeds the extractor found no single result";

    const auto output_root = root / name;
    const auto result = binwalk::execute_extractor(
        view(data), name + ".bin", *signature, *definition->extractor_definition,
        output_root.string()
    );

    ASSERT_TRUE(result.success)
        << name << ": internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure)
        << ". The oracle extracts this fixture successfully.";
    EXPECT_TRUE(result.size.has_value())
        << name << ": a successful extraction must report a size";
    EXPECT_FALSE(result.extractor.empty())
        << name << ": the extractor name is emitted in the --log JSON";

    const auto files = files_under(output_root);
    ASSERT_FALSE(files.empty())
        << name << ": extraction reported success but wrote nothing under "
        << output_root.string();

    bool matched = false;
    for(const auto& file : files) {
        const auto contents = read_whole(file);
        if(static_cast<std::uint64_t>(contents.size()) != expected_output_size) {
            continue;
        }
        matched = true;
        if(expected_content != nullptr) {
            EXPECT_EQ(contents, *expected_content)
                << name << ": extracted CONTENT is strict under section 5; the "
                << "decompressed bytes are not what the oracle produced";
        }
        break;
    }
    EXPECT_TRUE(matched)
        << name << ": no extracted file is " << expected_output_size
        << " bytes, which is what the oracle's decompression produced. Files "
        << "written:" << describe(files);
}

}

TEST(B1CompressionDryRun, ValidStreamsDryRunSuccessfullyWithASize) {
    struct entry {
        const char* name;
        const char* fixture;
        bool available;
    };
    const std::vector<entry> entries{
        {"gzip", "gzip_whole.bin", zlib_family_available()},
        {"xz", "xz.bin", binwalk::codec_available(binwalk::codec_id::xz)},
        {"lzma", "lzma.bin", binwalk::codec_available(binwalk::codec_id::lzma_alone)},
        {"bzip2", "bzip2.bin", binwalk::codec_available(binwalk::codec_id::bzip2)},
        {"gpg_signed", "gpg_signed.bin", zlib_family_available()}
    };

    for(const auto& value : entries) {
        if(!value.available) {
            continue;
        }
        const auto data = read_fixture(value.fixture);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic();

        const auto* definition = signature_named(value.name);
        ASSERT_NE(definition, nullptr) << value.name;
        ASSERT_TRUE(definition->extractor_definition.has_value()) << value.name;

        const auto signature = scanned_result(value.name, data);
        ASSERT_TRUE(signature.has_value()) << value.name;

        const auto result = binwalk::dry_run_extractor(
            *definition->extractor_definition, view(data), *signature
        );
        EXPECT_TRUE(result.success)
            << value.name << ": a dry run of a stream the oracle extracts "
            << "successfully must succeed; failure code "
            << static_cast<int>(result.failure);
        EXPECT_TRUE(result.size.has_value())
            << value.name << ": section 1 rule 2 -- a successful dry run carries "
            << "the true size, and parsers rely on it";
        EXPECT_TRUE(result.output_directory.empty())
            << value.name << ": a dry run must not name an output directory";
    }
}

TEST(B1CompressionDryRun, CorruptStreamsDoNotDryRunSuccessfully) {
    struct entry {
        const char* name;
        const char* fixture;
        std::size_t flip_first;
        std::size_t flip_last;
        bool available;
    };
    const std::vector<entry> entries{
        {"bzip2", "bzip2.bin", 12, 40, binwalk::codec_available(binwalk::codec_id::bzip2)},
        {"lzma", "lzma.bin", 13, 60, binwalk::codec_available(binwalk::codec_id::lzma_alone)},
        {"xz", "xz.bin", 14, 60, binwalk::codec_available(binwalk::codec_id::xz)}
    };

    for(const auto& value : entries) {
        const auto data = read_fixture(value.fixture);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic();
        const auto broken = flipped(data, value.flip_first, value.flip_last);

        const auto* definition = signature_named(value.name);
        ASSERT_NE(definition, nullptr) << value.name;
        ASSERT_TRUE(definition->extractor_definition.has_value()) << value.name;

        const auto result = binwalk::dry_run_extractor(
            *definition->extractor_definition,
            view(broken),
            whole_buffer_result(value.name, broken)
        );
        EXPECT_FALSE(result.success)
            << value.name << ": a dry run that accepts a destroyed compressed "
            << "body is not validating anything, and the parser that relies on "
            << "it would report a false positive";
        if(value.available) {

            EXPECT_NE(result.failure, binwalk::extraction_failure::unsupported)
                << value.name << ": the codec is built in, so a corrupt stream "
                << "must not be reported as unsupported";
        }
    }
}

TEST(B1CompressionDryRun, ExternalDefinitionsCannotBeDryRun) {

    for(const char* name : {"zstd", "lz4", "lzop", "lzfse", "compressd"}) {
        const auto* definition = signature_named(name);
        ASSERT_NE(definition, nullptr) << name;
        ASSERT_TRUE(definition->extractor_definition.has_value()) << name;

        const std::vector<std::uint8_t> data(64, 0x00);
        const auto result = binwalk::dry_run_extractor(
            *definition->extractor_definition, view(data), whole_buffer_result(name, data)
        );
        EXPECT_FALSE(result.success) << name;
        EXPECT_EQ(result.failure, binwalk::extraction_failure::unsupported)
            << name << ": a dry run of an external extractor is `unsupported`, "
            << "not a data error";
    }
}

TEST_F(b1_extraction_test, ZlibExtractionWritesTheExactDecompressedBytes) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the zlib/deflate codecs are compiled out of this build";
    }

    const auto data = zlib_stream(0x78, 0xDA);
    const auto payload = zlib_payload();
    ASSERT_EQ(payload.size(), std::size_t{288});
    expect_internal_extraction(root_, "zlib", data, 288, &payload);
}

TEST_F(b1_extraction_test, GzipExtractionProducesTheOracleOutputLength) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the gzip/deflate codecs are compiled out of this build";
    }
    const auto data = read_fixture("gzip_whole.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_internal_extraction(root_, "gzip", data, 512, nullptr);
}

TEST_F(b1_extraction_test, XzExtractionProducesTheOracleOutputLength) {
    if(!binwalk::codec_available(binwalk::codec_id::xz)) {

        GTEST_SKIP() << "the xz codec is compiled out of this build";
    }
    const auto data = read_fixture("xz.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_internal_extraction(root_, "xz", data, 4096, nullptr);
}

TEST_F(b1_extraction_test, LzmaExtractionProducesTheOracleOutputLength) {
    if(!binwalk::codec_available(binwalk::codec_id::lzma_alone)) {

        GTEST_SKIP() << "the lzma_alone codec is compiled out of this build";
    }
    const auto data = read_fixture("lzma.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_internal_extraction(root_, "lzma", data, 4096, nullptr);
}

TEST_F(b1_extraction_test, Bzip2ExtractionProducesTheOracleOutputLength) {
    if(!binwalk::codec_available(binwalk::codec_id::bzip2)) {

        GTEST_SKIP() << "the bzip2 codec is compiled out of this build";
    }
    const auto data = read_fixture("bzip2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_internal_extraction(root_, "bzip2", data, 8192, nullptr);
}

TEST_F(b1_extraction_test, GpgSignedExtractionProducesTheOracleOutputLength) {
    if(!zlib_family_available()) {

        GTEST_SKIP() << "the deflate codec is compiled out of this build";
    }
    const auto data = read_fixture("gpg_signed.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    expect_internal_extraction(root_, "gpg_signed", data, 1024, nullptr);
}

TEST_F(b1_extraction_test, FailedInternalExtractionWritesNothingUsable) {
    if(!binwalk::codec_available(binwalk::codec_id::bzip2)) {

        GTEST_SKIP() << "the bzip2 codec is compiled out of this build";
    }
    const auto data = read_fixture("bzip2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    const auto broken = flipped(data, 12, 40);

    const auto* definition = signature_named("bzip2");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());

    const auto output_root = root_ / "bzip2_broken";
    const auto result = binwalk::execute_extractor(
        view(broken), "bzip2.bin", whole_buffer_result("bzip2", broken),
        *definition->extractor_definition, output_root.string()
    );
    EXPECT_FALSE(result.success)
        << "extracting a destroyed bzip2 stream must not report success";
    EXPECT_NE(result.failure, binwalk::extraction_failure::unsupported)
        << "the bzip2 codec is built in, so this is a data failure";
}

namespace {

void run_external_extraction(
    const std::filesystem::path& root, const std::string& name, const char* fixture
) {
    const auto* definition = signature_named(name);
    ASSERT_NE(definition, nullptr) << name;
    ASSERT_TRUE(definition->extractor_definition.has_value()) << name;

    const auto data = read_fixture(fixture);
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();

    const auto signature = scanned_result(name, data);
    ASSERT_TRUE(signature.has_value())
        << name << ": detection must work before extraction can be tested";

    const auto output_root = root / name;
    const auto result = binwalk::execute_extractor(
        view(data), name + ".bin", *signature, *definition->extractor_definition,
        output_root.string()
    );

    EXPECT_NE(result.failure, binwalk::extraction_failure::utility_not_found)
        << name << ": the utility was reported as present, then not found";
    EXPECT_TRUE(result.success)
        << name << ": the external utility is installed and the fixture is one "
        << "the oracle detects, so extraction is expected to succeed; failure "
        << "code " << static_cast<int>(result.failure) << ". Files written:"
        << describe(files_under(output_root));
}

}

TEST_F(b1_extraction_test, ZstdExternalExtraction) {
    const auto* definition = signature_named("zstd");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());
    if(!binwalk::external_utility_available(*definition->extractor_definition)) {

        GTEST_SKIP() << "the external utility `zstd` is not installed";
    }
    run_external_extraction(root_, "zstd", "zstd.bin");
}

TEST_F(b1_extraction_test, Lz4ExternalExtraction) {
    const auto* definition = signature_named("lz4");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());
    if(!binwalk::external_utility_available(*definition->extractor_definition)) {

        GTEST_SKIP() << "the external utility `lz4` is not installed";
    }
    run_external_extraction(root_, "lz4", "lz4.bin");
}

TEST_F(b1_extraction_test, LzopExternalExtraction) {
    const auto* definition = signature_named("lzop");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());
    if(!binwalk::external_utility_available(*definition->extractor_definition)) {

        GTEST_SKIP() << "the external utility `lzop` is not installed";
    }
    run_external_extraction(root_, "lzop", "lzop.bin");
}

TEST_F(b1_extraction_test, LzfseExternalExtraction) {
    const auto* definition = signature_named("lzfse");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());
    if(!binwalk::external_utility_available(*definition->extractor_definition)) {

        GTEST_SKIP() << "the external utility `lzfse` is not installed";
    }
    run_external_extraction(root_, "lzfse", "lzfse.bin");
}

TEST_F(b1_extraction_test, CompressdExternalExtractionUsesSevenZip) {
    const auto* definition = signature_named("compressd");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());
    if(!binwalk::external_utility_available(*definition->extractor_definition)) {

        GTEST_SKIP() << "the external utility `7zz` is not installed";
    }

    const auto data = read_fixture("compressd.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic();
    const auto signature = scanned_result("compressd", data);
    ASSERT_TRUE(signature.has_value());

    const auto output_root = root_ / "compressd";
    const auto result = binwalk::execute_extractor(
        view(data), "compressd.bin", *signature, *definition->extractor_definition,
        output_root.string()
    );
    EXPECT_NE(result.failure, binwalk::extraction_failure::utility_not_found)
        << "7zz was reported as present, then not found when spawned";
}
