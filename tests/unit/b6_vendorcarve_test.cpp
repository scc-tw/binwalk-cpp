
#include "../../lib/src/formats/b6_vendorcarve.hpp"

#include <binwalk/builtin.hpp>
#include <binwalk/byte_view.hpp>
#include <binwalk/codec.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>
#include <binwalk/scanner.hpp>
#include <binwalk/signature.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
namespace {

using bytes = std::vector<std::uint8_t>;

const std::vector<binwalk::signature>& batch() {
    static const std::vector<binwalk::signature> value =
        binwalk::formats::b6_vendorcarve_signatures();
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

const std::array<const char*, 9>& batch_names() {
    static const std::array<const char*, 9> names{
        "trx", "jboot_arm", "jboot_stag", "jboot_sch2", "wince",
        "dahua_zip", "mh01", "csman", "dlke"
    };
    return names;
}

enum class tier { low, medium, high };

void expect_tier(std::uint8_t confidence, tier expected, const std::string& what) {
    switch(expected) {
    case tier::low:
        EXPECT_LT(confidence, binwalk::confidence_medium)
            << what << ": the oracle reports this in the LOW tier. Above medium "
            << "the scanner would skip past the result and hide anything inside it.";
        break;
    case tier::medium:
        EXPECT_GE(confidence, binwalk::confidence_medium) << what << ": oracle tier is MEDIUM";
        EXPECT_LT(confidence, binwalk::confidence_high) << what << ": oracle tier is MEDIUM, not HIGH";
        break;
    case tier::high:
        EXPECT_GE(confidence, binwalk::confidence_high) << what << ": oracle tier is HIGH";
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
                std::error_code probe;
                if(std::filesystem::exists(candidate / "trx.bin", probe)) {
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

std::string fixture_diagnostic(const std::string& name) {
    return "fixture \"" + name + "\" could not be read. tests/fixtures is committed, so "
        "this is a broken checkout rather than a reason to skip. Directories tried:\n"
        + fixtures().searched;
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

binwalk::byte_view view(const bytes& data) {
    return binwalk::byte_view(data.data(), data.size());
}

bytes truncated(const bytes& data, std::size_t length) {
    if(length >= data.size()) {
        return data;
    }
    return bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(length));
}

bytes poked(const bytes& data, std::size_t offset, std::uint8_t value) {
    bytes out = data;
    if(offset < out.size()) {
        out[offset] = value;
    }
    return out;
}

bytes poked_range(const bytes& data, std::size_t offset, std::size_t count, std::uint8_t value) {
    bytes out = data;
    for(std::size_t index = 0; index < count && offset + index < out.size(); ++index) {
        out[offset + index] = value;
    }
    return out;
}

bytes flipped_byte(const bytes& data, std::size_t offset) {
    bytes out = data;
    if(offset < out.size()) {
        out[offset] = static_cast<std::uint8_t>(out[offset] ^ 0xFFU);
    }
    return out;
}

bytes with_u32_le(const bytes& data, std::size_t offset, std::uint32_t value) {
    bytes out = data;
    for(std::size_t index = 0; index < 4U && offset + index < out.size(); ++index) {
        out[offset + index] =
            static_cast<std::uint8_t>((value >> (static_cast<unsigned>(index) * 8U)) & 0xFFU);
    }
    return out;
}

bytes with_u16_le(const bytes& data, std::size_t offset, std::uint16_t value) {
    bytes out = data;
    if(offset + 1U < out.size()) {
        out[offset] = static_cast<std::uint8_t>(value & 0xFFU);
        out[offset + 1U] = static_cast<std::uint8_t>((static_cast<unsigned>(value) >> 8U) & 0xFFU);
    }
    return out;
}

bytes trx_with_recomputed_crc(const bytes& data) {
    bytes out = data;
    if(out.size() < 12U) {
        return out;
    }
    const std::uint32_t total_size =
        static_cast<std::uint32_t>(out[4])
        | (static_cast<std::uint32_t>(out[5]) << 8U)
        | (static_cast<std::uint32_t>(out[6]) << 16U)
        | (static_cast<std::uint32_t>(out[7]) << 24U);
    if(total_size <= 12U || static_cast<std::size_t>(total_size) > out.size()) {
        return out;
    }
    const auto region = binwalk::byte_view(
        out.data() + 12, static_cast<std::size_t>(total_size) - 12U
    );
    const std::uint32_t checksum = binwalk::crc32(region) ^ 0xFFFFFFFFU;
    return with_u32_le(out, 8, checksum);
}

std::optional<binwalk::signature_result> parse_at(
    const std::string& name, const bytes& data, std::size_t offset
) {
    const auto* definition = signature_named(name);
    if(definition == nullptr || definition->parser == nullptr) {
        return std::nullopt;
    }
    return definition->parser(view(data), offset);
}

void expect_rejected(
    const std::string& name, const bytes& data, std::size_t offset, std::string_view why
) {
    SCOPED_TRACE(name + " @ " + std::to_string(offset) + ": " + std::string(why));
    const auto* definition = signature_named(name);
    ASSERT_NE(definition, nullptr) << name << " is not registered by b6_vendorcarve_signatures()";
    ASSERT_NE(definition->parser, nullptr) << name << " has a null parser";

    const auto result = definition->parser(view(data), offset);
    EXPECT_FALSE(result.has_value())
        << name << " accepted a buffer the oracle REJECTS (" << why << "). A required "
        << "rejection is exactly as strict as a required detection (policy).";
    if(result.has_value()) {
        ADD_FAILURE() << "  ... it reported offset " << result->offset
                      << " size " << result->size << ": " << result->description;
    }
}

const binwalk::scanner& batch_scanner() {
    static const binwalk::scanner value(binwalk::formats::b6_vendorcarve_signatures());
    return value;
}

std::vector<binwalk::signature_result> scan_batch(const bytes& data) {
    return batch_scanner().scan(view(data));
}

std::vector<binwalk::signature_result> scan_including(
    const std::string& name, const bytes& data
) {
    binwalk::scan_options options;
    options.include = {name};
    const binwalk::scanner scanner(binwalk::formats::b6_vendorcarve_signatures(), options);
    return scanner.scan(view(data));
}

std::optional<binwalk::signature_result> scanned_result(
    const std::string& name, const bytes& data
) {
    const auto results = scan_including(name, data);
    if(results.size() != 1U) {
        return std::nullopt;
    }
    return results.front();
}

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) {
        return static_cast<char>(
            character >= 'A' && character <= 'Z'
                ? static_cast<unsigned char>(character - 'A' + 'a')
                : character
        );
    });
    return text;
}

void expect_description_mentions(
    const std::string& description,
    std::initializer_list<const char*> facts,
    const std::string& what
) {
    EXPECT_FALSE(description.empty()) << what << ": the description must be informative";
    const std::string haystack = lowered(description);
    for(const char* fact : facts) {
        EXPECT_NE(haystack.find(lowered(std::string(fact))), std::string::npos)
            << what << ": the description omits the substantive fact \"" << fact
            << "\". Wording is FREE under section 5; the FACTS are not.\n  got: " << description;
    }
}

void expect_offset_in_bounds(
    const std::optional<binwalk::signature_result>& result,
    std::size_t buffer_size,
    const std::string& what
) {
    if(!result.has_value()) {
        return;
    }
    EXPECT_LE(result->offset, static_cast<std::uint64_t>(buffer_size))
        << what << ": reported an offset past the end of the buffer";
}

void expect_in_bounds(
    const std::optional<binwalk::signature_result>& result,
    std::size_t buffer_size,
    const std::string& what
) {
    if(!result.has_value()) {
        return;
    }
    expect_offset_in_bounds(result, buffer_size, what);
    if(result->offset <= static_cast<std::uint64_t>(buffer_size)) {
        EXPECT_LE(result->size, static_cast<std::uint64_t>(buffer_size) - result->offset)
            << what << ": carving this result would read past the end of the buffer";
    }
}

void expect_every_scanner_result_fits(
    const std::vector<binwalk::signature_result>& results,
    std::size_t buffer_size,
    const std::string& what
) {
    for(const auto& result : results) {
        EXPECT_LE(result.offset, static_cast<std::uint64_t>(buffer_size))
            << what << ": " << result.name << " survived the scanner with an offset past EOF";
        if(result.offset <= static_cast<std::uint64_t>(buffer_size)) {
            EXPECT_LE(result.size, static_cast<std::uint64_t>(buffer_size) - result.offset)
                << what << ": " << result.name << " survived the scanner with a size that "
                << "runs past EOF. scanner::scan must drop a result that does not fit, the "
                << "way upstream binwalk.rs does; a caller carving this reads out of bounds.";
        }
    }
}

bool zlib_backend_available() {
#if defined(BINWALK_TEST_HAS_ZLIB)
    return binwalk::codec_available(binwalk::codec_id::deflate)
        && binwalk::codec_available(binwalk::codec_id::zlib_stream);
#else
    return false;
#endif
}

const char* zlib_skip_reason() {
    return "BINWALK_WITH_ZLIB is OFF, so csman's compressed storage mode has no "
           "validator and this assertion would be vacuous. Policy "
           "requires this build to configure; policy rule 4 requires "
           "the resulting hole to be a visible SKIP rather than a silent pass.";
}

struct fixture_row {
    const char* signature;
    const char* file;
    std::size_t parse_offset;
    std::uint64_t offset;
    std::uint64_t size;
    tier confidence;
};

const std::array<fixture_row, 13>& fixture_table() {
    static const std::array<fixture_row, 13> rows{{
        {"trx",        "trx.bin",              0,  0, 128, tier::high},
        {"trx",        "trx_v1.bin",           0,  0,  96, tier::high},
        {"jboot_arm",  "jboot_arm.bin",       48,  0,  80, tier::medium},
        {"jboot_stag", "jboot_stag.bin",       0,  0,  16, tier::low},
        {"jboot_stag", "jboot_stag_factory.bin", 0, 0, 16, tier::low},
        {"jboot_sch2", "jboot_sch2.bin",       0,  0, 136, tier::high},
        {"wince",      "wince.bin",            0,  0, 123, tier::high},
        {"dahua_zip",  "dahua_zip.bin",        0,  0, 113, tier::high},
        {"mh01",       "mh01.bin",             0,  0, 192, tier::high},
        {"dlke",       "dlke.bin",             0,  0, 256, tier::high},
        {"csman",      "csman_stored.bin",     0,  0,  30, tier::high},
        {"csman",      "csman_be_stored.bin",  0,  0,  30, tier::high},
        {"csman",      "csman_dupkeys.bin",    0,  0,  50, tier::high}
    }};
    return rows;
}

const std::array<fixture_row, 2>& compressed_csman_table() {
    static const std::array<fixture_row, 2> rows{{
        {"csman", "csman.bin",    0, 0, 41, tier::high},
        {"csman", "csman_be.bin", 0, 0, 41, tier::high}
    }};
    return rows;
}

class b6_extraction_test : public ::testing::Test {
protected:
    void SetUp() override {
        std::error_code error;
        auto base = std::filesystem::temp_directory_path(error);
        if(error) {
            base = std::filesystem::path(".");
        }
        std::string name = "binwalk_b6_vendorcarve_";
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
        std::error_code probe;
        if(iterator->is_regular_file(probe)) {
            found.push_back(iterator->path());
        }
    }
    std::sort(found.begin(), found.end());
    return found;
}

std::map<std::string, bytes> extracted_by_name(const std::filesystem::path& directory) {
    std::map<std::string, bytes> found;
    for(const auto& path : files_under(directory)) {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if(error) {
            continue;
        }
        bytes buffer(static_cast<std::size_t>(size));
        std::ifstream stream(path, std::ios::binary);
        if(!stream) {
            continue;
        }
        if(!buffer.empty()) {
            stream.read(
                reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size())
            );
        }
        found[path.filename().string()] = buffer;
    }
    return found;
}

std::string describe(const std::map<std::string, bytes>& files) {
    std::string text;
    for(const auto& entry : files) {
        text += "\n    " + entry.first + " (" + std::to_string(entry.second.size()) + " bytes)";
    }
    return text.empty() ? "\n    <no files written>" : text;
}

bytes slice(const bytes& data, std::size_t offset, std::size_t length) {
    if(offset > data.size() || length > data.size() - offset) {
        return {};
    }
    return bytes(
        data.begin() + static_cast<std::ptrdiff_t>(offset),
        data.begin() + static_cast<std::ptrdiff_t>(offset + length)
    );
}

struct expected_file {
    const char* name;
    bytes content;
};

void expect_extraction(
    const std::filesystem::path& root,
    const std::string& signature_name,
    const bytes& data,
    const std::vector<expected_file>& expected
) {
    SCOPED_TRACE("extraction of " + signature_name);
    const auto* definition = signature_named(signature_name);
    ASSERT_NE(definition, nullptr) << signature_name << " is not registered";
    ASSERT_TRUE(definition->extractor_definition.has_value())
        << signature_name << " declares no extractor; upstream magic.rs gives it one";

    const auto signature = scanned_result(signature_name, data);
    ASSERT_TRUE(signature.has_value())
        << signature_name << ": the scan that feeds the extractor did not produce exactly "
        << "one result";

    const auto output_root = root / signature_name;
    const auto result = binwalk::execute_extractor(
        view(data), signature_name + ".bin", *signature,
        *definition->extractor_definition, output_root.string()
    );

    ASSERT_TRUE(result.success)
        << signature_name << ": internal extraction failed with extraction_failure "
        << static_cast<int>(result.failure) << ". The oracle extracts this fixture.";

    const auto produced = extracted_by_name(output_root);

    std::set<std::string> expected_names;
    for(const auto& entry : expected) {
        expected_names.insert(entry.name);
    }
    std::set<std::string> produced_names;
    for(const auto& entry : produced) {
        produced_names.insert(entry.first);
    }
    EXPECT_EQ(produced_names, expected_names)
        << signature_name << ": the extracted file set differs from the oracle's."
        << describe(produced);

    for(const auto& entry : expected) {
        const auto found = produced.find(entry.name);
        if(found == produced.end()) {
            ADD_FAILURE() << signature_name << ": expected file \"" << entry.name
                          << "\" was not written." << describe(produced);
            continue;
        }
        EXPECT_EQ(found->second.size(), entry.content.size())
            << signature_name << "/" << entry.name << ": wrong size";
        EXPECT_EQ(found->second, entry.content)
            << signature_name << "/" << entry.name << ": extracted BYTES differ from the "
            << "oracle's. Extracted content is STRICT under section 5 even though the file "
            << "NAME is free.";
    }
}

std::size_t working_directory_entry_count() {
    std::error_code error;
    const auto here = std::filesystem::current_path(error);
    if(error) {
        return 0;
    }
    std::size_t count = 0;
    for(std::filesystem::directory_iterator iterator(here, error), end;
        !error && iterator != end;
        iterator.increment(error)) {
        ++count;
    }
    return count;
}

}

TEST(B6VendorcarveRegistry, RegistersExactlyTheNineUpstreamNames) {
    std::set<std::string> produced;
    for(const auto& value : batch()) {
        EXPECT_TRUE(produced.insert(value.name).second)
            << "b6_vendorcarve registers \"" << value.name << "\" more than once";
    }
    for(const char* name : batch_names()) {
        EXPECT_EQ(produced.count(name), std::size_t{1})
            << "b6_vendorcarve does not register \"" << name << "\". Upstream src/magic.rs "
            << "registers it, so the format would silently not exist.";
    }
    EXPECT_EQ(produced.size(), batch_names().size())
        << "b6_vendorcarve registers a name outside its own nine; another batch owns it "
        << "and it would be a duplicate registration";
    EXPECT_EQ(batch().size(), std::size_t{9});
}

TEST(B6VendorcarveRegistry, EveryNameIsInTheFrozenUpstreamOrderTable) {
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
            upstream_order.begin(), upstream_order.end(),
            [&value](const char* entry) { return value.name == entry; }
        );
        EXPECT_NE(found, upstream_order.end())
            << "b6_vendorcarve produced signature name \"" << value.name << "\", which is "
            << "NOT in upstream magic.rs's 111-entry order table. builtin.cpp would sort it "
            << "to the end of the registry and it would vanish from --include/--exclude. "
            << "Fix the name in the batch; the table is frozen.";
    }

    for(const char* name : batch_names()) {
        EXPECT_NE(
            std::find_if(
                upstream_order.begin(), upstream_order.end(),
                [name](const char* entry) { return std::string(name) == entry; }
            ),
            upstream_order.end()
        ) << "this test file's spelling of \"" << name << "\" is not in the frozen table";
    }
}

TEST(B6VendorcarveRegistry, EveryNameReachesTheAggregatedRegistry) {
    const auto registry = binwalk::builtin_signatures();
    for(const char* name : batch_names()) {
        const auto found = std::find_if(
            registry.begin(), registry.end(),
            [name](const binwalk::signature& value) { return value.name == name; }
        );
        EXPECT_NE(found, registry.end())
            << "\"" << name << "\" is produced by b6_vendorcarve_signatures() but does not "
            << "appear in binwalk::builtin_signatures(); the aggregator dropped it";
    }
}

TEST(B6VendorcarveRegistry, FlagsAndMagicCountsMatchUpstreamMagicRs) {
    struct registry_fact {
        const char* name;
        bool short_signature;
        std::size_t magic_offset;
        bool always_display;
        std::size_t magic_count;
    };
    static const std::array<registry_fact, 9> facts{{

        {"trx",          false, 0,            false,          1},
        {"jboot_arm",    false, 0,            false,          1},
        {"jboot_stag",   false, 0,            false,          2},
        {"jboot_sch2",   false, 0,            false,          4},
        {"wince",        false, 0,            false,          1},
        {"dahua_zip",    false, 0,            false,          1},
        {"mh01",         false, 0,            false,          1},
        {"csman",        true,  0,            false,          2},
        {"dlke",         false, 0,            false,          2}
    }};

    std::size_t total_patterns = 0;
    for(const auto& fact : facts) {
        SCOPED_TRACE(fact.name);
        const auto* value = signature_named(fact.name);
        ASSERT_NE(value, nullptr) << fact.name << " is not registered";

        EXPECT_EQ(value->short_signature, fact.short_signature)
            << fact.name << ": `short` decides whether the signature is matched only at the "
            << "start of the file; upstream magic.rs says "
            << (fact.short_signature ? "true" : "false");
        EXPECT_EQ(value->magic_offset, fact.magic_offset) << fact.name;
        EXPECT_EQ(value->always_display, fact.always_display) << fact.name;
        EXPECT_EQ(value->magic.size(), fact.magic_count)
            << fact.name << ": wrong number of magic patterns. A missing pattern is a format "
            << "variant that is never detected.";
        for(const auto& pattern : value->magic) {
            EXPECT_FALSE(pattern.empty())
                << fact.name << " has an empty magic pattern, which would match at every "
                << "offset in every file";
        }
        total_patterns += value->magic.size();
    }
    EXPECT_EQ(total_patterns, std::size_t{15})
        << "this batch owns 15 magic patterns across its nine signatures";
}

TEST(B6VendorcarveRegistry, MagicPatternsMatchUpstreamByteForByte) {
    struct expectation {
        const char* name;
        std::vector<bytes> magic;
    };

    const std::vector<expectation> expectations{
        {"trx", {{'H', 'D', 'R', '0'}}},

        {"jboot_arm", {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0x48}}},
        {"jboot_stag", {{0x04, 0x04, 0x24, 0x2B}, {0xFF, 0x04, 0x24, 0x2B}}},
        {"jboot_sch2", {{0x24, 0x21, 0x00, 0x02}, {0x24, 0x21, 0x01, 0x02},
                        {0x24, 0x21, 0x02, 0x02}, {0x24, 0x21, 0x03, 0x02}}},
        {"wince", {{'B', '0', '0', '0', 'F', 'F', '\n'}}},
        {"dahua_zip", {{'D', 'H', 0x03, 0x04}}},
        {"mh01", {{'M', 'H', '0', '1'}}},
        {"csman", {{'S', 'C'}, {'C', 'S'}}},
        {"dlke", {{'D', 'L', 'K', '6', 'E', '8', '2', '0', '2', '0', '0', '1'},
                  {'D', 'L', 'K', '6', 'E', '6', '1', '1', '0', '0', '0', '2'}}}
    };

    for(const auto& expected : expectations) {
        const auto* value = signature_named(expected.name);
        ASSERT_NE(value, nullptr) << expected.name;
        const std::set<bytes> produced(value->magic.begin(), value->magic.end());
        const std::set<bytes> wanted(expected.magic.begin(), expected.magic.end());
        EXPECT_EQ(produced, wanted)
            << expected.name << ": magic byte patterns differ from upstream. A wrong pattern "
            << "means the format is either never found or found at the wrong offsets.";
    }
}

TEST(B6VendorcarveRegistry, NoMagicPatternIsAPrefixOfAnotherSignaturesPattern) {
    struct owned_pattern {
        std::string owner;
        bytes pattern;
    };
    std::vector<owned_pattern> all;
    for(const auto& value : batch()) {
        for(const auto& pattern : value.magic) {
            all.push_back({value.name, pattern});
        }
    }
    ASSERT_EQ(all.size(), std::size_t{15});

    for(std::size_t left = 0; left < all.size(); ++left) {
        for(std::size_t right = 0; right < all.size(); ++right) {
            if(left == right || all[left].owner == all[right].owner) {
                continue;
            }
            const auto& shorter = all[left].pattern;
            const auto& longer = all[right].pattern;
            if(shorter.size() > longer.size()) {
                continue;
            }
            const bool is_prefix =
                std::equal(shorter.begin(), shorter.end(), longer.begin());
            EXPECT_FALSE(is_prefix)
                << "the magic of \"" << all[left].owner << "\" is a prefix of a magic of \""
                << all[right].owner << "\". They can now match at the SAME offset, so the "
                << "equal-confidence arm of the scanner's overlap filter has become "
                << "reachable inside this batch and needs a tie-break test measured against "
                << "the oracle (policy).";
        }
    }
}

TEST(B6VendorcarveExtractors, TheSevenDeclaredExtractorsAreInternalAndCallable) {
    for(const char* name : {"trx", "jboot_sch2", "wince", "dahua_zip", "mh01", "csman", "dlke"}) {
        SCOPED_TRACE(name);
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name << " is not registered";
        ASSERT_TRUE(value->extractor_definition.has_value())
            << name << " declares NO extractor. Upstream magic.rs gives it one; without it "
            << "the format is detected and then never extracted.";

        const auto& definition = *value->extractor_definition;
        EXPECT_EQ(definition.type, binwalk::extractor_type::internal) << name;
        EXPECT_NE(definition.internal, nullptr)
            << name << ": an internal extractor with a null function pointer cannot dry-run, "
            << "so a parser that uses a dry run as its validator has no validator "
            << "(policy rule 3)";
        EXPECT_TRUE(definition.command.empty())
            << name << " is internal and must not name an external command";
        EXPECT_FALSE(definition.name.empty())
            << name << ": the extractor name is emitted in the --log JSON";
    }
}

TEST(B6VendorcarveExtractors, JbootArmAndJbootStagDeclareNoExtractor) {

    for(const char* name : {"jboot_arm", "jboot_stag"}) {
        const auto* value = signature_named(name);
        ASSERT_NE(value, nullptr) << name;
        if(value->extractor_definition.has_value()) {
            EXPECT_EQ(value->extractor_definition->type, binwalk::extractor_type::none)
                << name << " declares an extractor; upstream magic.rs gives it none";
        }
    }
}

TEST(B6VendorcarveDetection, EveryOracleValidatedFixtureParsesToItsMeasuredResult) {
    for(const auto& row : fixture_table()) {
        SCOPED_TRACE(std::string(row.signature) + " / " + row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto result = parse_at(row.signature, data, row.parse_offset);
        ASSERT_TRUE(result.has_value())
            << row.signature << " rejected " << row.file << ", which the oracle detects at "
            << "offset " << row.offset << " size " << row.size;

        EXPECT_EQ(result->offset, row.offset) << row.file << ": wrong offset";
        EXPECT_EQ(result->size, row.size)
            << row.file << ": wrong size. `size` drives carving bounds and the scanner's "
            << "skip-ahead, so a wrong size corrupts every downstream result.";
        expect_tier(result->confidence, row.confidence, row.file);
        EXPECT_FALSE(result->extraction_declined)
            << row.file << ": `extraction_declined` is STRICT under section 5 -- it decides "
            << "whether extraction is attempted at all";
        expect_in_bounds(result, data.size(), row.file);
    }
}

TEST(B6VendorcarveDetection, CompressedCsmanFixturesParseToTheirMeasuredResults) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    for(const auto& row : compressed_csman_table()) {
        SCOPED_TRACE(std::string(row.signature) + " / " + row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto result = parse_at(row.signature, data, row.parse_offset);
        ASSERT_TRUE(result.has_value())
            << row.signature << " rejected " << row.file << ", which the oracle detects at "
            << "offset " << row.offset << " size " << row.size;

        EXPECT_EQ(result->offset, row.offset) << row.file << ": wrong offset";
        EXPECT_EQ(result->size, row.size) << row.file << ": wrong size";
        expect_tier(result->confidence, row.confidence, row.file);
        EXPECT_FALSE(result->extraction_declined) << row.file;
        expect_in_bounds(result, data.size(), row.file);

        expect_description_mentions(result->description, {"41"}, row.file);
    }
}

TEST(B6VendorcarveDetection, CompressedCsmanCoversBothEndiannesses) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    struct expectation {
        const char* file;
        std::uint8_t magic0;
        std::uint8_t magic1;
    };
    const std::array<expectation, 2> expectations{{
        {"csman.bin",    'C', 'S'},
        {"csman_be.bin", 'S', 'C'}
    }};

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.file);
        const auto data = read_fixture(expected.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(expected.file);
        ASSERT_GE(data.size(), std::size_t{17});

        EXPECT_EQ(data[0], static_cast<std::uint8_t>(expected.magic0));
        EXPECT_EQ(data[1], static_cast<std::uint8_t>(expected.magic1));

        ASSERT_EQ(data[16], std::uint8_t{0x78})
            << expected.file << " is no longer a compressed fixture";

        const auto result = parse_at("csman", data, 0);
        ASSERT_TRUE(result.has_value()) << expected.file;
        EXPECT_EQ(result->offset, std::uint64_t{0});
        EXPECT_EQ(result->size, std::uint64_t{41});
        expect_tier(result->confidence, tier::high, expected.file);
    }
}

TEST(B6VendorcarveDetection, JbootArmRewindsFortyEightBytesFromItsMagic) {
    const auto data = read_fixture("jboot_arm.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("jboot_arm.bin");

    const auto* definition = signature_named("jboot_arm");
    ASSERT_NE(definition, nullptr);
    ASSERT_EQ(definition->magic.size(), std::size_t{1});
    const auto& magic = definition->magic.front();
    ASSERT_LE(magic.size(), data.size());
    ASSERT_LE(std::size_t{48} + magic.size(), data.size());
    EXPECT_TRUE(std::equal(magic.begin(), magic.end(), data.begin() + 48))
        << "jboot_arm.bin no longer carries this batch's jboot_arm magic at offset 48; "
        << "the rewind this test exercises would not be reachable";

    const auto result = parse_at("jboot_arm", data, 48);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0})
        << "the parser must report the START OF THE HEADER (0), not the offset the magic "
        << "matched at (48)";
    EXPECT_EQ(result->size, std::uint64_t{80});
}

TEST(B6VendorcarveDetection, DescriptionsCarryTheSubstantiveFactsTheOracleReports) {
    struct expectation {
        const char* signature;
        const char* file;
        std::size_t parse_offset;
        std::vector<const char*> facts;
    };

    const std::vector<expectation> expectations{
        {"trx", "trx.bin", 0, {"version 2", "partition count: 4", "32", "128"}},
        {"trx", "trx_v1.bin", 0, {"version 1", "partition count: 3", "28", "96"}},
        {"jboot_arm", "jboot_arm.bin", 48,
         {"ABCD12345678", "0x50000", "0x200000", "0x60000", "0x1000"}},
        {"jboot_stag", "jboot_stag.bin", 0, {"system upgrade"}},
        {"jboot_stag", "jboot_stag_factory.bin", 0, {"factory"}},
        {"jboot_sch2", "jboot_sch2.bin", 0, {"gzip", "0x80002000", "96"}},
        {"wince", "wince.bin", 0, {"0x1000", "123"}},
        {"dahua_zip", "dahua_zip.bin", 0, {"2.0", "113"}},
        {"mh01", "mh01.bin", 0,
         {"0xDEADBEEF01020304", "0123456789ABCDEF0123456789ABCDEF", "192"}},
        {"dlke", "dlke.bin", 0, {"32", "64"}},

        {"csman", "csman_dupkeys.bin", 0, {"50"}}
    };

    for(const auto& expected : expectations) {
        SCOPED_TRACE(std::string(expected.signature) + " / " + expected.file);
        const auto data = read_fixture(expected.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(expected.file);

        const auto result = parse_at(expected.signature, data, expected.parse_offset);
        ASSERT_TRUE(result.has_value()) << expected.file;

        std::string what = std::string(expected.signature) + " / " + expected.file;
        for(const char* fact : expected.facts) {
            EXPECT_NE(lowered(result->description).find(lowered(std::string(fact))),
                      std::string::npos)
                << what << ": the description omits the substantive fact \"" << fact
                << "\".\n  got: " << result->description;
        }
        EXPECT_FALSE(result->description.empty()) << what;
    }
}

TEST(B6VendorcarveDetection, JbootStagDistinguishesFactoryFromSystemUpgrade) {
    const auto upgrade = read_fixture("jboot_stag.bin");
    const auto factory = read_fixture("jboot_stag_factory.bin");
    ASSERT_FALSE(upgrade.empty()) << fixture_diagnostic("jboot_stag.bin");
    ASSERT_FALSE(factory.empty()) << fixture_diagnostic("jboot_stag_factory.bin");

    ASSERT_EQ(upgrade[0], std::uint8_t{0x04});
    ASSERT_EQ(upgrade[1], std::uint8_t{0x04});
    ASSERT_EQ(factory[0], std::uint8_t{0xFF});

    const auto upgrade_result = parse_at("jboot_stag", upgrade, 0);
    const auto factory_result = parse_at("jboot_stag", factory, 0);
    ASSERT_TRUE(upgrade_result.has_value());
    ASSERT_TRUE(factory_result.has_value());

    expect_description_mentions(
        upgrade_result->description, {"system upgrade"}, "jboot_stag.bin"
    );
    expect_description_mentions(
        factory_result->description, {"factory"}, "jboot_stag_factory.bin"
    );
    EXPECT_NE(upgrade_result->description, factory_result->description)
        << "a factory image and a system upgrade image must not describe identically";

    expect_tier(upgrade_result->confidence, tier::low, "jboot_stag.bin");
    expect_tier(factory_result->confidence, tier::low, "jboot_stag_factory.bin");
}

TEST(B6VendorcarveDetection, CsmanStoredCoversBothEndiannesses) {
    struct expectation {
        const char* file;
        std::uint64_t size;
        std::uint8_t magic0;
        std::uint8_t magic1;
    };
    const std::array<expectation, 2> expectations{{
        {"csman_stored.bin",    30, 'C', 'S'},
        {"csman_be_stored.bin", 30, 'S', 'C'}
    }};

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.file);
        const auto data = read_fixture(expected.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(expected.file);
        ASSERT_GE(data.size(), std::size_t{17});

        EXPECT_EQ(data[0], static_cast<std::uint8_t>(expected.magic0));
        EXPECT_EQ(data[1], static_cast<std::uint8_t>(expected.magic1));

        ASSERT_NE(data[16], std::uint8_t{0x78})
            << expected.file << " now looks compressed; it would need the zlib gate";

        const auto result = parse_at("csman", data, 0);
        ASSERT_TRUE(result.has_value()) << expected.file;
        EXPECT_EQ(result->offset, std::uint64_t{0});
        EXPECT_EQ(result->size, expected.size);
        expect_tier(result->confidence, tier::high, expected.file);
    }
}

TEST(B6VendorcarveRejections, TrxRejectsBadChecksumBadVersionAndTruncation) {
    const auto data = read_fixture("trx.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("trx.bin");

    expect_rejected("trx", flipped_byte(data, 8), 0, "image CRC corrupted");

    expect_rejected("trx", with_u16_le(data, 14, 3), 0, "version 3");
    expect_rejected("trx", with_u16_le(data, 14, 0), 0, "version 0");
    expect_rejected("trx", truncated(data, data.size() / 2U), 0, "truncated to half");
}

TEST(B6VendorcarveRejections, JbootArmRejectsEveryReservedAndSanityFieldViolation) {
    const auto data = read_fixture("jboot_arm.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("jboot_arm.bin");

    expect_rejected("jboot_arm", poked(data, 26, 2), 48, "lpvs != 1");
    expect_rejected("jboot_arm", poked(data, 27, 1), 48, "mbz != 0");
    expect_rejected("jboot_arm", poked(data, 66, 5), 48, "header_version > 4");
    expect_rejected("jboot_arm", poked(data, 20, 1), 48, "reserved2 != 0");
    expect_rejected("jboot_arm", poked(data, 24, 1), 48, "reserved3 != 0");
    expect_rejected("jboot_arm", poked(data, 68, 1), 48, "reserved8 != 0");
}

TEST(B6VendorcarveRejections, JbootArmRejectsItsMagicStandingAloneAtOffsetZero) {
    bytes magic_only(16, 0x00);
    magic_only.push_back(0x42);
    magic_only.push_back(0x48);
    ASSERT_EQ(magic_only.size(), std::size_t{18});

    expect_rejected("jboot_arm", magic_only, 0, "magic at offset 0, nothing to rewind into");

    bytes padded = magic_only;
    padded.insert(padded.end(), 256U, 0xA5);
    expect_rejected("jboot_arm", padded, 0, "magic at offset 0 followed by 256 bytes");
}

TEST(B6VendorcarveRejections, JbootStagRejectsACmarkThatIsNeitherFactoryNorTheId) {
    const auto data = read_fixture("jboot_stag.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("jboot_stag.bin");
    ASSERT_EQ(data[1], std::uint8_t{0x04});

    expect_rejected("jboot_stag", poked(data, 0, 0x05), 0, "cmark neither 0xFF nor id");
}

TEST(B6VendorcarveRejections, JbootSch2RejectsBadVersionSizeAndEitherChecksum) {
    const auto data = read_fixture("jboot_sch2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("jboot_sch2.bin");

    expect_rejected("jboot_sch2", poked(data, 3, 3), 0, "version != 2");

    expect_rejected("jboot_sch2", poked(data, 36, 41), 0, "declared header_size != 40");

    expect_rejected("jboot_sch2", flipped_byte(data, 32), 0, "header CRC corrupted");
    expect_rejected("jboot_sch2", flipped_byte(data, 12), 0, "kernel CRC corrupted");
    expect_rejected("jboot_sch2", truncated(data, 40), 0, "header only, no kernel");
}

TEST(B6VendorcarveRejections, WinceRejectsTooFewBlocksAndAHeaderWithNoBlocks) {
    const auto data = read_fixture("wince.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("wince.bin");

    expect_rejected("wince", truncated(data, 15U + 5U * 16U), 0, "five blocks, no terminator");
    expect_rejected("wince", truncated(data, 15), 0, "header only, no blocks");
}

TEST(B6VendorcarveRejections, DahuaZipRejectsBadCompressionAndReservedFlagBits) {
    const auto data = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dahua_zip.bin");

    expect_rejected("dahua_zip", poked_range(data, 8, 2, 0xFF), 0, "unknown compression method");
    bytes reserved_flags = poked(data, 6, 0x80);
    reserved_flags = poked(reserved_flags, 7, 0xD7);
    expect_rejected("dahua_zip", reserved_flags, 0, "reserved general-purpose flag bits set");
}

TEST(B6VendorcarveRejections, Mh01RejectsSecondMagicIvAndSaltViolations) {
    const auto data = read_fixture("mh01.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("mh01.bin");

    expect_rejected("mh01", poked(data, 16, 0x58), 0, "second magic is not MH01");

    expect_rejected("mh01", poked(data, 40, 0x00), 0, "NUL inside the IV string");

    expect_rejected("mh01", poked_range(data, 72, 8, 0x00), 0, "salt is all zero");
    expect_rejected("mh01", poked_range(data, 72, 8, 0x41), 0, "salt is all printable ASCII");
}

TEST(B6VendorcarveRejections, DlkeRejectsEitherBadHeaderAndAMissingSecondHeader) {
    const auto data = read_fixture("dlke.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dlke.bin");

    expect_rejected("dlke", poked(data, 26, 2), 0, "first header lpvs != 1");
    expect_rejected("dlke", poked(data, 112U + 26U, 2), 0, "second header lpvs != 1");
    expect_rejected("dlke", truncated(data, 112), 0, "second header missing");
}

TEST(B6VendorcarveRejections, CsmanRejectsAStoredHeaderWithNoEntries) {
    for(const char* file : {"csman_stored.bin", "csman_be_stored.bin", "csman_dupkeys.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(file);
        ASSERT_NE(data[16], std::uint8_t{0x78}) << file << " is no longer a stored fixture";

        expect_rejected("csman", truncated(data, 16), 0, "header only, no entries");

        expect_rejected(
            "csman", with_u32_le(data, 4, 0x4000), 0, "declared data_size past EOF"
        );
    }
}

TEST(B6VendorcarveRejections, CompressedCsmanRejectionsAreNotVacuous) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const auto data = read_fixture("csman.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman.bin");
    ASSERT_EQ(data[16], std::uint8_t{0x78});

    const auto control = parse_at("csman", data, 0);
    ASSERT_TRUE(control.has_value())
        << "csman.bin is not detected even though the zlib backend reports available, so "
        << "the rejections below would prove nothing";
    ASSERT_EQ(control->size, std::uint64_t{41});

    expect_rejected("csman", poked(data, 16, 0x79), 0, "compressed but no 0x78 zlib magic");
    expect_rejected("csman", truncated(data, 16), 0, "header only, no entries");
    expect_rejected("csman", with_u32_le(data, 4, 0x4000), 0, "declared data_size past EOF");
}

TEST(B6VendorcarveMeasuredMutants, OracleVerdictsForNonObviousFieldMutations) {
    struct row {
        const char* signature;
        const char* file;
        std::size_t parse_offset;
        const char* what;
        const char* why_it_rejects;
        std::size_t poke_offset;
        std::uint32_t poke_value;
    };

    const std::vector<row> rows{
        {"trx", "trx.bin", 0, "total_size below the header size",
         "parse_trx_header requires total_size > 32", 4, 16},
        {"trx", "trx.bin", 0, "total_size past EOF",
         "the extractor's CRC slice file_data[crc_start..crc_end] is out of range",
         4, 0x4000},
        {"jboot_stag", "jboot_stag.bin", 0, "image_size <= header_size",
         "parse_jboot_stag_header requires image_size > header_size (16)", 8, 16},
        {"jboot_stag", "jboot_stag.bin", 0, "image past EOF",
         "the signature requires offset + 16 + image_size < file length", 8, 0x4000},
        {"jboot_sch2", "jboot_sch2.bin", 0, "kernel size past EOF",
         "the kernel slice is out of range (and separately the header CRC no longer matches)",
         8, 0x4000},
        {"wince", "wince.bin", 0, "base address does not match the first block",
         "the extractor requires entries[0].address == header.base_address", 7, 0x9000},
        {"wince", "wince.bin", 0, "first block size past EOF",
         "the block walk breaks before it ever reaches the NUL terminator block", 19, 0x4000},
        {"mh01", "mh01.bin", 0, "iv_size past EOF",
         "parse_mh01_header's IV slice is out of range", 20, 0x4000},
        {"dlke", "dlke.bin", 0, "signature data size past EOF",
         "the second header's slice is out of range", 44, 0x4000},

        {"csman", "csman_stored.bin", 0, "data_size past EOF",
         "the entry-blob slice is out of range, with no codec involved", 4, 0x4000}
    };

    for(const auto& value : rows) {
        SCOPED_TRACE(std::string(value.signature) + " / " + value.what);
        const auto data = read_fixture(value.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(value.file);
        const auto mutated = with_u32_le(data, value.poke_offset, value.poke_value);
        expect_rejected(value.signature, mutated, value.parse_offset, value.why_it_rejects);
    }
}

TEST(B6VendorcarveMeasuredMutants, WinceRejectsWhenTheFirstBlockIsTheTerminator) {
    const auto data = read_fixture("wince.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("wince.bin");
    expect_rejected(
        "wince", poked_range(data, 15, 12, 0x00), 0,
        "first block header is all NUL, i.e. the terminator; fewer than six real blocks"
    );
}

TEST(B6VendorcarveMeasuredMutants, TrxDoesNotCheckTheFourthPartitionOffset) {

    const auto data = read_fixture("trx.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("trx.bin");

    const auto control = trx_with_recomputed_crc(data);
    ASSERT_EQ(control, data)
        << "recomputing the CRC over an UNMODIFIED trx.bin changed it, so this helper does "
        << "not reproduce upstream's trx_crc32 and the mutant below would be meaningless";

    const auto mutated = trx_with_recomputed_crc(with_u32_le(data, 28, 0x1000));
    const auto result = parse_at("trx", mutated, 0);
    ASSERT_TRUE(result.has_value())
        << "the oracle DETECTS a TRXv2 image whose fourth partition offset exceeds "
        << "total_size, because upstream never checks that field. Rejecting it is a "
        << "detection we lose relative to upstream (section 5).";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{128});
    expect_tier(result->confidence, tier::high, "trx partition4 past total_size");
    expect_description_mentions(
        result->description, {"partition count: 4"}, "trx partition4 past total_size"
    );
}

TEST(B6VendorcarveMeasuredMutants, CsmanIgnoresTheCompressedFixturesTrailingByte) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const auto data = read_fixture("csman.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman.bin");
    ASSERT_EQ(data[16], std::uint8_t{0x78}) << "csman.bin is no longer the compressed fixture";

    const auto mutated = poked(data, data.size() - 1U, 0x41);
    const auto result = parse_at("csman", mutated, 0);
    ASSERT_TRUE(result.has_value())
        << "the oracle still detects csman.bin with its last byte changed, because that byte "
        << "is in the zlib adler32 tail rather than in the entry blob. Rejecting it loses a "
        << "detection relative to upstream.";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{41});
    expect_tier(result->confidence, tier::high, "csman.bin non-NUL trailing byte");
}

TEST(B6VendorcarveMeasuredMutants, CsmanRejectsAStoredFixtureWhoseEofMarkerIsNotNul) {

    for(const char* file : {"csman_stored.bin", "csman_be_stored.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(file);
        ASSERT_EQ(data.size(), std::size_t{30});
        ASSERT_NE(data[16], std::uint8_t{0x78}) << file << " is no longer the stored fixture";

        for(std::size_t index = 26; index < 30U; ++index) {
            ASSERT_EQ(data[index], std::uint8_t{0x00}) << file << ": EOF marker is not NUL";
        }
        expect_rejected("csman", poked(data, 26, 0x41), 0, "EOF marker is not NUL");
    }
}

TEST(B6VendorcarveMeasuredMutants, Mh01AcceptsAPayloadThatDoesNotStartWithSaltedUnderscore) {

    const auto data = read_fixture("mh01.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("mh01.bin");
    ASSERT_GE(data.size(), std::size_t{72});
    ASSERT_EQ(data[64], static_cast<std::uint8_t>('S'));

    bytes mutated = data;
    const std::string replacement = "NOTSALT_";
    for(std::size_t index = 0; index < replacement.size(); ++index) {
        mutated[64U + index] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(replacement[index]));
    }

    const auto result = parse_at("mh01", mutated, 0);
    ASSERT_TRUE(result.has_value())
        << "the oracle DETECTS an MH01 image whose payload lacks the Salted__ magic; "
        << "rejecting it loses a detection relative to upstream";
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{192});
    expect_tier(result->confidence, tier::high, "mh01 without Salted__");
}

TEST(B6VendorcarveDivergences, DahuaZipWithNoEocdIsDetectedByUsAndNotByUpstream) {
    const auto data = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dahua_zip.bin");
    ASSERT_EQ(data.size(), std::size_t{113});

    ASSERT_EQ(data[91], static_cast<std::uint8_t>('P'));
    ASSERT_EQ(data[92], static_cast<std::uint8_t>('K'));
    ASSERT_EQ(data[93], std::uint8_t{0x05});
    ASSERT_EQ(data[94], std::uint8_t{0x06});

    struct expectation {
        std::size_t length;
        const char* what;
    };
    const std::array<expectation, 2> expectations{{
        {40, "truncated to its single local file entry"},
        {91, "central directory kept, EOCD record chopped off"}
    }};

    for(const auto& expected : expectations) {
        SCOPED_TRACE(expected.what);
        const auto shortened = truncated(data, expected.length);
        const auto result = parse_at("dahua_zip", shortened, 0);
        ASSERT_TRUE(result.has_value())
            << "D5: upstream reports NOTHING here and we deliberately report the true end "
            << "of the local-header chain. Losing this detection would be adopting an "
            << "upstream bug (contract/DIVERGENCES.md D5).";
        EXPECT_EQ(result->offset, std::uint64_t{0});
        EXPECT_EQ(result->size, std::uint64_t{40})
            << "D5: the local-header chain ends at 40 -- 30-byte header, 5-byte name, "
            << "5 bytes of stored data";
        expect_in_bounds(result, shortened.size(), expected.what);
    }
}

TEST(B6VendorcarveDivergences, DahuaZipStopsAtTheCentralDirectoryRecord) {
    const auto data = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dahua_zip.bin");

    ASSERT_EQ(data[40], static_cast<std::uint8_t>('P'));
    ASSERT_EQ(data[41], static_cast<std::uint8_t>('K'));
    ASSERT_EQ(data[42], std::uint8_t{0x01});
    ASSERT_EQ(data[43], std::uint8_t{0x02});

    const auto result = parse_at("dahua_zip", truncated(data, 91), 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size, std::uint64_t{40})
        << "D1: a PK\\x01\\x02 central directory record must not be swallowed as a local "
        << "file entry. Reporting 91 would mean the local-header magic is not validated.";
}

TEST(B6VendorcarveDivergences, DahuaZipWithItsEocdMatchesTheOracleExactly) {
    const auto data = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dahua_zip.bin");

    const auto result = parse_at("dahua_zip", data, 0);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, std::uint64_t{0});
    EXPECT_EQ(result->size, std::uint64_t{113});
    expect_tier(result->confidence, tier::high, "dahua_zip.bin");
    EXPECT_FALSE(result->extraction_declined);
}

TEST(B6VendorcarveDecompressionBomb, ScanningTheBombProducesAnEmptyFileMapPromptlyAndWritesNothing) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason()
                     << " Without an inflate this asserts an empty file_map that the absent "
                        "codec produces on its own, so the section 5b ceiling would not be "
                        "exercised at all.";
    }
    const auto data = read_fixture("csman_bomb.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman_bomb.bin");
    ASSERT_EQ(data.size(), std::size_t{122329})
        << "csman_bomb.bin is not the 122,329-byte fixture tests/golden/csman_bomb.json "
        << "was generated from";

    const auto benign = read_fixture("csman.bin");
    ASSERT_FALSE(benign.empty()) << fixture_diagnostic("csman.bin");
    const auto benign_results = scan_batch(benign);
    ASSERT_EQ(benign_results.size(), std::size_t{1})
        << "a compressed csman stream well under the 100 MiB ceiling is not detected in this "
        << "build, so an empty file_map for the bomb would prove nothing about the ceiling";
    ASSERT_EQ(benign_results.front().size, std::uint64_t{41});

    const auto before = working_directory_entry_count();
    const auto started = std::chrono::steady_clock::now();

    const auto results = scan_batch(data);

    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - started
    );
    const auto after = working_directory_entry_count();

    EXPECT_TRUE(results.empty())
        << "tests/golden/csman_bomb.json pins an EMPTY file_map for this file. We reported "
        << results.size() << " result(s), the first named \""
        << (results.empty() ? std::string() : results.front().name) << "\". A match here "
        << "means the 100 MiB decompression ceiling did not stop the inflate.";

    EXPECT_LT(elapsed.count(), 60)
        << "scanning a 120 KiB file took " << elapsed.count() << " s; the decompression "
        << "ceiling is not aborting the inflate";

    EXPECT_EQ(after, before)
        << "scanning wrote something into the working directory. Scanning must never write: "
        << "the parser's dry run validates and writes nothing (policy rule 1).";
}

TEST(B6VendorcarveDecompressionBomb, TruncatedBombsFailInsteadOfRunningAway) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const auto data = read_fixture("csman_bomb.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman_bomb.bin");

    const std::array<std::size_t, 9> lengths{
        16, 17, 18, 20, 64, 1024, 60000, 61164, data.size() - 1U
    };

    const auto started = std::chrono::steady_clock::now();
    for(const auto length : lengths) {
        SCOPED_TRACE("csman_bomb.bin truncated to " + std::to_string(length) + " bytes");
        const auto shortened = truncated(data, length);
        ASSERT_EQ(shortened.size(), length);

        const auto results = scan_batch(shortened);
        EXPECT_TRUE(results.empty())
            << "the oracle rejects this truncated bomb; we reported " << results.size()
            << " result(s)";

        const auto direct = parse_at("csman", shortened, 0);
        EXPECT_FALSE(direct.has_value())
            << "the csman parser accepted a truncated decompression bomb";
        expect_offset_in_bounds(direct, shortened.size(), "truncated bomb");
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - started
    );
    EXPECT_LT(elapsed.count(), 60) << "nine truncated bombs took " << elapsed.count() << " s";
}

TEST(B6VendorcarveDecompressionBomb, ADryRunOfTheBombExtractorFailsAndWritesNothing) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const auto data = read_fixture("csman_bomb.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman_bomb.bin");

    const auto* definition = signature_named("csman");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());

    binwalk::signature_result signature;
    signature.name = "csman";
    signature.offset = 0;
    signature.size = static_cast<std::uint64_t>(data.size());

    const auto before = working_directory_entry_count();
    const auto result = binwalk::dry_run_extractor(
        *definition->extractor_definition, view(data), signature
    );
    const auto after = working_directory_entry_count();

    EXPECT_FALSE(result.success)
        << "the csman dry run accepted a 120 MiB decompression bomb. This is the exact "
        << "v3.1.1 memory-exhaustion path (policy item 4).";
    EXPECT_EQ(after, before) << "a dry run wrote to disk (policy rule 1)";
}

TEST(B6VendorcarveSafety, EveryPrefixOfEveryFixtureReturnsWithItsOffsetInBounds) {
    for(const auto& row : fixture_table()) {
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        for(std::size_t length = 0; length <= data.size(); ++length) {
            const auto shortened = truncated(data, length);
            const auto result = parse_at(row.signature, shortened, row.parse_offset);

            expect_offset_in_bounds(
                result, shortened.size(),
                std::string(row.signature) + " / " + row.file + " truncated to "
                    + std::to_string(length)
            );
        }
    }
}

TEST(B6VendorcarveSafety, HostileThirtyTwoBitLengthFieldsReturnWithTheirOffsetInBounds) {

    for(const auto& row : fixture_table()) {
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const std::size_t limit = (std::min)(data.size(), std::size_t{128});
        for(std::size_t slot = 0; slot + 4U <= limit; slot += 4U) {
            const auto mutated = with_u32_le(data, slot, 0xFFFFFFFFU);
            const auto result = parse_at(row.signature, mutated, row.parse_offset);
            expect_offset_in_bounds(
                result, mutated.size(),
                std::string(row.signature) + " / " + row.file + " with u32@"
                    + std::to_string(slot) + " = 0xFFFFFFFF"
            );
        }
    }
}

TEST(B6VendorcarveSafety, NoResultSurvivingTheScannerRunsPastEof) {
    for(const auto& row : fixture_table()) {
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        for(std::size_t length = 0; length <= data.size(); ++length) {
            const auto shortened = truncated(data, length);
            expect_every_scanner_result_fits(
                scan_batch(shortened), shortened.size(),
                std::string(row.file) + " truncated to " + std::to_string(length)
            );
        }

        const std::size_t limit = (std::min)(data.size(), std::size_t{128});
        for(std::size_t slot = 0; slot + 4U <= limit; slot += 4U) {
            const auto mutated = with_u32_le(data, slot, 0xFFFFFFFFU);
            expect_every_scanner_result_fits(
                scan_batch(mutated), mutated.size(),
                std::string(row.file) + " with u32@" + std::to_string(slot) + " = 0xFFFFFFFF"
            );
        }
    }
}

TEST(B6VendorcarveSafety, EveryMagicPatternAloneIsHandledCleanly) {
    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        for(std::size_t index = 0; index < value.magic.size(); ++index) {
            const bytes pattern = value.magic[index];
            SCOPED_TRACE(value.name + " magic #" + std::to_string(index));

            expect_offset_in_bounds(
                value.parser(view(pattern), 0), pattern.size(), value.name + " magic alone"
            );

            if(pattern.size() > 1U) {
                const bytes shorter(pattern.begin(), pattern.end() - 1);
                expect_offset_in_bounds(
                    value.parser(view(shorter), 0), shorter.size(), value.name + " short magic"
                );
            }

            bytes padded = pattern;
            padded.insert(padded.end(), 1024U, 0xA5);
            expect_offset_in_bounds(
                value.parser(view(padded), 0), padded.size(), value.name + " magic + junk"
            );

            expect_every_scanner_result_fits(
                scan_batch(padded), padded.size(), value.name + " magic + junk (scanner)"
            );
        }
    }
}

TEST(B6VendorcarveSafety, EveryParserSurvivesAnOffsetAtOrPastTheEnd) {
    const bytes data(256, 0xA5);
    const std::array<std::size_t, 4> offsets{
        data.size(), data.size() + 1U, data.size() * 4U,
        (std::numeric_limits<std::size_t>::max)() / 2U
    };
    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        for(const auto offset : offsets) {
            const auto result = value.parser(view(data), offset);

            if(result.has_value()) {
                EXPECT_EQ(result->size, std::uint64_t{0})
                    << value.name << " reported a non-zero size for a match at offset "
                    << offset << " in a " << data.size() << "-byte buffer";
            }
        }
    }
}

TEST(B6VendorcarveSafety, AnEmptyBufferIsRejectedByEveryParser) {
    const bytes empty;
    for(const auto& value : batch()) {
        ASSERT_NE(value.parser, nullptr) << value.name;
        const auto result = value.parser(view(empty), 0);
        EXPECT_FALSE(result.has_value()) << value.name << " matched an empty buffer";
    }
}

TEST(B6VendorcarveSafety, ScanningMagicSoupNeverReportsOutOfBounds) {

    bytes data;
    std::uint32_t state = 0x1234567U;
    for(const auto& value : batch()) {
        for(const auto& pattern : value.magic) {
            data.insert(data.end(), pattern.begin(), pattern.end());
            for(int filler = 0; filler < 7; ++filler) {
                state = state * 1103515245U + 12345U;
                data.push_back(static_cast<std::uint8_t>((state >> 16U) & 0xFFU));
            }
        }
    }
    ASSERT_FALSE(data.empty());

    for(const auto& result : scan_batch(data)) {
        EXPECT_LE(result.offset, static_cast<std::uint64_t>(data.size()))
            << result.name << " offset past EOF";
        if(result.offset <= static_cast<std::uint64_t>(data.size())) {
            EXPECT_LE(result.size, static_cast<std::uint64_t>(data.size()) - result.offset)
                << result.name << " size runs past EOF";
        }
    }
}

TEST_F(b6_extraction_test, TrxCarvesItsFourPartitions) {
    const auto data = read_fixture("trx.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("trx.bin");

    expect_extraction(root_, "trx", data, {
        {"partition_0.bin", slice(data, 0x20, 32)},
        {"partition_1.bin", slice(data, 0x40, 32)},
        {"partition_2.bin", slice(data, 0x60, 16)},
        {"partition_3.bin", slice(data, 0x70, 16)}
    });
}

TEST_F(b6_extraction_test, TrxV1CarvesItsThreePartitions) {
    const auto data = read_fixture("trx_v1.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("trx_v1.bin");

    expect_extraction(root_, "trx", data, {
        {"partition_0.bin", slice(data, 0x1C, 28)},
        {"partition_1.bin", slice(data, 0x38, 20)},
        {"partition_2.bin", slice(data, 0x4C, 20)}
    });
}

TEST_F(b6_extraction_test, JbootSch2CarvesItsKernel) {
    const auto data = read_fixture("jboot_sch2.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("jboot_sch2.bin");
    expect_extraction(root_, "jboot_sch2", data, {
        {"kernel.bin", slice(data, 40, 96)}
    });
}

TEST_F(b6_extraction_test, WinceCarvesOneFilePerBlockNamedByItsLoadAddress) {
    const auto data = read_fixture("wince.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("wince.bin");

    expect_extraction(root_, "wince", data, {
        {"1000.bin", slice(data, 15U + 0U * 16U + 12U, 4)},
        {"2000.bin", slice(data, 15U + 1U * 16U + 12U, 4)},
        {"3000.bin", slice(data, 15U + 2U * 16U + 12U, 4)},
        {"4000.bin", slice(data, 15U + 3U * 16U + 12U, 4)},
        {"5000.bin", slice(data, 15U + 4U * 16U + 12U, 4)},
        {"6000.bin", slice(data, 15U + 5U * 16U + 12U, 4)}
    });
}

TEST_F(b6_extraction_test, DahuaZipRewritesTheLeadingDhBackToPk) {
    const auto data = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dahua_zip.bin");

    bytes repaired = data;
    repaired[0] = static_cast<std::uint8_t>('P');
    repaired[1] = static_cast<std::uint8_t>('K');

    expect_extraction(root_, "dahua_zip", data, {{"dahua.zip", repaired}});

    const auto produced = extracted_by_name(root_ / "dahua_zip");
    const auto found = produced.find("dahua.zip");
    ASSERT_NE(found, produced.end()) << describe(produced);
    ASSERT_GE(found->second.size(), std::size_t{4});
    EXPECT_EQ(found->second[0], static_cast<std::uint8_t>('P'));
    EXPECT_EQ(found->second[1], static_cast<std::uint8_t>('K'));
    EXPECT_EQ(found->second[2], std::uint8_t{0x03});
    EXPECT_EQ(found->second[3], std::uint8_t{0x04});
}

TEST_F(b6_extraction_test, Mh01CarvesItsIvSignatureAndEncryptedPayload) {
    const auto data = read_fixture("mh01.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("mh01.bin");

    expect_extraction(root_, "mh01", data, {
        {"iv.bin", slice(data, 32, 32)},
        {"encrypted.bin", slice(data, 64, 64)},
        {"signature.bin", slice(data, 128, 64)}
    });
}

TEST_F(b6_extraction_test, CsmanStoredExtractsItsEntryUnderTheKeyAsUppercaseHex) {
    const bytes value{0xAA, 0xBB, 0xCC, 0xDD};
    for(const char* file : {"csman_stored.bin", "csman_be_stored.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(file);

        const auto sub_root = root_ / file;
        std::error_code error;
        std::filesystem::create_directories(sub_root, error);
        expect_extraction(sub_root, "csman", data, {{"04030201.dat", value}});
    }
}

TEST_F(b6_extraction_test, CompressedCsmanExtractsItsEntry) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const bytes value{0xAA, 0xBB, 0xCC, 0xDD};
    for(const char* file : {"csman.bin", "csman_be.bin"}) {
        SCOPED_TRACE(file);
        const auto data = read_fixture(file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(file);
        ASSERT_EQ(data[16], std::uint8_t{0x78}) << file << " is no longer compressed";

        const auto sub_root = root_ / file;
        std::error_code error;
        std::filesystem::create_directories(sub_root, error);
        expect_extraction(sub_root, "csman", data, {{"04030201.dat", value}});
    }
}

TEST_F(b6_extraction_test, CsmanSuffixesTheSecondUseOfARepeatedKey) {
    const auto data = read_fixture("csman_dupkeys.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman_dupkeys.bin");

    expect_extraction(root_, "csman", data, {
        {"04030201.dat",   bytes{0xAA, 0xBB, 0xCC, 0xDD}},
        {"04030201.dat_1", bytes{0x55, 0x66, 0x77, 0x88}},
        {"0A0B0C0D.dat",   bytes{0x11, 0x22, 0x33, 0x44}}
    });
}

TEST_F(b6_extraction_test, EveryDryRunValidatesFullyReportsTheTrueSizeAndWritesNothing) {
    struct expectation {
        const char* signature;
        const char* file;
    };

    const std::array<expectation, 7> expectations{{
        {"trx", "trx.bin"},
        {"trx", "trx_v1.bin"},
        {"jboot_sch2", "jboot_sch2.bin"},
        {"wince", "wince.bin"},
        {"dahua_zip", "dahua_zip.bin"},
        {"mh01", "mh01.bin"},
        {"csman", "csman_stored.bin"}
    }};

    const auto before = working_directory_entry_count();

    for(const auto& expected : expectations) {
        SCOPED_TRACE(std::string(expected.signature) + " / " + expected.file);
        const auto data = read_fixture(expected.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(expected.file);

        const auto* definition = signature_named(expected.signature);
        ASSERT_NE(definition, nullptr) << expected.signature;
        ASSERT_TRUE(definition->extractor_definition.has_value()) << expected.signature;

        const auto signature = scanned_result(expected.signature, data);
        ASSERT_TRUE(signature.has_value()) << expected.file;

        const auto result = binwalk::dry_run_extractor(
            *definition->extractor_definition, view(data), *signature
        );

        EXPECT_TRUE(result.success)
            << expected.file << ": a dry run of data the oracle extracts successfully must "
            << "succeed. A dry run that skips validation is worse than one that writes "
            << "(policy rule 1); failure code "
            << static_cast<int>(result.failure);
        ASSERT_TRUE(result.size.has_value())
            << expected.file << ": section 1 rule 2 -- a successful dry run carries the true "
            << "total size, and callers rely on it";

        EXPECT_EQ(*result.size, signature->size)
            << expected.file << ": the dry run's size disagrees with the size the signature "
            << "reports, so whichever the caller uses it gets a different answer";
    }

    EXPECT_EQ(working_directory_entry_count(), before)
        << "a dry run wrote a file. `output_directory == nullptr` means parse and validate, "
        << "write NOTHING (policy rule 1).";

    EXPECT_TRUE(files_under(root_).empty())
        << "a dry run wrote into the test's temp directory:" << describe(extracted_by_name(root_));
}

TEST_F(b6_extraction_test, DryRunsRejectTheSameMutantsTheParsersReject) {

    struct expectation {
        const char* signature;
        const char* file;
        std::size_t poke_offset;
        std::uint8_t poke_value;
        const char* what;
    };

    const std::array<expectation, 4> expectations{{
        {"trx", "trx.bin", 8, 0x00, "image CRC corrupted"},
        {"jboot_sch2", "jboot_sch2.bin", 3, 0x03, "version != 2"},
        {"wince", "wince.bin", 15, 0xFF, "first block header mangled"},
        {"csman", "csman_stored.bin", 26, 0x41, "EOF marker is not NUL"}
    }};

    for(const auto& expected : expectations) {
        SCOPED_TRACE(std::string(expected.signature) + " / " + expected.what);
        const auto data = read_fixture(expected.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(expected.file);
        const auto mutated = poked(data, expected.poke_offset, expected.poke_value);

        const auto* definition = signature_named(expected.signature);
        ASSERT_NE(definition, nullptr);
        ASSERT_TRUE(definition->extractor_definition.has_value());

        binwalk::signature_result signature;
        signature.name = expected.signature;
        signature.offset = 0;
        signature.size = static_cast<std::uint64_t>(mutated.size());

        const auto result = binwalk::dry_run_extractor(
            *definition->extractor_definition, view(mutated), signature
        );
        EXPECT_FALSE(result.success)
            << expected.signature << ": the dry run accepted data the parser rejects, so the "
            << "parser has no validator";
    }
}

TEST_F(b6_extraction_test, CompressedCsmanDryRunValidatesAndRejects) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    const auto data = read_fixture("csman.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman.bin");
    ASSERT_EQ(data[16], std::uint8_t{0x78});

    const auto* definition = signature_named("csman");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value());

    const auto before = working_directory_entry_count();

    const auto signature = scanned_result("csman", data);
    ASSERT_TRUE(signature.has_value());
    const auto good = binwalk::dry_run_extractor(
        *definition->extractor_definition, view(data), *signature
    );
    EXPECT_TRUE(good.success)
        << "a dry run of a compressed stream the oracle extracts must succeed; failure code "
        << static_cast<int>(good.failure);
    ASSERT_TRUE(good.size.has_value()) << "section 1 rule 2: a successful dry run carries size";
    EXPECT_EQ(*good.size, signature->size);
    EXPECT_EQ(*good.size, std::uint64_t{41});

    const auto broken = poked(data, 16, 0x79);
    binwalk::signature_result whole;
    whole.name = "csman";
    whole.offset = 0;
    whole.size = static_cast<std::uint64_t>(broken.size());
    const auto bad = binwalk::dry_run_extractor(
        *definition->extractor_definition, view(broken), whole
    );
    EXPECT_FALSE(bad.success)
        << "the dry run accepted a compressed csman blob with no zlib magic, so the parser "
        << "that relies on it has no validator";
    EXPECT_NE(bad.failure, binwalk::extraction_failure::unsupported)
        << "the failure reads as `unsupported`, which means the codec was never consulted. "
        << "`unsupported` has exactly one meaning -- this build cannot do it at all -- and a "
        << "data error must not borrow it, or this test is vacuous even with zlib present.";

    EXPECT_EQ(working_directory_entry_count(), before)
        << "a dry run wrote a file (policy rule 1)";
    EXPECT_TRUE(files_under(root_).empty())
        << "a dry run wrote into the test's temp directory:" << describe(extracted_by_name(root_));
}

TEST_F(b6_extraction_test, DlkeExtractionIsAnUnsupportedStubAndSaysSo) {
    const auto data = read_fixture("dlke.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dlke.bin");

    const auto* definition = signature_named("dlke");
    ASSERT_NE(definition, nullptr);
    ASSERT_TRUE(definition->extractor_definition.has_value())
        << "dlke declares no extractor at all; upstream declares one, so the stub must exist "
        << "and report `unsupported` rather than silently vanishing";

    const auto signature = scanned_result("dlke", data);
    ASSERT_TRUE(signature.has_value());
    EXPECT_EQ(signature->offset, std::uint64_t{0});
    EXPECT_EQ(signature->size, std::uint64_t{256});
    expect_tier(signature->confidence, tier::high, "dlke.bin");

    const auto dry = binwalk::dry_run_extractor(
        *definition->extractor_definition, view(data), *signature
    );
    EXPECT_FALSE(dry.success) << "the dlke extractor is a stub; it must not claim success";
    EXPECT_EQ(dry.failure, binwalk::extraction_failure::unsupported)
        << "`unsupported` means \"this build cannot do it at all\", which is exactly the "
        << "case here: the delink decryption is not available to port. Any other failure "
        << "code would read as a data error.";

    const auto output_root = root_ / "dlke";
    const auto real = binwalk::execute_extractor(
        view(data), "dlke.bin", *signature, *definition->extractor_definition,
        output_root.string()
    );
    EXPECT_FALSE(real.success);
    EXPECT_EQ(real.failure, binwalk::extraction_failure::unsupported);
    EXPECT_TRUE(files_under(output_root).empty())
        << "the dlke stub wrote something:" << describe(extracted_by_name(output_root));
}

TEST(B6VendorcarveScanner, PopulateStampsTheNameOnEveryResult) {
    for(const auto& row : fixture_table()) {
        SCOPED_TRACE(std::string(row.signature) + " / " + row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto results = scan_including(row.signature, data);
        ASSERT_EQ(results.size(), std::size_t{1})
            << row.file << ": expected exactly one " << row.signature << " result";
        EXPECT_EQ(results.front().name, row.signature)
            << "`name` is the --include/--exclude filter key and is user-visible, so it is "
            << "STRICT under section 5. It is stamped by populate() AFTER the parser "
            << "returns, which is why it can only be asserted here.";
    }
}

TEST(B6VendorcarveScanner, EveryResultCarriesAnIdAndAlwaysDisplayIsFalse) {
    for(const auto& row : fixture_table()) {
        SCOPED_TRACE(std::string(row.signature) + " / " + row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto results = scan_including(row.signature, data);
        ASSERT_EQ(results.size(), std::size_t{1}) << row.file;

        EXPECT_FALSE(results.front().id.empty())
            << "`id` is emitted in the --log JSON and keys the `extractions` map; an empty "
            << "one collides with every other empty one";

        EXPECT_FALSE(results.front().always_display)
            << row.signature << ": upstream registers this with always_display false";
        EXPECT_FALSE(results.front().extraction_declined) << row.signature;
    }
}

TEST(B6VendorcarveScanner, TwoConcatenatedFixturesYieldTwoResultsWithDistinctIds) {
    const auto csman = read_fixture("csman_dupkeys.bin");
    const auto dahua = read_fixture("dahua_zip.bin");
    ASSERT_FALSE(csman.empty()) << fixture_diagnostic("csman_dupkeys.bin");
    ASSERT_FALSE(dahua.empty()) << fixture_diagnostic("dahua_zip.bin");
    ASSERT_EQ(csman.size(), std::size_t{50});

    bytes combined = csman;
    combined.insert(combined.end(), dahua.begin(), dahua.end());

    const auto results = scan_batch(combined);
    ASSERT_EQ(results.size(), std::size_t{2})
        << "the oracle reports exactly two results here: csman at 0 and dahua_zip at 50";

    EXPECT_EQ(results[0].name, "csman");
    EXPECT_EQ(results[0].offset, std::uint64_t{0});
    EXPECT_EQ(results[0].size, std::uint64_t{50});
    EXPECT_EQ(results[1].name, "dahua_zip");
    EXPECT_EQ(results[1].offset, std::uint64_t{50})
        << "the dahua_zip must be found at its real offset, not at 0";
    EXPECT_EQ(results[1].size, std::uint64_t{113});

    std::set<std::string> ids;
    for(const auto& result : results) {
        EXPECT_FALSE(result.id.empty()) << result.name;
        EXPECT_TRUE(ids.insert(result.id).second)
            << "two results share the id \"" << result.id << "\"; the --log JSON keys the "
            << "`extractions` map by it, so one extraction would overwrite the other";
    }
}

TEST(B6VendorcarveScanner, IncludeAndExcludeFilterOnTheStampedName) {
    const auto data = read_fixture("csman_dupkeys.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("csman_dupkeys.bin");

    EXPECT_EQ(scan_including("csman", data).size(), std::size_t{1});

    EXPECT_TRUE(scan_including("trx", data).empty())
        << "--include=trx returned a result from a csman file";

    binwalk::scan_options excluded;
    excluded.exclude = {"csman"};
    const binwalk::scanner scanner(binwalk::formats::b6_vendorcarve_signatures(), excluded);
    const auto results = scanner.scan(view(data));
    for(const auto& result : results) {
        EXPECT_NE(result.name, "csman")
            << "--exclude=csman still produced a csman result; the exclude filter keys off "
            << "the same stamped `name`";
    }
}

TEST(B6VendorcarveScanner, DlkeDisplacesJbootArmAtTheSameOffsetOnConfidence) {
    const auto data = read_fixture("dlke.bin");
    ASSERT_FALSE(data.empty()) << fixture_diagnostic("dlke.bin");

    const auto dlke_alone = parse_at("dlke", data, 0);
    ASSERT_TRUE(dlke_alone.has_value());
    EXPECT_EQ(dlke_alone->offset, std::uint64_t{0});
    expect_tier(dlke_alone->confidence, tier::high, "dlke at offset 0");

    const auto arm_alone = parse_at("jboot_arm", data, 48);
    ASSERT_TRUE(arm_alone.has_value())
        << "dlke.bin no longer parses as a JBOOT ARM header at its magic offset 48, so the "
        << "collision this test pins no longer occurs and the test is measuring nothing";
    EXPECT_EQ(arm_alone->offset, std::uint64_t{0});
    expect_tier(arm_alone->confidence, tier::medium, "jboot_arm inside dlke.bin");

    const auto results = scan_batch(data);
    ASSERT_EQ(results.size(), std::size_t{1})
        << "the oracle reports exactly one result for dlke.bin over the full registry";
    EXPECT_EQ(results.front().name, "dlke")
        << "dlke (HIGH, 250) must displace jboot_arm (MEDIUM, 128) at their shared offset 0";
    EXPECT_EQ(results.front().offset, std::uint64_t{0});
    EXPECT_EQ(results.front().size, std::uint64_t{256});
}

TEST(B6VendorcarveScanner, TheUserVisiblePathReproducesEveryMeasuredResult) {

    for(const auto& row : fixture_table()) {
        SCOPED_TRACE(std::string(row.signature) + " / " + row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto results = scan_including(row.signature, data);
        ASSERT_EQ(results.size(), std::size_t{1}) << row.file;

        const auto& result = results.front();
        EXPECT_EQ(result.name, row.signature);
        EXPECT_EQ(result.offset, row.offset);
        EXPECT_EQ(result.size, row.size);
        expect_tier(result.confidence, row.confidence, row.file);
        EXPECT_LE(result.offset, static_cast<std::uint64_t>(data.size()));
        if(result.offset <= static_cast<std::uint64_t>(data.size())) {
            EXPECT_LE(result.size, static_cast<std::uint64_t>(data.size()) - result.offset);
        }
    }
}

TEST(B6VendorcarveScanner, CompressedCsmanReachesTheUserVisiblePath) {
    if(!zlib_backend_available()) {
        GTEST_SKIP() << zlib_skip_reason();
    }
    for(const auto& row : compressed_csman_table()) {
        SCOPED_TRACE(row.file);
        const auto data = read_fixture(row.file);
        ASSERT_FALSE(data.empty()) << fixture_diagnostic(row.file);

        const auto results = scan_including(row.signature, data);
        ASSERT_EQ(results.size(), std::size_t{1}) << row.file;

        const auto& result = results.front();
        EXPECT_EQ(result.name, row.signature)
            << "`name` is stamped by populate() after the parser returns, so it can only be "
            << "asserted here";
        EXPECT_FALSE(result.id.empty());
        EXPECT_FALSE(result.always_display);
        EXPECT_FALSE(result.extraction_declined);
        EXPECT_EQ(result.offset, row.offset);
        EXPECT_EQ(result.size, row.size);
        expect_tier(result.confidence, row.confidence, row.file);
    }
}

TEST(B6VendorcarveScanner, TheBatchIsRegisteredWithTheScannerItIsGiven) {
    const auto& scanner = batch_scanner();
    EXPECT_EQ(scanner.signature_count(), std::size_t{9})
        << "the scanner did not take all nine of this batch's signatures";
    EXPECT_EQ(scanner.pattern_count(), std::size_t{15})
        << "the scanner did not index all 15 of this batch's magic patterns; an unindexed "
        << "pattern is a format variant the matcher can never find";
    EXPECT_EQ(scanner.signatures().size(), std::size_t{9});
}
