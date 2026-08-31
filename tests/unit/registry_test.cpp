#include <binwalk/builtin.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>
namespace {

const std::vector<std::string>& expected_registration_order() {
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

}

TEST(Registry, UpstreamOrderTableIsExactlyOneHundredEleven) {
    EXPECT_EQ(expected_registration_order().size(), 111U);
    const std::set<std::string> unique(
        expected_registration_order().begin(), expected_registration_order().end()
    );
    EXPECT_EQ(unique.size(), expected_registration_order().size())
        << "the upstream registry has no duplicate signature names";
}

TEST(Registry, EverySignatureNameIsKnownToTheOrderTable) {
    const auto& expected = expected_registration_order();
    for(const auto& value : binwalk::builtin_signatures()) {
        const auto found = std::find(expected.begin(), expected.end(), value.name);
        EXPECT_NE(found, expected.end())
            << "signature name \"" << value.name << "\" is not in upstream's magic.rs "
            << "registry order table. It would sort silently to the end of the "
            << "registry and drop out of --include/--exclude. Fix the name in the "
            << "batch that produced it; do NOT extend the table.";
    }
}

TEST(Registry, NoDuplicateRegistrations) {
    std::set<std::string> seen;
    for(const auto& value : binwalk::builtin_signatures()) {
        EXPECT_TRUE(seen.insert(value.name).second)
            << "signature name \"" << value.name << "\" is registered by more than "
            << "one batch. Each of the 111 registry entries has exactly one owner.";
    }
}

TEST(Registry, RegistrationOrderMatchesUpstreamPrecedence) {

    const auto& expected = expected_registration_order();
    std::size_t previous = 0;
    std::string previous_name;
    for(const auto& value : binwalk::builtin_signatures()) {
        const auto found = std::find(expected.begin(), expected.end(), value.name);
        if(found == expected.end()) {
            continue;
        }
        const auto index = static_cast<std::size_t>(std::distance(expected.begin(), found));
        EXPECT_GE(index, previous)
            << "\"" << value.name << "\" (upstream index " << index << ") is registered "
            << "after \"" << previous_name << "\" (upstream index " << previous << "). "
            << "Overlap resolution would differ from upstream.";
        previous = index;
        previous_name = value.name;
    }
}

TEST(Registry, RegistrySizeNeverExceedsUpstream) {
    EXPECT_LE(binwalk::builtin_signatures().size(), expected_registration_order().size());
}
