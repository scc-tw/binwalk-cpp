#include <binwalk/builtin.hpp>

#include "formats/b10a_kernels.hpp"
#include "formats/b10b_executables.hpp"
#include "formats/b1_compression.hpp"
#include "formats/b2_media.hpp"
#include "formats/b3_constants.hpp"
#include "formats/b4_encrypted.hpp"
#include "formats/b5_vendorhdr.hpp"
#include "formats/b6_vendorcarve.hpp"
#include "formats/b7_archives.hpp"
#include "formats/b8a_filesystems.hpp"
#include "formats/b8b_volumes.hpp"
#include "formats/b9a_squashfs.hpp"
#include "formats/b9b_jffs2_yaffs.hpp"
#include "formats/b9c_ubi.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <utility>
#include <vector>
namespace binwalk {
namespace {

constexpr std::array<const char*, 111> upstream_registration_order{
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

[[nodiscard]] std::size_t registration_rank(const std::string& name) noexcept {
    for(std::size_t index = 0; index < upstream_registration_order.size(); ++index) {
        if(name == upstream_registration_order[index]) {
            return index;
        }
    }
    return upstream_registration_order.size();
}

}

std::vector<signature> builtin_signatures() {
    std::vector<signature> signatures;

    const auto append = [&signatures](std::vector<signature> batch) {
        signatures.insert(
            signatures.end(),
            std::make_move_iterator(batch.begin()),
            std::make_move_iterator(batch.end())
        );
    };

    append(formats::b1_compression_signatures());
    append(formats::b2_media_signatures());
    append(formats::b3_constants_signatures());
    append(formats::b4_encrypted_signatures());
    append(formats::b5_vendorhdr_signatures());
    append(formats::b6_vendorcarve_signatures());
    append(formats::b7_archives_signatures());
    append(formats::b8a_filesystems_signatures());
    append(formats::b8b_volumes_signatures());
    append(formats::b9a_squashfs_signatures());
    append(formats::b9b_jffs2_yaffs_signatures());
    append(formats::b9c_ubi_signatures());
    append(formats::b10a_kernels_signatures());
    append(formats::b10b_executables_signatures());

    std::vector<std::pair<std::size_t, signature>> ranked;
    ranked.reserve(signatures.size());
    for(auto& value : signatures) {
        const auto rank = registration_rank(value.name);
        ranked.emplace_back(rank, std::move(value));
    }
    std::stable_sort(
        ranked.begin(),
        ranked.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; }
    );

    signatures.clear();
    for(auto& entry : ranked) {
        signatures.push_back(std::move(entry.second));
    }
    return signatures;
}

}
