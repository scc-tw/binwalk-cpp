#include "builtin_extractors.hpp"

#include <binwalk/binary_reader.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string>

#if defined(BINWALK_HAS_ZLIB)
#    include <zlib.h>
#endif

namespace binwalk::detail {
namespace {

[[nodiscard]] bool write_range(
    byte_view data,
    std::uint64_t offset,
    std::uint64_t size,
    const std::filesystem::path& path
) {
    if(offset > data.size() || size > data.size() - offset) {
        return false;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if(!output) {
        return false;
    }

    constexpr std::size_t chunk_limit = 1024U * 1024U * 1024U;
    auto cursor = static_cast<std::size_t>(offset);
    auto remaining = static_cast<std::size_t>(size);
    while(remaining > 0 && output) {
        const auto chunk = std::min(remaining, chunk_limit);
        output.write(
            reinterpret_cast<const char*>(data.data() + cursor),
            static_cast<std::streamsize>(chunk)
        );
        cursor += chunk;
        remaining -= chunk;
    }
    return static_cast<bool>(output);
}

[[nodiscard]] extraction_result carve_single(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory,
    const std::string& file_name
) {
    extraction_result result;
    result.size = signature.size;
    result.success = write_range(
        data,
        signature.offset,
        signature.size,
        std::filesystem::path(output_directory) / file_name
    );
    return result;
}

#if defined(BINWALK_HAS_ZLIB)
struct raw_inflate_result {
    bool success = false;
    std::size_t input_size = 0;
    std::uint32_t adler32 = 1;
};

[[nodiscard]] raw_inflate_result inflate_raw(
    byte_view data,
    std::size_t offset,
    const std::filesystem::path* output_path
) {
    raw_inflate_result result;
    if(offset > data.size()) {
        return result;
    }

    std::ofstream output;
    if(output_path != nullptr) {
        output.open(*output_path, std::ios::binary | std::ios::trunc);
        if(!output) {
            return result;
        }
    }

    z_stream stream{};
    if(inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        return result;
    }

    constexpr std::size_t output_buffer_size = 8192;
    std::array<std::uint8_t, output_buffer_size> output_buffer{};
    std::size_t supplied = 0;
    std::uint64_t total_output = 0;
    auto adler_checksum = ::adler32(0L, Z_NULL, 0);
    const auto input_size = data.size() - offset;

    for(;;) {
        if(stream.avail_in == 0 && supplied < input_size) {
            const auto chunk = std::min<std::size_t>(
                input_size - supplied,
                std::numeric_limits<uInt>::max()
            );
            stream.next_in = const_cast<Bytef*>(
                reinterpret_cast<const Bytef*>(data.data() + offset + supplied)
            );
            stream.avail_in = static_cast<uInt>(chunk);
            supplied += chunk;
        }

        stream.next_out = reinterpret_cast<Bytef*>(output_buffer.data());
        stream.avail_out = static_cast<uInt>(output_buffer.size());
        const auto status = inflate(&stream, Z_NO_FLUSH);
        const auto produced = output_buffer.size() - stream.avail_out;
        total_output += produced;
        if(produced > 0) {
            adler_checksum = ::adler32(
                adler_checksum,
                reinterpret_cast<const Bytef*>(output_buffer.data()),
                static_cast<uInt>(produced)
            );
        }

        if(output_path != nullptr && produced > 0) {
            output.write(
                reinterpret_cast<const char*>(output_buffer.data()),
                static_cast<std::streamsize>(produced)
            );
            if(!output) {
                inflateEnd(&stream);
                return result;
            }
        }

        if(status == Z_STREAM_END) {
            result.success = total_output > 0;
            result.input_size = supplied - stream.avail_in;
            result.adler32 = static_cast<std::uint32_t>(adler_checksum);
            inflateEnd(&stream);
            return result;
        }
        if(status != Z_OK || (produced == 0 && stream.avail_in == 0 && supplied == input_size)) {
            inflateEnd(&stream);
            return result;
        }
    }
}

[[nodiscard]] std::optional<std::string> read_cstring(byte_view data, std::size_t& cursor) {
    std::string result;
    while(cursor < data.size()) {
        const auto value = data[cursor++];
        if(value == 0) {
            return result;
        }
        result.push_back(static_cast<char>(value));
    }
    return std::nullopt;
}

[[nodiscard]] std::string gzip_os_name(std::uint8_t value) {
    switch(value) {
    case 0: return "FAT filesystem (MS-DOS, OS/2, NT/Win32";
    case 1: return "Amiga";
    case 2: return "VMS (or OpenVMS)";
    case 3: return "Unix";
    case 4: return "VM/CMS";
    case 5: return "Atari TOS";
    case 6: return "HPFS filesystem (OS/2, NT)";
    case 7: return "Macintosh";
    case 8: return "Z-System";
    case 9: return "CP/M";
    case 10: return "TOPS-20";
    case 11: return "NTFS filesystem (NT)";
    case 12: return "QDOS";
    case 13: return "Acorn RISCOS";
    case 255: return "unknown";
    default: return {};
    }
}

[[nodiscard]] std::optional<gzip_info> parse_and_inflate_gzip(
    byte_view data,
    std::size_t offset,
    const std::filesystem::path* output_path
) {
    constexpr std::uint8_t flag_crc = 0x02;
    constexpr std::uint8_t flag_extra = 0x04;
    constexpr std::uint8_t flag_name = 0x08;
    constexpr std::uint8_t flag_comment = 0x10;
    constexpr std::uint8_t reserved_flags = 0xe0;
    constexpr std::size_t fixed_header_size = 10;

    if(!data.contains(offset, fixed_header_size)
        || data[offset] != 0x1f
        || data[offset + 1] != 0x8b
        || data[offset + 2] != 8) {
        return std::nullopt;
    }
    const auto flags = data[offset + 3];
    if((flags & reserved_flags) != 0) {
        return std::nullopt;
    }
    const auto operating_system = gzip_os_name(data[offset + 9]);
    if(operating_system.empty()) {
        return std::nullopt;
    }

    binary_reader<byte_order::little> reader(data);
    const auto timestamp = reader.read<std::uint32_t>(offset + 4);
    if(!timestamp) {
        return std::nullopt;
    }
    auto cursor = offset + fixed_header_size;

    if((flags & flag_extra) != 0) {
        if(!data.contains(cursor, 4)) {
            return std::nullopt;
        }
        const auto extra_size = reader.read<std::uint16_t>(cursor + 2);
        if(!extra_size || !data.contains(cursor, 4U + *extra_size)) {
            return std::nullopt;
        }
        cursor += 4U + *extra_size;
    }

    std::string original_name;
    if((flags & flag_name) != 0) {
        auto value = read_cstring(data, cursor);
        if(!value) {
            return std::nullopt;
        }
        original_name = std::move(*value);
    }
    if((flags & flag_comment) != 0 && !read_cstring(data, cursor)) {
        return std::nullopt;
    }
    if((flags & flag_crc) != 0) {
        if(!data.contains(cursor, 2)) {
            return std::nullopt;
        }
        cursor += 2;
    }

    const auto inflated = inflate_raw(data, cursor, output_path);
    if(!inflated.success) {
        return std::nullopt;
    }
    return gzip_info{
        cursor - offset,
        inflated.input_size,
        operating_system,
        original_name,
        *timestamp
    };
}
#endif

[[nodiscard]] std::string mbr_partition_name(std::uint8_t type) {
    switch(type) {
    case 0x07: return "NTFS_IFS_HPFS_exFAT";
    case 0x0b:
    case 0x0c: return "FAT32";
    case 0x43:
    case 0x83: return "Linux";
    case 0x4d: return "QNX Primary Volume";
    case 0x4e: return "QNX Secondary Volume";
    case 0x81: return "Minix";
    case 0x8e: return "Linux LVM";
    case 0x96: return "ISO-9660";
    case 0xb1:
    case 0xb2:
    case 0xb3: return "QNXv6 File System";
    case 0xee: return "EFI GPT Protective";
    case 0xef: return "EFI System Partition";
    default: return "Unknown";
    }
}

} // namespace

std::optional<gzip_info> inspect_gzip(byte_view data, std::size_t offset) {
#if defined(BINWALK_HAS_ZLIB)
    return parse_and_inflate_gzip(data, offset, nullptr);
#else
    (void)data;
    (void)offset;
    return std::nullopt;
#endif
}

std::optional<zlib_info> inspect_zlib(byte_view data, std::size_t offset) {
#if defined(BINWALK_HAS_ZLIB)
    constexpr std::size_t header_size = 2;
    constexpr std::size_t checksum_size = 4;
    if(!data.contains(offset, header_size)) {
        return std::nullopt;
    }
    const auto inflated = inflate_raw(data, offset + header_size, nullptr);
    if(!inflated.success) {
        return std::nullopt;
    }
    const auto checksum_offset = offset + header_size + inflated.input_size;
    binary_reader<byte_order::big> reader(data);
    const auto reported_checksum = reader.read<std::uint32_t>(checksum_offset);
    if(!reported_checksum || *reported_checksum != inflated.adler32) {
        return std::nullopt;
    }
    return zlib_info{
        inflated.input_size,
        header_size + inflated.input_size + checksum_size
    };
#else
    (void)data;
    (void)offset;
    return std::nullopt;
#endif
}

extraction_result extract_bmp(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    return carve_single(data, signature, output_directory, "image.bmp");
}

extraction_result extract_jpeg(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    return carve_single(data, signature, output_directory, "image.jpg");
}

extraction_result extract_gzip(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    extraction_result result;
#if defined(BINWALK_HAS_ZLIB)
    const auto output_path = std::filesystem::path(output_directory) / "decompressed.bin";
    const auto info = parse_and_inflate_gzip(
        data, static_cast<std::size_t>(signature.offset), &output_path
    );
    if(info) {
        result.size = info->deflate_size;
        result.success = true;
    }
#else
    (void)data;
    (void)signature;
    (void)output_directory;
#endif
    return result;
}

extraction_result extract_png(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    return carve_single(data, signature, output_directory, "image.png");
}

extraction_result extract_riff(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    std::string output_name = "image.riff";
    if(data.contains(static_cast<std::size_t>(signature.offset) + 8, 4)
        && data[static_cast<std::size_t>(signature.offset) + 8] == 'W'
        && data[static_cast<std::size_t>(signature.offset) + 9] == 'A'
        && data[static_cast<std::size_t>(signature.offset) + 10] == 'V'
        && data[static_cast<std::size_t>(signature.offset) + 11] == 'E') {
        output_name = "video.wav";
    }
    return carve_single(data, signature, output_directory, output_name);
}

extraction_result extract_zlib(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    extraction_result result;
#if defined(BINWALK_HAS_ZLIB)
    constexpr std::size_t header_size = 2;
    const auto output_path = std::filesystem::path(output_directory) / "decompressed.bin";
    const auto inflated = inflate_raw(
        data,
        static_cast<std::size_t>(signature.offset) + header_size,
        &output_path
    );
    if(!inflated.success) {
        return result;
    }
    const auto checksum_offset = static_cast<std::size_t>(signature.offset)
        + header_size + inflated.input_size;
    binary_reader<byte_order::big> reader(data);
    const auto reported_checksum = reader.read<std::uint32_t>(checksum_offset);
    if(reported_checksum && *reported_checksum == inflated.adler32) {
        result.success = true;
        result.size = header_size + inflated.input_size + 4U;
    }
#else
    (void)data;
    (void)signature;
    (void)output_directory;
#endif
    return result;
}

extraction_result extract_mbr(
    byte_view data,
    const signature_result& signature,
    const std::string& output_directory
) {
    constexpr std::size_t block_size = 512;
    constexpr std::size_t partition_table_offset = 446;
    constexpr std::size_t partition_entry_size = 16;
    constexpr std::size_t partition_count = 4;

    extraction_result result;
    result.size = signature.size;
    if(!data.contains(static_cast<std::size_t>(signature.offset), block_size)) {
        return result;
    }

    binary_reader<byte_order::little> reader(data);
    std::size_t extracted_count = 0;
    for(std::size_t index = 0; index < partition_count; ++index) {
        const auto entry = static_cast<std::size_t>(signature.offset)
            + partition_table_offset + index * partition_entry_size;
        const auto status = data[entry];
        const auto type = data[entry + 4];
        const auto lba_start = reader.read<std::uint32_t>(entry + 8);
        const auto lba_count = reader.read<std::uint32_t>(entry + 12);
        if(!lba_start || !lba_count || (status != 0 && status != 0x80)
            || (type == 0 && *lba_count == 0)) {
            continue;
        }
        const auto start = static_cast<std::uint64_t>(*lba_start) * block_size;
        const auto size = static_cast<std::uint64_t>(*lba_count) * block_size;
        if(start == 0 || start > data.size() || size > data.size() - start) {
            continue;
        }
        const auto output_name = mbr_partition_name(type) + "_partition."
            + std::to_string(extracted_count);
        if(!write_range(
            data, start, size, std::filesystem::path(output_directory) / output_name
        )) {
            return result;
        }
        ++extracted_count;
    }
    result.success = extracted_count > 0;
    return result;
}

} // namespace binwalk::detail
