#include <binwalk/binary_reader.hpp>
#include <binwalk/builtin.hpp>

#include "builtin_extractors.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace binwalk {
namespace {

struct bmp_format {};
struct gzip_format {};
struct jpeg_format {};
struct mbr_format {};
struct pdf_format {};
struct png_format {};
struct riff_format {};

[[nodiscard]] bool bytes_equal(
    byte_view data,
    std::size_t offset,
    const std::vector<std::uint8_t>& expected
) noexcept {
    if(!data.contains(offset, expected.size())) {
        return false;
    }
    for(std::size_t index = 0; index < expected.size(); ++index) {
        if(data[offset + index] != expected[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string epoch_to_string(std::uint32_t timestamp) {
    const auto value = static_cast<std::time_t>(timestamp);
    std::tm utc{};
#if defined(_WIN32)
    if(gmtime_s(&utc, &value) != 0) {
        return {};
    }
#else
    if(gmtime_r(&value, &utc) == nullptr) {
        return {};
    }
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

} // namespace

template<>
struct format_traits<bmp_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "bmp"; }
    static std::string description() { return "BMP image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'B', 'M'}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "bmp_built_in", detail::extract_bmp, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t file_header_size = 14;
        constexpr std::size_t minimum_header_size = file_header_size + 4;
        if(!data.contains(offset, minimum_header_size)) {
            return std::nullopt;
        }

        binary_reader<byte_order::little> reader(data);
        const auto file_size = reader.read<std::uint32_t>(offset + 2);
        const auto pixel_offset = reader.read<std::uint32_t>(offset + 10);
        const auto dib_size = reader.read<std::uint32_t>(offset + 14);
        static constexpr std::array<std::uint32_t, 4> valid_dib_sizes{12, 40, 108, 124};
        const auto available = data.size() - offset;
        if(!file_size || !pixel_offset || !dib_size
            || *file_size == 0
            || *pixel_offset == 0
            || *file_size > available
            || *pixel_offset > available
            || std::find(valid_dib_sizes.begin(), valid_dib_sizes.end(), *dib_size)
                == valid_dib_sizes.end()
            || *pixel_offset < file_header_size + *dib_size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *file_size;
        result.confidence = confidence_medium;
        result.description = "BMP image, total size: " + std::to_string(*file_size);
        return result;
    }
};

template<>
struct format_traits<gzip_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "gzip"; }
    static std::string description() { return "gzip compressed data"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x1f, 0x8b, 0x08}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "gzip_built_in", detail::extract_gzip};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t trailer_size = 8;
        const auto info = detail::inspect_gzip(data, offset);
        if(!info) {
            return std::nullopt;
        }
        const auto total_size = info->header_size + info->deflate_size + trailer_size;
        if(!data.contains(offset, total_size)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_high;
        result.description = description() + ",";
        if(!info->original_name.empty()) {
            result.description += " original file name: \"" + info->original_name + "\",";
        }
        result.description += " operating system: " + info->operating_system
            + ", timestamp: " + epoch_to_string(info->timestamp)
            + ", total size: " + std::to_string(total_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<jpeg_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "jpeg"; }
    static std::string description() { return "JPEG image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
            {0xff, 0xd8, 0xff, 0xe1},
            {0xff, 0xd8, 0xff, 0xdb}
        };
    }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal,
            "jpeg_built_in",
            detail::extract_jpeg,
            {}, {}, {}, {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static constexpr std::array<std::uint8_t, 12> no_length_markers{
            0x00, 0x01, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9
        };
        static constexpr std::array<std::uint8_t, 9> scan_skip_markers{
            0x00, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
        };
        constexpr std::uint8_t marker_prefix = 0xff;
        constexpr std::uint8_t start_of_scan = 0xda;
        constexpr std::uint8_t end_of_image = 0xd9;

        std::size_t cursor = offset;
        while(data.contains(cursor, 2)) {
            if(data[cursor] != marker_prefix) {
                return std::nullopt;
            }
            const auto marker = data[cursor + 1];
            cursor += 2;

            if(std::find(no_length_markers.begin(), no_length_markers.end(), marker)
                == no_length_markers.end()) {
                binary_reader<byte_order::big> reader(data);
                const auto marker_size = reader.read<std::uint16_t>(cursor);
                if(!marker_size || *marker_size < 2 || !data.contains(cursor, *marker_size)) {
                    return std::nullopt;
                }
                cursor += *marker_size;
            }

            if(marker == start_of_scan) {
                bool found_next_marker = false;
                while(data.contains(cursor, 2)) {
                    if(data[cursor] == marker_prefix
                        && std::find(
                            scan_skip_markers.begin(), scan_skip_markers.end(), data[cursor + 1]
                        ) == scan_skip_markers.end()) {
                        found_next_marker = true;
                        break;
                    }
                    ++cursor;
                }
                if(!found_next_marker) {
                    return std::nullopt;
                }
            }

            if(marker == end_of_image) {
                signature_result result;
                result.offset = offset;
                result.size = cursor - offset;
                result.confidence = confidence_medium;
                result.description = "JPEG image, total size: " + std::to_string(result.size)
                    + " bytes";
                result.extraction_declined = offset == 0 && result.size == data.size();
                return result;
            }
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<mbr_format> {
    static constexpr bool short_signature = true;
    static constexpr std::size_t magic_offset = 0x1fe;
    static constexpr bool always_display = false;

    static std::string name() { return "mbr"; }
    static std::string description() { return "DOS Master Boot Record"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x55, 0xaa}}; }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "mbr_built_in", detail::extract_mbr};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t block_size = 512;
        constexpr std::size_t partition_table_offset = 446;
        constexpr std::size_t partition_entry_size = 16;
        constexpr std::size_t partition_count = 4;
        if(offset != magic_offset || !data.contains(0, block_size)) {
            return std::nullopt;
        }

        struct partition {
            std::uint64_t start;
            std::uint64_t size;
            std::string name;
        };
        std::vector<partition> partitions;
        std::uint64_t image_size = 0;
        binary_reader<byte_order::little> reader(data);

        const auto partition_name = [](std::uint8_t type) -> std::string {
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
        };

        for(std::size_t index = 0; index < partition_count; ++index) {
            const auto entry = partition_table_offset + index * partition_entry_size;
            const auto status = data[entry];
            const auto type = data[entry + 4];
            const auto lba_start = reader.read<std::uint32_t>(entry + 8);
            const auto lba_count = reader.read<std::uint32_t>(entry + 12);
            if(!lba_start || !lba_count || (status != 0 && status != 0x80)) {
                continue;
            }
            if(type == 0 && *lba_count == 0) {
                continue;
            }

            const auto start = static_cast<std::uint64_t>(*lba_start) * block_size;
            const auto size = static_cast<std::uint64_t>(*lba_count) * block_size;
            if(start > data.size() || size > data.size() - start) {
                continue;
            }
            const auto end = start + size;
            image_size = std::max(image_size, end);
            if(start != 0) {
                partitions.push_back({start, size, partition_name(type)});
            }
        }

        if(partitions.empty() || image_size <= block_size * 2) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = 0;
        result.size = image_size;
        result.confidence = confidence_medium;
        result.description = description();
        for(const auto& value : partitions) {
            result.description += ", partition: " + value.name;
        }
        result.description += ", image size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<pdf_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "pdf"; }
    static std::string description() { return "PDF document"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'%', 'P', 'D', 'F', '-', '1', '.'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t minimum_size = 16;
        if(!data.contains(offset, minimum_size)) {
            return std::nullopt;
        }
        const auto minor = data[offset + 7];
        if(minor < '0' || minor > '9') {
            return std::nullopt;
        }

        for(std::size_t cursor = offset + 8; cursor < offset + minimum_size; ++cursor) {
            const auto value = data[cursor];
            if(value == '\n' || value == '\r') {
                continue;
            }
            if(value == '%') {
                signature_result result;
                result.offset = offset;
                result.description = "PDF document, version 1.";
                result.description.push_back(static_cast<char>(minor));
                return result;
            }
            break;
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<png_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "png"; }
    static std::string description() { return "PNG image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 'I', 'H', 'D', 'R'}};
    }
    static binwalk::extractor extractor() {
        return {extractor_type::internal, "png_built_in", detail::extract_png, {}, {}, {}, {}, true};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static const std::vector<std::uint8_t> png_prefix{
            0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
        };
        if(!bytes_equal(data, offset, png_prefix)) {
            return std::nullopt;
        }

        binary_reader<byte_order::big> reader(data);
        std::size_t cursor = offset + png_prefix.size();
        bool first_chunk = true;

        while(data.contains(cursor, 12)) {
            const auto payload_size = reader.read<std::uint32_t>(cursor);
            const auto chunk_type = reader.read<std::uint32_t>(cursor + 4);
            if(!payload_size || !chunk_type) {
                return std::nullopt;
            }

            constexpr std::uint32_t ihdr = 0x49484452U;
            constexpr std::uint32_t iend = 0x49454e44U;
            if(first_chunk && (*chunk_type != ihdr || *payload_size != 13)) {
                return std::nullopt;
            }
            first_chunk = false;

            constexpr std::size_t chunk_overhead = 12;
            if(*payload_size > std::numeric_limits<std::size_t>::max() - chunk_overhead) {
                return std::nullopt;
            }
            const auto chunk_size = static_cast<std::size_t>(*payload_size) + chunk_overhead;
            if(!data.contains(cursor, chunk_size)) {
                return std::nullopt;
            }
            cursor += chunk_size;

            if(*chunk_type == iend) {
                if(*payload_size != 0) {
                    return std::nullopt;
                }
                signature_result result;
                result.offset = offset;
                result.size = cursor - offset;
                result.confidence = confidence_high;
                result.description = "PNG image, total size: " + std::to_string(result.size) + " bytes";
                result.extraction_declined = offset == 0;
                return result;
            }
        }
        return std::nullopt;
    }
};

template<>
struct format_traits<riff_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "riff"; }
    static std::string description() { return "RIFF image"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{'R', 'I', 'F', 'F'}}; }
    static binwalk::extractor extractor() {
        return {
            extractor_type::internal,
            "riff_built_in",
            detail::extract_riff,
            {}, {}, {}, {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        if(!data.contains(offset, 12)) {
            return std::nullopt;
        }
        binary_reader<byte_order::little> reader(data);
        const auto payload_size = reader.read<std::uint32_t>(offset + 4);
        if(!payload_size) {
            return std::nullopt;
        }
        const auto total_size = static_cast<std::uint64_t>(*payload_size) + 8;
        if(total_size > data.size() - offset) {
            return std::nullopt;
        }

        std::string chunk_type;
        for(std::size_t index = 0; index < 4; ++index) {
            const auto value = data[offset + 8 + index];
            if(value > 0x7f) {
                return std::nullopt;
            }
            chunk_type.push_back(static_cast<char>(value));
        }
        while(!chunk_type.empty()
            && std::isspace(static_cast<unsigned char>(chunk_type.back())) != 0) {
            chunk_type.pop_back();
        }
        while(!chunk_type.empty()
            && std::isspace(static_cast<unsigned char>(chunk_type.front())) != 0) {
            chunk_type.erase(chunk_type.begin());
        }

        signature_result result;
        result.offset = offset;
        result.size = total_size;
        result.confidence = confidence_medium;
        result.description = "RIFF image, encoding type: " + chunk_type
            + ", total size: " + std::to_string(result.size) + " bytes";
        result.extraction_declined = offset == 0 && result.size == data.size();
        return result;
    }
};

std::vector<signature> builtin_signatures() {
    return make_signatures(type_list<
        gzip_format,
        bmp_format,
        pdf_format,
        png_format,
        jpeg_format,
        riff_format,
        mbr_format
    >{});
}

} // namespace binwalk
