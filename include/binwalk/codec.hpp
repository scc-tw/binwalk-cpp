#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {

enum class codec_id {

    deflate,

    zlib_stream,

    gzip,

    bzip2,

    xz,

    lzma_alone,

    lz4_frame,

    lz4_legacy,

    lz4_block,

    zstd,

    lzfse,

    lzvn,

    lzo1x
};

enum class codec_status {

    ok,

    unsupported,

    invalid_data,

    truncated_data,

    output_limit_exceeded,

    write_error,

    internal_error
};

inline constexpr std::uint64_t codec_default_max_output_size = 100ULL * 1024ULL * 1024ULL;

struct codec_options {

    std::optional<std::uint64_t> expected_output_size;

    std::uint64_t max_output_size = codec_default_max_output_size;
};

struct codec_result {
    codec_status status = codec_status::internal_error;

    std::size_t input_consumed = 0;

    std::uint64_t output_size = 0;

    [[nodiscard]] bool success() const noexcept { return status == codec_status::ok; }

    [[nodiscard]] bool unsupported() const noexcept {
        return status == codec_status::unsupported;
    }
};

[[nodiscard]] BINWALK_API bool codec_available(codec_id id) noexcept;

[[nodiscard]] BINWALK_API std::string codec_name(codec_id id);

[[nodiscard]] BINWALK_API codec_result codec_decompress(
    codec_id id,
    byte_view data,
    std::size_t offset,
    const std::string* output_path,
    const codec_options& options = {}
);

[[nodiscard]] BINWALK_API codec_result codec_decompress_to_buffer(
    codec_id id,
    byte_view data,
    std::size_t offset,
    std::vector<std::uint8_t>& output,
    const codec_options& options = {}
);

}
