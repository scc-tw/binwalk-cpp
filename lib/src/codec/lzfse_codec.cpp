#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_LZFSE)
#include <cstring>
#include <vector>

#include <lzfse.h>
#endif
namespace binwalk::codec_detail {

bool lzfse_backend_available() noexcept {
#if defined(BINWALK_HAS_LZFSE)
    return true;
#else
    return false;
#endif
}

#if defined(BINWALK_HAS_LZFSE)
namespace {

constexpr std::uint32_t lzfse_endofstream_magic = 0x24787662u;
constexpr std::uint32_t lzfse_uncompressed_magic = 0x2D787662u;
constexpr std::uint32_t lzfse_compressed_v1_magic = 0x31787662u;
constexpr std::uint32_t lzfse_compressed_v2_magic = 0x32787662u;
constexpr std::uint32_t lzfse_compressed_lzvn_magic = 0x6E787662u;

constexpr std::size_t lzfse_block_header_size = 12u;
constexpr std::size_t lzfse_endofstream_size = 4u;

constexpr std::size_t lzvn_max_payload = 64u * 1024u * 1024u;

constexpr std::size_t lzfse_min_capacity = 64u * 1024u;

[[nodiscard]] std::uint32_t read_le32(const std::uint8_t* src) noexcept {
    return static_cast<std::uint32_t>(src[0])
        | (static_cast<std::uint32_t>(src[1]) << 8)
        | (static_cast<std::uint32_t>(src[2]) << 16)
        | (static_cast<std::uint32_t>(src[3]) << 24);
}

void write_le32(std::uint8_t* dst, std::uint32_t value) noexcept {
    dst[0] = static_cast<std::uint8_t>(value & 0xFFu);
    dst[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    dst[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    dst[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

[[nodiscard]] bool is_lzfse_block_magic(std::uint32_t value) noexcept {
    return value == lzfse_endofstream_magic
        || value == lzfse_uncompressed_magic
        || value == lzfse_compressed_v1_magic
        || value == lzfse_compressed_v2_magic
        || value == lzfse_compressed_lzvn_magic;
}

[[nodiscard]] std::size_t find_endofstream(
    const std::uint8_t* base,
    std::size_t size,
    std::size_t from
) noexcept {
    static constexpr std::uint8_t marker[4] = {0x62u, 0x76u, 0x78u, 0x24u};
    if(size < lzfse_endofstream_size) {
        return static_cast<std::size_t>(-1);
    }
    for(std::size_t index = from; index + lzfse_endofstream_size <= size; ++index) {
        if(base[index] == marker[0]
            && base[index + 1] == marker[1]
            && base[index + 2] == marker[2]
            && base[index + 3] == marker[3]) {
            return index;
        }
    }
    return static_cast<std::size_t>(-1);
}

[[nodiscard]] codec_status decode_lzfse_stream(
    const std::uint8_t* src,
    std::size_t src_size,
    output_sink& sink,
    std::uint64_t& produced
) {
    produced = 0;

    const std::uint64_t ceiling = sink.limit();

    const std::uint64_t hard_cap = ceiling < UINT64_MAX ? ceiling + 1u : ceiling;

    std::uint64_t capacity = static_cast<std::uint64_t>(src_size);
    if(capacity > UINT64_MAX / 4u) {
        capacity = UINT64_MAX / 4u;
    }
    capacity *= 4u;
    if(capacity < lzfse_min_capacity) {
        capacity = lzfse_min_capacity;
    }
    if(capacity > hard_cap) {
        capacity = hard_cap;
    }

    std::vector<std::uint8_t> scratch;
    const std::size_t scratch_size = lzfse_decode_scratch_size();
    if(scratch_size > 0) {
        scratch.resize(scratch_size);
    }

    std::vector<std::uint8_t> destination;

    for(;;) {
        if(capacity > static_cast<std::uint64_t>(SIZE_MAX)) {
            return codec_status::output_limit_exceeded;
        }
        const std::size_t want = static_cast<std::size_t>(capacity);
        destination.assign(want, 0u);

        const std::size_t decoded = lzfse_decode_buffer(
            destination.data(),
            want,
            src,
            src_size,
            scratch.empty() ? nullptr : scratch.data()
        );

        if(decoded == 0) {

            if(src_size == lzfse_endofstream_size) {
                return codec_status::ok;
            }
            return codec_status::invalid_data;
        }
        if(decoded < want) {
            if(static_cast<std::uint64_t>(decoded) > ceiling) {
                return codec_status::output_limit_exceeded;
            }
            std::size_t written = 0;
            while(written < decoded) {
                const std::size_t piece = (decoded - written) < codec_chunk_size
                    ? (decoded - written)
                    : codec_chunk_size;
                if(!sink.write(destination.data() + written, piece)) {
                    return sink.status();
                }
                written += piece;
            }
            produced = static_cast<std::uint64_t>(decoded);
            return codec_status::ok;
        }

        if(capacity >= hard_cap) {
            return codec_status::output_limit_exceeded;
        }
        if(capacity > UINT64_MAX / 2u) {
            return codec_status::output_limit_exceeded;
        }
        capacity *= 2u;
        if(capacity > hard_cap) {
            capacity = hard_cap;
        }
    }
}

}
#endif

codec_result decompress_lzfse(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_LZFSE)
    (void)id;
    (void)data;
    (void)offset;
    (void)sink;
    (void)options;
    return unsupported_result();
#else
    if(!data.contains(offset, 0)) {
        return make_result(codec_status::invalid_data);
    }
    const std::size_t available = data.size() - offset;
    if(available == 0) {
        return make_result(codec_status::invalid_data);
    }
    const std::uint8_t* const base = data.data() + offset;

    const bool looks_like_container =
        available >= 4u && is_lzfse_block_magic(read_le32(base));

    if(id == codec_id::lzfse || looks_like_container) {
        if(!looks_like_container) {
            return make_result(codec_status::invalid_data);
        }

        const std::size_t terminator = find_endofstream(base, available, 0);
        if(terminator == static_cast<std::size_t>(-1)) {

            return make_result(codec_status::truncated_data);
        }
        const std::size_t consumed = terminator + lzfse_endofstream_size;

        std::uint64_t produced = 0;
        const codec_status status = decode_lzfse_stream(base, consumed, sink, produced);
        if(status != codec_status::ok) {
            return make_result(status, consumed, 0);
        }
        return make_result(codec_status::ok, consumed, produced);
    }

    if(!options.expected_output_size.has_value()) {
        return make_result(codec_status::invalid_data);
    }
    const std::uint64_t target = *options.expected_output_size;
    if(target > options.max_output_size) {
        return make_result(codec_status::output_limit_exceeded);
    }
    if(target > 0xFFFFFFFFull) {

        return make_result(codec_status::invalid_data);
    }
    if(available > lzvn_max_payload) {
        return make_result(codec_status::invalid_data);
    }

    std::vector<std::uint8_t> wrapped(
        lzfse_block_header_size + available + lzfse_endofstream_size
    );
    write_le32(wrapped.data(), lzfse_compressed_lzvn_magic);
    write_le32(wrapped.data() + 4, static_cast<std::uint32_t>(target));
    write_le32(wrapped.data() + 8, static_cast<std::uint32_t>(available));
    std::memcpy(wrapped.data() + lzfse_block_header_size, base, available);
    write_le32(wrapped.data() + lzfse_block_header_size + available, lzfse_endofstream_magic);

    std::uint64_t produced = 0;
    const codec_status status =
        decode_lzfse_stream(wrapped.data(), wrapped.size(), sink, produced);
    if(status != codec_status::ok) {
        return make_result(status, available, 0);
    }
    if(produced != target) {
        return make_result(codec_status::invalid_data, available, 0);
    }
    return make_result(codec_status::ok, available, produced);
#endif
}

}
