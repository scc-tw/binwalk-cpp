#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_LZ4)
#include <vector>

#include <lz4frame.h>
#endif
namespace binwalk::codec_detail {

bool lz4_backend_available() noexcept {
#if defined(BINWALK_HAS_LZ4)
    return true;
#else
    return false;
#endif
}

namespace {

constexpr std::size_t lz4_min_match = 4u;

}

#if defined(BINWALK_HAS_LZ4)
namespace {

constexpr std::size_t lz4_history = 65536u;

constexpr std::uint32_t lz4_legacy_magic = 0x184C2102u;
constexpr std::uint32_t lz4_frame_magic = 0x184D2204u;
constexpr std::uint32_t lz4_skippable_mask = 0xFFFFFFF0u;
constexpr std::uint32_t lz4_skippable_base = 0x184D2A50u;

constexpr std::size_t lz4_legacy_block_output = 8u * 1024u * 1024u;

constexpr std::size_t lz4_legacy_block_input =
    lz4_legacy_block_output + (lz4_legacy_block_output / 255u) + 16u;

[[nodiscard]] std::uint32_t read_le32(const std::uint8_t* src) noexcept {
    return static_cast<std::uint32_t>(src[0])
        | (static_cast<std::uint32_t>(src[1]) << 8)
        | (static_cast<std::uint32_t>(src[2]) << 16)
        | (static_cast<std::uint32_t>(src[3]) << 24);
}

[[nodiscard]] bool is_lz4_container_magic(std::uint32_t value) noexcept {
    return value == lz4_legacy_magic
        || value == lz4_frame_magic
        || (value & lz4_skippable_mask) == lz4_skippable_base;
}

}
#endif

lz4_block_outcome decode_lz4_block_sequence(
    const std::uint8_t* src,
    std::size_t src_size,
    window_writer& out,
    const std::uint64_t* output_target
) {
    const std::uint64_t start_produced = out.produced();
    std::size_t cursor = 0;

    for(;;) {
        const std::uint64_t emitted = out.produced() - start_produced;
        if(output_target != nullptr && emitted >= *output_target) {
            break;
        }
        if(cursor >= src_size) {
            if(output_target != nullptr) {

                return {codec_status::truncated_data, cursor};
            }
            break;
        }

        const std::uint8_t token = src[cursor];
        ++cursor;

        std::size_t literals = static_cast<std::size_t>(token >> 4);
        if(literals == 15u) {
            for(;;) {
                if(cursor >= src_size) {
                    return {codec_status::truncated_data, cursor};
                }
                const std::uint8_t extra = src[cursor];
                ++cursor;
                if(literals > SIZE_MAX - extra) {
                    return {codec_status::invalid_data, cursor};
                }
                literals += extra;
                if(extra != 255u) {
                    break;
                }
            }
        }

        if(literals > src_size - cursor) {

            const std::size_t partial = src_size - cursor;
            if(partial > 0 && !out.append(src + cursor, partial)) {
                return {out.status(), cursor};
            }
            return {codec_status::truncated_data, src_size};
        }
        if(literals > 0) {
            if(!out.append(src + cursor, literals)) {
                return {out.status(), cursor};
            }
            cursor += literals;
        }

        if(cursor == src_size) {
            continue;
        }
        if(output_target != nullptr
            && (out.produced() - start_produced) >= *output_target) {

            continue;
        }
        if(src_size - cursor < 2u) {
            return {codec_status::truncated_data, cursor};
        }

        const std::size_t distance = static_cast<std::size_t>(src[cursor])
            | (static_cast<std::size_t>(src[cursor + 1]) << 8);
        cursor += 2u;

        std::size_t match = static_cast<std::size_t>(token & 0x0Fu);
        if(match == 15u) {
            for(;;) {
                if(cursor >= src_size) {
                    return {codec_status::truncated_data, cursor};
                }
                const std::uint8_t extra = src[cursor];
                ++cursor;
                if(match > SIZE_MAX - extra) {
                    return {codec_status::invalid_data, cursor};
                }
                match += extra;
                if(extra != 255u) {
                    break;
                }
            }
        }
        match += lz4_min_match;

        if(distance == 0) {
            return {codec_status::invalid_data, cursor};
        }
        if(!out.copy_match(distance, match)) {
            return {out.status(), cursor};
        }
    }

    if(output_target != nullptr && (out.produced() - start_produced) != *output_target) {

        return {codec_status::invalid_data, cursor};
    }
    return {codec_status::ok, cursor};
}

codec_result decompress_lz4(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_LZ4)
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

    if(id == codec_id::lz4_block) {
        if(!options.expected_output_size.has_value()) {

            return make_result(codec_status::invalid_data);
        }
        const std::uint64_t target = *options.expected_output_size;
        if(target > options.max_output_size) {

            return make_result(codec_status::output_limit_exceeded);
        }

        window_writer writer(sink, lz4_history);
        const lz4_block_outcome outcome =
            decode_lz4_block_sequence(base, available, writer, &target);
        if(outcome.status != codec_status::ok) {
            return finish_partial(writer, outcome.status, outcome.input_used);
        }
        if(!writer.flush()) {
            return make_result(writer.status(), outcome.input_used, 0);
        }
        return make_result(codec_status::ok, outcome.input_used, writer.produced());
    }

    if(id == codec_id::lz4_legacy) {
        if(available < 4u || read_le32(base) != lz4_legacy_magic) {
            return make_result(codec_status::invalid_data);
        }

        window_writer writer(sink, lz4_history);
        std::size_t cursor = 4u;
        std::size_t blocks = 0;

        for(;;) {
            if(available - cursor < 4u) {
                break;
            }
            const std::uint32_t declared = read_le32(base + cursor);
            if(is_lz4_container_magic(declared)) {

                break;
            }
            if(declared == 0 || declared > lz4_legacy_block_input) {
                break;
            }
            const std::size_t block_size = static_cast<std::size_t>(declared);
            if(block_size > available - cursor - 4u) {

                const std::size_t partial = available - cursor - 4u;
                if(partial > 0) {
                    (void)decode_lz4_block_sequence(
                        base + cursor + 4u, partial, writer, nullptr);
                }
                return finish_partial(writer, codec_status::truncated_data, available);
            }

            const std::uint64_t before = writer.produced();
            const lz4_block_outcome outcome =
                decode_lz4_block_sequence(base + cursor + 4u, block_size, writer, nullptr);
            if(outcome.status != codec_status::ok) {
                if(blocks == 0
                    || outcome.status == codec_status::output_limit_exceeded
                    || outcome.status == codec_status::write_error) {

                    return finish_partial(
                        writer, outcome.status, cursor + 4u + outcome.input_used);
                }

                break;
            }
            if(writer.produced() - before > lz4_legacy_block_output) {
                return make_result(codec_status::invalid_data, cursor, 0);
            }

            cursor += 4u + block_size;
            ++blocks;
        }

        if(blocks == 0) {
            return make_result(codec_status::invalid_data, cursor, 0);
        }
        if(!writer.flush()) {
            return make_result(writer.status(), cursor, 0);
        }
        return make_result(codec_status::ok, cursor, writer.produced());
    }

    LZ4F_dctx* context = nullptr;
    if(LZ4F_isError(LZ4F_createDecompressionContext(&context, LZ4F_VERSION)) != 0) {
        return make_result(codec_status::internal_error);
    }

    std::vector<std::uint8_t> chunk(codec_chunk_size);
    std::size_t cursor = 0;
    std::uint64_t produced = 0;
    codec_status status = codec_status::internal_error;

    for(;;) {
        if(cursor >= available) {
            status = codec_status::truncated_data;
            break;
        }
        std::size_t out_size = chunk.size();
        std::size_t in_size = available - cursor;
        const std::size_t hint =
            LZ4F_decompress(context, chunk.data(), &out_size, base + cursor, &in_size, nullptr);
        if(LZ4F_isError(hint) != 0) {
            status = codec_status::invalid_data;
            break;
        }
        cursor += in_size;
        if(out_size > 0) {
            if(!sink.write(chunk.data(), out_size)) {
                status = sink.status();
                break;
            }
            produced += out_size;
        }
        if(hint == 0) {
            status = codec_status::ok;
            break;
        }
        if(in_size == 0 && out_size == 0) {
            status = codec_status::invalid_data;
            break;
        }
    }

    (void)LZ4F_freeDecompressionContext(context);

    if(status != codec_status::ok) {

        return make_result(status, cursor, retained_output(status, produced));
    }
    return make_result(codec_status::ok, cursor, produced);
#endif
}

}
