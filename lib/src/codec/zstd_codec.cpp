#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_ZSTD)
#include <vector>

#include <zstd.h>
#endif
namespace binwalk::codec_detail {

bool zstd_backend_available() noexcept {
#if defined(BINWALK_HAS_ZSTD)
    return true;
#else
    return false;
#endif
}

codec_result decompress_zstd(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_ZSTD)
    (void)data;
    (void)offset;
    (void)sink;
    (void)options;
    return unsupported_result();
#else
    (void)options;

    if(!data.contains(offset, 0)) {
        return make_result(codec_status::invalid_data);
    }
    const std::size_t available = data.size() - offset;
    if(available == 0) {
        return make_result(codec_status::invalid_data);
    }

    ZSTD_DStream* stream = ZSTD_createDStream();
    if(stream == nullptr) {
        return make_result(codec_status::internal_error);
    }
    if(ZSTD_isError(ZSTD_initDStream(stream)) != 0) {
        (void)ZSTD_freeDStream(stream);
        return make_result(codec_status::internal_error);
    }

    std::size_t chunk_size = ZSTD_DStreamOutSize();
    if(chunk_size == 0 || chunk_size > 4u * 1024u * 1024u) {
        chunk_size = codec_chunk_size;
    }
    std::vector<std::uint8_t> chunk(chunk_size);

    ZSTD_inBuffer input{data.data() + offset, available, 0};
    std::uint64_t produced = 0;
    codec_status status = codec_status::internal_error;

    for(;;) {
        ZSTD_outBuffer output{chunk.data(), chunk.size(), 0};
        const std::size_t before_in = input.pos;
        const std::size_t code = ZSTD_decompressStream(stream, &output, &input);
        if(ZSTD_isError(code) != 0) {
            status = codec_status::invalid_data;
            break;
        }
        if(output.pos > 0) {
            if(!sink.write(chunk.data(), output.pos)) {
                status = sink.status();
                break;
            }
            produced += output.pos;
        }
        if(code == 0) {

            status = codec_status::ok;
            break;
        }
        if(input.pos >= input.size) {

            status = codec_status::truncated_data;
            break;
        }
        if(input.pos == before_in && output.pos == 0) {
            status = codec_status::invalid_data;
            break;
        }
    }

    const std::size_t consumed = input.pos;
    (void)ZSTD_freeDStream(stream);

    if(status != codec_status::ok) {

        return make_result(status, consumed, retained_output(status, produced));
    }
    return make_result(codec_status::ok, consumed, produced);
#endif
}

}
