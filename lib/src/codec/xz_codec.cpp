#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_LZMA)
#include <limits>
#include <vector>

#include <lzma.h>
#endif
namespace binwalk::codec_detail {

bool xz_backend_available() noexcept {
#if defined(BINWALK_HAS_LZMA)
    return true;
#else
    return false;
#endif
}

#if defined(BINWALK_HAS_LZMA)
namespace {

[[nodiscard]] codec_status map_lzma_error(lzma_ret code) noexcept {
    switch(code) {
    case LZMA_FORMAT_ERROR:
    case LZMA_DATA_ERROR:
    case LZMA_OPTIONS_ERROR:
    case LZMA_UNSUPPORTED_CHECK:
        return codec_status::invalid_data;
    case LZMA_BUF_ERROR:
        return codec_status::truncated_data;
    default:
        return codec_status::internal_error;
    }
}

}
#endif

codec_result decompress_xz(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_LZMA)
    (void)id;
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

    lzma_stream stream = LZMA_STREAM_INIT;
    const std::uint64_t memlimit = std::numeric_limits<std::uint64_t>::max();
    const lzma_ret init = (id == codec_id::lzma_alone)
        ? lzma_alone_decoder(&stream, memlimit)
        : lzma_stream_decoder(&stream, memlimit, 0);
    if(init != LZMA_OK) {
        return make_result(codec_status::internal_error);
    }

    std::vector<std::uint8_t> chunk(codec_chunk_size);
    stream.next_in = data.data() + offset;
    stream.avail_in = available;

    std::uint64_t produced = 0;
    codec_status status = codec_status::internal_error;
    int idle_rounds = 0;

    for(;;) {
        const std::size_t before_in = stream.avail_in;
        stream.next_out = chunk.data();
        stream.avail_out = chunk.size();

        const lzma_ret code = lzma_code(&stream, LZMA_FINISH);
        const std::size_t got = chunk.size() - stream.avail_out;

        if(got > 0) {
            if(!sink.write(chunk.data(), got)) {
                status = sink.status();
                break;
            }
            produced += got;
        }

        if(code == LZMA_STREAM_END) {
            status = codec_status::ok;
            break;
        }
        if(code == LZMA_OK || code == LZMA_NO_CHECK || code == LZMA_GET_CHECK) {
            const bool progressed = got > 0 || stream.avail_in != before_in;
            if(!progressed) {
                if(stream.avail_in == 0) {
                    status = codec_status::truncated_data;
                    break;
                }
                if(++idle_rounds > 2) {
                    status = codec_status::invalid_data;
                    break;
                }
            } else {
                idle_rounds = 0;
            }
            continue;
        }
        status = map_lzma_error(code);
        break;
    }

    const std::size_t consumed = available - stream.avail_in;
    lzma_end(&stream);

    if(status != codec_status::ok) {

        return make_result(status, consumed, retained_output(status, produced));
    }
    return make_result(codec_status::ok, consumed, produced);
#endif
}

}
