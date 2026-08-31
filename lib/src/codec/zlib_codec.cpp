#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_ZLIB)
#include <limits>
#include <vector>

#include <zlib.h>
#endif
namespace binwalk::codec_detail {

bool zlib_backend_available() noexcept {
#if defined(BINWALK_HAS_ZLIB)
    return true;
#else
    return false;
#endif
}

#if defined(BINWALK_HAS_ZLIB)
namespace {

[[nodiscard]] int window_bits_for(codec_id id) noexcept {
    switch(id) {
    case codec_id::deflate:
        return -MAX_WBITS;
    case codec_id::gzip:
        return MAX_WBITS + 16;
    default:
        return MAX_WBITS;
    }
}

[[nodiscard]] codec_status map_inflate_error(int code) noexcept {
    switch(code) {
    case Z_DATA_ERROR:
    case Z_NEED_DICT:
        return codec_status::invalid_data;
    default:
        return codec_status::internal_error;
    }
}

}
#endif

codec_result decompress_zlib(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_ZLIB)
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

    z_stream stream{};
    if(inflateInit2(&stream, window_bits_for(id)) != Z_OK) {
        return make_result(codec_status::internal_error);
    }

    static constexpr std::size_t max_feed =
        static_cast<std::size_t>(std::numeric_limits<uInt>::max());

    std::vector<std::uint8_t> chunk(codec_chunk_size);
    std::size_t fed_total = 0;
    std::uint64_t produced = 0;
    codec_status status = codec_status::internal_error;
    int idle_rounds = 0;

    for(;;) {
        if(stream.avail_in == 0) {
            const std::size_t left = available - fed_total;
            if(left == 0) {
                status = codec_status::truncated_data;
                break;
            }
            const std::size_t feed = left > max_feed ? max_feed : left;
            stream.next_in = const_cast<Bytef*>(data.data() + offset + fed_total);
            stream.avail_in = static_cast<uInt>(feed);
            fed_total += feed;
        }

        const uInt before_in = stream.avail_in;
        stream.next_out = chunk.data();
        stream.avail_out = static_cast<uInt>(chunk.size());
        const int code = inflate(&stream, Z_NO_FLUSH);
        const std::size_t got = chunk.size() - static_cast<std::size_t>(stream.avail_out);

        if(got > 0) {
            if(!sink.write(chunk.data(), got)) {
                status = sink.status();
                break;
            }
            produced += got;
        }

        if(code == Z_STREAM_END) {
            status = codec_status::ok;
            break;
        }
        if(code == Z_OK || code == Z_BUF_ERROR) {
            const bool progressed = got > 0 || stream.avail_in != before_in;
            if(!progressed) {
                if(stream.avail_in == 0 && fed_total >= available) {
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
        status = map_inflate_error(code);
        break;
    }

    const std::size_t consumed = fed_total - static_cast<std::size_t>(stream.avail_in);
    (void)inflateEnd(&stream);

    if(status != codec_status::ok) {

        return make_result(status, consumed, retained_output(status, produced));
    }
    return make_result(codec_status::ok, consumed, produced);
#endif
}

}
