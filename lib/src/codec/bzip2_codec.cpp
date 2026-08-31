#include "backend.hpp"

#include <cstddef>
#include <cstdint>

#if defined(BINWALK_HAS_BZIP2)
#include <limits>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN 1
#endif
#if !defined(NOMINMAX)
#define NOMINMAX 1
#endif
#endif

#include <bzlib.h>
#endif
namespace binwalk::codec_detail {

bool bzip2_backend_available() noexcept {
#if defined(BINWALK_HAS_BZIP2)
    return true;
#else
    return false;
#endif
}

codec_result decompress_bzip2(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_BZIP2)
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

    bz_stream stream{};
    if(BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK) {
        return make_result(codec_status::internal_error);
    }

    static constexpr std::size_t max_feed =
        static_cast<std::size_t>(std::numeric_limits<unsigned int>::max());

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

            stream.next_in =
                const_cast<char*>(reinterpret_cast<const char*>(data.data() + offset + fed_total));
            stream.avail_in = static_cast<unsigned int>(feed);
            fed_total += feed;
        }

        const unsigned int before_in = stream.avail_in;
        stream.next_out = reinterpret_cast<char*>(chunk.data());
        stream.avail_out = static_cast<unsigned int>(chunk.size());
        const int code = BZ2_bzDecompress(&stream);
        const std::size_t got = chunk.size() - static_cast<std::size_t>(stream.avail_out);

        if(got > 0) {
            if(!sink.write(chunk.data(), got)) {
                status = sink.status();
                break;
            }
            produced += got;
        }

        if(code == BZ_STREAM_END) {
            status = codec_status::ok;
            break;
        }
        if(code == BZ_OK) {
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
        if(code == BZ_DATA_ERROR || code == BZ_DATA_ERROR_MAGIC) {
            status = codec_status::invalid_data;
            break;
        }
        if(code == BZ_UNEXPECTED_EOF) {
            status = codec_status::truncated_data;
            break;
        }
        status = codec_status::internal_error;
        break;
    }

    const std::size_t consumed = fed_total - static_cast<std::size_t>(stream.avail_in);
    (void)BZ2_bzDecompressEnd(&stream);

    if(status != codec_status::ok) {

        return make_result(status, consumed, retained_output(status, produced));
    }
    return make_result(codec_status::ok, consumed, produced);
#endif
}

}
