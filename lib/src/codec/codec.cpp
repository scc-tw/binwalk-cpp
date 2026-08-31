#include "backend.hpp"

#include <binwalk/codec.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
namespace binwalk {
namespace codec_detail {

bool output_sink::write(const std::uint8_t* data, std::size_t size) {
    if(status_ != codec_status::ok) {
        return false;
    }
    if(size == 0) {
        return true;
    }
    if(written_ > max_output_size_ || size > max_output_size_ - written_) {
        status_ = codec_status::output_limit_exceeded;
        return false;
    }
    if(!commit(data, size)) {
        status_ = codec_status::write_error;
        return false;
    }
    written_ += size;
    return true;
}

bool null_sink::commit(const std::uint8_t* data, std::size_t size) {
    (void)data;
    (void)size;
    return true;
}

bool buffer_sink::commit(const std::uint8_t* data, std::size_t size) {
    if(target_ == nullptr) {
        return false;
    }
    target_->insert(target_->end(), data, data + size);
    return true;
}

struct file_sink::state {
    std::ofstream stream;
    bool created = false;
};

file_sink::~file_sink() {
    delete state_;
}

bool file_sink::commit(const std::uint8_t* data, std::size_t size) {
    if(state_ == nullptr) {
        state_ = new state();
        state_->stream.open(path_, std::ios::binary | std::ios::trunc);
        if(!state_->stream) {
            return false;
        }
        state_->created = true;
    }
    state_->stream.write(
        reinterpret_cast<const char*>(data),
        static_cast<std::streamsize>(size)
    );
    return static_cast<bool>(state_->stream);
}

bool file_sink::finish() {
    if(state_ == nullptr) {

        std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
        const auto good = static_cast<bool>(stream);
        if(good) {
            state_ = new state();
            state_->created = true;
        }
        return good;
    }
    state_->stream.flush();
    const auto good = static_cast<bool>(state_->stream);
    state_->stream.close();
    return good;
}

void file_sink::discard() {
    if(state_ != nullptr && state_->stream.is_open()) {
        state_->stream.close();
    }

    (void)std::remove(path_.c_str());
    if(state_ != nullptr) {
        state_->created = false;
    }
}

window_writer::window_writer(output_sink& sink, std::size_t history)
    : sink_(&sink), history_(history) {
    buffer_.reserve(history_ * 2u);
}

bool window_writer::check_ceiling(std::size_t size) {
    if(status_ != codec_status::ok) {
        return false;
    }
    const std::uint64_t limit = sink_->limit();
    if(produced_ > limit || static_cast<std::uint64_t>(size) > limit - produced_) {
        status_ = codec_status::output_limit_exceeded;
        return false;
    }
    return true;
}

bool window_writer::drain_to_history() {
    if(status_ != codec_status::ok) {
        return false;
    }
    if(buffer_.size() <= history_) {
        return true;
    }
    const std::size_t emit = buffer_.size() - history_;
    if(!sink_->write(buffer_.data(), emit)) {
        status_ = sink_->status();
        if(status_ == codec_status::ok) {
            status_ = codec_status::write_error;
        }
        return false;
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(emit));
    return true;
}

bool window_writer::reserve_room(std::size_t wanted) {

    if(buffer_.size() + wanted > history_ * 2u) {
        return drain_to_history();
    }
    return true;
}

bool window_writer::append(const std::uint8_t* src, std::size_t size) {
    if(status_ != codec_status::ok) {
        return false;
    }
    if(size == 0) {
        return true;
    }
    if(!check_ceiling(size)) {
        return false;
    }
    std::size_t remaining = size;
    const std::uint8_t* cursor = src;
    while(remaining > 0) {
        const std::size_t chunk = remaining < history_ ? remaining : history_;
        if(!reserve_room(chunk)) {
            return false;
        }
        buffer_.insert(buffer_.end(), cursor, cursor + chunk);
        cursor += chunk;
        remaining -= chunk;
        produced_ += chunk;
    }
    return true;
}

bool window_writer::copy_match(std::size_t distance, std::size_t length) {
    if(status_ != codec_status::ok) {
        return false;
    }
    if(distance == 0 || distance > history_ || distance > buffer_.size()) {
        status_ = codec_status::invalid_data;
        return false;
    }
    if(length == 0) {
        return true;
    }
    if(!check_ceiling(length)) {
        return false;
    }
    std::size_t remaining = length;
    while(remaining > 0) {
        const std::size_t chunk = remaining < history_ ? remaining : history_;
        if(!reserve_room(chunk)) {
            return false;
        }

        const std::size_t start = buffer_.size() - distance;
        for(std::size_t index = 0; index < chunk; ++index) {
            const std::uint8_t value = buffer_[start + index];
            buffer_.push_back(value);
        }
        remaining -= chunk;
        produced_ += chunk;
    }
    return true;
}

bool window_writer::flush() {
    if(status_ != codec_status::ok) {
        return false;
    }
    if(buffer_.empty()) {
        return true;
    }
    if(!sink_->write(buffer_.data(), buffer_.size())) {
        status_ = sink_->status();
        if(status_ == codec_status::ok) {
            status_ = codec_status::write_error;
        }
        return false;
    }
    buffer_.clear();
    return true;
}

codec_result finish_partial(
    window_writer& writer,
    codec_status status,
    std::size_t input_consumed
) {
    if(status != codec_status::truncated_data) {
        return make_result(status, input_consumed, 0);
    }

    if(!writer.flush()) {

        return make_result(writer.status(), input_consumed, 0);
    }
    return make_result(codec_status::truncated_data, input_consumed, writer.produced());
}

namespace {

[[nodiscard]] codec_result dispatch(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
    switch(id) {
    case codec_id::deflate:
    case codec_id::zlib_stream:
    case codec_id::gzip:
        return decompress_zlib(id, data, offset, sink, options);
    case codec_id::bzip2:
        return decompress_bzip2(data, offset, sink, options);
    case codec_id::xz:
    case codec_id::lzma_alone:
        return decompress_xz(id, data, offset, sink, options);
    case codec_id::lz4_frame:
    case codec_id::lz4_legacy:
    case codec_id::lz4_block:
        return decompress_lz4(id, data, offset, sink, options);
    case codec_id::zstd:
        return decompress_zstd(data, offset, sink, options);
    case codec_id::lzfse:
    case codec_id::lzvn:
        return decompress_lzfse(id, data, offset, sink, options);
    case codec_id::lzo1x:
        return decompress_lzo(data, offset, sink, options);
    }
    codec_result result;
    result.status = codec_status::internal_error;
    return result;
}

void reconcile(codec_result& result, const output_sink& sink) {
    if(result.status == codec_status::ok && sink.status() != codec_status::ok) {
        result.status = sink.status();
    }
    if(result.status != codec_status::ok
        && result.status != codec_status::truncated_data) {
        result.output_size = 0;
        return;
    }
    result.output_size = sink.written();
}

}
}

bool codec_available(codec_id id) noexcept {
    switch(id) {
    case codec_id::deflate:
    case codec_id::zlib_stream:
    case codec_id::gzip:
        return codec_detail::zlib_backend_available();
    case codec_id::bzip2:
        return codec_detail::bzip2_backend_available();
    case codec_id::xz:
    case codec_id::lzma_alone:
        return codec_detail::xz_backend_available();
    case codec_id::lz4_frame:
    case codec_id::lz4_legacy:
    case codec_id::lz4_block:
        return codec_detail::lz4_backend_available();
    case codec_id::zstd:
        return codec_detail::zstd_backend_available();
    case codec_id::lzfse:
    case codec_id::lzvn:
        return codec_detail::lzfse_backend_available();
    case codec_id::lzo1x:
        return codec_detail::lzo_backend_available();
    }
    return false;
}

std::string codec_name(codec_id id) {
    switch(id) {
    case codec_id::deflate: return "deflate";
    case codec_id::zlib_stream: return "zlib";
    case codec_id::gzip: return "gzip";
    case codec_id::bzip2: return "bzip2";
    case codec_id::xz: return "xz";
    case codec_id::lzma_alone: return "lzma_alone";
    case codec_id::lz4_frame: return "lz4_frame";
    case codec_id::lz4_legacy: return "lz4_legacy";
    case codec_id::lz4_block: return "lz4_block";
    case codec_id::zstd: return "zstd";
    case codec_id::lzfse: return "lzfse";
    case codec_id::lzvn: return "lzvn";
    case codec_id::lzo1x: return "lzo1x";
    }
    return "unknown";
}

codec_result codec_decompress(
    codec_id id,
    byte_view data,
    std::size_t offset,
    const std::string* output_path,
    const codec_options& options
) {
    if(output_path == nullptr) {
        codec_detail::null_sink sink(options.max_output_size);
        auto result = codec_detail::dispatch(id, data, offset, sink, options);
        codec_detail::reconcile(result, sink);
        return result;
    }

    codec_detail::file_sink sink(*output_path, options.max_output_size);
    auto result = codec_detail::dispatch(id, data, offset, sink, options);
    codec_detail::reconcile(result, sink);

    const bool keep = result.status == codec_status::ok
        || result.status == codec_status::truncated_data;
    if(keep && !sink.finish()) {
        result.status = codec_status::write_error;
    }
    if(result.status != codec_status::ok
        && result.status != codec_status::truncated_data) {

        sink.discard();
        result.output_size = 0;
    }
    return result;
}

codec_result codec_decompress_to_buffer(
    codec_id id,
    byte_view data,
    std::size_t offset,
    std::vector<std::uint8_t>& output,
    const codec_options& options
) {
    output.clear();
    codec_detail::buffer_sink sink(output, options.max_output_size);
    auto result = codec_detail::dispatch(id, data, offset, sink, options);
    codec_detail::reconcile(result, sink);

    if(result.status != codec_status::ok
        && result.status != codec_status::truncated_data) {
        output.clear();
        output.shrink_to_fit();
    }
    return result;
}

}
