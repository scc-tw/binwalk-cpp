#pragma once

#include <binwalk/codec.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
namespace binwalk::codec_detail {

class output_sink {
public:
    explicit output_sink(std::uint64_t max_output_size) noexcept
        : max_output_size_(max_output_size) {}

    output_sink(const output_sink&) = delete;
    output_sink& operator=(const output_sink&) = delete;
    output_sink(output_sink&&) = delete;
    output_sink& operator=(output_sink&&) = delete;
    virtual ~output_sink() = default;

    [[nodiscard]] bool write(const std::uint8_t* data, std::size_t size);

    [[nodiscard]] std::uint64_t written() const noexcept { return written_; }
    [[nodiscard]] codec_status status() const noexcept { return status_; }

    [[nodiscard]] std::uint64_t limit() const noexcept { return max_output_size_; }

    [[nodiscard]] std::uint64_t remaining() const noexcept {
        return written_ >= max_output_size_ ? 0 : max_output_size_ - written_;
    }

protected:

    [[nodiscard]] virtual bool commit(const std::uint8_t* data, std::size_t size) = 0;

private:
    std::uint64_t max_output_size_ = 0;
    std::uint64_t written_ = 0;
    codec_status status_ = codec_status::ok;
};

class null_sink final : public output_sink {
public:
    explicit null_sink(std::uint64_t max_output_size) noexcept
        : output_sink(max_output_size) {}

protected:
    [[nodiscard]] bool commit(const std::uint8_t* data, std::size_t size) override;
};

class buffer_sink final : public output_sink {
public:
    buffer_sink(std::vector<std::uint8_t>& target, std::uint64_t max_output_size) noexcept
        : output_sink(max_output_size), target_(&target) {}

protected:
    [[nodiscard]] bool commit(const std::uint8_t* data, std::size_t size) override;

private:
    std::vector<std::uint8_t>* target_ = nullptr;
};

class file_sink final : public output_sink {
public:
    file_sink(std::string path, std::uint64_t max_output_size)
        : output_sink(max_output_size), path_(std::move(path)) {}
    ~file_sink() override;

    [[nodiscard]] bool finish();

    void discard();

protected:
    [[nodiscard]] bool commit(const std::uint8_t* data, std::size_t size) override;

private:
    struct state;
    std::string path_;
    state* state_ = nullptr;
};

[[nodiscard]] inline codec_result make_result(
    codec_status status,
    std::size_t input_consumed = 0,
    std::uint64_t output_size = 0
) noexcept {
    codec_result result;
    result.status = status;
    result.input_consumed = input_consumed;
    result.output_size = output_size;
    return result;
}

[[nodiscard]] inline codec_result unsupported_result() noexcept {
    return make_result(codec_status::unsupported);
}

[[nodiscard]] inline std::uint64_t retained_output(
    codec_status status,
    std::uint64_t produced
) noexcept {
    return status == codec_status::truncated_data ? produced : 0;
}

inline constexpr std::size_t codec_chunk_size = 64u * 1024u;

class window_writer {
public:
    window_writer(output_sink& sink, std::size_t history);

    window_writer(const window_writer&) = delete;
    window_writer& operator=(const window_writer&) = delete;

    [[nodiscard]] bool append(const std::uint8_t* src, std::size_t size);

    [[nodiscard]] bool copy_match(std::size_t distance, std::size_t length);

    [[nodiscard]] bool flush();

    [[nodiscard]] std::uint64_t produced() const noexcept { return produced_; }
    [[nodiscard]] codec_status status() const noexcept { return status_; }
    [[nodiscard]] bool ok() const noexcept { return status_ == codec_status::ok; }

private:
    [[nodiscard]] bool reserve_room(std::size_t wanted);
    [[nodiscard]] bool drain_to_history();
    [[nodiscard]] bool check_ceiling(std::size_t size);

    output_sink* sink_ = nullptr;
    std::vector<std::uint8_t> buffer_;
    std::size_t history_ = 0;
    std::uint64_t produced_ = 0;
    codec_status status_ = codec_status::ok;
};

[[nodiscard]] codec_result finish_partial(
    window_writer& writer,
    codec_status status,
    std::size_t input_consumed
);

struct lz4_block_outcome {
    codec_status status = codec_status::invalid_data;
    std::size_t input_used = 0;
};

[[nodiscard]] lz4_block_outcome decode_lz4_block_sequence(
    const std::uint8_t* src,
    std::size_t src_size,
    window_writer& out,
    const std::uint64_t* output_target
);

[[nodiscard]] codec_result decompress_zlib(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_bzip2(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_xz(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_lz4(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_zstd(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_lzfse(
    codec_id id,
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);
[[nodiscard]] codec_result decompress_lzo(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
);

[[nodiscard]] bool zlib_backend_available() noexcept;
[[nodiscard]] bool bzip2_backend_available() noexcept;
[[nodiscard]] bool xz_backend_available() noexcept;
[[nodiscard]] bool lz4_backend_available() noexcept;
[[nodiscard]] bool zstd_backend_available() noexcept;
[[nodiscard]] bool lzfse_backend_available() noexcept;
[[nodiscard]] bool lzo_backend_available() noexcept;

}
