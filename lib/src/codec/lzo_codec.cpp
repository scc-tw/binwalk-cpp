#include "backend.hpp"

#include <cstddef>
#include <cstdint>
namespace binwalk::codec_detail {

bool lzo_backend_available() noexcept {
#if defined(BINWALK_HAS_LZO)
    return true;
#else
    return false;
#endif
}

#if defined(BINWALK_HAS_LZO)
namespace {

constexpr std::size_t lzo_history = 65536u;

constexpr std::size_t lzo_max_run = 1u << 30;

class lzo_reader {
public:
    lzo_reader(const std::uint8_t* src, std::size_t size) noexcept
        : src_(src), size_(size) {}

    [[nodiscard]] bool have(std::size_t count) const noexcept {
        return size_ - position_ >= count;
    }

    [[nodiscard]] std::size_t remaining() const noexcept { return size_ - position_; }

    [[nodiscard]] bool byte(std::uint8_t& value) noexcept {
        if(position_ >= size_) {
            return false;
        }
        value = src_[position_];
        ++position_;
        return true;
    }

    [[nodiscard]] bool peek(std::uint8_t& value) const noexcept {
        if(position_ >= size_) {
            return false;
        }
        value = src_[position_];
        return true;
    }

    [[nodiscard]] const std::uint8_t* cursor() const noexcept { return src_ + position_; }
    [[nodiscard]] std::size_t position() const noexcept { return position_; }
    void skip(std::size_t count) noexcept { position_ += count; }

private:
    const std::uint8_t* src_ = nullptr;
    std::size_t size_ = 0;
    std::size_t position_ = 0;
};

enum class lzo_phase {
    top,
    first_literal_run,
    match,
    match_done,
    match_next
};

[[nodiscard]] bool copy_literal_run(
    lzo_reader& in,
    window_writer& writer,
    std::size_t length,
    codec_status& status
) {
    const bool short_run = !in.have(length);
    const std::size_t usable = short_run ? in.remaining() : length;
    if(usable > 0 && !writer.append(in.cursor(), usable)) {
        status = writer.status();
        return false;
    }
    in.skip(usable);
    if(short_run) {
        status = codec_status::truncated_data;
        return false;
    }
    return true;
}

[[nodiscard]] bool read_length_extension(
    lzo_reader& in,
    std::size_t base,
    std::size_t& length,
    codec_status& status
) {
    for(;;) {
        std::uint8_t value = 0;
        if(!in.byte(value)) {
            status = codec_status::truncated_data;
            return false;
        }
        if(value != 0) {
            length += base + static_cast<std::size_t>(value);
            return true;
        }
        length += 255u;
        if(length > lzo_max_run) {
            status = codec_status::invalid_data;
            return false;
        }
    }
}

}
#endif

codec_result decompress_lzo(
    byte_view data,
    std::size_t offset,
    output_sink& sink,
    const codec_options& options
) {
#if !defined(BINWALK_HAS_LZO)
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
    if(!options.expected_output_size.has_value()) {
        return make_result(codec_status::invalid_data);
    }
    const std::uint64_t target = *options.expected_output_size;
    if(target > options.max_output_size) {

        return make_result(codec_status::output_limit_exceeded);
    }

    lzo_reader in(data.data() + offset, available);
    window_writer writer(sink, lzo_history);

    codec_status status = codec_status::invalid_data;
    lzo_phase phase = lzo_phase::top;
    std::size_t token = 0;
    std::size_t pending = 0;
    bool finished = false;

    {
        std::uint8_t first = 0;
        if(!in.peek(first)) {
            return make_result(codec_status::truncated_data, 0, 0);
        }
        if(first > 17u) {
            in.skip(1);
            const std::size_t run = static_cast<std::size_t>(first) - 17u;
            if(run < 4u) {
                pending = run;
                phase = lzo_phase::match_next;
            } else {
                if(!copy_literal_run(in, writer, run, status)) {
                    finished = true;
                } else {
                    phase = lzo_phase::first_literal_run;
                }
            }
        }
    }

    while(!finished) {
        switch(phase) {
        case lzo_phase::top: {
            if(writer.produced() == target && !in.have(1)) {

                status = codec_status::ok;
                finished = true;
                break;
            }
            std::uint8_t value = 0;
            if(!in.byte(value)) {
                status = codec_status::truncated_data;
                finished = true;
                break;
            }
            std::size_t length = static_cast<std::size_t>(value);
            if(length >= 16u) {
                token = length;
                phase = lzo_phase::match;
                break;
            }
            if(length == 0) {
                if(!read_length_extension(in, 15u, length, status)) {
                    finished = true;
                    break;
                }
            }
            length += 3u;
            if(!copy_literal_run(in, writer, length, status)) {
                finished = true;
                break;
            }
            phase = lzo_phase::first_literal_run;
            break;
        }

        case lzo_phase::first_literal_run: {
            std::uint8_t value = 0;
            if(!in.byte(value)) {
                status = codec_status::truncated_data;
                finished = true;
                break;
            }
            const std::size_t length = static_cast<std::size_t>(value);
            if(length >= 16u) {
                token = length;
                phase = lzo_phase::match;
                break;
            }
            std::uint8_t high = 0;
            if(!in.byte(high)) {
                status = codec_status::truncated_data;
                finished = true;
                break;
            }

            const std::size_t distance = 1u + 0x0800u
                + (length >> 2)
                + (static_cast<std::size_t>(high) << 2);
            if(!writer.copy_match(distance, 3u)) {
                status = writer.status();
                finished = true;
                break;
            }
            pending = length & 3u;
            phase = lzo_phase::match_done;
            break;
        }

        case lzo_phase::match: {
            if(token >= 64u) {

                std::uint8_t high = 0;
                if(!in.byte(high)) {
                    status = codec_status::truncated_data;
                    finished = true;
                    break;
                }
                const std::size_t distance = 1u
                    + ((token >> 2) & 7u)
                    + (static_cast<std::size_t>(high) << 3);
                const std::size_t length = (token >> 5) + 1u;
                if(!writer.copy_match(distance, length)) {
                    status = writer.status();
                    finished = true;
                    break;
                }
                pending = token & 3u;
                phase = lzo_phase::match_done;
                break;
            }
            if(token >= 32u) {

                std::size_t length = token & 31u;
                if(length == 0) {
                    if(!read_length_extension(in, 31u, length, status)) {
                        finished = true;
                        break;
                    }
                }
                if(!in.have(2)) {
                    status = codec_status::truncated_data;
                    finished = true;
                    break;
                }
                const std::uint8_t low = in.cursor()[0];
                const std::uint8_t high = in.cursor()[1];
                in.skip(2);
                const std::size_t distance = 1u
                    + (static_cast<std::size_t>(low) >> 2)
                    + (static_cast<std::size_t>(high) << 6);
                if(!writer.copy_match(distance, length + 2u)) {
                    status = writer.status();
                    finished = true;
                    break;
                }
                pending = static_cast<std::size_t>(low) & 3u;
                phase = lzo_phase::match_done;
                break;
            }
            if(token >= 16u) {

                const std::size_t distance_high =
                    (token & 8u) << 11;
                std::size_t length = token & 7u;
                if(length == 0) {
                    if(!read_length_extension(in, 7u, length, status)) {
                        finished = true;
                        break;
                    }
                }
                if(!in.have(2)) {
                    status = codec_status::truncated_data;
                    finished = true;
                    break;
                }
                const std::uint8_t low = in.cursor()[0];
                const std::uint8_t high = in.cursor()[1];
                in.skip(2);
                const std::size_t distance_low =
                    (static_cast<std::size_t>(low) >> 2)
                    + (static_cast<std::size_t>(high) << 6);
                if(distance_high + distance_low == 0) {
                    status = codec_status::ok;
                    finished = true;
                    break;
                }
                const std::size_t distance = distance_high + distance_low + 0x4000u;
                if(!writer.copy_match(distance, length + 2u)) {
                    status = writer.status();
                    finished = true;
                    break;
                }
                pending = static_cast<std::size_t>(low) & 3u;
                phase = lzo_phase::match_done;
                break;
            }

            std::uint8_t high = 0;
            if(!in.byte(high)) {
                status = codec_status::truncated_data;
                finished = true;
                break;
            }
            const std::size_t distance = 1u
                + (token >> 2)
                + (static_cast<std::size_t>(high) << 2);
            if(!writer.copy_match(distance, 2u)) {
                status = writer.status();
                finished = true;
                break;
            }
            pending = token & 3u;
            phase = lzo_phase::match_done;
            break;
        }

        case lzo_phase::match_done: {
            phase = (pending == 0) ? lzo_phase::top : lzo_phase::match_next;
            break;
        }

        case lzo_phase::match_next: {
            if(!copy_literal_run(in, writer, pending, status)) {
                finished = true;
                break;
            }
            std::uint8_t value = 0;
            if(!in.byte(value)) {
                status = codec_status::truncated_data;
                finished = true;
                break;
            }
            token = static_cast<std::size_t>(value);
            phase = lzo_phase::match;
            break;
        }
        }

        if(!finished && writer.produced() > target) {

            status = codec_status::invalid_data;
            finished = true;
        }
    }

    const std::size_t consumed = in.position();

    if(status != codec_status::ok) {

        return finish_partial(writer, status, consumed);
    }
    if(writer.produced() > target) {

        return make_result(codec_status::invalid_data, consumed, 0);
    }
    if(writer.produced() != target) {

        return finish_partial(writer, codec_status::truncated_data, consumed);
    }
    if(!writer.flush()) {
        return make_result(writer.status(), consumed, 0);
    }
    return make_result(codec_status::ok, consumed, writer.produced());
#endif
}

}
