#include <binwalk/entropy.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <utility>

#if defined(BINWALK_HAS_ZLIB)
#    include <zlib.h>
#endif
namespace binwalk {
namespace {

#if defined(BINWALK_HAS_ZLIB)
void append_big_endian(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_png_chunk(
    std::vector<std::uint8_t>& output,
    const std::array<std::uint8_t, 4>& type,
    const std::vector<std::uint8_t>& data
) {
    append_big_endian(output, static_cast<std::uint32_t>(data.size()));
    const auto crc_start = output.size();
    output.insert(output.end(), type.begin(), type.end());
    output.insert(output.end(), data.begin(), data.end());

    auto checksum = ::crc32(0L, Z_NULL, 0);
    checksum = ::crc32(
        checksum,
        reinterpret_cast<const Bytef*>(output.data() + crc_start),
        static_cast<uInt>(type.size() + data.size())
    );
    append_big_endian(output, static_cast<std::uint32_t>(checksum));
}
#endif

struct rgb_image {
    rgb_image(std::uint32_t width_value, std::uint32_t height_value)
        : width(width_value), height(height_value), pixels(
            static_cast<std::size_t>(width) * height * 3U,
            0xff
        ) {}

    void set_pixel(int x, int y, std::array<std::uint8_t, 3> color) {
        if(x < 0 || y < 0 || x >= static_cast<int>(width) || y >= static_cast<int>(height)) {
            return;
        }
        const auto offset = (static_cast<std::size_t>(y) * width + static_cast<std::size_t>(x)) * 3U;
        std::copy(color.begin(), color.end(), pixels.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    void line(int x0, int y0, int x1, int y1, std::array<std::uint8_t, 3> color) {
        const auto dx = std::abs(x1 - x0);
        const auto sx = x0 < x1 ? 1 : -1;
        const auto dy = -std::abs(y1 - y0);
        const auto sy = y0 < y1 ? 1 : -1;
        auto error = dx + dy;
        for(;;) {
            set_pixel(x0, y0, color);
            if(x0 == x1 && y0 == y1) {
                break;
            }
            const auto doubled = 2 * error;
            if(doubled >= dy) {
                error += dy;
                x0 += sx;
            }
            if(doubled <= dx) {
                error += dx;
                y0 += sy;
            }
        }
    }

    std::uint32_t width;
    std::uint32_t height;
    std::vector<std::uint8_t> pixels;
};

}

std::vector<entropy_block> entropy_blocks(byte_view data, std::size_t target_block_count) {
    std::vector<entropy_block> result;
    if(data.empty() || target_block_count == 0) {
        return result;
    }

    const auto block_size = data.size() < target_block_count
        ? data.size()
        : data.size() / target_block_count;
    result.reserve((data.size() + block_size - 1) / block_size);

    for(std::size_t start = 0; start < data.size(); start += block_size) {
        const auto size = std::min(block_size, data.size() - start);
        std::array<std::size_t, 256> frequencies{};
        for(std::size_t index = 0; index < size; ++index) {
            ++frequencies[data[start + index]];
        }

        double entropy = 0.0;
        for(const auto count : frequencies) {
            if(count == 0) {
                continue;
            }
            const auto probability = static_cast<double>(count) / static_cast<double>(size);
            entropy -= probability * std::log2(probability);
        }
        result.push_back({start + size, start, static_cast<float>(entropy)});
    }
    return result;
}

bool write_entropy_png(
    const std::vector<entropy_block>& blocks,
    const std::string& output_path,
    std::uint32_t width,
    std::uint32_t height
) {
#if !defined(BINWALK_HAS_ZLIB)
    (void)blocks;
    (void)output_path;
    (void)width;
    (void)height;
    return false;
#else
    constexpr std::uint32_t minimum_dimension = 128;
    constexpr std::uint32_t maximum_dimension = 16384;
    if(blocks.empty()
        || width < minimum_dimension
        || height < minimum_dimension
        || width > maximum_dimension
        || height > maximum_dimension) {
        return false;
    }

    rgb_image image(width, height);
    constexpr int left_margin = 64;
    constexpr int right_margin = 32;
    constexpr int top_margin = 32;
    constexpr int bottom_margin = 48;
    const auto plot_width = static_cast<int>(width) - left_margin - right_margin;
    const auto plot_height = static_cast<int>(height) - top_margin - bottom_margin;
    if(plot_width <= 0 || plot_height <= 0 || blocks.back().end == 0) {
        return false;
    }

    constexpr std::array<std::uint8_t, 3> axis_color{0x20, 0x20, 0x20};
    constexpr std::array<std::uint8_t, 3> graph_color{0x1f, 0x6f, 0xd2};
    const auto axis_y = top_margin + plot_height;
    image.line(left_margin, top_margin, left_margin, axis_y, axis_color);
    image.line(left_margin, axis_y, left_margin + plot_width, axis_y, axis_color);

    const auto max_offset = static_cast<double>(blocks.back().end);
    const auto map_x = [&](std::size_t offset) {
        return left_margin + static_cast<int>(std::lround(
            static_cast<double>(offset) / max_offset * plot_width
        ));
    };
    const auto map_y = [&](float entropy) {
        const auto bounded = std::clamp(static_cast<double>(entropy), 0.0, 8.0);
        return top_margin + static_cast<int>(std::lround((8.0 - bounded) / 8.0 * plot_height));
    };

    auto previous_x = map_x(blocks.front().start);
    auto previous_y = map_y(blocks.front().entropy);
    for(const auto& block : blocks) {
        const auto start_x = map_x(block.start);
        const auto end_x = map_x(block.end);
        const auto y = map_y(block.entropy);
        image.line(previous_x, previous_y, start_x, y, graph_color);
        image.line(start_x, y, end_x, y, graph_color);
        previous_x = end_x;
        previous_y = y;
    }

    const auto row_size = static_cast<std::size_t>(width) * 3U;
    std::vector<std::uint8_t> raw;
    raw.reserve((row_size + 1U) * height);
    for(std::uint32_t row = 0; row < height; ++row) {
        raw.push_back(0);
        const auto start = static_cast<std::size_t>(row) * row_size;
        raw.insert(
            raw.end(),
            image.pixels.begin() + static_cast<std::ptrdiff_t>(start),
            image.pixels.begin() + static_cast<std::ptrdiff_t>(start + row_size)
        );
    }
    if(raw.size() > std::numeric_limits<uLong>::max()) {
        return false;
    }

    uLongf compressed_size = ::compressBound(static_cast<uLong>(raw.size()));
    std::vector<std::uint8_t> compressed(compressed_size);
    if(::compress2(
        reinterpret_cast<Bytef*>(compressed.data()),
        &compressed_size,
        reinterpret_cast<const Bytef*>(raw.data()),
        static_cast<uLong>(raw.size()),
        Z_BEST_COMPRESSION
    ) != Z_OK) {
        return false;
    }
    compressed.resize(compressed_size);

    std::vector<std::uint8_t> png{
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    std::vector<std::uint8_t> header;
    append_big_endian(header, width);
    append_big_endian(header, height);
    header.insert(header.end(), {8, 2, 0, 0, 0});
    append_png_chunk(png, {'I', 'H', 'D', 'R'}, header);
    append_png_chunk(png, {'I', 'D', 'A', 'T'}, compressed);
    append_png_chunk(png, {'I', 'E', 'N', 'D'}, {});

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if(!output) {
        return false;
    }
    output.write(
        reinterpret_cast<const char*>(png.data()),
        static_cast<std::streamsize>(png.size())
    );
    return static_cast<bool>(output);
#endif
}

}
