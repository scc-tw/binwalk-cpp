#include <binwalk/common.hpp>

#include "detail/cstring_length_memo.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
namespace binwalk {
namespace {

constexpr std::size_t crc_table_size = 256;

using crc_table = std::array<std::uint32_t, crc_table_size>;

[[nodiscard]] constexpr crc_table make_reflected_table(std::uint32_t polynomial) noexcept {
    crc_table table{};
    for(std::size_t index = 0; index < crc_table_size; ++index) {
        std::uint32_t entry = static_cast<std::uint32_t>(index);
        for(int bit = 0; bit < 8; ++bit) {
            const bool low_bit_set = (entry & 1U) != 0U;
            entry >>= 1U;
            if(low_bit_set) {
                entry ^= polynomial;
            }
        }
        table[index] = entry;
    }
    return table;
}

[[nodiscard]] constexpr crc_table make_forward_table(std::uint32_t polynomial) noexcept {
    crc_table table{};
    for(std::size_t index = 0; index < crc_table_size; ++index) {
        std::uint32_t entry = static_cast<std::uint32_t>(static_cast<std::uint32_t>(index) << 24U);
        for(int bit = 0; bit < 8; ++bit) {
            const bool high_bit_set = (entry & 0x80000000U) != 0U;
            entry = static_cast<std::uint32_t>(entry << 1U);
            if(high_bit_set) {
                entry ^= polynomial;
            }
        }
        table[index] = entry;
    }
    return table;
}

constexpr std::uint32_t reflected_polynomial = 0xEDB88320U;

constexpr std::uint32_t forward_polynomial = 0x04C11DB7U;

constexpr crc_table reflected_table = make_reflected_table(reflected_polynomial);
constexpr crc_table forward_table = make_forward_table(forward_polynomial);

[[nodiscard]] std::uint32_t to_little_endian(std::uint32_t value) noexcept {
    constexpr std::uint32_t probe = 1;
    const auto* const first = reinterpret_cast<const unsigned char*>(&probe);
    if(*first == 1) {
        return value;
    }
    return ((value & 0x000000FFU) << 24U) | ((value & 0x0000FF00U) << 8U)
        | ((value & 0x00FF0000U) >> 8U) | ((value & 0xFF000000U) >> 24U);
}

constexpr std::size_t crc_bytes_per_slice_step = 8;

using crc_slice_table = std::array<crc_table, crc_bytes_per_slice_step>;

[[nodiscard]] constexpr crc_slice_table make_reflected_slices(const crc_table& base) noexcept {
    crc_slice_table slices{};
    slices[0] = base;
    for(std::size_t index = 0; index < crc_table_size; ++index) {
        for(std::size_t slice = 1; slice < slices.size(); ++slice) {
            const auto previous = slices[slice - 1][index];
            slices[slice][index] =
                base[static_cast<std::size_t>(previous & 0xFFU)] ^ (previous >> 8U);
        }
    }
    return slices;
}

constexpr crc_slice_table reflected_slices = make_reflected_slices(reflected_table);

constexpr std::size_t crc_smallest_worthwhile_slice_run = 64;

[[nodiscard]] std::uint32_t reflected_advance_eight_bytes(
    std::uint32_t register_value,
    const std::uint8_t* bytes
) noexcept {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    std::memcpy(&low, bytes, sizeof(low));
    std::memcpy(&high, bytes + sizeof(low), sizeof(high));
    low = to_little_endian(low) ^ register_value;
    high = to_little_endian(high);

    return reflected_slices[7][static_cast<std::size_t>(low & 0xFFU)]
        ^ reflected_slices[6][static_cast<std::size_t>((low >> 8U) & 0xFFU)]
        ^ reflected_slices[5][static_cast<std::size_t>((low >> 16U) & 0xFFU)]
        ^ reflected_slices[4][static_cast<std::size_t>((low >> 24U) & 0xFFU)]
        ^ reflected_slices[3][static_cast<std::size_t>(high & 0xFFU)]
        ^ reflected_slices[2][static_cast<std::size_t>((high >> 8U) & 0xFFU)]
        ^ reflected_slices[1][static_cast<std::size_t>((high >> 16U) & 0xFFU)]
        ^ reflected_slices[0][static_cast<std::size_t>((high >> 24U) & 0xFFU)];
}

[[nodiscard]] std::uint32_t reflected_advance_one_byte(
    std::uint32_t register_value,
    std::uint8_t byte
) noexcept {
    const std::uint32_t slot = (register_value ^ static_cast<std::uint32_t>(byte)) & 0xFFU;
    return reflected_table[static_cast<std::size_t>(slot)]
        ^ static_cast<std::uint32_t>(register_value >> 8U);
}

[[nodiscard]] std::uint32_t reflected_advance(std::uint32_t register_value, byte_view data) noexcept {
    const auto* bytes = data.data();
    auto remaining = data.size();

    if(remaining >= crc_smallest_worthwhile_slice_run) {
        while(remaining >= crc_bytes_per_slice_step) {
            register_value = reflected_advance_eight_bytes(register_value, bytes);
            bytes += crc_bytes_per_slice_step;
            remaining -= crc_bytes_per_slice_step;
        }
    }

    for(std::size_t index = 0; index < remaining; ++index) {
        register_value = reflected_advance_one_byte(register_value, bytes[index]);
    }
    return register_value;
}

[[nodiscard]] std::uint32_t forward_advance(std::uint32_t register_value, byte_view data) noexcept {
    for(std::size_t index = 0; data.contains(index); ++index) {
        const std::uint32_t slot =
            (static_cast<std::uint32_t>(register_value >> 24U)
             ^ static_cast<std::uint32_t>(data[index]))
            & 0xFFU;
        register_value = forward_table[static_cast<std::size_t>(slot)]
            ^ static_cast<std::uint32_t>(register_value << 8U);
    }
    return register_value;
}

[[nodiscard]] std::string format_epoch(std::time_t value) {
    std::tm utc{};
#if defined(_WIN32)
    if(gmtime_s(&utc, &value) != 0) {
        return {};
    }
#else
    if(gmtime_r(&value, &utc) == nullptr) {
        return {};
    }
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

[[nodiscard]] const std::uint8_t* find_terminator(
    const std::uint8_t* begin,
    std::size_t length
) noexcept {
    if(length == 0) {
        return nullptr;
    }

    const void* const found = std::memchr(begin, 0, length);
    return static_cast<const std::uint8_t*>(found);
}

struct memoised_run {
    byte_view within;
    const std::uint8_t* verified_begin = nullptr;
    const std::uint8_t* verified_end = nullptr;
    const std::uint8_t* terminator = nullptr;

    [[nodiscard]] bool covers(const std::uint8_t* begin, const std::uint8_t* limit) const noexcept {
        return within.data() != nullptr
            && begin >= within.data()
            && limit <= within.data() + within.size();
    }

    [[nodiscard]] bool starts_inside_verified_run(const std::uint8_t* begin) const noexcept {
        return begin >= verified_begin && begin < verified_end;
    }
};

[[nodiscard]] memoised_run& memoised_run_for_this_thread() noexcept {
    static thread_local memoised_run run;
    return run;
}

[[nodiscard]] std::size_t skip_ascii_octets(
    const std::uint8_t* bytes,
    std::size_t index,
    std::size_t length
) noexcept {
    constexpr std::uint64_t high_bit_of_each_byte = 0x8080808080808080ULL;
    while(length - index >= sizeof(std::uint64_t)) {
        std::uint64_t octet = 0;
        std::memcpy(&octet, bytes + index, sizeof(octet));
        if((octet & high_bit_of_each_byte) != 0U) {
            break;
        }
        index += sizeof(std::uint64_t);
    }
    return index;
}

[[nodiscard]] bool is_valid_utf8(const std::uint8_t* bytes, std::size_t length) noexcept {
    std::size_t index = 0;

    while(index < length) {
        index = skip_ascii_octets(bytes, index, length);
        if(index >= length) {
            break;
        }

        const std::uint8_t lead = bytes[index];

        if(lead <= 0x7F) {
            index += 1;
            continue;
        }

        std::size_t sequence_length = 0;
        std::uint8_t second_minimum = 0x80;
        std::uint8_t second_maximum = 0xBF;

        if(lead >= 0xC2 && lead <= 0xDF) {
            sequence_length = 2;
        } else if(lead == 0xE0) {
            sequence_length = 3;
            second_minimum = 0xA0;
        } else if(lead >= 0xE1 && lead <= 0xEC) {
            sequence_length = 3;
        } else if(lead == 0xED) {
            sequence_length = 3;
            second_maximum = 0x9F;
        } else if(lead >= 0xEE && lead <= 0xEF) {
            sequence_length = 3;
        } else if(lead == 0xF0) {
            sequence_length = 4;
            second_minimum = 0x90;
        } else if(lead >= 0xF1 && lead <= 0xF3) {
            sequence_length = 4;
        } else if(lead == 0xF4) {
            sequence_length = 4;
            second_maximum = 0x8F;
        } else {
            return false;
        }

        if(length - index < sequence_length) {
            return false;
        }

        const std::uint8_t second = bytes[index + 1];
        if(second < second_minimum || second > second_maximum) {
            return false;
        }

        for(std::size_t offset = 2; offset < sequence_length; ++offset) {
            const std::uint8_t continuation = bytes[index + offset];
            if(continuation < 0x80 || continuation > 0xBF) {
                return false;
            }
        }

        index += sequence_length;
    }

    return true;
}

}

namespace detail {

cstring_length_memo::cstring_length_memo(byte_view data) noexcept {
    auto& run = memoised_run_for_this_thread();
    restored_view_ = run.within;
    restored_verified_begin_ = run.verified_begin;
    restored_verified_end_ = run.verified_end;
    restored_terminator_ = run.terminator;

    run.within = data;
    run.verified_begin = nullptr;
    run.verified_end = nullptr;
    run.terminator = nullptr;
}

cstring_length_memo::~cstring_length_memo() {
    auto& run = memoised_run_for_this_thread();
    run.within = restored_view_;
    run.verified_begin = static_cast<const std::uint8_t*>(restored_verified_begin_);
    run.verified_end = static_cast<const std::uint8_t*>(restored_verified_end_);
    run.terminator = static_cast<const std::uint8_t*>(restored_terminator_);
}

}

std::uint32_t crc32(byte_view data) noexcept {
    return crc32(data, 0, data.size());
}

std::uint32_t crc32(byte_view data, std::size_t offset, std::size_t size) noexcept {
    if(!data.contains(offset, size)) {

        return 0;
    }
    return ~reflected_advance(0xFFFFFFFFU, data.subview(offset, size));
}

std::uint32_t crc32_update(std::uint32_t crc, byte_view data) noexcept {

    return ~reflected_advance(~crc, data);
}

std::uint32_t crc32_jamcrc(byte_view data) noexcept {

    return reflected_advance(0xFFFFFFFFU, data);
}

std::uint32_t crc32_bzip2(byte_view data) noexcept {
    return ~forward_advance(0xFFFFFFFFU, data);
}

std::uint32_t crc32_posix(byte_view data) noexcept {

    return ~forward_advance(0U, data);
}

std::uint32_t adler32(byte_view data) noexcept {
    return adler32_update(1U, data);
}

std::uint32_t adler32_update(std::uint32_t adler, byte_view data) noexcept {

    constexpr std::uint32_t modulus = 65521U;

    constexpr std::size_t maximum_block = 5552;

    std::uint32_t low = adler & 0xFFFFU;
    std::uint32_t high = static_cast<std::uint32_t>(adler >> 16U) & 0xFFFFU;

    std::size_t index = 0;
    while(index < data.size()) {
        const std::size_t block = std::min(maximum_block, data.size() - index);
        if(!data.contains(index, block)) {
            break;
        }
        for(std::size_t step = 0; step < block; ++step) {
            low += static_cast<std::uint32_t>(data[index + step]);
            high += low;
        }
        low %= modulus;
        high %= modulus;
        index += block;
    }

    return static_cast<std::uint32_t>(high << 16U) | low;
}

std::string epoch_to_string(std::uint32_t epoch_timestamp) {
    return format_epoch(static_cast<std::time_t>(epoch_timestamp));
}

std::string epoch_to_string(std::int64_t epoch_timestamp) {
    if constexpr(sizeof(std::time_t) < sizeof(std::int64_t)) {

        constexpr auto lowest = static_cast<std::int64_t>(std::numeric_limits<std::time_t>::min());
        constexpr auto highest = static_cast<std::int64_t>(std::numeric_limits<std::time_t>::max());
        if(epoch_timestamp < lowest || epoch_timestamp > highest) {
            return {};
        }
    }
    return format_epoch(static_cast<std::time_t>(epoch_timestamp));
}

bool is_offset_safe(
    std::size_t available_data,
    std::size_t next_offset,
    std::optional<std::size_t> last_offset
) noexcept {

    if(last_offset.has_value() && *last_offset >= next_offset) {
        return false;
    }
    if(next_offset >= available_data) {
        return false;
    }
    return true;
}

bool is_range_safe(
    std::size_t available_data,
    std::size_t offset,
    std::size_t size
) noexcept {
    if(offset > std::numeric_limits<std::size_t>::max() - size) {
        return false;
    }
    return offset + size <= available_data;
}

std::optional<std::uint64_t> checked_multiply(std::uint64_t left, std::uint64_t right) noexcept {
    if(left != 0U && right > std::numeric_limits<std::uint64_t>::max() / left) {
        return std::nullopt;
    }
    return left * right;
}

bool is_ascii_number(std::uint8_t value) noexcept {
    constexpr std::uint8_t ascii_zero = 0x30;
    constexpr std::uint8_t ascii_nine = 0x39;
    return value >= ascii_zero && value <= ascii_nine;
}

bool is_printable_ascii(std::uint8_t value) noexcept {

    constexpr std::uint8_t ascii_minimum = 0x0A;
    constexpr std::uint8_t ascii_maximum = 0x7E;
    return value >= ascii_minimum && value <= ascii_maximum;
}

std::size_t cstring_length(byte_view data) noexcept {
    if(data.empty()) {
        return 0;
    }

    const auto* const begin = data.data();
    const auto* const limit = begin + data.size();

    auto& run = memoised_run_for_this_thread();
    const bool memoisable = run.covers(begin, limit);

    if(memoisable && run.starts_inside_verified_run(begin)) {
        if(limit <= run.verified_end) {
            return data.size();
        }
        if(run.terminator != nullptr) {
            return static_cast<std::size_t>(run.terminator - begin);
        }

        const auto* const extended = find_terminator(
            run.verified_end, static_cast<std::size_t>(limit - run.verified_end)
        );
        run.verified_end = extended != nullptr ? extended : limit;
        run.terminator = extended;
        return static_cast<std::size_t>(run.verified_end - begin);
    }

    const auto* const found = find_terminator(begin, data.size());
    if(memoisable) {
        run.verified_begin = begin;
        run.verified_end = found != nullptr ? found : limit;
        run.terminator = found;
    }
    return found != nullptr ? static_cast<std::size_t>(found - begin) : data.size();
}

std::vector<std::uint8_t> get_cstring_bytes(byte_view data) {
    const auto length = cstring_length(data);
    return std::vector<std::uint8_t>(data.data(), data.data() + length);
}

std::string get_cstring(byte_view data) {
    const auto length = cstring_length(data);
    if(!is_valid_utf8(data.data(), length)) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(data.data()), length);
}

std::string get_cstring(byte_view data, std::size_t offset, std::size_t max_length) {
    if(!data.contains(offset, max_length)) {
        return {};
    }
    return get_cstring(data.subview(offset, max_length));
}

std::string printable_prefix(byte_view data, std::size_t offset, std::size_t max_length) {
    if(!data.contains(offset, max_length)) {
        return {};
    }

    const byte_view span = data.subview(offset, max_length);
    std::string result;
    for(std::size_t index = 0; span.contains(index); ++index) {
        const std::uint8_t value = span[index];
        if(!is_printable_ascii(value)) {
            break;
        }
        result.push_back(static_cast<char>(value));
    }
    return result;
}

bool is_printable_range(byte_view data, std::size_t offset, std::size_t size) noexcept {
    if(!data.contains(offset, size)) {
        return false;
    }

    const byte_view span = data.subview(offset, size);
    for(std::size_t index = 0; span.contains(index); ++index) {
        if(!is_printable_ascii(span[index])) {
            return false;
        }
    }
    return true;
}

}
