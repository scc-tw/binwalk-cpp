#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
namespace binwalk {

[[nodiscard]] BINWALK_API std::uint32_t crc32(byte_view data) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t crc32(
    byte_view data,
    std::size_t offset,
    std::size_t size
) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t crc32_update(
    std::uint32_t crc,
    byte_view data
) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t crc32_jamcrc(byte_view data) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t crc32_bzip2(byte_view data) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t crc32_posix(byte_view data) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t adler32(byte_view data) noexcept;

[[nodiscard]] BINWALK_API std::uint32_t adler32_update(
    std::uint32_t adler,
    byte_view data
) noexcept;

[[nodiscard]] BINWALK_API std::string epoch_to_string(std::uint32_t epoch_timestamp);

[[nodiscard]] BINWALK_API std::string epoch_to_string(std::int64_t epoch_timestamp);

template<typename Integer, std::enable_if_t<std::is_integral_v<Integer>, int> = 0>
[[nodiscard]] inline std::string epoch_to_string(Integer epoch_timestamp) {
    if constexpr(std::is_signed_v<Integer>) {
        return epoch_to_string(static_cast<std::int64_t>(epoch_timestamp));
    } else {
        constexpr auto representable_maximum =
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        if(static_cast<std::uint64_t>(epoch_timestamp) > representable_maximum) {
            return std::string{};
        }
        return epoch_to_string(static_cast<std::int64_t>(epoch_timestamp));
    }
}

[[nodiscard]] BINWALK_API bool is_offset_safe(
    std::size_t available_data,
    std::size_t next_offset,
    std::optional<std::size_t> last_offset
) noexcept;

[[nodiscard]] BINWALK_API bool is_range_safe(
    std::size_t available_data,
    std::size_t offset,
    std::size_t size
) noexcept;

[[nodiscard]] BINWALK_API std::optional<std::uint64_t> checked_multiply(
    std::uint64_t left,
    std::uint64_t right
) noexcept;

[[nodiscard]] BINWALK_API bool is_ascii_number(std::uint8_t value) noexcept;

[[nodiscard]] BINWALK_API bool is_printable_ascii(std::uint8_t value) noexcept;

[[nodiscard]] BINWALK_API std::vector<std::uint8_t> get_cstring_bytes(byte_view data);

[[nodiscard]] BINWALK_API std::string get_cstring(byte_view data);

[[nodiscard]] BINWALK_API std::string get_cstring(
    byte_view data,
    std::size_t offset,
    std::size_t max_length
);

[[nodiscard]] BINWALK_API std::string printable_prefix(
    byte_view data,
    std::size_t offset,
    std::size_t max_length
);

[[nodiscard]] BINWALK_API bool is_printable_range(
    byte_view data,
    std::size_t offset,
    std::size_t size
) noexcept;

}
