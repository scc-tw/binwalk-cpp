#pragma once

#include <binwalk/byte_view.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
namespace binwalk {

enum class byte_order { little, big };

template<byte_order Order>
class binary_reader {
public:
    explicit constexpr binary_reader(byte_view data) noexcept : data_(data) {}

    template<typename UInt, std::enable_if_t<std::is_unsigned_v<UInt>, int> = 0>
    [[nodiscard]] constexpr std::optional<UInt> read(std::size_t offset) const noexcept {
        static_assert(std::is_integral_v<UInt>, "binary_reader only reads unsigned integers");
        if(!data_.contains(offset, sizeof(UInt))) {
            return std::nullopt;
        }

        UInt value = 0;
        for(std::size_t index = 0; index < sizeof(UInt); ++index) {
            const auto source_index = Order == byte_order::big ? index : sizeof(UInt) - index - 1;
            value = static_cast<UInt>((value << 8U) | data_[offset + source_index]);
        }
        return value;
    }

    [[nodiscard]] constexpr std::optional<std::uint32_t> read_u24(std::size_t offset) const noexcept {
        if(!data_.contains(offset, 3)) {
            return std::nullopt;
        }
        if constexpr(Order == byte_order::big) {
            return (static_cast<std::uint32_t>(data_[offset]) << 16U)
                | (static_cast<std::uint32_t>(data_[offset + 1]) << 8U)
                | static_cast<std::uint32_t>(data_[offset + 2]);
        } else {
            return (static_cast<std::uint32_t>(data_[offset + 2]) << 16U)
                | (static_cast<std::uint32_t>(data_[offset + 1]) << 8U)
                | static_cast<std::uint32_t>(data_[offset]);
        }
    }

private:
    byte_view data_;
};

}
