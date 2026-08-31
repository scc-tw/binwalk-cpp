#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace binwalk {

class byte_view {
public:
    constexpr byte_view() noexcept = default;

    constexpr byte_view(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    explicit byte_view(const std::vector<std::uint8_t>& data) noexcept
        : byte_view(data.data(), data.size()) {}

    [[nodiscard]] constexpr const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }

    [[nodiscard]] constexpr bool contains(std::size_t offset, std::size_t length = 1) const noexcept {
        return offset <= size_ && length <= size_ - offset;
    }

    [[nodiscard]] constexpr std::uint8_t operator[](std::size_t offset) const noexcept {
        return data_[offset];
    }

    [[nodiscard]] constexpr byte_view subview(std::size_t offset, std::size_t length) const noexcept {
        return contains(offset, length) ? byte_view(data_ + offset, length) : byte_view{};
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace binwalk
