#pragma once

#include <cstddef>

namespace binwalk {
namespace detail {

[[nodiscard]] std::size_t physical_core_count() noexcept;

}
}
