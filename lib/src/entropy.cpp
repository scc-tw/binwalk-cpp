#include <binwalk/entropy.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>

namespace binwalk {

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

} // namespace binwalk
