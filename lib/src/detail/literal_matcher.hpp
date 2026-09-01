#pragma once

#include <binwalk/byte_view.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

namespace binwalk {
namespace detail {

class task_pool;

class literal_matcher {
public:
    enum class backend { automatic, scalar, interleaved };

    explicit literal_matcher(
        const std::vector<std::vector<std::uint8_t>>& patterns,
        backend requested = backend::automatic
    );

    literal_matcher(const literal_matcher&) = delete;
    literal_matcher& operator=(const literal_matcher&) = delete;

    using match_sink = bool (*)(void* context, std::size_t pattern_index, std::size_t match_end);

    bool find(
        byte_view data,
        std::size_t from,
        match_sink callback,
        void* context,
        task_pool* pool = nullptr
    ) const;

    template<typename Callback>
    bool search(byte_view data, std::size_t from, Callback&& callback) const {
        using body = std::remove_reference_t<Callback>;
        return find(
            data,
            from,
            [](void* raw, std::size_t pattern_index, std::size_t match_end) {
                return (*static_cast<body*>(raw))(pattern_index, match_end);
            },
            const_cast<void*>(static_cast<const void*>(std::addressof(callback)))
        );
    }

    [[nodiscard]] std::size_t state_count() const noexcept { return state_count_; }

private:
    struct match_record {
        std::size_t end = 0;
        std::uint32_t length = 0;
        std::uint32_t index = 0;
    };

    using match_buffer = std::vector<match_record>;

    struct walk_state;
    struct padded_lane_buffer;

    struct earlier_in_report_order {
        [[nodiscard]] bool operator()(
            const match_record& left,
            const match_record& right
        ) const noexcept {
            if(left.end != right.end) {
                return left.end < right.end;
            }
            if(left.length != right.length) {
                return left.length > right.length;
            }
            return left.index < right.index;
        }
    };

    void build_automaton(const std::vector<std::vector<std::uint8_t>>& patterns);

    void collect_matches(
        match_buffer& sink,
        std::uint32_t node,
        std::size_t match_end,
        std::size_t slice_end
    ) const;

    template<std::size_t Span>
    void walk_one_window(const std::uint8_t* bytes, std::size_t begin, match_buffer& sink) const;

    void walk_without_interleaving(
        const std::uint8_t* bytes,
        std::size_t begin,
        std::size_t end,
        match_buffer& sink
    ) const;

    [[nodiscard]] std::size_t walk_windows_across_pool(
        walk_state& state,
        const std::uint8_t* bytes,
        std::size_t size,
        std::size_t cursor,
        task_pool& pool
    ) const;

    [[nodiscard]] std::size_t walk_windows_on_this_thread(
        walk_state& state,
        const std::uint8_t* bytes,
        std::size_t size,
        std::size_t cursor
    ) const;

    [[nodiscard]] std::size_t lookahead() const noexcept {
        return longest_pattern_ > 0 ? longest_pattern_ - 1 : 0;
    }

    static bool release_matches_ending_at_or_before(walk_state& state, std::size_t limit);

    backend backend_ = backend::scalar;
    std::size_t longest_pattern_ = 0;
    std::size_t state_count_ = 0;

    std::uint32_t first_reporting_state_ = 0;

    std::vector<std::uint32_t> transitions_;
    std::vector<std::uint32_t> reported_patterns_begin_;
    std::vector<std::uint32_t> reported_patterns_;
    std::vector<std::uint32_t> pattern_lengths_;
};

}
}
