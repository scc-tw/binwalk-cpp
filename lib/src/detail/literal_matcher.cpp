#include "literal_matcher.hpp"

#include "task_pool.hpp"

#include <algorithm>
#include <queue>

namespace binwalk {
namespace detail {
namespace {

constexpr std::size_t interleaved_walks = 8;
constexpr std::size_t wide_slice = 8192;
constexpr std::size_t narrow_slice = 512;
constexpr std::size_t wide_window = interleaved_walks * wide_slice;
constexpr std::size_t narrow_window = interleaved_walks * narrow_slice;
constexpr std::size_t max_windows_per_lane = 8;
constexpr std::size_t cache_line_size = 64;

struct goto_table {
    std::vector<std::uint32_t> transitions;
    std::vector<std::vector<std::uint32_t>> node_outputs;

    [[nodiscard]] std::size_t node_count() const noexcept { return node_outputs.size(); }
};

[[nodiscard]] goto_table build_trie(const std::vector<std::vector<std::uint8_t>>& patterns) {
    std::size_t node_ceiling = 1;
    for(const auto& pattern : patterns) {
        node_ceiling += pattern.size();
    }

    goto_table trie;
    trie.transitions.reserve(node_ceiling * 256);
    trie.transitions.resize(256, 0);
    trie.node_outputs.emplace_back();

    for(std::uint32_t index = 0; index < patterns.size(); ++index) {
        const auto& pattern = patterns[index];
        if(pattern.empty()) {
            continue;
        }
        std::uint32_t node = 0;
        for(const auto byte : pattern) {
            const auto slot = (static_cast<std::size_t>(node) << 8U) | byte;
            if(trie.transitions[slot] == 0) {
                const auto created = static_cast<std::uint32_t>(trie.node_count());
                trie.transitions.resize(trie.transitions.size() + 256, 0);
                trie.node_outputs.emplace_back();
                trie.transitions[slot] = created;
            }
            node = trie.transitions[slot];
        }
        trie.node_outputs[node].push_back(index);
    }
    return trie;
}

void complete_transitions_and_inherit_outputs(goto_table& trie) {
    std::vector<std::uint32_t> failure(trie.node_count(), 0);
    std::queue<std::uint32_t> pending;
    for(std::size_t byte = 0; byte < 256; ++byte) {
        if(trie.transitions[byte] != 0) {
            pending.push(trie.transitions[byte]);
        }
    }

    while(!pending.empty()) {
        const auto node = pending.front();
        pending.pop();
        const auto row = static_cast<std::size_t>(node) << 8U;
        const auto failure_row = static_cast<std::size_t>(failure[node]) << 8U;

        for(std::size_t byte = 0; byte < 256; ++byte) {
            const auto child = trie.transitions[row + byte];
            if(child == 0) {
                trie.transitions[row + byte] = trie.transitions[failure_row + byte];
                continue;
            }
            pending.push(child);
            const auto target = trie.transitions[failure_row + byte];
            failure[child] = target;
            const auto& inherited = trie.node_outputs[target];
            trie.node_outputs[child].insert(
                trie.node_outputs[child].end(), inherited.begin(), inherited.end()
            );
        }
    }
}

struct state_numbering {
    std::vector<std::uint32_t> renumbered;
    std::uint32_t first_reporting = 0;
};

[[nodiscard]] state_numbering number_reporting_states_last(const goto_table& trie) {
    state_numbering numbering;
    numbering.renumbered.assign(trie.node_count(), 0);

    std::uint32_t next = 0;
    for(std::size_t node = 0; node < trie.node_count(); ++node) {
        if(trie.node_outputs[node].empty()) {
            numbering.renumbered[node] = next++;
        }
    }
    numbering.first_reporting = next;
    for(std::size_t node = 0; node < trie.node_count(); ++node) {
        if(!trie.node_outputs[node].empty()) {
            numbering.renumbered[node] = next++;
        }
    }
    return numbering;
}

}

#if defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 4324)
#endif
struct alignas(cache_line_size) literal_matcher::padded_lane_buffer {
    match_buffer matches;
};
#if defined(_MSC_VER)
#    pragma warning(pop)
#endif

struct literal_matcher::walk_state {
    match_sink callback = nullptr;
    void* context = nullptr;
    match_buffer pending;
    bool stopped = false;
};

literal_matcher::literal_matcher(
    const std::vector<std::vector<std::uint8_t>>& patterns,
    backend requested
) {
    build_automaton(patterns);
    backend_ = requested == backend::automatic ? backend::interleaved : requested;
}

void literal_matcher::build_automaton(const std::vector<std::vector<std::uint8_t>>& patterns) {
    pattern_lengths_.reserve(patterns.size());
    for(const auto& pattern : patterns) {
        pattern_lengths_.push_back(static_cast<std::uint32_t>(pattern.size()));
        longest_pattern_ = std::max(longest_pattern_, pattern.size());
    }

    auto trie = build_trie(patterns);
    complete_transitions_and_inherit_outputs(trie);

    const auto numbering = number_reporting_states_last(trie);
    const auto nodes = trie.node_count();

    state_count_ = nodes;
    first_reporting_state_ = numbering.first_reporting;

    transitions_.assign(nodes * 256, 0);
    for(std::size_t node = 0; node < nodes; ++node) {
        const auto target_row = static_cast<std::size_t>(numbering.renumbered[node]) << 8U;
        const auto source_row = node << 8U;
        for(std::size_t byte = 0; byte < 256; ++byte) {
            transitions_[target_row + byte] =
                numbering.renumbered[trie.transitions[source_row + byte]];
        }
    }

    reported_patterns_begin_.assign(nodes - first_reporting_state_ + 1, 0);
    for(std::size_t node = 0; node < nodes; ++node) {
        if(trie.node_outputs[node].empty()) {
            continue;
        }
        const auto slot = numbering.renumbered[node] - first_reporting_state_;
        reported_patterns_begin_[slot + 1] =
            static_cast<std::uint32_t>(trie.node_outputs[node].size());
    }
    for(std::size_t slot = 1; slot < reported_patterns_begin_.size(); ++slot) {
        reported_patterns_begin_[slot] += reported_patterns_begin_[slot - 1];
    }

    reported_patterns_.resize(reported_patterns_begin_.back());
    for(std::size_t node = 0; node < nodes; ++node) {
        if(trie.node_outputs[node].empty()) {
            continue;
        }
        const auto slot = numbering.renumbered[node] - first_reporting_state_;
        std::copy(
            trie.node_outputs[node].begin(),
            trie.node_outputs[node].end(),
            reported_patterns_.begin() + reported_patterns_begin_[slot]
        );
    }
}

bool literal_matcher::release_matches_ending_at_or_before(walk_state& state, std::size_t limit) {
    if(state.pending.empty()) {
        return true;
    }
    std::sort(state.pending.begin(), state.pending.end(), earlier_in_report_order{});

    std::size_t released = 0;
    while(released < state.pending.size() && state.pending[released].end <= limit) {
        const auto record = state.pending[released];
        ++released;
        if(!state.callback(state.context, record.index, record.end)) {
            state.stopped = true;
            break;
        }
    }
    state.pending.erase(
        state.pending.begin(), state.pending.begin() + static_cast<std::ptrdiff_t>(released)
    );
    return !state.stopped;
}

void literal_matcher::collect_matches(
    match_buffer& sink,
    std::uint32_t node,
    std::size_t match_end,
    std::size_t slice_end
) const {
    if(node < first_reporting_state_) {
        return;
    }
    const auto slot = node - first_reporting_state_;
    const auto first = reported_patterns_begin_[slot];
    const auto last = reported_patterns_begin_[slot + 1U];

    for(auto entry = first; entry < last; ++entry) {
        const auto index = reported_patterns_[entry];
        const auto length = pattern_lengths_[index];
        const auto match_start = match_end - length;
        if(match_start >= slice_end) {
            continue;
        }
        sink.push_back({match_end, length, index});
    }
}

void literal_matcher::walk_without_interleaving(
    const std::uint8_t* bytes,
    std::size_t begin,
    std::size_t end,
    match_buffer& sink
) const {
    const auto* const table = transitions_.data();
    std::uint32_t node = 0;

    for(std::size_t offset = begin; offset < end; ++offset) {
        node = table[(static_cast<std::size_t>(node) << 8U) | bytes[offset]];
        if(node >= first_reporting_state_) {
            collect_matches(sink, node, offset + 1, end);
        }
    }
}

template<std::size_t Span>
void literal_matcher::walk_one_window(
    const std::uint8_t* bytes,
    std::size_t begin,
    match_buffer& sink
) const {
    const auto* const table = transitions_.data();
    const auto reporting = first_reporting_state_;
    const auto* cursor = bytes + begin;
    const auto steps = Span + lookahead();

    std::uint32_t node0 = 0;
    std::uint32_t node1 = 0;
    std::uint32_t node2 = 0;
    std::uint32_t node3 = 0;
    std::uint32_t node4 = 0;
    std::uint32_t node5 = 0;
    std::uint32_t node6 = 0;
    std::uint32_t node7 = 0;

    for(std::size_t step = 0; step < steps; ++step) {
        node0 = table[(static_cast<std::size_t>(node0) << 8U) | cursor[0 * Span]];
        node1 = table[(static_cast<std::size_t>(node1) << 8U) | cursor[1 * Span]];
        node2 = table[(static_cast<std::size_t>(node2) << 8U) | cursor[2 * Span]];
        node3 = table[(static_cast<std::size_t>(node3) << 8U) | cursor[3 * Span]];
        node4 = table[(static_cast<std::size_t>(node4) << 8U) | cursor[4 * Span]];
        node5 = table[(static_cast<std::size_t>(node5) << 8U) | cursor[5 * Span]];
        node6 = table[(static_cast<std::size_t>(node6) << 8U) | cursor[6 * Span]];
        node7 = table[(static_cast<std::size_t>(node7) << 8U) | cursor[7 * Span]];
        ++cursor;

        const auto highest = std::max(
            std::max(std::max(node0, node1), std::max(node2, node3)),
            std::max(std::max(node4, node5), std::max(node6, node7))
        );
        if(highest < reporting) {
            continue;
        }

        const std::uint32_t nodes[interleaved_walks] = {
            node0, node1, node2, node3, node4, node5, node6, node7
        };
        for(std::size_t walk = 0; walk < interleaved_walks; ++walk) {
            const auto slice_begin = begin + walk * Span;
            collect_matches(sink, nodes[walk], slice_begin + step + 1, slice_begin + Span);
        }
    }
}

std::size_t literal_matcher::walk_windows_across_pool(
    walk_state& state,
    const std::uint8_t* bytes,
    std::size_t size,
    std::size_t cursor,
    task_pool& pool
) const {
    const auto lanes = pool.width();
    const auto lookahead_bytes = lookahead();
    std::vector<padded_lane_buffer> harvest(lanes);

    while(size >= lookahead_bytes && cursor <= size - lookahead_bytes) {
        const auto windows = (size - lookahead_bytes - cursor) / wide_window;
        if(windows < lanes) {
            break;
        }
        const auto windows_per_lane = std::min(max_windows_per_lane, windows / lanes);
        const auto lane_stride = windows_per_lane * wide_window;
        const auto origin = cursor;

        pool.run(lanes, [&](std::size_t lane) {
            auto& sink = harvest[lane].matches;
            sink.clear();
            const auto lane_begin = origin + lane * lane_stride;
            for(std::size_t window = 0; window < windows_per_lane; ++window) {
                walk_one_window<wide_slice>(bytes, lane_begin + window * wide_window, sink);
            }
        });

        for(const auto& lane : harvest) {
            state.pending.insert(
                state.pending.end(), lane.matches.begin(), lane.matches.end()
            );
        }
        cursor += lanes * lane_stride;
        if(!release_matches_ending_at_or_before(state, cursor)) {
            return cursor;
        }
    }
    return cursor;
}

std::size_t literal_matcher::walk_windows_on_this_thread(
    walk_state& state,
    const std::uint8_t* bytes,
    std::size_t size,
    std::size_t cursor
) const {
    const auto lookahead_bytes = lookahead();

    while(size >= lookahead_bytes + wide_window && cursor <= size - lookahead_bytes - wide_window) {
        walk_one_window<wide_slice>(bytes, cursor, state.pending);
        cursor += wide_window;
        if(!release_matches_ending_at_or_before(state, cursor)) {
            return cursor;
        }
    }
    while(size >= lookahead_bytes + narrow_window && cursor <= size - lookahead_bytes - narrow_window) {
        walk_one_window<narrow_slice>(bytes, cursor, state.pending);
        cursor += narrow_window;
        if(!release_matches_ending_at_or_before(state, cursor)) {
            return cursor;
        }
    }
    return cursor;
}

bool literal_matcher::find(
    byte_view data,
    std::size_t from,
    match_sink callback,
    void* context,
    task_pool* pool
) const {
    if(data.empty() || from >= data.size() || transitions_.empty()) {
        return true;
    }

    walk_state state;
    state.callback = callback;
    state.context = context;
    state.pending.reserve(64);

    const auto* const bytes = data.data();
    const auto size = data.size();
    std::size_t cursor = from;

    if(backend_ == backend::interleaved) {
        if(pool != nullptr && pool->width() > 1) {
            cursor = walk_windows_across_pool(state, bytes, size, cursor, *pool);
            if(state.stopped) {
                return false;
            }
        }
        cursor = walk_windows_on_this_thread(state, bytes, size, cursor);
        if(state.stopped) {
            return false;
        }
    }

    if(cursor < size) {
        walk_without_interleaving(bytes, cursor, size, state.pending);
    }
    release_matches_ending_at_or_before(state, size);
    return !state.stopped;
}

}
}
