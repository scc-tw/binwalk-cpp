#include <binwalk/builtin.hpp>
#include <binwalk/scanner.hpp>

#include "detail/cpu_topology.hpp"
#include "detail/literal_matcher.hpp"
#include "detail/task_pool.hpp"
#include "detail/cstring_length_memo.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(BINWALK_PROFILE_COUNTERS)
#    include <chrono>
#    include <cstdio>
#endif

namespace binwalk {
namespace {

#if defined(BINWALK_PROFILE_COUNTERS)

struct hot_path_profile {
    std::uint64_t matches = 0;
    std::uint64_t parser_calls = 0;
    std::uint64_t parser_nanoseconds = 0;
    std::vector<std::uint64_t> per_signature_nanoseconds;
    std::vector<std::uint64_t> per_signature_calls;
    std::vector<std::string> signature_names;

    void account(std::size_t index, const std::string& name, std::uint64_t elapsed) {
        if(per_signature_nanoseconds.size() <= index) {
            per_signature_nanoseconds.resize(index + 1);
            per_signature_calls.resize(index + 1);
            signature_names.resize(index + 1);
        }
        per_signature_nanoseconds[index] += elapsed;
        per_signature_calls[index] += 1;
        signature_names[index] = name;
        parser_nanoseconds += elapsed;
        ++parser_calls;
    }

    ~hot_path_profile() {
        std::fprintf(
            stderr,
            "[profile] matches=%llu parser_calls=%llu parser_ms=%.2f\n",
            static_cast<unsigned long long>(matches),
            static_cast<unsigned long long>(parser_calls),
            static_cast<double>(parser_nanoseconds) / 1e6
        );

        std::vector<std::size_t> order(per_signature_nanoseconds.size());
        for(std::size_t index = 0; index < order.size(); ++index) {
            order[index] = index;
        }
        std::sort(order.begin(), order.end(), [this](std::size_t left, std::size_t right) {
            return per_signature_nanoseconds[left] > per_signature_nanoseconds[right];
        });
        for(std::size_t rank = 0; rank < order.size() && rank < 12; ++rank) {
            const auto index = order[rank];
            if(per_signature_nanoseconds[index] == 0) {
                break;
            }
            std::fprintf(
                stderr,
                "[profile]   %-24s %9.2f ms  %10llu calls  %8.3f us/call\n",
                signature_names[index].c_str(),
                static_cast<double>(per_signature_nanoseconds[index]) / 1e6,
                static_cast<unsigned long long>(per_signature_calls[index]),
                static_cast<double>(per_signature_nanoseconds[index]) / 1e3
                    / static_cast<double>(per_signature_calls[index] | 1U)
            );
        }
    }
};

[[nodiscard]] hot_path_profile& profile() {
    static hot_path_profile value;
    return value;
}

void count_match() noexcept {
    ++profile().matches;
}

class parser_timer {
public:
    parser_timer(std::size_t index, const std::string& name)
        : index_(index), name_(name), started_(std::chrono::steady_clock::now()) {}

    ~parser_timer() {
        profile().account(
            index_,
            name_,
            static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - started_
                ).count()
            )
        );
    }

    parser_timer(const parser_timer&) = delete;
    parser_timer& operator=(const parser_timer&) = delete;

private:
    std::size_t index_;
    const std::string& name_;
    std::chrono::steady_clock::time_point started_;
};

#else

inline void count_match() noexcept {}

class parser_timer {
public:
    parser_timer(std::size_t, const std::string&) noexcept {}
};

#endif

struct pattern_owner {
    std::size_t signature_index = 0;
    std::size_t pattern_size = 0;
};

[[nodiscard]] bool result_within(const signature_result& result, byte_view data) noexcept {
    return result.offset <= data.size() && result.size <= data.size() - result.offset;
}

[[nodiscard]] bool matches_at(
    byte_view data,
    std::size_t offset,
    const std::vector<std::uint8_t>& pattern
) noexcept {
    if(!data.contains(offset, pattern.size())) {
        return false;
    }
    for(std::size_t index = 0; index < pattern.size(); ++index) {
        if(data[offset + index] != pattern[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string make_uuid_v4() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    std::array<std::uint8_t, 16> bytes{};
    for(auto& byte : bytes) {
        byte = static_cast<std::uint8_t>(generator() & 0xffU);
    }
    bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U);

    static constexpr char digits[] = "0123456789abcdef";
    std::string text(36, '-');
    std::size_t cursor = 0;
    for(std::size_t index = 0; index < bytes.size(); ++index) {
        if(index == 4 || index == 6 || index == 8 || index == 10) {
            ++cursor;
        }
        text[cursor++] = digits[bytes[index] >> 4U];
        text[cursor++] = digits[bytes[index] & 0x0FU];
    }
    return text;
}

[[nodiscard]] std::string ascii_lowercase(std::string value) {
    for(auto& character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if(byte >= 'A' && byte <= 'Z') {
            character = static_cast<char>(byte - 'A' + 'a');
        }
    }
    return value;
}

[[nodiscard]] bool name_listed(const std::vector<std::string>& names, const std::string& name) {
    const auto lowered = ascii_lowercase(name);
    return std::any_of(names.begin(), names.end(), [&lowered](const std::string& candidate) {
        return ascii_lowercase(candidate) == lowered;
    });
}

[[nodiscard]] bool selected(const signature& value, const scan_options& options) {

    if(!options.include.empty()) {
        return name_listed(options.include, value.name);
    }
    return !name_listed(options.exclude, value.name);
}

void populate(signature_result& result, const signature& definition) {
    result.id = make_uuid_v4();
    result.name = definition.name;
    result.always_display = definition.always_display;
    if(result.description.empty()) {
        result.description = definition.description;
    }
}

}

std::size_t recommended_scan_threads() noexcept {
    return detail::physical_core_count();
}

struct scanner::implementation {
    explicit implementation(std::vector<signature> definitions, scan_options scan_options_value)
        : options(std::move(scan_options_value)) {
        for(auto& definition : definitions) {
            if(selected(definition, options)) {
                signatures.push_back(std::move(definition));
            }
        }

        for(std::size_t signature_index = 0; signature_index < signatures.size(); ++signature_index) {
            const auto& definition = signatures[signature_index];

            pattern_total += definition.magic.size();
            if(definition.short_signature && !options.search_all) {
                short_signature_indices.push_back(signature_index);
                continue;
            }
            for(const auto& pattern : definition.magic) {
                if(pattern.empty()) {
                    continue;
                }
                pattern_owners.push_back({signature_index, pattern.size()});
                patterns.push_back(pattern);
            }
        }
        matcher = std::make_unique<detail::literal_matcher>(patterns);
    }

    [[nodiscard]] detail::task_pool* lend_workers(std::size_t size) {
        constexpr std::size_t smallest_scan_worth_splitting = 1024 * 1024;
        if(options.worker_threads <= 1 || size < smallest_scan_worth_splitting) {
            return nullptr;
        }
        if(!workers) {
            workers = std::make_unique<detail::task_pool>(options.worker_threads);
        }
        return workers.get();
    }

    void retain() noexcept {
        references.fetch_add(1, std::memory_order_relaxed);
    }

    void release() noexcept {
        if(references.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete this;
        }
    }

    std::atomic<std::size_t> references{1};
    scan_options options;
    std::vector<signature> signatures;

    std::size_t pattern_total = 0;
    std::vector<std::size_t> short_signature_indices;
    std::vector<std::vector<std::uint8_t>> patterns;
    std::vector<pattern_owner> pattern_owners;
    std::unique_ptr<detail::literal_matcher> matcher;
    std::unique_ptr<detail::task_pool> workers;
    std::mutex workers_in_use;
};

scanner::scanner() : scanner(builtin_signatures(), {}) {}

scanner::scanner(scan_options options) : scanner(builtin_signatures(), std::move(options)) {}

scanner::scanner(std::vector<signature> signatures, scan_options options)
    : implementation_(new implementation(std::move(signatures), std::move(options))) {}

scanner::scanner(const scanner& other) noexcept : implementation_(other.implementation_) {
    implementation_->retain();
}

scanner& scanner::operator=(const scanner& other) noexcept {
    if(this == &other) {
        return *this;
    }
    other.implementation_->retain();
    implementation_->release();
    implementation_ = other.implementation_;
    return *this;
}

scanner::~scanner() {
    implementation_->release();
}

std::vector<signature_result> scanner::scan(byte_view data) const {
    const detail::cstring_length_memo memo(data);

    std::vector<signature_result> results;

    for(const auto signature_index : implementation_->short_signature_indices) {
        const auto& definition = implementation_->signatures[signature_index];
        for(const auto& pattern : definition.magic) {
            const auto magic_offset = definition.magic_offset;

            if(pattern.empty() || magic_offset > data.size()
                || pattern.size() >= data.size() - magic_offset) {
                continue;
            }
            if(!matches_at(data, magic_offset, pattern) || definition.parser == nullptr) {
                continue;
            }
            if(auto result = definition.parser(data, magic_offset)) {

                if(!result_within(*result, data)) {
                    continue;
                }
                populate(*result, definition);
                results.push_back(std::move(*result));
                break;
            }
        }
    }

    std::unique_lock<std::mutex> lease(implementation_->workers_in_use, std::try_to_lock);
    auto* const workers =
        lease.owns_lock() ? implementation_->lend_workers(data.size()) : nullptr;

    std::size_t first_unclaimed_offset = 0;

    auto visit = [&](std::size_t pattern_index, std::size_t match_end) {
        const auto& owner = implementation_->pattern_owners[pattern_index];
        const auto& definition = implementation_->signatures[owner.signature_index];
        const auto magic_offset = match_end - owner.pattern_size;
        count_match();

        if(magic_offset < first_unclaimed_offset || definition.parser == nullptr) {
            return true;
        }

        std::optional<signature_result> result;
        {
            const parser_timer timing(owner.signature_index, definition.name);
            result = definition.parser(data, magic_offset);
        }
        if(!result) {
            return true;
        }
        if(!result_within(*result, data)) {
            return true;
        }

        populate(*result, definition);
        const auto result_end = static_cast<std::size_t>(result->offset + result->size);
        const auto skip_contents = !implementation_->options.search_all
            && result->confidence >= confidence_medium
            && result->size > 0;
        results.push_back(std::move(*result));

        if(!skip_contents) {
            return true;
        }

        if(result_end <= first_unclaimed_offset) {
            return false;
        }
        first_unclaimed_offset = result_end;
        return true;
    };

    implementation_->matcher->find(
        data,
        0,
        [](void* raw, std::size_t pattern_index, std::size_t match_end) {
            return (*static_cast<decltype(visit)*>(raw))(pattern_index, match_end);
        },
        &visit,
        workers
    );

    std::stable_sort(results.begin(), results.end());
    std::vector<signature_result> filtered;
    std::uint64_t next_non_overlapping_offset = 0;
    for(auto& candidate : results) {
        if(!filtered.empty() && filtered.back().offset == candidate.offset) {
            if(candidate.confidence > filtered.back().confidence) {
                filtered.back() = std::move(candidate);
            }
            continue;
        }
        if(candidate.offset < next_non_overlapping_offset) {
            continue;
        }
        if(candidate.confidence >= confidence_medium) {
            next_non_overlapping_offset = candidate.offset + candidate.size;
        }
        filtered.push_back(std::move(candidate));
    }

    for(std::size_t index = 0; index < filtered.size(); ++index) {
        if(filtered[index].size != 0) {
            continue;
        }
        auto end = static_cast<std::uint64_t>(data.size());
        for(std::size_t next = index + 1; next < filtered.size(); ++next) {
            if(filtered[next].confidence >= confidence_medium) {
                end = filtered[next].offset;
                break;
            }
        }
        filtered[index].size = end - filtered[index].offset;
    }
    return filtered;
}

std::unordered_map<std::string, extraction_result> scanner::extract(
    byte_view data,
    const std::string& source_path,
    const std::vector<signature_result>& file_map,
    const std::string& output_root
) const {
    std::unordered_map<std::string, extraction_result> results;
    for(const auto& identified : file_map) {
        if(identified.extraction_declined) {
            continue;
        }

        const extractor* selected = identified.preferred_extractor
            ? &*identified.preferred_extractor
            : nullptr;
        if(selected == nullptr) {
            const auto definition = std::find_if(
                implementation_->signatures.begin(),
                implementation_->signatures.end(),
                [&](const auto& candidate) { return candidate.name == identified.name; }
            );
            if(definition == implementation_->signatures.end()
                || !definition->extractor_definition) {
                continue;
            }
            selected = &*definition->extractor_definition;
        }
        auto extraction = execute_extractor(data, source_path, identified, *selected, output_root);

        const auto available = identified.offset <= data.size()
            ? static_cast<std::uint64_t>(data.size()) - identified.offset
            : std::uint64_t{0};
        if(!extraction.success && identified.size < available) {
            signature_result widened = identified;
            widened.size = available;

            extraction = execute_extractor(data, source_path, widened, *selected, output_root);
        }

        results.emplace(identified.id, std::move(extraction));
    }
    return results;
}

analysis_results scanner::analyze(
    byte_view data,
    const std::string& source_path,
    bool do_extraction,
    const std::string& output_root
) const {
    analysis_results results;
    results.file_path = source_path;
    results.file_map = scan(data);
    if(do_extraction && !results.file_map.empty()) {
        results.extractions = extract(data, source_path, results.file_map, output_root);
    }
    return results;
}

std::size_t scanner::signature_count() const noexcept {
    return implementation_->signatures.size();
}

std::size_t scanner::pattern_count() const noexcept {
    return implementation_->pattern_total;
}

const std::vector<signature>& scanner::signatures() const noexcept {
    return implementation_->signatures;
}

}
