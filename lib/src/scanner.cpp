#include <binwalk/builtin.hpp>
#include <binwalk/scanner.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <queue>
#include <random>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
namespace binwalk {
namespace {

struct pattern_owner {
    std::size_t signature_index = 0;
    std::size_t pattern_size = 0;
};

class aho_corasick {
public:
    explicit aho_corasick(const std::vector<std::vector<std::uint8_t>>& patterns) {
        nodes_.emplace_back();
        for(std::size_t index = 0; index < patterns.size(); ++index) {
            add(patterns[index], index);
        }
        build_failure_links();
    }

    template<typename Callback>
    bool search(byte_view data, std::size_t start, Callback&& callback) const {
        std::size_t state = 0;
        for(std::size_t offset = start; offset < data.size(); ++offset) {
            state = nodes_[state].next[data[offset]];
            for(const auto pattern_index : nodes_[state].outputs) {
                if(!callback(pattern_index, offset + 1)) {
                    return false;
                }
            }
        }
        return true;
    }

private:
    struct node {
        std::array<std::size_t, 256> next{};
        std::size_t failure = 0;
        std::vector<std::size_t> outputs;
    };

    void add(const std::vector<std::uint8_t>& pattern, std::size_t pattern_index) {
        std::size_t state = 0;
        for(const auto byte : pattern) {
            if(nodes_[state].next[byte] == 0) {
                nodes_[state].next[byte] = nodes_.size();
                nodes_.emplace_back();
            }
            state = nodes_[state].next[byte];
        }
        nodes_[state].outputs.push_back(pattern_index);
    }

    void build_failure_links() {
        std::queue<std::size_t> pending;
        for(std::size_t byte = 0; byte < 256; ++byte) {
            const auto child = nodes_[0].next[byte];
            if(child != 0) {
                pending.push(child);
            }
        }

        while(!pending.empty()) {
            const auto state = pending.front();
            pending.pop();

            for(std::size_t byte = 0; byte < 256; ++byte) {
                const auto child = nodes_[state].next[byte];
                if(child != 0) {
                    pending.push(child);
                    const auto failure = nodes_[nodes_[state].failure].next[byte];
                    nodes_[child].failure = failure;
                    const auto& inherited = nodes_[failure].outputs;
                    nodes_[child].outputs.insert(
                        nodes_[child].outputs.end(), inherited.begin(), inherited.end()
                    );
                } else {
                    nodes_[state].next[byte] = nodes_[nodes_[state].failure].next[byte];
                }
            }
        }
    }

    std::vector<node> nodes_;
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

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for(std::size_t index = 0; index < bytes.size(); ++index) {
        if(index == 4 || index == 6 || index == 8 || index == 10) {
            output << '-';
        }
        output << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return output.str();
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
        matcher = std::make_unique<aho_corasick>(patterns);
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
    std::unique_ptr<aho_corasick> matcher;
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

    std::size_t next_valid_offset = 0;
    while(next_valid_offset < data.size()) {
        auto new_offset = next_valid_offset;
        implementation_->matcher->search(
            data,
            next_valid_offset,
            [&](std::size_t pattern_index, std::size_t match_end) {
                const auto& owner = implementation_->pattern_owners[pattern_index];
                const auto& definition = implementation_->signatures[owner.signature_index];
                const auto magic_offset = match_end - owner.pattern_size;
                if(definition.parser == nullptr) {
                    return true;
                }

                auto result = definition.parser(data, magic_offset);
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
                if(skip_contents) {
                    new_offset = result_end;
                    return false;
                }
                return true;
            }
        );

        if(new_offset <= next_valid_offset) {
            break;
        }
        next_valid_offset = new_offset;
    }

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
