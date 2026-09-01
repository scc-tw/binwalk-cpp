#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>
#include <binwalk/signature.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
namespace binwalk {

struct scan_options {
    std::vector<std::string> include;
    std::vector<std::string> exclude;
    bool search_all = false;
    std::size_t worker_threads = 0;
};

[[nodiscard]] BINWALK_API std::size_t recommended_scan_threads() noexcept;

class BINWALK_API scanner {
public:
    scanner();
    explicit scanner(scan_options options);
    scanner(std::vector<signature> signatures, scan_options options = {});
    scanner(const scanner& other) noexcept;
    scanner& operator=(const scanner& other) noexcept;
    ~scanner();

    [[nodiscard]] std::vector<signature_result> scan(byte_view data) const;
    [[nodiscard]] std::unordered_map<std::string, extraction_result> extract(
        byte_view data,
        const std::string& source_path,
        const std::vector<signature_result>& file_map,
        const std::string& output_root
    ) const;
    [[nodiscard]] analysis_results analyze(
        byte_view data,
        const std::string& source_path,
        bool do_extraction = false,
        const std::string& output_root = {}
    ) const;
    [[nodiscard]] std::size_t signature_count() const noexcept;
    [[nodiscard]] std::size_t pattern_count() const noexcept;
    [[nodiscard]] const std::vector<signature>& signatures() const noexcept;

private:
    struct implementation;
    implementation* implementation_ = nullptr;
};

}
