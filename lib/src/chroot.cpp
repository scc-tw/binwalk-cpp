
#include <binwalk/chroot.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#endif
namespace fs = std::filesystem;

namespace binwalk {
namespace {

#if defined(_WIN32)
constexpr char k_separator = '\\';
#else
constexpr char k_separator = '/';
#endif

constexpr std::size_t k_max_component_length = 250;

constexpr bool is_separator(char ch) noexcept {
    return ch == '/' || ch == '\\';
}

constexpr bool is_ascii_alpha(char ch) noexcept {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

constexpr char to_upper_ascii(char ch) noexcept {
    return (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - ('a' - 'A')) : ch;
}

constexpr bool path_chars_equal(char lhs, char rhs) noexcept {
    if (is_separator(lhs) && is_separator(rhs)) {
        return true;
    }
    return to_upper_ascii(lhs) == to_upper_ascii(rhs);
}

byte_view as_bytes(const std::string& text) noexcept {
    return byte_view(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

bool is_reserved_device_name(std::string_view stem) noexcept {
    if (stem.size() != 3 && stem.size() != 4) {
        return false;
    }

    char upper[4] = {};
    for (std::size_t i = 0; i < stem.size(); ++i) {
        upper[i] = to_upper_ascii(stem[i]);
    }
    const std::string_view name(upper, stem.size());

    if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL") {
        return true;
    }
    if (name.size() == 4 && name[3] >= '1' && name[3] <= '9') {
        const std::string_view prefix = name.substr(0, 3);
        if (prefix == "COM" || prefix == "LPT") {
            return true;
        }
    }
    return false;
}

std::string sanitize_component(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());

    for (const char ch : raw) {
        const auto code = static_cast<unsigned char>(ch);
        if (code < 0x20u) {
            out.push_back('_');
            continue;
        }
        switch (ch) {
        case '<':
        case '>':
        case ':':
        case '"':
        case '|':
        case '?':
        case '*':
        case '/':
        case '\\':
            out.push_back('_');
            break;
        default:
            out.push_back(ch);
            break;
        }
    }

    if (out.size() > k_max_component_length) {
        out.resize(k_max_component_length);
    }

    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) {
        out.pop_back();
    }
    if (out.empty()) {
        return std::string("_");
    }

    const std::size_t dot = out.find('.');
    std::string stem = (dot == std::string::npos) ? out : out.substr(0, dot);
    while (!stem.empty() && (stem.back() == '.' || stem.back() == ' ')) {
        stem.pop_back();
    }
    if (is_reserved_device_name(stem)) {
        out.insert(out.begin(), '_');
    }

    return out;
}

bool starts_with_root(const std::string& root, std::string_view candidate) noexcept {
    if (root.empty() || candidate.size() < root.size()) {
        return false;
    }
    for (std::size_t i = 0; i < root.size(); ++i) {
        if (!path_chars_equal(root[i], candidate[i])) {
            return false;
        }
    }
    if (candidate.size() == root.size()) {
        return true;
    }

    return is_separator(root.back()) || is_separator(candidate[root.size()]);
}

std::string_view strip_leading_prefixes(const std::string& root, std::string_view path) noexcept {
    while (path.size() >= 4 && is_separator(path[0]) && is_separator(path[1]) &&
           (path[2] == '?' || path[2] == '.') && is_separator(path[3])) {
        path.remove_prefix(4);
    }

    if (starts_with_root(root, path)) {
        path.remove_prefix(root.size());
    }

    if (path.size() >= 2 && is_ascii_alpha(path[0]) && path[1] == ':') {
        path.remove_prefix(2);
    }

    return path;
}

std::vector<std::string> relative_components(const std::string& root, std::string_view path) {
    std::vector<std::string> stack;
    const std::string_view trimmed = strip_leading_prefixes(root, path);

    std::size_t start = 0;
    for (;;) {
        std::size_t end = start;
        while (end < trimmed.size() && !is_separator(trimmed[end])) {
            ++end;
        }

        const std::string_view component = trimmed.substr(start, end - start);
        if (component.empty() || component == ".") {

        } else if (component == "..") {
            if (!stack.empty()) {
                stack.pop_back();
            }
        } else {
            stack.push_back(sanitize_component(component));
        }

        if (end >= trimmed.size()) {
            break;
        }
        start = end + 1;
    }

    return stack;
}

bool traverses_above_root(const std::string& root, std::string_view path) noexcept {
    const std::string_view trimmed = strip_leading_prefixes(root, path);
    std::size_t depth = 0;

    std::size_t start = 0;
    for (;;) {
        std::size_t end = start;
        while (end < trimmed.size() && !is_separator(trimmed[end])) {
            ++end;
        }

        const std::string_view component = trimmed.substr(start, end - start);
        if (component == "..") {
            if (depth == 0) {
                return true;
            }
            --depth;
        } else if (!component.empty() && component != ".") {
            ++depth;
        }

        if (end >= trimmed.size()) {
            break;
        }
        start = end + 1;
    }

    return false;
}

std::string join_components(const std::string& root, const std::vector<std::string>& components) {
    std::string out = root;
    for (const std::string& component : components) {
        if (!out.empty() && !is_separator(out.back())) {
            out.push_back(k_separator);
        }
        out += component;
    }
    return out;
}

fs::path to_path(const std::string& text) {
    return fs::path(text);
}

bool entry_exists(const fs::path& target) {
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(target, ec);
    return !ec && status.type() != fs::file_type::not_found;
}

bool is_link_like(const fs::path& target) {
#if defined(_WIN32)
    const DWORD attributes = ::GetFileAttributesW(target.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u) {
        return true;
    }
#endif
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(target, ec);
    return !ec && fs::is_symlink(status);
}

bool neutralize_links(
    const std::string& root,
    const std::vector<std::string>& components,
    std::size_t count
) {
    fs::path current = to_path(root);

    for (std::size_t i = 0; i < count; ++i) {
        current /= components[i];

        if (!entry_exists(current)) {

            return true;
        }

        if (is_link_like(current)) {
            std::error_code ec;
            fs::remove(current, ec);
            if (ec) {
                return false;
            }

            return true;
        }

        std::error_code ec;
        if (!fs::is_directory(current, ec) || ec) {
            return false;
        }
    }

    return true;
}

bool is_within(const fs::path& outer, const fs::path& inner) {
    auto outer_it = outer.begin();
    auto inner_it = inner.begin();
    for (; outer_it != outer.end(); ++outer_it, ++inner_it) {
        if (inner_it == inner.end()) {
            return false;
        }
        if (*outer_it != *inner_it) {
            return false;
        }
    }
    return true;
}

bool parent_is_contained(const std::string& root, const fs::path& parent) {
    std::error_code root_ec;
    const fs::path canonical_root = fs::canonical(to_path(root), root_ec);
    if (root_ec) {
        return true;
    }

    std::error_code parent_ec;
    const fs::path canonical_parent = fs::canonical(parent, parent_ec);
    if (parent_ec) {
        return true;
    }

    return is_within(canonical_root, canonical_parent);
}

bool prepare_parent(const std::string& root, const std::vector<std::string>& components) {
    if (components.empty()) {
        return false;
    }

    if (!neutralize_links(root, components, components.size() - 1)) {
        return false;
    }

    fs::path parent = to_path(root);
    for (std::size_t i = 0; i + 1 < components.size(); ++i) {
        parent /= components[i];
    }

    std::error_code ec;
    fs::create_directories(parent, ec);
    if (!fs::is_directory(parent, ec) || ec) {
        return false;
    }

    return parent_is_contained(root, parent);
}

bool write_bytes(const fs::path& target, byte_view data, bool append) {
    std::ios::openmode mode = std::ios::out | std::ios::binary;
    mode |= append ? std::ios::app : std::ios::trunc;

    std::ofstream stream(target, mode);
    if (!stream.is_open()) {
        return false;
    }

    if (data.size() > 0 && data.data() != nullptr) {
        stream.write(
            reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size())
        );
        if (!stream.good()) {
            return false;
        }
    }

    stream.close();
    return !stream.fail();
}

}

chroot::chroot(std::string root) : root_() {
    std::error_code ec;
    fs::path resolved;

    if (root.empty()) {
        resolved = fs::current_path(ec);
        if (ec) {
            resolved = fs::path(".");
        }
    } else {
        resolved = fs::absolute(fs::path(root), ec);
        if (ec) {
            resolved = fs::path(root);
        }
    }

    std::string normalized = resolved.lexically_normal().string();

    while (normalized.size() > 1 && is_separator(normalized.back())) {
        const bool is_drive_root = normalized.size() == 3 && is_ascii_alpha(normalized[0]) &&
                                   normalized[1] == ':';
        if (is_drive_root) {
            break;
        }
        normalized.pop_back();
    }
    if (normalized.empty()) {
        normalized = ".";
    }

    root_ = std::move(normalized);

    std::error_code create_ec;
    if (!fs::exists(to_path(root_), create_ec)) {
        fs::create_directories(to_path(root_), create_ec);
    }
}

const std::string& chroot::root() const noexcept {
    return root_;
}

std::string chroot::safe_path_join(std::string_view first, std::string_view second) const {
    std::string combined;
    combined.reserve(first.size() + second.size() + 1);
    combined.append(first);
    combined.push_back(k_separator);
    combined.append(second);

    return join_components(root_, relative_components(root_, combined));
}

std::string chroot::chrooted_path(std::string_view path) const {

    return safe_path_join(path, std::string_view());
}

bool chroot::create_file(std::string_view path, byte_view data) const {
    const std::vector<std::string> components = relative_components(root_, path);
    if (components.empty()) {

        return false;
    }

    if (!prepare_parent(root_, components)) {
        return false;
    }

    const fs::path target = to_path(join_components(root_, components));

    if (entry_exists(target)) {
        return false;
    }

    return write_bytes(target, data, false);
}

bool chroot::carve_file(
    std::string_view path,
    byte_view data,
    std::size_t offset,
    std::size_t size
) const {

    if (!data.contains(offset, size)) {
        return false;
    }
    return create_file(path, data.subview(offset, size));
}

bool chroot::append_to_file(std::string_view path, byte_view data) const {
    const std::vector<std::string> components = relative_components(root_, path);
    if (components.empty()) {
        return false;
    }

    if (!prepare_parent(root_, components)) {
        return false;
    }

    const fs::path target = to_path(join_components(root_, components));

    if (entry_exists(target)) {

        if (is_link_like(target)) {
            return false;
        }
        std::error_code ec;
        if (!fs::is_regular_file(target, ec) || ec) {
            return false;
        }
    }

    return write_bytes(target, data, true);
}

bool chroot::create_directory(std::string_view path) const {
    const std::vector<std::string> components = relative_components(root_, path);
    const fs::path target = to_path(join_components(root_, components));

    if (components.empty()) {

        std::error_code ec;
        return fs::is_directory(target, ec) && !ec;
    }

    if (!neutralize_links(root_, components, components.size())) {
        return false;
    }

    std::error_code ec;
    fs::create_directories(target, ec);
    if (!fs::is_directory(target, ec) || ec) {
        return false;
    }

    return parent_is_contained(root_, target);
}

bool chroot::remove_directory(std::string_view path) const {
    const std::vector<std::string> components = relative_components(root_, path);
    if (components.empty()) {

        return false;
    }

    if (!neutralize_links(root_, components, components.size() - 1)) {
        return false;
    }

    const fs::path target = to_path(join_components(root_, components));

    if (!entry_exists(target)) {

        return true;
    }

    std::error_code ec;
    if (is_link_like(target)) {

        fs::remove(target, ec);
        return !ec;
    }

    fs::remove_all(target, ec);
    return !ec;
}

bool chroot::create_symlink(std::string_view path, std::string_view target) const {
    const std::vector<std::string> link_components = relative_components(root_, path);
    if (link_components.empty()) {
        return false;
    }

#if !defined(_WIN32)

    const bool target_is_absolute =
        (!target.empty() && is_separator(target[0])) ||
        (target.size() >= 2 && is_ascii_alpha(target[0]) && target[1] == ':');

    // A destination that had to be clamped at the extraction root has lost
    // some of its original parent context.  Do not reinterpret a relative
    // target against that rewritten location: preserve it as inert metadata.
    if (!target_is_absolute && !traverses_above_root(root_, path)) {
        std::vector<std::string> resolved(link_components.begin(), link_components.end() - 1);
        bool escaped = false;

        std::size_t start = 0;
        for (;;) {
            std::size_t end = start;
            while (end < target.size() && !is_separator(target[end])) {
                ++end;
            }

            const std::string_view component = target.substr(start, end - start);
            if (component.empty() || component == ".") {

            } else if (component == "..") {
                if (resolved.empty()) {
                    escaped = true;
                    break;
                }
                resolved.pop_back();
            } else {
                resolved.push_back(sanitize_component(component));
            }

            if (end >= target.size()) {
                break;
            }
            start = end + 1;
        }

        if (!escaped && !resolved.empty() && prepare_parent(root_, link_components)) {
            const fs::path link_path = to_path(join_components(root_, link_components));
            const fs::path target_path = to_path(join_components(root_, resolved));
            const fs::path relative_target =
                target_path.lexically_relative(link_path.parent_path());

            if (!relative_target.empty() && !entry_exists(link_path)) {
                std::error_code ec;
                fs::create_symlink(relative_target, link_path, ec);
                if (!ec) {
                    return true;
                }
            }
        }
    }
#endif

    std::string placeholder("symlink ");
    placeholder.append(target);
    return create_file(path, as_bytes(placeholder));
}

bool chroot::create_character_device(
    std::string_view path,
    std::uint32_t major_id,
    std::uint32_t minor_id
) const {
    const std::string contents =
        "c " + std::to_string(major_id) + " " + std::to_string(minor_id);
    return create_file(path, as_bytes(contents));
}

bool chroot::create_block_device(
    std::string_view path,
    std::uint32_t major_id,
    std::uint32_t minor_id
) const {
    const std::string contents =
        "b " + std::to_string(major_id) + " " + std::to_string(minor_id);
    return create_file(path, as_bytes(contents));
}

bool chroot::create_fifo(std::string_view path) const {
    const std::string contents("fifo");
    return create_file(path, as_bytes(contents));
}

bool chroot::create_socket(std::string_view path) const {
    const std::string contents("socket");
    return create_file(path, as_bytes(contents));
}

bool chroot::make_executable(std::string_view path) const {
#if defined(_WIN32)

    (void)path;
    return true;
#else
    const std::vector<std::string> components = relative_components(root_, path);
    if (components.empty()) {
        return false;
    }

    const fs::path target = to_path(join_components(root_, components));

    std::error_code ec;
    const fs::file_status status = fs::symlink_status(target, ec);
    if (ec || status.type() == fs::file_type::not_found || fs::is_symlink(status)) {
        return false;
    }

    fs::permissions(target, fs::perms::others_exec, fs::perm_options::add, ec);
    return !ec;
#endif
}

std::vector<std::string> chroot::extracted_files(std::string_view directory) {
    std::vector<std::string> files;
    if (directory.empty()) {
        return files;
    }

    std::error_code ec;
    fs::path base = fs::absolute(to_path(std::string(directory)), ec);
    if (ec) {
        base = to_path(std::string(directory));
    }

    const auto keep = [&files](const fs::path& candidate) {
        std::error_code status_ec;
        const fs::file_status status = fs::symlink_status(candidate, status_ec);
        if (status_ec || !fs::is_regular_file(status)) {
            return;
        }
        std::error_code size_ec;
        const std::uintmax_t size = fs::file_size(candidate, size_ec);
        if (size_ec || size == 0u) {
            return;
        }
        files.push_back(candidate.string());
    };

    std::error_code dir_ec;
    if (!fs::is_directory(base, dir_ec) || dir_ec) {

        keep(base);
        std::sort(files.begin(), files.end());
        return files;
    }

    std::error_code iter_ec;
    fs::recursive_directory_iterator it(
        base,
        fs::directory_options::skip_permission_denied,
        iter_ec
    );
    if (iter_ec) {
        return files;
    }

    const fs::recursive_directory_iterator end;
    while (it != end) {
        keep(it->path());

        it.increment(iter_ec);
        if (iter_ec) {
            break;
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

}
