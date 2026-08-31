#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
namespace binwalk {

class chroot {
public:

    BINWALK_API explicit chroot(std::string root);

    [[nodiscard]] BINWALK_API const std::string& root() const noexcept;

    [[nodiscard]] BINWALK_API std::string safe_path_join(
        std::string_view first,
        std::string_view second
    ) const;

    [[nodiscard]] BINWALK_API std::string chrooted_path(std::string_view path) const;

    [[nodiscard]] BINWALK_API bool create_file(std::string_view path, byte_view data) const;

    [[nodiscard]] BINWALK_API bool carve_file(
        std::string_view path,
        byte_view data,
        std::size_t offset,
        std::size_t size
    ) const;

    [[nodiscard]] BINWALK_API bool append_to_file(std::string_view path, byte_view data) const;

    [[nodiscard]] BINWALK_API bool create_directory(std::string_view path) const;

    [[nodiscard]] BINWALK_API bool remove_directory(std::string_view path) const;

    [[nodiscard]] BINWALK_API bool create_symlink(
        std::string_view path,
        std::string_view target
    ) const;

    [[nodiscard]] BINWALK_API bool create_character_device(
        std::string_view path,
        std::uint32_t major,
        std::uint32_t minor
    ) const;

    [[nodiscard]] BINWALK_API bool create_block_device(
        std::string_view path,
        std::uint32_t major,
        std::uint32_t minor
    ) const;

    [[nodiscard]] BINWALK_API bool create_fifo(std::string_view path) const;

    [[nodiscard]] BINWALK_API bool create_socket(std::string_view path) const;

    [[nodiscard]] BINWALK_API bool make_executable(std::string_view path) const;

    [[nodiscard]] BINWALK_API static std::vector<std::string> extracted_files(
        std::string_view directory
    );

private:
    std::string root_;
};

}
