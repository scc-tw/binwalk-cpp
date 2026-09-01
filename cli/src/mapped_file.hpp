#pragma once

#include <binwalk/byte_view.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
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
#else
#    include <fcntl.h>
#    include <sys/mman.h>
#    include <sys/stat.h>
#    include <unistd.h>
#endif

namespace binwalk_cli {

class mapped_file {
public:
    mapped_file() = default;

    mapped_file(const mapped_file&) = delete;
    mapped_file& operator=(const mapped_file&) = delete;

    mapped_file(mapped_file&& other) noexcept { swap(other); }

    mapped_file& operator=(mapped_file&& other) noexcept {
        if(this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    ~mapped_file() { close(); }

    [[nodiscard]] static bool open(const std::string& path, mapped_file& result) {
        mapped_file opened;
        if(!opened.map_for_sequential_reading(path)) {
            opened.close();
            if(!opened.read_whole_file(path)) {
                return false;
            }
        }
        result = std::move(opened);
        return true;
    }

    [[nodiscard]] binwalk::byte_view view() const noexcept { return {data_, size_}; }

private:
    void swap(mapped_file& other) noexcept {
        std::swap(data_, other.data_);
        std::swap(size_, other.size_);
        buffer_.swap(other.buffer_);
#if defined(_WIN32)
        std::swap(mapping_, other.mapping_);
        std::swap(file_, other.file_);
#else
        std::swap(mapped_, other.mapped_);
        std::swap(mapped_size_, other.mapped_size_);
#endif
    }

#if defined(_WIN32)
    [[nodiscard]] static std::wstring widen(const std::string& path) {
        const int length = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        if(length <= 0) {
            return {};
        }
        std::wstring wide(static_cast<std::size_t>(length), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), length);
        wide.pop_back();
        return wide;
    }

    void prefetch_whole_mapping() const noexcept {
        struct memory_range {
            void* address;
            SIZE_T length;
        };
        using prefetch_entry_point = BOOL(WINAPI*)(HANDLE, ULONG_PTR, memory_range*, ULONG);

        auto* const kernel32 = GetModuleHandleW(L"kernel32.dll");
        if(kernel32 == nullptr) {
            return;
        }
        auto* const prefetch_virtual_memory = reinterpret_cast<prefetch_entry_point>(
            reinterpret_cast<void*>(GetProcAddress(kernel32, "PrefetchVirtualMemory"))
        );
        if(prefetch_virtual_memory == nullptr) {
            return;
        }
        memory_range range{const_cast<std::uint8_t*>(data_), size_};
        prefetch_virtual_memory(GetCurrentProcess(), 1, &range, 0);
    }

    [[nodiscard]] bool map_for_sequential_reading(const std::string& path) {
        const auto wide = widen(path);
        if(wide.empty()) {
            return false;
        }

        file_ = CreateFileW(
            wide.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr
        );
        if(file_ == INVALID_HANDLE_VALUE) {
            return false;
        }

        LARGE_INTEGER length{};
        if(GetFileSizeEx(file_, &length) == 0 || length.QuadPart <= 0) {
            return false;
        }
        if(static_cast<unsigned long long>(length.QuadPart)
            > static_cast<unsigned long long>(static_cast<std::size_t>(-1))) {
            return false;
        }

        mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if(mapping_ == nullptr) {
            return false;
        }
        auto* const address = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if(address == nullptr) {
            return false;
        }

        data_ = static_cast<const std::uint8_t*>(address);
        size_ = static_cast<std::size_t>(length.QuadPart);
        prefetch_whole_mapping();
        return true;
    }
#else
    void advise_sequential_access() const noexcept {
        ::madvise(const_cast<std::uint8_t*>(data_), size_, MADV_SEQUENTIAL);
        ::madvise(const_cast<std::uint8_t*>(data_), size_, MADV_WILLNEED);
    }

    [[nodiscard]] bool map_for_sequential_reading(const std::string& path) {
        const int descriptor = ::open(path.c_str(), O_RDONLY);
        if(descriptor < 0) {
            return false;
        }
        struct stat status {};
        if(::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size <= 0) {
            ::close(descriptor);
            return false;
        }

        const auto length = static_cast<std::size_t>(status.st_size);
        void* const address = ::mmap(nullptr, length, PROT_READ, MAP_PRIVATE, descriptor, 0);
        ::close(descriptor);
        if(address == MAP_FAILED) {
            return false;
        }

        mapped_ = address;
        mapped_size_ = length;
        data_ = static_cast<const std::uint8_t*>(address);
        size_ = length;
        advise_sequential_access();
        return true;
    }
#endif

    [[nodiscard]] bool read_whole_file(const std::string& path) {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if(!input) {
            return false;
        }
        const auto length = input.tellg();
        if(length < 0) {
            return false;
        }
        input.seekg(0, std::ios::beg);

        buffer_.resize(static_cast<std::size_t>(length));
        if(!buffer_.empty()) {
            input.read(
                reinterpret_cast<char*>(buffer_.data()),
                static_cast<std::streamsize>(buffer_.size())
            );
            if(input.gcount() != static_cast<std::streamsize>(buffer_.size())) {
                return false;
            }
        }
        data_ = buffer_.data();
        size_ = buffer_.size();
        return true;
    }

    void close() noexcept {
#if defined(_WIN32)
        if(mapping_ != nullptr) {
            if(data_ != nullptr) {
                UnmapViewOfFile(data_);
            }
            CloseHandle(mapping_);
            mapping_ = nullptr;
        }
        if(file_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
        }
#else
        if(mapped_ != nullptr) {
            ::munmap(mapped_, mapped_size_);
            mapped_ = nullptr;
            mapped_size_ = 0;
        }
#endif
        data_ = nullptr;
        size_ = 0;
        std::vector<std::uint8_t>().swap(buffer_);
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::vector<std::uint8_t> buffer_;

#if defined(_WIN32)
    HANDLE mapping_ = nullptr;
    HANDLE file_ = INVALID_HANDLE_VALUE;
#else
    void* mapped_ = nullptr;
    std::size_t mapped_size_ = 0;
#endif
};

}
