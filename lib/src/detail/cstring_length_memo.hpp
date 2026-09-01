#pragma once

#include <binwalk/byte_view.hpp>

namespace binwalk {
namespace detail {

class cstring_length_memo {
public:
    explicit cstring_length_memo(byte_view data) noexcept;
    ~cstring_length_memo();

    cstring_length_memo(const cstring_length_memo&) = delete;
    cstring_length_memo& operator=(const cstring_length_memo&) = delete;
    cstring_length_memo(cstring_length_memo&&) = delete;
    cstring_length_memo& operator=(cstring_length_memo&&) = delete;

private:
    byte_view restored_view_;
    const void* restored_verified_begin_;
    const void* restored_verified_end_;
    const void* restored_terminator_;
};

}
}
