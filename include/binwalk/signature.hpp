#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/extractor.hpp>
#include <binwalk/result.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace binwalk {

using signature_parser = std::optional<signature_result> (*)(byte_view, std::size_t);

struct signature {
    std::string name;
    bool short_signature = false;
    std::vector<std::vector<std::uint8_t>> magic;
    std::size_t magic_offset = 0;
    std::string description;
    bool always_display = false;
    signature_parser parser = nullptr;
    std::optional<extractor> extractor_definition;
};

template<typename... Types>
struct type_list {};

template<typename Format>
struct format_traits;

template<typename Format, typename = void>
struct has_format_traits : std::false_type {};

template<typename Format>
struct has_format_traits<Format, std::void_t<
    decltype(format_traits<Format>::name()),
    decltype(format_traits<Format>::description()),
    decltype(format_traits<Format>::magic()),
    decltype(format_traits<Format>::parse(std::declval<byte_view>(), std::declval<std::size_t>()))
>> : std::true_type {};

template<typename Format>
inline constexpr bool has_format_traits_v = has_format_traits<Format>::value;

template<typename Format, typename = void>
struct has_short_signature_flag : std::false_type {};

template<typename Format>
struct has_short_signature_flag<Format, std::void_t<decltype(format_traits<Format>::short_signature)>>
    : std::true_type {};

template<typename Format, typename = void>
struct has_magic_offset : std::false_type {};

template<typename Format>
struct has_magic_offset<Format, std::void_t<decltype(format_traits<Format>::magic_offset)>>
    : std::true_type {};

template<typename Format, typename = void>
struct has_always_display_flag : std::false_type {};

template<typename Format>
struct has_always_display_flag<Format, std::void_t<decltype(format_traits<Format>::always_display)>>
    : std::true_type {};

template<typename Format, typename = void>
struct has_extractor_definition : std::false_type {};

template<typename Format>
struct has_extractor_definition<Format, std::void_t<decltype(format_traits<Format>::extractor())>>
    : std::true_type {};

template<typename Format>
[[nodiscard]] signature make_signature() {
    static_assert(has_format_traits_v<Format>, "Format must provide a format_traits specialization");
    using traits = format_traits<Format>;

    signature value;
    value.name = traits::name();
    value.description = traits::description();
    value.magic = traits::magic();
    value.parser = &traits::parse;

    if constexpr(has_short_signature_flag<Format>::value) {
        value.short_signature = static_cast<bool>(traits::short_signature);
    }
    if constexpr(has_magic_offset<Format>::value) {
        value.magic_offset = static_cast<std::size_t>(traits::magic_offset);
    }
    if constexpr(has_always_display_flag<Format>::value) {
        value.always_display = static_cast<bool>(traits::always_display);
    }
    if constexpr(has_extractor_definition<Format>::value) {
        value.extractor_definition = traits::extractor();
    }
    return value;
}

template<typename... Formats>
[[nodiscard]] std::vector<signature> make_signatures(type_list<Formats...>) {
    std::vector<signature> signatures;
    signatures.reserve(sizeof...(Formats));
    (signatures.push_back(make_signature<Formats>()), ...);
    return signatures;
}

} // namespace binwalk
