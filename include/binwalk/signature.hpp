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

namespace meta {

struct nonesuch {
    nonesuch() = delete;
    ~nonesuch() = delete;
    nonesuch(const nonesuch&) = delete;
    void operator=(const nonesuch&) = delete;
};

namespace detail {

template<typename Default, typename AlwaysVoid, template<typename...> class Op, typename... Args>
struct detector {
    using value_t = std::false_type;
    using type = Default;
};

template<typename Default, template<typename...> class Op, typename... Args>
struct detector<Default, std::void_t<Op<Args...>>, Op, Args...> {
    using value_t = std::true_type;
    using type = Op<Args...>;
};

} // namespace detail

template<template<typename...> class Op, typename... Args>
using is_detected = typename detail::detector<nonesuch, void, Op, Args...>::value_t;

template<template<typename...> class Op, typename... Args>
inline constexpr bool is_detected_v = is_detected<Op, Args...>::value;

template<template<typename...> class Op, typename... Args>
using detected_t = typename detail::detector<nonesuch, void, Op, Args...>::type;

template<typename Default, template<typename...> class Op, typename... Args>
using detected_or_t = typename detail::detector<Default, void, Op, Args...>::type;

template<typename Expected, template<typename...> class Op, typename... Args>
inline constexpr bool is_detected_exact_v = std::is_same<Expected, detected_t<Op, Args...>>::value;

template<typename To, template<typename...> class Op, typename... Args>
inline constexpr bool is_detected_convertible_v = std::is_convertible<detected_t<Op, Args...>, To>::value;

template<typename Expected, template<typename...> class Op, typename... Args>
inline constexpr bool is_detected_decayed_v =
    std::is_same<Expected, typename std::decay<detected_t<Op, Args...>>::type>::value;

template<typename T>
inline constexpr bool is_index_like_v =
    std::is_integral<typename std::decay<T>::type>::value
    && !std::is_same<typename std::decay<T>::type, bool>::value;

template<typename T, typename... Ts>
inline constexpr std::size_t occurrences_v = (static_cast<std::size_t>(std::is_same<T, Ts>::value) + ... + std::size_t{0});

template<typename... Ts>
inline constexpr bool all_distinct_v = ((occurrences_v<Ts, Ts...> == std::size_t{1}) && ... && true);

} // namespace meta

template<typename... Types>
struct type_list {
    static constexpr std::size_t size = sizeof...(Types);
};

template<typename... Left, typename... Right>
constexpr type_list<Left..., Right...> operator+(type_list<Left...>, type_list<Right...>) noexcept {
    return {};
}

template<typename Format>
struct format_traits;

namespace meta {

template<typename F> using trait_name_t = decltype(format_traits<F>::name());
template<typename F> using trait_description_t = decltype(format_traits<F>::description());
template<typename F> using trait_magic_t = decltype(format_traits<F>::magic());
template<typename F> using trait_parse_ptr_t = decltype(&format_traits<F>::parse);
template<typename F> using trait_extractor_t = decltype(format_traits<F>::extractor());
template<typename F> using trait_short_signature_t = decltype(format_traits<F>::short_signature);
template<typename F> using trait_magic_offset_t = decltype(format_traits<F>::magic_offset);
template<typename F> using trait_always_display_t = decltype(format_traits<F>::always_display);

} // namespace meta

template<typename Format>
struct format_probe {
    static constexpr bool has_name = meta::is_detected_v<meta::trait_name_t, Format>;
    static constexpr bool has_description = meta::is_detected_v<meta::trait_description_t, Format>;
    static constexpr bool has_magic = meta::is_detected_v<meta::trait_magic_t, Format>;
    static constexpr bool has_parse = meta::is_detected_v<meta::trait_parse_ptr_t, Format>;

    static constexpr bool has_extractor = meta::is_detected_v<meta::trait_extractor_t, Format>;
    static constexpr bool has_short_signature = meta::is_detected_v<meta::trait_short_signature_t, Format>;
    static constexpr bool has_magic_offset = meta::is_detected_v<meta::trait_magic_offset_t, Format>;
    static constexpr bool has_always_display = meta::is_detected_v<meta::trait_always_display_t, Format>;

    static constexpr bool name_ok = meta::is_detected_convertible_v<std::string, meta::trait_name_t, Format>;
    static constexpr bool description_ok = meta::is_detected_convertible_v<std::string, meta::trait_description_t, Format>;
    static constexpr bool magic_ok =
        meta::is_detected_convertible_v<std::vector<std::vector<std::uint8_t>>, meta::trait_magic_t, Format>;
    static constexpr bool parse_ok = meta::is_detected_exact_v<signature_parser, meta::trait_parse_ptr_t, Format>;
    static constexpr bool extractor_ok = meta::is_detected_convertible_v<extractor, meta::trait_extractor_t, Format>;
    static constexpr bool short_signature_ok =
        meta::is_detected_decayed_v<bool, meta::trait_short_signature_t, Format>;
    static constexpr bool magic_offset_ok =
        meta::is_index_like_v<meta::detected_t<meta::trait_magic_offset_t, Format>>;
    static constexpr bool always_display_ok =
        meta::is_detected_decayed_v<bool, meta::trait_always_display_t, Format>;

    static constexpr bool complete = has_name && has_description && has_magic && has_parse;
    static constexpr bool well_typed = name_ok && description_ok && magic_ok && parse_ok
        && (!has_extractor || extractor_ok)
        && (!has_short_signature || short_signature_ok)
        && (!has_magic_offset || magic_offset_ok)
        && (!has_always_display || always_display_ok);
};

template<typename Format>
inline constexpr bool is_format_v = format_probe<Format>::complete && format_probe<Format>::well_typed;

template<typename Format>
struct assert_format {
    using probe = format_probe<Format>;

    static_assert(probe::has_name,
        "format_traits<Format> must declare: static std::string name()");
    static_assert(probe::has_description,
        "format_traits<Format> must declare: static std::string description()");
    static_assert(probe::has_magic,
        "format_traits<Format> must declare: static std::vector<std::vector<std::uint8_t>> magic()");
    static_assert(probe::has_parse,
        "format_traits<Format> must declare: static std::optional<signature_result> parse(byte_view, std::size_t)");

    static_assert(!probe::has_name || probe::name_ok,
        "format_traits<Format>::name() must return something convertible to std::string");
    static_assert(!probe::has_description || probe::description_ok,
        "format_traits<Format>::description() must return something convertible to std::string");
    static_assert(!probe::has_magic || probe::magic_ok,
        "format_traits<Format>::magic() must return something convertible to std::vector<std::vector<std::uint8_t>>");
    static_assert(!probe::has_parse || probe::parse_ok,
        "format_traits<Format>::parse must be exactly std::optional<signature_result>(byte_view, std::size_t) "
        "and must not be overloaded or a template");
    static_assert(!probe::has_extractor || probe::extractor_ok,
        "format_traits<Format>::extractor() must return something convertible to binwalk::extractor");
    static_assert(!probe::has_short_signature || probe::short_signature_ok,
        "format_traits<Format>::short_signature must be exactly bool");
    static_assert(!probe::has_magic_offset || probe::magic_offset_ok,
        "format_traits<Format>::magic_offset must be a non-bool integral type");
    static_assert(!probe::has_always_display || probe::always_display_ok,
        "format_traits<Format>::always_display must be exactly bool");

    static constexpr bool value = true;
};

template<typename Format>
[[nodiscard]] constexpr bool short_signature_of() noexcept {
    if constexpr(format_probe<Format>::has_short_signature) {
        return static_cast<bool>(format_traits<Format>::short_signature);
    } else {
        return false;
    }
}

template<typename Format>
[[nodiscard]] constexpr std::size_t magic_offset_of() noexcept {
    if constexpr(format_probe<Format>::has_magic_offset) {
        return static_cast<std::size_t>(format_traits<Format>::magic_offset);
    } else {
        return std::size_t{0};
    }
}

template<typename Format>
[[nodiscard]] constexpr bool always_display_of() noexcept {
    if constexpr(format_probe<Format>::has_always_display) {
        return static_cast<bool>(format_traits<Format>::always_display);
    } else {
        return false;
    }
}

template<typename Format>
[[nodiscard]] std::optional<extractor> extractor_of() {
    if constexpr(format_probe<Format>::has_extractor) {
        return format_traits<Format>::extractor();
    } else {
        return std::nullopt;
    }
}

template<typename Format>
[[nodiscard]] signature make_signature() {
    static_assert(assert_format<Format>::value);
    using traits = format_traits<Format>;

    signature value;
    value.name = traits::name();
    value.description = traits::description();
    value.magic = traits::magic();
    value.parser = &traits::parse;
    value.short_signature = short_signature_of<Format>();
    value.magic_offset = magic_offset_of<Format>();
    value.always_display = always_display_of<Format>();
    value.extractor_definition = extractor_of<Format>();
    return value;
}

template<typename... Formats>
[[nodiscard]] std::vector<signature> make_signatures(type_list<Formats...>) {
    static_assert(meta::all_distinct_v<Formats...>,
        "the same format type is registered more than once in this type_list");

    std::vector<signature> signatures;
    signatures.reserve(sizeof...(Formats));
    (signatures.emplace_back(make_signature<Formats>()), ...);
    return signatures;
}

} // namespace binwalk
