#include <binwalk/common.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <string>
#include <vector>
namespace {

constexpr char kCheckString[] = "123456789";

std::vector<std::uint8_t> ascii_bytes(const char* text) {
    std::vector<std::uint8_t> out;
    for(const char* cursor = text; *cursor != '\0'; ++cursor) {
        out.push_back(static_cast<std::uint8_t>(*cursor));
    }
    return out;
}

std::string bytes_to_string(const std::vector<std::uint8_t>& data) {
    std::string out;
    out.reserve(data.size());
    for(const std::uint8_t value : data) {
        out.push_back(static_cast<char>(value));
    }
    return out;
}

std::uint32_t adler32_closed_form(const std::vector<std::uint8_t>& data) {
    const std::uint64_t length = data.size();
    std::uint64_t sum = 0;
    std::uint64_t weighted_sum = 0;
    for(std::uint64_t index = 1; index <= length; ++index) {
        const std::uint64_t value = data[static_cast<std::size_t>(index - 1)];
        sum += value;
        weighted_sum += value * (length - index + 1);
    }
    const auto s1 = static_cast<std::uint32_t>((std::uint64_t{1} + sum) % 65521U);
    const auto s2 = static_cast<std::uint32_t>((length + weighted_sum) % 65521U);
    return (s2 << 16) | s1;
}

std::vector<std::uint8_t> pseudo_random_bytes(std::size_t length) {
    std::vector<std::uint8_t> out(length);
    for(std::size_t index = 0; index < length; ++index) {
        out[index] = static_cast<std::uint8_t>((index * 7U + 11U) & 0xFFU);
    }
    return out;
}

constexpr std::size_t kSizeMax = std::numeric_limits<std::size_t>::max();
constexpr std::uint64_t kUint64Max = std::numeric_limits<std::uint64_t>::max();

}

TEST(CommonChecksums, Crc32MatchesIsoHdlcCatalogueCheckValue) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);
    ASSERT_EQ(data.size(), std::size_t{9});

    EXPECT_EQ(binwalk::crc32(binwalk::byte_view(data)), 0xCBF43926U);
}

TEST(CommonChecksums, Crc32MatchesUpstreamDoctest) {

    const std::vector<std::uint8_t> data = ascii_bytes("ABCD");
    EXPECT_EQ(binwalk::crc32(binwalk::byte_view(data)), 0xDB1720A5U);
}

TEST(CommonChecksums, Crc32JamcrcMatchesCatalogueCheckValue) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);

    EXPECT_EQ(binwalk::crc32_jamcrc(binwalk::byte_view(data)), 0x340BC6D9U);
    EXPECT_EQ(binwalk::crc32_jamcrc(binwalk::byte_view(data)), 0xCBF43926U ^ 0xFFFFFFFFU);
}

TEST(CommonChecksums, Crc32Bzip2MatchesCatalogueCheckValue) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);

    EXPECT_EQ(binwalk::crc32_bzip2(binwalk::byte_view(data)), 0xFC891918U);
}

TEST(CommonChecksums, Crc32PosixMatchesCatalogueCheckValue) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);

    EXPECT_EQ(binwalk::crc32_posix(binwalk::byte_view(data)), 0x765E7680U);
}

TEST(CommonChecksums, Adler32MatchesCatalogueCheckValue) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);

    EXPECT_EQ(binwalk::adler32(binwalk::byte_view(data)), 0x091E01DEU);
    EXPECT_EQ(binwalk::adler32(binwalk::byte_view(data)), (2334U << 16) | 478U);
    EXPECT_EQ(binwalk::adler32(binwalk::byte_view(data)), adler32_closed_form(data));
}

TEST(CommonChecksums, AllFourCrcVariantsDifferOnTheSameInput) {

    const std::vector<std::uint8_t> check = ascii_bytes(kCheckString);
    const binwalk::byte_view view(check);

    const std::uint32_t iso_hdlc = binwalk::crc32(view);
    const std::uint32_t jamcrc = binwalk::crc32_jamcrc(view);
    const std::uint32_t bzip2 = binwalk::crc32_bzip2(view);
    const std::uint32_t posix = binwalk::crc32_posix(view);

    EXPECT_NE(iso_hdlc, jamcrc);
    EXPECT_NE(iso_hdlc, bzip2);
    EXPECT_NE(iso_hdlc, posix);
    EXPECT_NE(jamcrc, bzip2);
    EXPECT_NE(jamcrc, posix);
    EXPECT_NE(bzip2, posix);

    const std::vector<std::uint8_t> abcd = ascii_bytes("ABCD");
    const binwalk::byte_view abcd_view(abcd);

    EXPECT_NE(binwalk::crc32(abcd_view), binwalk::crc32_jamcrc(abcd_view));
    EXPECT_NE(binwalk::crc32(abcd_view), binwalk::crc32_bzip2(abcd_view));
    EXPECT_NE(binwalk::crc32(abcd_view), binwalk::crc32_posix(abcd_view));
    EXPECT_NE(binwalk::crc32_jamcrc(abcd_view), binwalk::crc32_bzip2(abcd_view));
    EXPECT_NE(binwalk::crc32_jamcrc(abcd_view), binwalk::crc32_posix(abcd_view));
    EXPECT_NE(binwalk::crc32_bzip2(abcd_view), binwalk::crc32_posix(abcd_view));
}

TEST(CommonChecksums, EmptyInputYieldsInitXorFinalXor) {
    const std::vector<std::uint8_t> empty_data;
    const binwalk::byte_view empty_view(empty_data);
    ASSERT_TRUE(empty_view.empty());

    EXPECT_EQ(binwalk::crc32(empty_view), 0xFFFFFFFFU ^ 0xFFFFFFFFU);
    EXPECT_EQ(binwalk::crc32(empty_view), 0x00000000U);

    EXPECT_EQ(binwalk::crc32_jamcrc(empty_view), 0xFFFFFFFFU);

    EXPECT_EQ(binwalk::crc32_bzip2(empty_view), 0xFFFFFFFFU ^ 0xFFFFFFFFU);
    EXPECT_EQ(binwalk::crc32_bzip2(empty_view), 0x00000000U);

    EXPECT_EQ(binwalk::crc32_posix(empty_view), 0x00000000U ^ 0xFFFFFFFFU);
    EXPECT_EQ(binwalk::crc32_posix(empty_view), 0xFFFFFFFFU);

    EXPECT_EQ(binwalk::adler32(empty_view), 1U);

    const binwalk::byte_view default_view;
    EXPECT_EQ(binwalk::crc32(default_view), 0x00000000U);
    EXPECT_EQ(binwalk::crc32_jamcrc(default_view), 0xFFFFFFFFU);
    EXPECT_EQ(binwalk::crc32_bzip2(default_view), 0x00000000U);
    EXPECT_EQ(binwalk::crc32_posix(default_view), 0xFFFFFFFFU);
    EXPECT_EQ(binwalk::adler32(default_view), 1U);
}

TEST(CommonChecksums, Crc32UpdateIsChunkTransparent) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);
    const binwalk::byte_view view(data);

    EXPECT_EQ(binwalk::crc32_update(0U, view), binwalk::crc32(view));
    EXPECT_EQ(binwalk::crc32_update(0U, view), 0xCBF43926U);

    std::uint32_t running = 0U;
    running = binwalk::crc32_update(running, view.subview(0, 3));
    running = binwalk::crc32_update(running, view.subview(3, 0));
    running = binwalk::crc32_update(running, view.subview(3, 1));
    running = binwalk::crc32_update(running, view.subview(4, 5));

    EXPECT_EQ(running, 0xCBF43926U);
    EXPECT_EQ(running, binwalk::crc32(view));

    const binwalk::byte_view empty_view = view.subview(9, 0);
    ASSERT_TRUE(empty_view.empty());
    EXPECT_EQ(binwalk::crc32_update(0xCBF43926U, empty_view), 0xCBF43926U);
    EXPECT_EQ(binwalk::crc32_update(0U, empty_view), 0x00000000U);
}

TEST(CommonChecksums, Adler32UpdateIsChunkTransparent) {
    const std::vector<std::uint8_t> data = ascii_bytes(kCheckString);
    const binwalk::byte_view view(data);

    EXPECT_EQ(binwalk::adler32_update(1U, view), binwalk::adler32(view));
    EXPECT_EQ(binwalk::adler32_update(1U, view), 0x091E01DEU);

    std::uint32_t running = 1U;
    running = binwalk::adler32_update(running, view.subview(0, 3));
    running = binwalk::adler32_update(running, view.subview(3, 0));
    running = binwalk::adler32_update(running, view.subview(3, 1));
    running = binwalk::adler32_update(running, view.subview(4, 5));

    EXPECT_EQ(running, 0x091E01DEU);
    EXPECT_EQ(running, binwalk::adler32(view));

    const binwalk::byte_view empty_view = view.subview(9, 0);
    ASSERT_TRUE(empty_view.empty());
    EXPECT_EQ(binwalk::adler32_update(1U, empty_view), 1U);
    EXPECT_EQ(binwalk::adler32_update(0x091E01DEU, empty_view), 0x091E01DEU);
}

TEST(CommonChecksums, Adler32HandlesInputsLongerThanTheModuloBlock) {

    const std::vector<std::uint8_t> ones(6000, 0xFFU);
    const binwalk::byte_view ones_view(ones);

    EXPECT_EQ(binwalk::adler32(ones_view), 0xA49759EAU);
    EXPECT_EQ(binwalk::adler32(ones_view), (42135U << 16) | 23018U);
    EXPECT_EQ(binwalk::adler32(ones_view), adler32_closed_form(ones));

    const std::vector<std::uint8_t> pseudo = pseudo_random_bytes(6000);
    const binwalk::byte_view pseudo_view(pseudo);
    EXPECT_EQ(binwalk::adler32(pseudo_view), adler32_closed_form(pseudo));
    EXPECT_EQ(binwalk::adler32(pseudo_view), 0x0895ABEEU);

    std::uint32_t running = 1U;
    running = binwalk::adler32_update(running, pseudo_view.subview(0, 5551));
    running = binwalk::adler32_update(running, pseudo_view.subview(5551, 1));
    running = binwalk::adler32_update(running, pseudo_view.subview(5552, 0));
    running = binwalk::adler32_update(running, pseudo_view.subview(5552, 448));
    EXPECT_EQ(running, binwalk::adler32(pseudo_view));
    EXPECT_EQ(running, 0x0895ABEEU);
}

TEST(CommonChecksums, Crc32RangeOverloadHonoursItsBounds) {

    const std::vector<std::uint8_t> data = ascii_bytes("XABCD");
    const binwalk::byte_view view(data);
    ASSERT_EQ(data.size(), std::size_t{5});

    EXPECT_EQ(binwalk::crc32(view, 1, 4), 0xDB1720A5U);

    EXPECT_EQ(binwalk::crc32(view, 0, 5), binwalk::crc32(view));

    EXPECT_EQ(binwalk::crc32(view, 0, 6), 0U);
    EXPECT_EQ(binwalk::crc32(view, 6, 0), 0U);
    EXPECT_EQ(binwalk::crc32(view, 2, 4), 0U);
    EXPECT_EQ(binwalk::crc32(view, kSizeMax, 1), 0U);

    EXPECT_EQ(binwalk::crc32(view, 1, kSizeMax), 0U);
    EXPECT_EQ(binwalk::crc32(view, kSizeMax, kSizeMax), 0U);
    EXPECT_EQ(binwalk::crc32(view, kSizeMax - 3, 4), 0U);
}

TEST(CommonTimestamps, EpochToStringMatchesUpstreamDoctest) {

    EXPECT_EQ(binwalk::epoch_to_string(0), "1970-01-01 00:00:00");

    EXPECT_EQ(binwalk::epoch_to_string(std::uint32_t{0}), "1970-01-01 00:00:00");
    EXPECT_EQ(binwalk::epoch_to_string(std::int64_t{0}), "1970-01-01 00:00:00");
    EXPECT_EQ(binwalk::epoch_to_string(std::size_t{0}), "1970-01-01 00:00:00");
}

TEST(CommonTimestamps, EpochToStringFormatsKnownUtcInstants) {
    EXPECT_EQ(binwalk::epoch_to_string(59), "1970-01-01 00:00:59");
    EXPECT_EQ(binwalk::epoch_to_string(86399), "1970-01-01 23:59:59");
    EXPECT_EQ(binwalk::epoch_to_string(86400), "1970-01-02 00:00:00");

    EXPECT_EQ(binwalk::epoch_to_string(946684800), "2000-01-01 00:00:00");
    EXPECT_EQ(binwalk::epoch_to_string(951782400), "2000-02-29 00:00:00");

    EXPECT_EQ(binwalk::epoch_to_string(1000000000), "2001-09-09 01:46:40");

    EXPECT_EQ(binwalk::epoch_to_string(2147483647), "2038-01-19 03:14:07");
    EXPECT_EQ(binwalk::epoch_to_string(std::int64_t{2147483647}), "2038-01-19 03:14:07");

    EXPECT_EQ(binwalk::epoch_to_string(std::uint32_t{4294967295U}), "2106-02-07 06:28:15");
}

TEST(CommonTimestamps, EpochToStringRejectsUnrepresentableValues) {

    EXPECT_EQ(binwalk::epoch_to_string(std::int64_t{1} << 60), "");

    EXPECT_EQ(binwalk::epoch_to_string(std::numeric_limits<std::int64_t>::max()), "");

    EXPECT_EQ(binwalk::epoch_to_string(std::uint64_t{1} << 63), "");
    EXPECT_EQ(binwalk::epoch_to_string(std::numeric_limits<std::uint64_t>::max()), "");
}

namespace {

std::optional<std::size_t> previous(std::size_t value) {
    return std::optional<std::size_t>{value};
}

void expect_product(std::uint64_t left, std::uint64_t right, std::uint64_t expected) {
    const std::optional<std::uint64_t> product = binwalk::checked_multiply(left, right);
    ASSERT_TRUE(product.has_value()) << left << " * " << right << " must not overflow";
    EXPECT_EQ(*product, expected);
}

void expect_overflow(std::uint64_t left, std::uint64_t right) {
    EXPECT_FALSE(binwalk::checked_multiply(left, right).has_value())
        << left << " * " << right << " must be reported as overflow";
}

}

TEST(CommonOffsetSafety, IsOffsetSafeMatchesUpstreamCases) {

    EXPECT_TRUE(binwalk::is_offset_safe(4, 0, std::nullopt));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 4, std::nullopt));
    EXPECT_TRUE(binwalk::is_offset_safe(4, 2, previous(1)));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 2, previous(2)));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 1, previous(2)));

    EXPECT_FALSE(binwalk::is_offset_safe(4, 4, previous(3)));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 5, std::nullopt));

    EXPECT_FALSE(binwalk::is_offset_safe(0, 0, std::nullopt));
    EXPECT_FALSE(binwalk::is_offset_safe(0, 1, std::nullopt));
    EXPECT_FALSE(binwalk::is_offset_safe(0, 0, previous(0)));

    EXPECT_FALSE(binwalk::is_offset_safe(4, 0, previous(0)));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 3, previous(3)));
    EXPECT_TRUE(binwalk::is_offset_safe(4, 3, previous(2)));
    EXPECT_TRUE(binwalk::is_offset_safe(4, 3, previous(0)));

    EXPECT_FALSE(binwalk::is_offset_safe(4, 1, previous(3)));

    EXPECT_FALSE(binwalk::is_offset_safe(kSizeMax, kSizeMax, std::nullopt));
    EXPECT_TRUE(binwalk::is_offset_safe(kSizeMax, kSizeMax - 1, previous(0)));
    EXPECT_FALSE(binwalk::is_offset_safe(kSizeMax, 0, previous(kSizeMax)));
}

TEST(CommonOffsetSafety, IsRangeSafeUsesContainsSemantics) {
    EXPECT_TRUE(binwalk::is_range_safe(4, 0, 0));
    EXPECT_TRUE(binwalk::is_range_safe(4, 0, 4));
    EXPECT_TRUE(binwalk::is_range_safe(4, 2, 2));
    EXPECT_TRUE(binwalk::is_range_safe(4, 1, 3));

    EXPECT_FALSE(binwalk::is_range_safe(4, 0, 5));
    EXPECT_FALSE(binwalk::is_range_safe(4, 2, 3));
    EXPECT_FALSE(binwalk::is_range_safe(4, 4, 1));
    EXPECT_FALSE(binwalk::is_range_safe(4, 5, 0));

    EXPECT_TRUE(binwalk::is_range_safe(4, 4, 0));
    EXPECT_FALSE(binwalk::is_offset_safe(4, 4, std::nullopt));

    EXPECT_TRUE(binwalk::is_range_safe(0, 0, 0));
    EXPECT_FALSE(binwalk::is_range_safe(0, 0, 1));
    EXPECT_FALSE(binwalk::is_range_safe(0, 1, 0));
}

TEST(CommonOffsetSafety, IsRangeSafeRejectsOverflowingRanges) {

    EXPECT_FALSE(binwalk::is_range_safe(4, 1, kSizeMax));
    EXPECT_FALSE(binwalk::is_range_safe(4, kSizeMax, 1));
    EXPECT_FALSE(binwalk::is_range_safe(4, kSizeMax, kSizeMax));

    EXPECT_FALSE(binwalk::is_range_safe(4, kSizeMax - 3, 4));

    EXPECT_FALSE(binwalk::is_range_safe(100, kSizeMax - 10, 20));

    EXPECT_TRUE(binwalk::is_range_safe(kSizeMax, 0, kSizeMax));
    EXPECT_TRUE(binwalk::is_range_safe(kSizeMax, kSizeMax, 0));
    EXPECT_TRUE(binwalk::is_range_safe(kSizeMax, 1, kSizeMax - 1));
    EXPECT_FALSE(binwalk::is_range_safe(kSizeMax, kSizeMax, 1));
    EXPECT_FALSE(binwalk::is_range_safe(kSizeMax, 1, kSizeMax));
}

TEST(CommonOffsetSafety, CheckedMultiplyGuardsTheBlockCountPattern) {

    expect_product(0, 0, 0);
    expect_product(0, kUint64Max, 0);
    expect_product(kUint64Max, 0, 0);
    expect_product(kUint64Max, 1, kUint64Max);
    expect_product(1, kUint64Max, kUint64Max);

    expect_product(0xFFFFFFFFULL, 0xFFFFFFFFULL, 0xFFFFFFFE00000001ULL);
    expect_product(1ULL << 32, (1ULL << 32) - 1ULL, 0xFFFFFFFF00000000ULL);
    expect_product((1ULL << 32) - 1ULL, 1ULL << 32, 0xFFFFFFFF00000000ULL);
    expect_product(kUint64Max / 2ULL, 2ULL, 0xFFFFFFFFFFFFFFFEULL);

    expect_overflow(1ULL << 32, 1ULL << 32);
    expect_overflow(kUint64Max, 2);
    expect_overflow(2, kUint64Max);
    expect_overflow(kUint64Max, kUint64Max);
    expect_overflow((kUint64Max / 2ULL) + 1ULL, 2ULL);

    expect_product(kUint64Max / 4096ULL, 4096ULL, 0xFFFFFFFFFFFFF000ULL);
    expect_overflow((kUint64Max / 4096ULL) + 1ULL, 4096ULL);
}

TEST(CommonByteClassification, IsAsciiNumber) {

    EXPECT_TRUE(binwalk::is_ascii_number(0x31));
    EXPECT_FALSE(binwalk::is_ascii_number(0xFE));

    EXPECT_FALSE(binwalk::is_ascii_number(0x2F));
    EXPECT_TRUE(binwalk::is_ascii_number(0x30));
    EXPECT_TRUE(binwalk::is_ascii_number(0x39));
    EXPECT_FALSE(binwalk::is_ascii_number(0x3A));

    for(unsigned int value = 0; value <= 0xFFU; ++value) {
        const auto byte = static_cast<std::uint8_t>(value);
        const bool expected = (value >= 0x30U && value <= 0x39U);
        EXPECT_EQ(binwalk::is_ascii_number(byte), expected) << "byte 0x" << std::hex << value;
    }
}

TEST(CommonByteClassification, IsPrintableAsciiCoversZeroAToSevenE) {

    EXPECT_TRUE(binwalk::is_printable_ascii(0x41));
    EXPECT_FALSE(binwalk::is_printable_ascii(0xFE));

    EXPECT_FALSE(binwalk::is_printable_ascii(0x09));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x0A));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x7E));
    EXPECT_FALSE(binwalk::is_printable_ascii(0x7F));

    EXPECT_TRUE(binwalk::is_printable_ascii(0x0D));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x1B));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x1C));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x1F));
    EXPECT_TRUE(binwalk::is_printable_ascii(0x20));

    EXPECT_FALSE(binwalk::is_printable_ascii(0x00));
    EXPECT_FALSE(binwalk::is_printable_ascii(0x08));
    EXPECT_FALSE(binwalk::is_printable_ascii(0x80));
    EXPECT_FALSE(binwalk::is_printable_ascii(0xFF));

    for(unsigned int value = 0; value <= 0xFFU; ++value) {
        const auto byte = static_cast<std::uint8_t>(value);
        const bool expected = (value >= 0x0AU && value <= 0x7EU);
        EXPECT_EQ(binwalk::is_printable_ascii(byte), expected) << "byte 0x" << std::hex << value;
    }
}

namespace {

void expect_invalid_utf8(const std::vector<std::uint8_t>& data, const char* description) {
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(data)), "")
        << "must reject " << description;
}

void expect_valid_utf8(
    const std::vector<std::uint8_t>& data,
    const std::vector<std::uint8_t>& expected_bytes,
    const char* description
) {
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(data)), bytes_to_string(expected_bytes))
        << "must accept " << description;
}

}

TEST(CommonStrings, GetCstringBytesStopsAtTheFirstNul) {
    const std::vector<std::uint8_t> terminated{0x61, 0x62, 0x63, 0x00, 0x64};
    EXPECT_EQ(
        binwalk::get_cstring_bytes(binwalk::byte_view(terminated)),
        (std::vector<std::uint8_t>{0x61, 0x62, 0x63})
    );

    const std::vector<std::uint8_t> unterminated{0x61, 0x62, 0x63};
    EXPECT_EQ(
        binwalk::get_cstring_bytes(binwalk::byte_view(unterminated)),
        (std::vector<std::uint8_t>{0x61, 0x62, 0x63})
    );

    const std::vector<std::uint8_t> immediate{0x00, 0x61, 0x62};
    EXPECT_TRUE(binwalk::get_cstring_bytes(binwalk::byte_view(immediate)).empty());

    const std::vector<std::uint8_t> empty_data;
    EXPECT_TRUE(binwalk::get_cstring_bytes(binwalk::byte_view(empty_data)).empty());
    EXPECT_TRUE(binwalk::get_cstring_bytes(binwalk::byte_view{}).empty());

    const std::vector<std::uint8_t> raw{0x80, 0xFF, 0x00, 0x41};
    EXPECT_EQ(
        binwalk::get_cstring_bytes(binwalk::byte_view(raw)),
        (std::vector<std::uint8_t>{0x80, 0xFF})
    );
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(raw)), "");

    const std::vector<std::uint8_t> just_nul{0x00};
    EXPECT_TRUE(binwalk::get_cstring_bytes(binwalk::byte_view(just_nul)).empty());
}

TEST(CommonStrings, GetCstringMatchesUpstreamDoctest) {

    std::vector<std::uint8_t> data = ascii_bytes("this_is_a_c_string");
    data.push_back(0x00);
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(data)), "this_is_a_c_string");

    const std::vector<std::uint8_t> trailing{0x41, 0x00, 0xFF, 0x80};
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(trailing)), "A");

    const std::vector<std::uint8_t> unterminated = ascii_bytes("no_terminator_here");
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(unterminated)), "no_terminator_here");

    const std::vector<std::uint8_t> leading_nul{0x00, 0x41, 0x42};
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(leading_nul)), "");

    const std::vector<std::uint8_t> empty_data;
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view(empty_data)), "");
    EXPECT_EQ(binwalk::get_cstring(binwalk::byte_view{}), "");
}

TEST(CommonStrings, GetCstringRejectsInvalidUtf8) {
    expect_invalid_utf8({0x80, 0x00}, "a bare continuation byte");
    expect_invalid_utf8({0xBF, 0x00}, "the highest bare continuation byte");
    expect_invalid_utf8({0x41, 0x80, 0x42, 0x00}, "a continuation byte with no lead");

    expect_invalid_utf8({0xC0, 0x80, 0x00}, "the overlong two-byte encoding of NUL");
    expect_invalid_utf8({0xC1, 0xBF, 0x00}, "an overlong two-byte lead 0xC1");
    expect_invalid_utf8({0xE0, 0x80, 0xAF, 0x00}, "an overlong three-byte encoding");
    expect_invalid_utf8({0xF0, 0x82, 0x82, 0xAC, 0x00}, "an overlong four-byte euro sign");

    expect_invalid_utf8({0xF5, 0x80, 0x80, 0x80, 0x00}, "out-of-range lead 0xF5");
    expect_invalid_utf8({0xF8, 0x00}, "out-of-range lead 0xF8");
    expect_invalid_utf8({0xFE, 0x00}, "out-of-range lead 0xFE");
    expect_invalid_utf8({0xFF, 0x00}, "out-of-range lead 0xFF");
    expect_invalid_utf8({0xF4, 0x90, 0x80, 0x80, 0x00}, "a code point above U+10FFFF");

    expect_invalid_utf8({0xED, 0xA0, 0x80, 0x00}, "the surrogate U+D800");
    expect_invalid_utf8({0xED, 0xBF, 0xBF, 0x00}, "the surrogate U+DFFF");

    expect_invalid_utf8({0xE2, 0x82}, "a three-byte sequence truncated by the buffer end");
    expect_invalid_utf8({0xC3}, "a two-byte sequence truncated by the buffer end");
    expect_invalid_utf8({0xF0, 0x9F, 0x92}, "a four-byte sequence truncated by the buffer end");
    expect_invalid_utf8({0xE2, 0x82, 0x00}, "a three-byte sequence truncated by the NUL");
    expect_invalid_utf8({0x41, 0xC2, 0x00}, "a two-byte lead with no continuation");

    expect_invalid_utf8({0xE2, 0x28, 0xA1, 0x00}, "a bad continuation in a three-byte sequence");
    expect_invalid_utf8({0xC2, 0x41, 0x00}, "a bad continuation in a two-byte sequence");
}

TEST(CommonStrings, GetCstringAcceptsValidUtf8) {

    expect_valid_utf8({0xE2, 0x82, 0xAC, 0x00}, {0xE2, 0x82, 0xAC}, "the euro sign U+20AC");
    expect_valid_utf8({0xC3, 0xA9, 0x00}, {0xC3, 0xA9}, "U+00E9");
    expect_valid_utf8({0xC2, 0x80, 0x00}, {0xC2, 0x80}, "the smallest two-byte code point U+0080");
    expect_valid_utf8({0xF0, 0x9F, 0x92, 0xA9, 0x00}, {0xF0, 0x9F, 0x92, 0xA9}, "a four-byte code point");

    expect_valid_utf8({0xED, 0x9F, 0xBF, 0x00}, {0xED, 0x9F, 0xBF}, "U+D7FF, just below the surrogates");
    expect_valid_utf8({0xEE, 0x80, 0x80, 0x00}, {0xEE, 0x80, 0x80}, "U+E000, just above the surrogates");

    expect_valid_utf8({0xF4, 0x8F, 0xBF, 0xBF, 0x00}, {0xF4, 0x8F, 0xBF, 0xBF}, "U+10FFFF");

    expect_valid_utf8(
        {0x41, 0xE2, 0x82, 0xAC, 0x42, 0x00},
        {0x41, 0xE2, 0x82, 0xAC, 0x42},
        "ASCII around a three-byte code point"
    );
    expect_valid_utf8({0xE2, 0x82, 0xAC}, {0xE2, 0x82, 0xAC}, "an unterminated euro sign");
}

TEST(CommonStrings, GetCstringRangeOverload) {

    const std::vector<std::uint8_t> data{
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x77, 0x6F, 0x72, 0x6C, 0x64
    };
    const binwalk::byte_view view(data);
    ASSERT_EQ(data.size(), std::size_t{11});

    EXPECT_EQ(binwalk::get_cstring(view, 0, 6), "hello");
    EXPECT_EQ(binwalk::get_cstring(view, 0, 11), "hello");

    EXPECT_EQ(binwalk::get_cstring(view, 0, 5), "hello");
    EXPECT_EQ(binwalk::get_cstring(view, 0, 3), "hel");
    EXPECT_EQ(binwalk::get_cstring(view, 6, 5), "world");

    EXPECT_EQ(binwalk::get_cstring(view, 5, 6), "");
    EXPECT_EQ(binwalk::get_cstring(view, 5, 1), "");

    EXPECT_EQ(binwalk::get_cstring(view, 0, 0), "");
    EXPECT_EQ(binwalk::get_cstring(view, 11, 0), "");

    EXPECT_EQ(binwalk::get_cstring(view, 0, 12), "");
    EXPECT_EQ(binwalk::get_cstring(view, 11, 1), "");
    EXPECT_EQ(binwalk::get_cstring(view, 12, 0), "");
    EXPECT_EQ(binwalk::get_cstring(view, 12, 1), "");
    EXPECT_EQ(binwalk::get_cstring(view, kSizeMax, 1), "");

    EXPECT_EQ(binwalk::get_cstring(view, 1, kSizeMax), "");
    EXPECT_EQ(binwalk::get_cstring(view, kSizeMax - 3, 4), "");
    EXPECT_EQ(binwalk::get_cstring(view, kSizeMax, kSizeMax), "");

    const std::vector<std::uint8_t> euro{0xE2, 0x82, 0xAC, 0x00};
    const binwalk::byte_view euro_view(euro);
    EXPECT_EQ(binwalk::get_cstring(euro_view, 0, 4), bytes_to_string({0xE2, 0x82, 0xAC}));
    EXPECT_EQ(binwalk::get_cstring(euro_view, 0, 2), "");
}

TEST(CommonStrings, PrintablePrefixStopsAtFirstNonPrintableByte) {

    const std::vector<std::uint8_t> with_nul{0x41, 0x42, 0x43, 0x00, 0x44};
    const binwalk::byte_view nul_view(with_nul);
    EXPECT_EQ(binwalk::printable_prefix(nul_view, 0, 5), "ABC");
    EXPECT_EQ(binwalk::printable_prefix(nul_view, 0, 2), "AB");
    EXPECT_EQ(binwalk::printable_prefix(nul_view, 3, 2), "");
    EXPECT_EQ(binwalk::printable_prefix(nul_view, 4, 1), "D");

    const std::vector<std::uint8_t> with_tab{0x68, 0x69, 0x09, 0x6A};
    EXPECT_EQ(binwalk::printable_prefix(binwalk::byte_view(with_tab), 0, 4), "hi");

    const std::vector<std::uint8_t> with_high{0x68, 0x69, 0xFF, 0x6A};
    EXPECT_EQ(binwalk::printable_prefix(binwalk::byte_view(with_high), 0, 4), "hi");
    const std::vector<std::uint8_t> with_del{0x41, 0x7F, 0x42};
    EXPECT_EQ(binwalk::printable_prefix(binwalk::byte_view(with_del), 0, 3), "A");

    const std::vector<std::uint8_t> with_fs{0x41, 0x1C, 0x42};
    EXPECT_EQ(
        binwalk::printable_prefix(binwalk::byte_view(with_fs), 0, 3),
        bytes_to_string({0x41, 0x1C, 0x42})
    );

    const std::vector<std::uint8_t> endpoints{0x0A, 0x7E, 0x41, 0x09};
    EXPECT_EQ(
        binwalk::printable_prefix(binwalk::byte_view(endpoints), 0, 4),
        bytes_to_string({0x0A, 0x7E, 0x41})
    );

    const std::vector<std::uint8_t> leading_stop{0x00, 0x41, 0x42};
    EXPECT_EQ(binwalk::printable_prefix(binwalk::byte_view(leading_stop), 0, 3), "");
}

TEST(CommonStrings, PrintablePrefixRejectsOutOfRangeWindows) {
    const std::vector<std::uint8_t> data{0x41, 0x42, 0x43, 0x44};
    const binwalk::byte_view view(data);

    EXPECT_EQ(binwalk::printable_prefix(view, 0, 0), "");
    EXPECT_EQ(binwalk::printable_prefix(view, 4, 0), "");

    EXPECT_EQ(binwalk::printable_prefix(view, 0, 5), "");
    EXPECT_EQ(binwalk::printable_prefix(view, 4, 1), "");
    EXPECT_EQ(binwalk::printable_prefix(view, 5, 0), "");
    EXPECT_EQ(binwalk::printable_prefix(view, kSizeMax, 1), "");

    EXPECT_EQ(binwalk::printable_prefix(view, 1, kSizeMax), "");
    EXPECT_EQ(binwalk::printable_prefix(view, kSizeMax - 3, 4), "");
    EXPECT_EQ(binwalk::printable_prefix(view, kSizeMax, kSizeMax), "");
}

TEST(CommonStrings, IsPrintableRange) {
    const std::vector<std::uint8_t> printable{0x0A, 0x41, 0x7E};
    const binwalk::byte_view printable_view(printable);
    EXPECT_TRUE(binwalk::is_printable_range(printable_view, 0, 3));
    EXPECT_TRUE(binwalk::is_printable_range(printable_view, 1, 2));
    EXPECT_TRUE(binwalk::is_printable_range(printable_view, 2, 1));

    const std::vector<std::uint8_t> mixed{0x41, 0x00, 0x42};
    const binwalk::byte_view mixed_view(mixed);
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 0, 3));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 0, 2));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 1, 1));
    EXPECT_TRUE(binwalk::is_printable_range(mixed_view, 0, 1));
    EXPECT_TRUE(binwalk::is_printable_range(mixed_view, 2, 1));

    const std::vector<std::uint8_t> boundaries{0x09, 0x0A, 0x7E, 0x7F};
    const binwalk::byte_view boundary_view(boundaries);
    EXPECT_FALSE(binwalk::is_printable_range(boundary_view, 0, 1));
    EXPECT_TRUE(binwalk::is_printable_range(boundary_view, 1, 2));
    EXPECT_FALSE(binwalk::is_printable_range(boundary_view, 3, 1));
    EXPECT_FALSE(binwalk::is_printable_range(boundary_view, 0, 4));

    EXPECT_TRUE(binwalk::is_printable_range(mixed_view, 0, 0));
    EXPECT_TRUE(binwalk::is_printable_range(mixed_view, 1, 0));
    EXPECT_TRUE(binwalk::is_printable_range(mixed_view, 3, 0));

    const std::vector<std::uint8_t> empty_data;
    EXPECT_TRUE(binwalk::is_printable_range(binwalk::byte_view(empty_data), 0, 0));

    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 0, 4));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 3, 1));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 4, 0));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, kSizeMax, 1));
    EXPECT_FALSE(binwalk::is_printable_range(binwalk::byte_view(empty_data), 0, 1));
    EXPECT_FALSE(binwalk::is_printable_range(binwalk::byte_view(empty_data), 1, 0));

    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, 1, kSizeMax));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, kSizeMax - 2, 3));
    EXPECT_FALSE(binwalk::is_printable_range(mixed_view, kSizeMax, kSizeMax));
}
