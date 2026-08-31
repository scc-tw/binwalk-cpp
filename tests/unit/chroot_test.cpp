#include <binwalk/byte_view.hpp>
#include <binwalk/chroot.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
namespace {

namespace fs = std::filesystem;

constexpr std::size_t k_size_max = std::numeric_limits<std::size_t>::max();

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    std::vector<std::uint8_t> out;
    out.reserve(text.size());
    for(const char character : text) {
        out.push_back(static_cast<std::uint8_t>(character));
    }
    return out;
}

std::string read_file_binary(const fs::path& target) {
    std::ifstream stream(target, std::ios::binary);
    if(!stream) {
        return std::string();
    }
    return std::string(
        std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()
    );
}

std::vector<std::string> path_components(const fs::path& value) {
    std::vector<std::string> parts;
    for(const auto& element : value.lexically_normal()) {
        std::string text = element.string();
        if(text.empty() || text == "/" || text == "\\") {
            continue;
        }
        parts.push_back(std::move(text));
    }
    return parts;
}

bool same_path(const fs::path& left, const fs::path& right) {
    return path_components(left) == path_components(right);
}

bool contains_equivalent(const std::vector<std::string>& entries, const fs::path& target) {
    for(const std::string& entry : entries) {
        std::error_code error;
        if(fs::equivalent(entry, target, error)) {
            return true;
        }
    }
    return false;
}

void expect_inside_root(const binwalk::chroot& area, const std::string& resolved) {
    ASSERT_FALSE(resolved.empty());
    EXPECT_EQ(resolved.compare(0, area.root().size(), area.root()), 0)
        << "resolved '" << resolved << "' does not start with root '" << area.root() << "'";
    EXPECT_TRUE(fs::path(resolved).is_absolute()) << resolved;

    for(const auto& element : fs::path(resolved)) {
        EXPECT_NE(element.string(), "..") << "'..' component survived in " << resolved;
    }

    const std::vector<std::string> root_parts = path_components(area.root());
    const std::vector<std::string> resolved_parts = path_components(resolved);
    ASSERT_GE(resolved_parts.size(), root_parts.size())
        << "resolved '" << resolved << "' is shallower than root '" << area.root() << "'";
    for(std::size_t index = 0; index < root_parts.size(); ++index) {
        EXPECT_EQ(resolved_parts[index], root_parts[index])
            << "resolved '" << resolved << "' escapes root '" << area.root() << "'";
    }
}

void expect_placeholder_file(const fs::path& target, const std::string& expected) {
    std::error_code error;
    ASSERT_TRUE(fs::exists(target, error)) << target.string();
    EXPECT_FALSE(fs::is_symlink(fs::symlink_status(target, error))) << target.string();
    EXPECT_TRUE(fs::is_regular_file(target, error)) << target.string();
    const std::string content = read_file_binary(target);
    EXPECT_EQ(content, expected);
    EXPECT_EQ(content.size(), expected.size());
    EXPECT_EQ(fs::file_size(target, error), static_cast<std::uintmax_t>(expected.size()));
}

std::string unique_directory_name() {
    static std::atomic<unsigned long long> counter{0};
    const ::testing::TestInfo* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string label = info != nullptr ? std::string(info->name()) : std::string("unknown");
    for(char& character : label) {
        if(std::isalnum(static_cast<unsigned char>(character)) == 0) {
            character = '_';
        }
    }
    if(label.size() > 40) {
        label.resize(40);
    }
    return "binwalk_chroot_" + label + "_" + std::to_string(counter.fetch_add(1));
}

std::vector<std::string> hostile_paths() {
    return {
        "",
        ".",
        "..",
        "/",
        "\\",
        "//",
        "\\\\",
        "./",
        "../",
        "..\\",
        "../x",
        "a/../../b",
        "../../etc/passwd",
        "..\\..\\b",
        "..\\a/../..\\b",
        "../../../../etc/passwd",
        "/etc/passwd",
        "/../../etc/passwd",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "\\\\?\\C:\\Windows\\win.ini",
        "\\\\.\\C:\\Windows\\win.ini",
        "\\\\?\\\\\\?\\C:\\Windows\\win.ini",
        "\\\\server\\share\\x",
        "C:foo",
        "C:",
        "C:\\",
        "a/./b/../c",
        "a//b",
        "a\\\\b",
        "/a/b/",
        "a/b/",
        "dir/NUL.txt",
        "CON",
        "com1",
        "lpt9.log",
        "dir/foo.",
        "dir/foo ",
        "dir/...",
        "dir/   ",
        "....",
        ". ",
        " .",
        ".../x",
        "dir/a<b>c:d\"e|f?g*h",
        "dir/a\x01" "b",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    };
}

class BinwalkChroot : public ::testing::Test {
protected:
    void SetUp() override {
        base_ = fs::temp_directory_path() / unique_directory_name();
        std::error_code error;
        fs::remove_all(base_, error);
        ASSERT_TRUE(fs::create_directories(base_, error))
            << base_.string() << ": " << error.message();
        sentinel_ = base_ / "sentinel";
        ASSERT_TRUE(fs::create_directories(sentinel_, error))
            << sentinel_.string() << ": " << error.message();
        root_ = base_ / "root";
    }

    void TearDown() override {
        std::error_code error;
        fs::remove_all(base_, error);
    }

    [[nodiscard]] binwalk::chroot make_chroot() const {
        return binwalk::chroot(root_.string());
    }

    [[nodiscard]] fs::path root_of(const binwalk::chroot& area) const {
        return fs::path(area.root());
    }

    void expect_nothing_outside_root(
        const std::vector<std::string>& allowed = {"root", "sentinel"}
    ) const {
        std::error_code error;
        for(const auto& entry : fs::directory_iterator(sentinel_, error)) {
            ADD_FAILURE() << "entry created inside the sentinel directory: "
                          << entry.path().string();
        }
        for(const auto& entry : fs::directory_iterator(base_, error)) {
            const std::string name = entry.path().filename().string();
            const bool is_allowed =
                std::find(allowed.begin(), allowed.end(), name) != allowed.end();
            EXPECT_TRUE(is_allowed)
                << "entry created outside the chroot root: " << entry.path().string();
        }
    }

    fs::path base_;
    fs::path sentinel_;
    fs::path root_;
};

TEST_F(BinwalkChroot, ConstructorCreatesMissingRootDirectory) {
    ASSERT_FALSE(fs::exists(root_));

    const binwalk::chroot area = make_chroot();

    EXPECT_FALSE(area.root().empty());
    EXPECT_TRUE(fs::path(area.root()).is_absolute()) << area.root();
    EXPECT_TRUE(fs::is_directory(area.root())) << area.root();

    std::error_code error;
    EXPECT_TRUE(fs::equivalent(area.root(), root_, error)) << area.root();

    ASSERT_FALSE(area.root().empty());
    EXPECT_NE(area.root().back(), '/');
    EXPECT_NE(area.root().back(), '\\');

    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, EmptyRootMeansCurrentWorkingDirectory) {

    const std::string empty_root;
    const binwalk::chroot area(empty_root);

    EXPECT_FALSE(area.root().empty());
    EXPECT_TRUE(fs::path(area.root()).is_absolute()) << area.root();

    std::error_code current_error;
    const fs::path working_directory = fs::current_path(current_error);
    ASSERT_FALSE(current_error) << current_error.message();

    std::error_code compare_error;
    EXPECT_TRUE(fs::equivalent(area.root(), working_directory, compare_error)) << area.root();
    EXPECT_EQ(area.chrooted_path(""), area.root());
}

TEST_F(BinwalkChroot, DotDotIsAbsorbedInEveryPosition) {
    const binwalk::chroot area = make_chroot();
    const fs::path root = root_of(area);

    const std::vector<std::pair<std::string, fs::path>> cases{
        {"../x", root / "x"},
        {"a/../../b", root / "b"},
        {"../../etc/passwd", root / "etc" / "passwd"},
        {"..\\..\\b", root / "b"},
        {"..\\a/../..\\b", root / "b"},

        {"../../../../etc/passwd", root / "etc" / "passwd"},
        {"a/./b/../c", root / "a" / "c"},
        {"/../../etc/passwd", root / "etc" / "passwd"},
    };

    for(const auto& entry : cases) {
        const std::string resolved = area.chrooted_path(entry.first);
        expect_inside_root(area, resolved);
        EXPECT_TRUE(same_path(resolved, entry.second))
            << "input '" << entry.first << "' resolved to '" << resolved
            << "', expected '" << entry.second.string() << "'";
    }
}

TEST_F(BinwalkChroot, DegenerateInputsResolveToRootItself) {
    const binwalk::chroot area = make_chroot();

    for(const char* input : {"", ".", "/", "..", "\\", "//", "./", "../", "..\\", "/.."}) {
        const std::string resolved = area.chrooted_path(input);
        EXPECT_FALSE(resolved.empty()) << "input '" << input << "'";
        EXPECT_EQ(resolved, area.root()) << "input '" << input << "'";
    }
}

TEST_F(BinwalkChroot, ChrootedPathOfRootIsRoot) {
    const binwalk::chroot area = make_chroot();
    EXPECT_EQ(area.chrooted_path(area.root()), area.root());
}

TEST_F(BinwalkChroot, PosixAbsolutePathIsNeutralised) {
    const binwalk::chroot area = make_chroot();
    const std::string resolved = area.chrooted_path("/etc/passwd");
    expect_inside_root(area, resolved);
    EXPECT_TRUE(same_path(resolved, root_of(area) / "etc" / "passwd")) << resolved;
}

TEST_F(BinwalkChroot, WindowsAbsolutePathIsNeutralised) {
    const binwalk::chroot area = make_chroot();

    for(const char* input : {"C:\\Windows\\win.ini", "C:/Windows/win.ini"}) {
        const std::string resolved = area.chrooted_path(input);
        expect_inside_root(area, resolved);
        EXPECT_NE(resolved, area.root()) << input;
        EXPECT_EQ(fs::path(resolved).filename().string(), "win.ini") << input;
        EXPECT_EQ(area.chrooted_path(resolved), resolved) << input;
    }
}

TEST_F(BinwalkChroot, DriveRelativePathIsNeutralised) {
    const binwalk::chroot area = make_chroot();
    const std::string resolved = area.chrooted_path("C:foo");
    expect_inside_root(area, resolved);
    EXPECT_NE(resolved, area.root());
    EXPECT_EQ(area.chrooted_path(resolved), resolved);
}

TEST_F(BinwalkChroot, ExtendedLengthPrefixesAreStripped) {
    const binwalk::chroot area = make_chroot();
    const std::string plain = area.chrooted_path("C:\\Windows\\win.ini");

    EXPECT_EQ(area.chrooted_path("\\\\?\\C:\\Windows\\win.ini"), plain);
    EXPECT_EQ(area.chrooted_path("\\\\.\\C:\\Windows\\win.ini"), plain);
    EXPECT_EQ(area.chrooted_path("\\\\?\\\\\\?\\C:\\Windows\\win.ini"), plain);

    expect_inside_root(area, area.chrooted_path("\\\\?\\C:\\Windows\\win.ini"));
}

TEST_F(BinwalkChroot, UncPathIsNeutralised) {
    const binwalk::chroot area = make_chroot();
    const std::string resolved = area.chrooted_path("\\\\server\\share\\x");
    expect_inside_root(area, resolved);
    EXPECT_EQ(fs::path(resolved).filename().string(), "x") << resolved;
    EXPECT_EQ(area.chrooted_path(resolved), resolved);
    EXPECT_EQ(area.chrooted_path("\\\\server\\share\\x"), resolved);
}

TEST_F(BinwalkChroot, RootPrefixStripIsComponentWiseNotStringPrefix) {
    const binwalk::chroot area((base_ / "out").string());
    const fs::path root = root_of(area);

    const fs::path sibling = root.parent_path() / "output" / "x";
    const std::string resolved = area.chrooted_path(sibling.string());
    expect_inside_root(area, resolved);
    EXPECT_NE(resolved, sibling.string());
    EXPECT_EQ(area.chrooted_path(resolved), resolved);

    const std::string inside = area.chrooted_path("x");
    EXPECT_EQ(area.chrooted_path(inside), inside);
    EXPECT_TRUE(same_path(inside, root / "x")) << inside;

    expect_nothing_outside_root({"root", "sentinel", "out"});
}

TEST_F(BinwalkChroot, IllegalNtfsCharactersBecomeUnderscores) {
    const binwalk::chroot area = make_chroot();

    const std::string resolved = area.chrooted_path("dir/a<b>c:d\"e|f?g*h");
    expect_inside_root(area, resolved);
    EXPECT_EQ(fs::path(resolved).filename().string(), "a_b_c_d_e_f_g_h") << resolved;
    EXPECT_EQ(fs::path(resolved).parent_path().filename().string(), "dir") << resolved;

    const std::string with_control = area.chrooted_path("dir/a\x01" "b");
    expect_inside_root(area, with_control);
    EXPECT_EQ(fs::path(with_control).filename().string(), "a_b") << with_control;
}

TEST_F(BinwalkChroot, TrailingDotsAndSpacesAreRemoved) {
    const binwalk::chroot area = make_chroot();

    const std::vector<std::pair<std::string, std::string>> cases{
        {"dir/foo.", "foo"},
        {"dir/foo ", "foo"},
        {"dir/foo...", "foo"},
        {"dir/foo. . ", "foo"},

        {"dir/...", "_"},
        {"dir/   ", "_"},
    };

    for(const auto& entry : cases) {
        const std::string resolved = area.chrooted_path(entry.first);
        expect_inside_root(area, resolved);
        EXPECT_EQ(fs::path(resolved).filename().string(), entry.second)
            << "input '" << entry.first << "' resolved to '" << resolved << "'";
        EXPECT_EQ(fs::path(resolved).parent_path().filename().string(), "dir") << resolved;
    }
}

TEST_F(BinwalkChroot, WindowsReservedDeviceNamesArePrefixed) {
    const binwalk::chroot area = make_chroot();

    for(const char* name : {"CON",  "PRN",  "AUX",     "NUL",     "COM1",    "COM9",
                            "LPT1", "LPT9", "con",     "nul",     "Aux",     "lpt1",
                            "NUL.txt", "nul.TXT", "Com1.bin", "LPT9.log"}) {
        const std::string resolved = area.chrooted_path(std::string("dir/") + name);
        expect_inside_root(area, resolved);
        EXPECT_EQ(fs::path(resolved).filename().string(), std::string("_") + name)
            << "input '" << name << "' resolved to '" << resolved << "'";
    }
}

TEST_F(BinwalkChroot, NonReservedLookalikeNamesAreLeftAlone) {
    const binwalk::chroot area = make_chroot();

    for(const char* name : {"COM10", "COM0",  "CONSOLE", "COMMON", "LPT10",
                            "LPT0",  "NULL",  "AUXX",    "PRNT",   "CONS",
                            "com10", "common"}) {
        const std::string resolved = area.chrooted_path(std::string("dir/") + name);
        expect_inside_root(area, resolved);
        EXPECT_EQ(fs::path(resolved).filename().string(), std::string(name))
            << "input '" << name << "' resolved to '" << resolved << "'";
    }
}

TEST_F(BinwalkChroot, OverlongComponentIsTruncated) {
    const binwalk::chroot area = make_chroot();

    const std::string long_name(300, 'a');
    const std::string resolved = area.chrooted_path("dir/" + long_name);
    expect_inside_root(area, resolved);

    const std::string leaf = fs::path(resolved).filename().string();
    EXPECT_FALSE(leaf.empty());
    EXPECT_LE(leaf.size(), std::size_t{250}) << leaf.size();
    EXPECT_EQ(leaf, std::string(leaf.size(), 'a'));
    EXPECT_EQ(area.chrooted_path(resolved), resolved);
}

TEST_F(BinwalkChroot, ChrootedPathIsDeterministicIdempotentAndContained) {
    const binwalk::chroot area = make_chroot();

    for(const std::string& input : hostile_paths()) {
        const std::string first = area.chrooted_path(input);
        const std::string second = area.chrooted_path(input);

        EXPECT_FALSE(first.empty()) << "input '" << input << "'";
        EXPECT_EQ(first, second) << "input '" << input << "' is not deterministic";
        expect_inside_root(area, first);
        EXPECT_EQ(area.chrooted_path(first), first)
            << "input '" << input << "' resolved to '" << first << "' which is not idempotent";
    }

    EXPECT_TRUE(fs::is_directory(area.root()));
    std::error_code error;
    for(const auto& entry : fs::directory_iterator(area.root(), error)) {
        ADD_FAILURE() << "chrooted_path wrote to disk: " << entry.path().string();
    }
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SafePathJoinKeepsBothFragments) {
    const binwalk::chroot area = make_chroot();

    const std::string joined = area.safe_path_join("/etc", "/passwd");
    expect_inside_root(area, joined);
    EXPECT_TRUE(same_path(joined, root_of(area) / "etc" / "passwd")) << joined;

    EXPECT_EQ(area.safe_path_join("", ""), area.root());
    EXPECT_EQ(area.safe_path_join("..", ".."), area.root());
}

TEST_F(BinwalkChroot, SafePathJoinIsChrootedPathOfTheJoinedFragments) {
    const binwalk::chroot area = make_chroot();

    const std::vector<std::pair<std::string, std::string>> pairs{
        {"a", "b"},
        {"/etc", "/passwd"},
        {"..", "../x"},
        {"../..", "etc/passwd"},
        {"C:\\Windows", "win.ini"},
        {"dir", "NUL.txt"},
        {"", "x"},
        {"x", ""},
    };

    for(const auto& entry : pairs) {
        const std::string joined = area.safe_path_join(entry.first, entry.second);
        expect_inside_root(area, joined);
        EXPECT_EQ(joined, area.chrooted_path(entry.first + "/" + entry.second))
            << "'" << entry.first << "' + '" << entry.second << "'";
    }

    for(const std::string& input : hostile_paths()) {
        EXPECT_EQ(area.chrooted_path(input), area.safe_path_join(input, ""))
            << "input '" << input << "'";
    }
}

TEST_F(BinwalkChroot, CreateFileWritesDataAndCreatesParents) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("payload-bytes");

    EXPECT_TRUE(area.create_file("a/b/c.bin", binwalk::byte_view(payload)));

    const fs::path written = root_of(area) / "a" / "b" / "c.bin";
    ASSERT_TRUE(fs::is_regular_file(written)) << written.string();
    EXPECT_EQ(read_file_binary(written), std::string("payload-bytes"));
    expect_inside_root(area, area.chrooted_path("a/b/c.bin"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CreateFileWritesEmptyPayload) {
    const binwalk::chroot area = make_chroot();
    EXPECT_TRUE(area.create_file("empty.bin", binwalk::byte_view()));

    const fs::path written = root_of(area) / "empty.bin";
    ASSERT_TRUE(fs::is_regular_file(written)) << written.string();
    std::error_code error;
    EXPECT_EQ(fs::file_size(written, error), std::uintmax_t{0});
}

TEST_F(BinwalkChroot, CreateFileRefusesToOverwrite) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> first = bytes_of("first");
    const std::vector<std::uint8_t> second = bytes_of("second-and-longer");

    ASSERT_TRUE(area.create_file("f.bin", binwalk::byte_view(first)));
    EXPECT_FALSE(area.create_file("f.bin", binwalk::byte_view(second)));

    const fs::path written = root_of(area) / "f.bin";
    EXPECT_EQ(read_file_binary(written), std::string("first"));
}

TEST_F(BinwalkChroot, CreateFileRefusesAnExistingDirectory) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("x");

    ASSERT_TRUE(area.create_directory("collide"));
    EXPECT_FALSE(area.create_file("collide", binwalk::byte_view(payload)));
    EXPECT_TRUE(fs::is_directory(root_of(area) / "collide"));
}

TEST_F(BinwalkChroot, CreateFileRefusesPathsResolvingToRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("x");

    for(const char* input : {"", ".", "/", "..", "\\", "//"}) {
        EXPECT_FALSE(area.create_file(input, binwalk::byte_view(payload)))
            << "input '" << input << "'";
    }
    EXPECT_TRUE(fs::is_directory(area.root()));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CreateFileWithTraversalInASingleNameLandsInsideRoot) {

    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("not-passwd");

    const std::string resolved = area.chrooted_path("../../etc/passwd");
    expect_inside_root(area, resolved);
    EXPECT_TRUE(same_path(resolved, root_of(area) / "etc" / "passwd")) << resolved;

    EXPECT_TRUE(area.create_file("../../etc/passwd", binwalk::byte_view(payload)));
    ASSERT_TRUE(fs::is_regular_file(resolved)) << resolved;
    EXPECT_EQ(read_file_binary(resolved), std::string("not-passwd"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CreateFileWithWindowsSystemPathLandsInsideRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("not-hosts");

    const std::string resolved =
        area.chrooted_path("C:\\Windows\\System32\\drivers\\etc\\hosts");
    expect_inside_root(area, resolved);
    EXPECT_EQ(fs::path(resolved).filename().string(), "hosts") << resolved;

    EXPECT_TRUE(
        area.create_file("C:\\Windows\\System32\\drivers\\etc\\hosts", binwalk::byte_view(payload))
    );
    ASSERT_TRUE(fs::is_regular_file(resolved)) << resolved;
    EXPECT_EQ(read_file_binary(resolved), std::string("not-hosts"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, NoHostilePathEverWritesOutsideRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("sweep");

    for(const std::string& input : hostile_paths()) {
        if(input.size() > 80) {
            continue;
        }
        const std::string resolved = area.chrooted_path(input);
        expect_inside_root(area, resolved);

        if(area.create_file(input, binwalk::byte_view(payload))) {
            EXPECT_TRUE(fs::is_regular_file(resolved)) << "input '" << input << "'";
        }
    }

    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CarveFileWritesTheRequestedRange) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{0, 1, 2, 3, 4, 5, 6, 7};
    const binwalk::byte_view data(payload);

    EXPECT_TRUE(area.carve_file("carved.bin", data, 2, 3));

    const fs::path written = root_of(area) / "carved.bin";
    ASSERT_TRUE(fs::is_regular_file(written)) << written.string();
    const std::string content = read_file_binary(written);
    ASSERT_EQ(content.size(), std::size_t{3});
    EXPECT_EQ(static_cast<std::uint8_t>(content[0]), std::uint8_t{2});
    EXPECT_EQ(static_cast<std::uint8_t>(content[1]), std::uint8_t{3});
    EXPECT_EQ(static_cast<std::uint8_t>(content[2]), std::uint8_t{4});

    EXPECT_TRUE(area.carve_file("whole.bin", data, 0, payload.size()));
    EXPECT_EQ(read_file_binary(root_of(area) / "whole.bin").size(), payload.size());
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CarveFileZeroSizeAtEndOfBufferIsInBounds) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{9, 9, 9, 9};
    const binwalk::byte_view data(payload);

    EXPECT_TRUE(area.carve_file("tail.bin", data, payload.size(), 0));

    const fs::path written = root_of(area) / "tail.bin";
    ASSERT_TRUE(fs::is_regular_file(written)) << written.string();
    std::error_code error;
    EXPECT_EQ(fs::file_size(written, error), std::uintmax_t{0});
}

TEST_F(BinwalkChroot, CarveFileRejectsOutOfBoundsRanges) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{0, 1, 2, 3, 4, 5, 6, 7};
    const binwalk::byte_view data(payload);
    const std::size_t length = payload.size();

    struct bad_range {
        const char* name;
        std::size_t offset;
        std::size_t size;
    };

    const std::vector<bad_range> ranges{
        {"offset_past_end", length + 1, 0},
        {"offset_far_past_end", length * 4, 1},
        {"size_past_end", 0, length + 1},
        {"offset_plus_size_past_end", length - 1, 2},
        {"offset_at_end_nonzero_size", length, 1},

        {"overflow_max_offset", k_size_max, 4},
        {"overflow_max_size", 4, k_size_max},
        {"overflow_both", k_size_max, k_size_max},
        {"overflow_wrap_to_small", k_size_max - 2, 8},
    };

    for(const bad_range& range : ranges) {
        EXPECT_FALSE(area.carve_file(range.name, data, range.offset, range.size))
            << range.name;
        EXPECT_FALSE(fs::exists(root_of(area) / range.name)) << range.name;
    }

    EXPECT_FALSE(area.carve_file("from_empty", binwalk::byte_view(), 0, 1));
    EXPECT_FALSE(fs::exists(root_of(area) / "from_empty"));

    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CarveFileInheritsRefuseToOverwrite) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    const binwalk::byte_view data(payload);

    ASSERT_TRUE(area.carve_file("once.bin", data, 0, 2));
    EXPECT_FALSE(area.carve_file("once.bin", data, 2, 2));
    EXPECT_EQ(read_file_binary(root_of(area) / "once.bin").size(), std::size_t{2});
}

TEST_F(BinwalkChroot, CarveFileRefusesPathsResolvingToRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    const binwalk::byte_view data(payload);

    for(const char* input : {"", ".", "/", ".."}) {
        EXPECT_FALSE(area.carve_file(input, data, 0, 2)) << "input '" << input << "'";
    }
    EXPECT_TRUE(fs::is_directory(area.root()));
}

TEST_F(BinwalkChroot, CarveFileWithTraversalNameLandsInsideRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload{7, 8, 9};
    const binwalk::byte_view data(payload);

    EXPECT_TRUE(area.carve_file("../../../carved/out.bin", data, 1, 2));
    const std::string resolved = area.chrooted_path("../../../carved/out.bin");
    expect_inside_root(area, resolved);
    ASSERT_TRUE(fs::is_regular_file(resolved)) << resolved;
    EXPECT_EQ(read_file_binary(resolved).size(), std::size_t{2});
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, AppendToFileCreatesThenExtends) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> first = bytes_of("abc");
    const std::vector<std::uint8_t> second = bytes_of("def");

    EXPECT_TRUE(area.append_to_file("stream/out.bin", binwalk::byte_view(first)));
    EXPECT_TRUE(area.append_to_file("stream/out.bin", binwalk::byte_view(second)));

    const fs::path written = root_of(area) / "stream" / "out.bin";
    ASSERT_TRUE(fs::is_regular_file(written)) << written.string();
    EXPECT_EQ(read_file_binary(written), std::string("abcdef"));

    EXPECT_TRUE(area.append_to_file("stream/out.bin", binwalk::byte_view()));
    EXPECT_EQ(read_file_binary(written), std::string("abcdef"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, AppendToFileRefusesADirectory) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("x");

    ASSERT_TRUE(area.create_directory("adir"));
    EXPECT_FALSE(area.append_to_file("adir", binwalk::byte_view(payload)));
    EXPECT_TRUE(fs::is_directory(root_of(area) / "adir"));

    for(const char* input : {"", ".", "/", ".."}) {
        EXPECT_FALSE(area.append_to_file(input, binwalk::byte_view(payload)))
            << "input '" << input << "'";
    }
    EXPECT_TRUE(fs::is_directory(area.root()));
}

TEST_F(BinwalkChroot, AppendToFileWithTraversalNameLandsInsideRoot) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("appended");

    EXPECT_TRUE(area.append_to_file("..\\..\\etc\\shadow", binwalk::byte_view(payload)));
    const std::string resolved = area.chrooted_path("..\\..\\etc\\shadow");
    expect_inside_root(area, resolved);
    ASSERT_TRUE(fs::is_regular_file(resolved)) << resolved;
    EXPECT_EQ(read_file_binary(resolved), std::string("appended"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CreateDirectoryIsIdempotentAndRecursive) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_directory("a/b/c"));
    EXPECT_TRUE(area.create_directory("a/b/c"));
    EXPECT_TRUE(fs::is_directory(root_of(area) / "a" / "b" / "c"));

    for(const char* input : {"", ".", "/", ".."}) {
        EXPECT_TRUE(area.create_directory(input)) << "input '" << input << "'";
    }
    EXPECT_TRUE(fs::is_directory(area.root()));

    EXPECT_TRUE(area.create_directory("../../escaped"));
    const std::string resolved = area.chrooted_path("../../escaped");
    expect_inside_root(area, resolved);
    EXPECT_TRUE(fs::is_directory(resolved)) << resolved;
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, RemoveDirectoryDeletesTreeAndIsIdempotent) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("x");

    ASSERT_TRUE(area.create_directory("tree/inner"));
    ASSERT_TRUE(area.create_file("tree/inner/file.bin", binwalk::byte_view(payload)));

    EXPECT_TRUE(area.remove_directory("tree"));
    EXPECT_FALSE(fs::exists(root_of(area) / "tree"));

    EXPECT_TRUE(area.remove_directory("tree"));
    EXPECT_TRUE(area.remove_directory("never/existed/at/all"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, RemoveDirectoryRefusesRootItself) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("keep");

    ASSERT_TRUE(area.create_file("keep.bin", binwalk::byte_view(payload)));

    for(const char* input : {"", ".", "/", "..", "\\", "//", "../.."}) {
        EXPECT_FALSE(area.remove_directory(input)) << "input '" << input << "'";
    }

    EXPECT_TRUE(fs::is_directory(area.root()));
    EXPECT_TRUE(fs::is_regular_file(root_of(area) / "keep.bin"));
    EXPECT_EQ(read_file_binary(root_of(area) / "keep.bin"), std::string("keep"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SymlinkWithEscapingRelativeTargetWritesInertPlaceholder) {
    const binwalk::chroot area = make_chroot();
    const std::string target = "../sentinel/escaped.txt";

    EXPECT_TRUE(area.create_symlink("link", target));

    const fs::path written = root_of(area) / "link";
    expect_placeholder_file(written, "symlink " + target);
    EXPECT_FALSE(fs::is_symlink(written));

    EXPECT_FALSE(fs::exists(sentinel_ / "escaped.txt"));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SymlinkWithAbsoluteTargetWritesInertPlaceholder) {
    const binwalk::chroot area = make_chroot();
#if defined(_WIN32)
    const std::string target = "C:\\Windows\\win.ini";
#else
    const std::string target = "/etc/passwd";
#endif

    EXPECT_TRUE(area.create_symlink("abs/link", target));

    const fs::path written = root_of(area) / "abs" / "link";
    expect_placeholder_file(written, "symlink " + target);
    EXPECT_FALSE(fs::is_symlink(written));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SymlinkPlaceholderContentIsExactlyEightBytesPlusTarget) {
    const binwalk::chroot area = make_chroot();
    const std::string target = "../../../etc/passwd";

    EXPECT_TRUE(area.create_symlink("l", target));

    const fs::path written = root_of(area) / "l";
    const std::string content = read_file_binary(written);
    ASSERT_EQ(content.size(), std::size_t{8} + target.size());
    EXPECT_EQ(content.substr(0, 8), std::string("symlink "));
    EXPECT_EQ(content.substr(8), target);
    EXPECT_EQ(content, std::string("symlink ../../../etc/passwd"));
    EXPECT_FALSE(fs::is_symlink(written));
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SymlinkWithTraversalPathLandsInsideRoot) {
    const binwalk::chroot area = make_chroot();
    const std::string target = "../sentinel/nope";

    EXPECT_TRUE(area.create_symlink("../../var/link", target));
    const std::string resolved = area.chrooted_path("../../var/link");
    expect_inside_root(area, resolved);
    expect_placeholder_file(resolved, "symlink " + target);
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SymlinkRefusesAnExistingPath) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("original");

    ASSERT_TRUE(area.create_file("taken", binwalk::byte_view(payload)));
    EXPECT_FALSE(area.create_symlink("taken", "../sentinel/x"));
    EXPECT_EQ(read_file_binary(root_of(area) / "taken"), std::string("original"));
}

TEST_F(BinwalkChroot, SymlinkWithTargetInsideRootSucceeds) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("real");
    ASSERT_TRUE(area.create_file("real.txt", binwalk::byte_view(payload)));

    EXPECT_TRUE(area.create_symlink("sub/link", "../real.txt"));

    const fs::path written = root_of(area) / "sub" / "link";
    std::error_code error;
    EXPECT_NE(fs::symlink_status(written, error).type(), fs::file_type::not_found)
        << written.string();
#if defined(_WIN32)

    expect_placeholder_file(written, std::string("symlink ../real.txt"));
#endif
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, CharacterDevicePlaceholderContent) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_character_device("dev/c", 1U, 2U));
    expect_placeholder_file(root_of(area) / "dev" / "c", "c 1 2");

    EXPECT_TRUE(area.create_character_device("dev/zero", 0U, 0U));
    expect_placeholder_file(root_of(area) / "dev" / "zero", "c 0 0");

    EXPECT_TRUE(area.create_character_device("dev/big", 4294967295U, 4294967295U));
    expect_placeholder_file(root_of(area) / "dev" / "big", "c 4294967295 4294967295");

    EXPECT_TRUE(area.create_character_device("dev/wide", 250U, 65535U));
    expect_placeholder_file(root_of(area) / "dev" / "wide", "c 250 65535");
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, BlockDevicePlaceholderContent) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_block_device("dev/b", 1U, 2U));
    expect_placeholder_file(root_of(area) / "dev" / "b", "b 1 2");

    EXPECT_TRUE(area.create_block_device("dev/sda", 8U, 0U));
    expect_placeholder_file(root_of(area) / "dev" / "sda", "b 8 0");

    EXPECT_TRUE(area.create_block_device("dev/big", 4294967295U, 4294967295U));
    expect_placeholder_file(root_of(area) / "dev" / "big", "b 4294967295 4294967295");
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, FifoPlaceholderContent) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_fifo("pipes/p"));
    expect_placeholder_file(root_of(area) / "pipes" / "p", "fifo");

    const std::string content = read_file_binary(root_of(area) / "pipes" / "p");
    EXPECT_EQ(content.size(), std::size_t{4});
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, SocketPlaceholderContent) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_socket("run/s.sock"));
    expect_placeholder_file(root_of(area) / "run" / "s.sock", "socket");

    const std::string content = read_file_binary(root_of(area) / "run" / "s.sock");
    EXPECT_EQ(content.size(), std::size_t{6});
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, NodePlaceholdersRefuseToOverwrite) {
    const binwalk::chroot area = make_chroot();

    ASSERT_TRUE(area.create_fifo("node"));
    EXPECT_FALSE(area.create_fifo("node"));
    EXPECT_FALSE(area.create_socket("node"));
    EXPECT_FALSE(area.create_character_device("node", 1U, 2U));
    EXPECT_FALSE(area.create_block_device("node", 1U, 2U));
    EXPECT_EQ(read_file_binary(root_of(area) / "node"), std::string("fifo"));
}

TEST_F(BinwalkChroot, NodePlaceholdersWithTraversalNamesLandInsideRoot) {
    const binwalk::chroot area = make_chroot();

    EXPECT_TRUE(area.create_character_device("../../dev/console", 5U, 1U));
    const std::string console = area.chrooted_path("../../dev/console");
    expect_inside_root(area, console);
    expect_placeholder_file(console, "c 5 1");

    EXPECT_TRUE(area.create_block_device("..\\..\\dev\\sda1", 8U, 1U));
    const std::string sda1 = area.chrooted_path("..\\..\\dev\\sda1");
    expect_inside_root(area, sda1);
    expect_placeholder_file(sda1, "b 8 1");

    EXPECT_TRUE(area.create_fifo("/dev/initctl"));
    const std::string initctl = area.chrooted_path("/dev/initctl");
    expect_inside_root(area, initctl);
    expect_placeholder_file(initctl, "fifo");

    EXPECT_TRUE(area.create_socket("../../run/log"));
    const std::string log = area.chrooted_path("../../run/log");
    expect_inside_root(area, log);
    expect_placeholder_file(log, "socket");

    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, MakeExecutableSucceedsForAnExistingFile) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("#!/bin/sh\n");

    ASSERT_TRUE(area.create_file("bin/tool", binwalk::byte_view(payload)));
    EXPECT_TRUE(area.make_executable("bin/tool"));

    EXPECT_EQ(read_file_binary(root_of(area) / "bin" / "tool"), std::string("#!/bin/sh\n"));

#if defined(_WIN32)

    EXPECT_TRUE(area.make_executable("bin/absent"));
    EXPECT_FALSE(fs::exists(root_of(area) / "bin" / "absent"));
#endif
    expect_nothing_outside_root();
}

TEST_F(BinwalkChroot, ExtractedFilesFindsNestedNonEmptyFilesSorted) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("abcdefgh");
    const binwalk::byte_view data(payload);

    ASSERT_TRUE(area.create_file("a.bin", data));
    ASSERT_TRUE(area.create_file("d/b.bin", data));
    ASSERT_TRUE(area.create_file("d/e/c.bin", data));
    ASSERT_TRUE(area.create_directory("d/f"));

    ASSERT_TRUE(area.carve_file("empty.bin", data, payload.size(), 0));

    const fs::path root = root_of(area);
    std::error_code error;
    ASSERT_TRUE(fs::is_regular_file(root / "empty.bin"));
    ASSERT_EQ(fs::file_size(root / "empty.bin", error), std::uintmax_t{0});

    const std::vector<std::string> found = binwalk::chroot::extracted_files(area.root());

    ASSERT_EQ(found.size(), std::size_t{3});
    EXPECT_TRUE(std::is_sorted(found.begin(), found.end()));
    for(const std::string& entry : found) {
        EXPECT_TRUE(fs::path(entry).is_absolute()) << entry;
        expect_inside_root(area, entry);
        EXPECT_TRUE(fs::is_regular_file(entry)) << entry;
        EXPECT_NE(fs::file_size(entry, error), std::uintmax_t{0}) << entry;
        EXPECT_NE(fs::path(entry).filename().string(), "empty.bin") << entry;
        EXPECT_NE(fs::path(entry).filename().string(), "f") << entry;
    }

    EXPECT_TRUE(contains_equivalent(found, root / "a.bin"));
    EXPECT_TRUE(contains_equivalent(found, root / "d" / "b.bin"));
    EXPECT_TRUE(contains_equivalent(found, root / "d" / "e" / "c.bin"));
}

TEST_F(BinwalkChroot, ExtractedFilesReturnsEmptyForMissingDirectory) {
    const std::vector<std::string> found =
        binwalk::chroot::extracted_files((base_ / "no_such_directory").string());
    EXPECT_TRUE(found.empty());
}

TEST_F(BinwalkChroot, ExtractedFilesReturnsEmptyForDirectoryWithNoContent) {
    const binwalk::chroot area = make_chroot();
    ASSERT_TRUE(area.create_directory("only/directories/here"));

    const std::vector<std::string> found = binwalk::chroot::extracted_files(area.root());
    EXPECT_TRUE(found.empty());
}

TEST_F(BinwalkChroot, ExtractedFilesIsDeterministic) {
    const binwalk::chroot area = make_chroot();
    const std::vector<std::uint8_t> payload = bytes_of("zz");
    const binwalk::byte_view data(payload);

    ASSERT_TRUE(area.create_file("z.bin", data));
    ASSERT_TRUE(area.create_file("m/y.bin", data));
    ASSERT_TRUE(area.create_file("a/x.bin", data));

    const std::vector<std::string> first = binwalk::chroot::extracted_files(area.root());
    const std::vector<std::string> second = binwalk::chroot::extracted_files(area.root());
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), std::size_t{3});
    EXPECT_TRUE(std::is_sorted(first.begin(), first.end()));
}

}
