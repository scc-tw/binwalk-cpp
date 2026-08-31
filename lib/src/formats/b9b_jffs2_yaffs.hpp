#pragma once

#include <binwalk/export.hpp>
#include <binwalk/signature.hpp>

#include <vector>
namespace binwalk::formats {

[[nodiscard]] BINWALK_API std::vector<signature> b9b_jffs2_yaffs_signatures();

}
