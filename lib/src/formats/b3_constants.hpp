#pragma once

#include <binwalk/export.hpp>
#include <binwalk/signature.hpp>

#include <vector>
namespace binwalk::formats {

[[nodiscard]] BINWALK_API std::vector<signature> b3_constants_signatures();

}
