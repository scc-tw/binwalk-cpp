#pragma once

#include <binwalk/export.hpp>
#include <binwalk/signature.hpp>

#include <vector>
namespace binwalk {

[[nodiscard]] BINWALK_API std::vector<signature> builtin_signatures();

}
