#pragma once

#include <binwalk/byte_view.hpp>
#include <binwalk/export.hpp>
#include <binwalk/result.hpp>
#include <binwalk/signature.hpp>

#include <string>
#include <vector>
namespace binwalk::formats {

[[nodiscard]] BINWALK_API std::vector<signature> b4_encrypted_signatures();

[[nodiscard]] BINWALK_API extraction_result encfw_decrypt(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

[[nodiscard]] BINWALK_API extraction_result autel_deobfuscate(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

[[nodiscard]] BINWALK_API extraction_result extract_obfuscated_lzma(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

[[nodiscard]] BINWALK_API extraction_result extract_swapped_u16(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
);

}
