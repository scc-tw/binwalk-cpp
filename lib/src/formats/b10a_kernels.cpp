#include "b10a_kernels.hpp"

#include <binwalk/binary_reader.hpp>
#include <binwalk/chroot.hpp>
#include <binwalk/common.hpp>
#include <binwalk/extractor.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace binwalk {
namespace {

struct elf_format {};
struct uimage_format {};
struct linux_kernel_format {};
struct linux_boot_image_format {};
struct linux_arm_zimage_format {};
struct linux_arm64_boot_image_format {};
struct wind_kernel_format {};
struct vxworks_symtab_format {};
struct ecos_format {};

[[nodiscard]] bool bytes_equal(
    byte_view data,
    std::size_t offset,
    const std::vector<std::uint8_t>& expected
) noexcept {
    if(!data.contains(offset, expected.size())) {
        return false;
    }
    for(std::size_t index = 0; index < expected.size(); ++index) {
        if(data[offset + index] != expected[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool any_pattern_at(
    byte_view data,
    std::size_t offset,
    const std::vector<std::vector<std::uint8_t>>& patterns
) noexcept {
    for(const auto& pattern : patterns) {
        if(bytes_equal(data, offset, pattern)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string to_hex_upper(std::uint64_t value) {
    static const char digits[] = "0123456789ABCDEF";
    if(value == 0) {
        return "0x0";
    }
    std::string body;
    while(value != 0) {
        body.push_back(digits[static_cast<std::size_t>(value & 0xFU)]);
        value >>= 4U;
    }
    std::string text = "0x";
    text.append(body.rbegin(), body.rend());
    return text;
}

[[nodiscard]] std::string trim_ascii(const std::string& text) {
    const auto is_space = [](unsigned char character) {
        return character == ' ' || character == '\t' || character == '\n'
            || character == '\r' || character == '\v' || character == '\f';
    };
    std::size_t begin = 0;
    std::size_t end = text.size();
    while(begin < end && is_space(static_cast<unsigned char>(text[begin]))) {
        ++begin;
    }
    while(end > begin && is_space(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(begin, end - begin);
}

template<typename Value>
struct code_name {
    Value code;
    const char* name;
};

template<typename Value, std::size_t Count>
[[nodiscard]] const char* lookup(
    const code_name<Value> (&table)[Count],
    Value code
) noexcept {
    for(std::size_t index = 0; index < Count; ++index) {
        if(table[index].code == code) {
            return table[index].name;
        }
    }
    return nullptr;
}

constexpr code_name<std::uint32_t> elf_osabi_table[] = {
    {0, "System-V (Unix)"}, {1, "HP-UX"}, {2, "NetBSD"}, {3, "Linux"},
    {4, "GNU Hurd"}, {5, "86Open"}, {6, "Solaris"}, {7, "AIX"}, {8, "IRIX"},
    {9, "FreeBSD"}, {10, "Tru64"}, {11, "Novell Modesto"}, {12, "OpenBSD"},
    {13, "OpenVMS"}, {14, "NonStop Kernel"}, {15, "AROS"}, {16, "FenixOS"},
    {17, "Nuxi CloudABI"}, {18, "OpenVOS"}, {97, "ARM ABI"}, {102, "Cell LV2"},
    {202, "Cafe OS"}, {255, "embedded"}
};

constexpr code_name<std::uint32_t> elf_type_table[] = {
    {0, "no file type"}, {1, "relocatable"}, {2, "executable"},
    {3, "shared object"}, {4, "core file"}
};

constexpr code_name<std::uint32_t> elf_machine_table[] = {
    {0, "no machine"}, {1, "AT&T WE 32100"}, {2, "SPARC"}, {3, "x86"},
    {4, "Motorola 68k"}, {5, "Motorola 88k"}, {6, "Intel MCU"},
    {7, "Intel 80860"}, {8, "MIPS"}, {9, "IBM System/370"}, {10, "MIPS RS3000"},
    {11, "RS6000"}, {15, "HP PA-RISC"}, {16, "nCUBE"}, {17, "Fujitsu VPP500"},
    {18, "SPARC32PLUS"}, {19, "Intel 80960"}, {20, "PowerPC"},
    {21, "PowerPC 64-bit"}, {22, "S390"}, {23, "IBM SPU/SPC"},
    {24, "cisco SVIP"}, {25, "cisco 7200"}, {36, "NEC V800"},
    {37, "Fujitsu FR20"}, {38, "TRW RH-32"}, {39, "Motorola RCE"}, {40, "ARM"},
    {41, "Digital Alpha"}, {42, "SuperH"}, {43, "SPARCv9"},
    {44, "Siemens TriCore embedded processor"}, {45, "Argonaut RISC Core"},
    {46, "Hitachi H8/300"}, {47, "Hitachi H8/300H"}, {48, "Hitachi H8S"},
    {49, "Hitachi H8/500"}, {50, "IA-64"}, {51, "Stanford MIPS-X"},
    {52, "Motorola ColdFire"}, {53, "Motorola M68HC12"},
    {54, "Fujitsu MMA Multimedia Accelerator"}, {55, "Siemens PCP"},
    {56, "Sony nCPU embedded RISC processor"}, {57, "Denso NDR1 microprocessor"},
    {58, "Motorola StarCore"}, {59, "Toyota ME16"},
    {60, "STMicroelectronics ST100"},
    {61, "Advanced Logic TinyJ embedded processor"}, {62, "AMD X86-64"},
    {63, "Sony DSP processor"}, {64, "PDP-10"}, {65, "PDP-11"},
    {66, "Siemens FX66"}, {67, "STMicroelectronics ST9+"},
    {68, "STMicroelectronics ST7"}, {69, "Motorola MC68HC16"},
    {70, "Motorola MC68HC11"}, {71, "Motorola MC68HC08"},
    {72, "Motorola MC68HC05"}, {73, "Silicon Graphics SVx"},
    {74, "STMicroelectonrics ST19"}, {75, "Digital VAX"},
    {76, "Axis Communications 32-bit CPU"},
    {77, "Infineon Technologies 32-bit CPU"}, {78, "Element 14 64-bit DSP"},
    {79, "LSI Logic 16-bit DSP"}, {80, "MMIX"},
    {81, "Harvard machine-independent"}, {82, "SiTera Prism"},
    {83, "Atmel AVR 8-bit"}, {84, "Fujitsu FR30"}, {85, "Mitsubishi D10V"},
    {86, "Mitsubishi D30V"}, {87, "NEC v850"}, {88, "Renesas M32R"},
    {89, "Matsushita MN10300"}, {90, "Matsushita MN10200"}, {91, "picoJava"},
    {92, "OpenRISC"}, {93, "Synopsys ARCompact ARC700 cores"},
    {94, "Tensilica Xtensa"}, {95, "Alphamosaic VideoCore"},
    {96, "Thompson Multimedia"}, {97, "NatSemi 32k"},
    {98, "Tenor Network TPC"}, {99, "Trebia SNP 1000"},
    {100, "STMicroelectronics ST200"}, {101, "Ubicom IP2022"},
    {102, "MAX Processor"}, {103, "NatSemi CompactRISC"},
    {104, "Fujitsu F2MC16"}, {105, "TI msp430"},
    {106, "Analog Devices Blackfin"}, {107, "S1C33 Family of Seiko Epson"},
    {108, "Sharp embedded"}, {109, "Arca RISC"}, {110, "PKU-Unity Ltd."},
    {111, "eXcess: 16/32/64-bit"}, {112, "Icera Deep Execution Processor"},
    {113, "Altera Nios II"}, {114, "NatSemi CRX"}, {115, "Motorola XGATE"},
    {116, "Infineon C16x/XC16x"}, {117, "Renesas M16C series"},
    {118, "Microchip dsPIC30F"}, {119, "Freescale RISC core"},
    {120, "Renesas M32C series"}, {131, "Altium TSK3000 core"},
    {132, "Freescale RS08"}, {134, "Cyan Technology eCOG2"},
    {135, "Sunplus S+core7 RISC"},
    {136, "New Japan Radio (NJR) 24-bit DSP"},
    {137, "Broadcom VideoCore III processor"}, {138, "LatticeMico32"},
    {139, "Seiko Epson C17 family"}, {140, "TMS320C6000"},
    {141, "TMS320C2000"}, {142, "TMS320C55x"},
    {144, "TI Programmable Realtime Unit"},
    {160, "STMicroelectronics 64bit VLIW DSP"}, {161, "Cypress M8C"},
    {162, "Renesas R32C series"}, {163, "NXP TriMedia family"},
    {164, "Qualcomm DSP6"}, {165, "Intel 8051 and variants"},
    {166, "STMicroelectronics STxP7x family"}, {167, "Andes embedded RISC"},
    {168, "Cyan eCOG1X family"}, {169, "Dallas MAXQ30"},
    {170, "New Japan Radio (NJR) 16-bit DSP"},
    {171, "M2000 Reconfigurable RISC"}, {172, "Cray NV2 vector architecture"},
    {173, "Renesas RX family"}, {174, "META"}, {175, "MCST Elbrus e2k"},
    {176, "Cyan Technology eCOG16 family"}, {177, "NatSemi CompactRISC"},
    {178, "Freescale Extended Time Processing Unit"}, {179, "Infineon SLE9X"},
    {180, "Intel L1OM"}, {181, "Intel K1OM"}, {183, "ARM 64-bit"},
    {185, "Atmel 32-bit family"}, {186, "STMicroeletronics STM8 8-bit"},
    {187, "Tilera TILE64"}, {188, "Tilera TILEPro"},
    {189, "Xilinx MicroBlaze 32-bit RISC"}, {190, "NVIDIA CUDA architecture"},
    {191, "Tilera TILE-Gx"}, {195, "Synopsys ARCv2/HS3x/HS4x cores"},
    {197, "Renesas RL78 family"}, {199, "Renesas 78K0R"},
    {200, "Freescale 56800EX"}, {201, "Beyond BA1"}, {202, "Beyond BA2"},
    {203, "XMOS xCORE"}, {204, "Microchip 8-bit PIC(r)"}, {210, "KM211 KM32"},
    {211, "KM211 KMX32"}, {212, "KM211 KMX16"}, {213, "KM211 KMX8"},
    {214, "KM211 KVARC"}, {215, "Paneve CDP"},
    {216, "Cognitive Smart Memory"}, {217, "iCelero CoolEngine"},
    {218, "Nanoradio Optimized RISC"},
    {219, "CSR Kalimba architecture family"}, {220, "Zilog Z80"},
    {221, "Controls and Data Services VISIUMcore processor"},
    {222, "FTDI Chip FT32 high performance 32-bit RISC architecture"},
    {223, "Moxie processor family"}, {224, "AMD GPU architecture"},
    {243, "RISC-V"}, {244, "Lanai 32-bit processor"},
    {245, "CEVA Processor Architecture Family"},
    {246, "CEVA X2 Processor Family"}, {247, "Berkeley Packet Filter"},
    {248, "Graphcore Intelligent Processing Unit"},
    {249, "Imagination Technologies"}, {250, "Netronome Flow Processor"},
    {251, "NEC Vector Engine"}, {252, "C-SKY processor family"},
    {253, "Synopsys ARCv3 64-bit ISA/HS6x cores"},
    {254, "MOS Technology MCS 6502 processor"},
    {255, "Synopsys ARCv3 32-bit"},
    {256, "Kalray VLIW core of the MPPA family"}, {257, "WDC 65C816"},
    {258, "LoongArch"}, {259, "ChipON KungFu32"}
};

struct elf_header {
    const char* bit_class = nullptr;
    const char* osabi = nullptr;
    const char* machine = nullptr;
    const char* exe_type = nullptr;
    const char* endianness = nullptr;
};

[[nodiscard]] std::optional<elf_header> inspect_elf(byte_view data, std::size_t offset) {
    constexpr std::size_t ident_size = 16;
    constexpr std::size_t info_size = 8;
    constexpr std::uint32_t expected_version = 1;

    static const std::vector<std::uint8_t> elf_magic_bytes = {0x7F, 'E', 'L', 'F'};
    if(!bytes_equal(data, offset, elf_magic_bytes)) {
        return std::nullopt;
    }
    if(!data.contains(offset, ident_size + info_size)) {
        return std::nullopt;
    }

    const binary_reader<byte_order::little> little(data);

    const auto class_byte = data[offset + 4];
    const auto endian_byte = data[offset + 5];
    const auto version_byte = data[offset + 6];
    const auto osabi_byte = data[offset + 7];

    if(version_byte != expected_version) {
        return std::nullopt;
    }

    const auto padding_1 = little.read<std::uint32_t>(offset + 9);
    const auto padding_2 = little.read_u24(offset + 13);
    if(!padding_1 || !padding_2 || *padding_1 != 0 || *padding_2 != 0) {
        return std::nullopt;
    }

    elf_header header;
    if(class_byte == 1) {
        header.bit_class = "32";
    } else if(class_byte == 2) {
        header.bit_class = "64";
    } else {
        return std::nullopt;
    }

    const bool big_endian = endian_byte == 2;
    if(endian_byte == 1) {
        header.endianness = "little";
    } else if(endian_byte == 2) {
        header.endianness = "big";
    } else {
        return std::nullopt;
    }

    header.osabi = lookup(elf_osabi_table, static_cast<std::uint32_t>(osabi_byte));
    if(header.osabi == nullptr) {
        return std::nullopt;
    }

    const auto info_offset = offset + ident_size;
    std::optional<std::uint16_t> exe_type;
    std::optional<std::uint16_t> machine;
    std::optional<std::uint32_t> version;
    if(big_endian) {
        const binary_reader<byte_order::big> big(data);
        exe_type = big.read<std::uint16_t>(info_offset);
        machine = big.read<std::uint16_t>(info_offset + 2);
        version = big.read<std::uint32_t>(info_offset + 4);
    } else {
        exe_type = little.read<std::uint16_t>(info_offset);
        machine = little.read<std::uint16_t>(info_offset + 2);
        version = little.read<std::uint32_t>(info_offset + 4);
    }
    if(!exe_type || !machine || !version || *version != expected_version) {
        return std::nullopt;
    }

    header.exe_type = lookup(elf_type_table, static_cast<std::uint32_t>(*exe_type));
    if(header.exe_type == nullptr) {
        return std::nullopt;
    }

    header.machine = lookup(elf_machine_table, static_cast<std::uint32_t>(*machine));
    if(header.machine == nullptr) {
        header.machine = "Unknown";
    }
    return header;
}

constexpr std::uint32_t uimage_magic_standard = 0x27051956;
constexpr std::uint32_t uimage_magic_okli = 0x4F4B4C49;
constexpr std::size_t uimage_header_size = 64;
constexpr std::size_t uimage_name_offset = 32;

constexpr code_name<std::uint32_t> uimage_os_table[] = {
    {1, "OpenBSD"}, {2, "NetBSD"}, {3, "FreeBSD"}, {4, "4.4BSD"}, {5, "Linux"},
    {6, "SVR4"}, {7, "Esix"}, {8, "Solaris"}, {9, "Irix"}, {10, "SCO"},
    {11, "Dell"}, {12, "NCR"}, {13, "LynxOS"}, {14, "VxWorks"}, {15, "pSOS"},
    {16, "QNX"}, {17, "Firmware"}, {18, "RTEMS"}, {19, "ARTOS"},
    {20, "Unity OS"}, {21, "INTEGRITY"}, {22, "OSE"}, {23, "Plan 9"},
    {24, "OpenRTOS"}, {25, "ARM Trusted Firmware"},
    {26, "Trusted Execution Environment"}, {27, "OpenSBI"},
    {28, "EFI Firmware"}, {29, "ELF Image"}
};

constexpr code_name<std::uint32_t> uimage_cpu_table[] = {
    {1, "Alpha"}, {2, "ARM"}, {3, "Intel x86"}, {4, "IA64"}, {5, "MIPS32"},
    {6, "MIPS64"}, {7, "PowerPC"}, {8, "IBM S390"}, {10, "SuperH"},
    {11, "Sparc"}, {12, "Sparc64"}, {13, "M68K"}, {14, "Nios-32"},
    {15, "MicroBlaze"}, {16, "Nios-II"}, {17, "Blackfin"}, {18, "AVR32"},
    {19, "ST200"}, {20, "Sandbox"}, {21, "NDS32"}, {22, "OpenRISC"},
    {23, "ARM64"}, {24, "ARC"}, {25, "x86-64"}, {26, "Xtensa"}, {27, "RISC-V"}
};

constexpr code_name<std::uint32_t> uimage_compression_table[] = {
    {0, "none"}, {1, "gzip"}, {2, "bzip2"}, {3, "lzma"}, {4, "lzo"},
    {5, "lz4"}, {6, "zstd"}
};

constexpr code_name<std::uint32_t> uimage_image_type_table[] = {
    {1, "Standalone Program"}, {2, "OS Kernel Image"}, {3, "RAMDisk Image"},
    {4, "Multi-File Image"}, {5, "Firmware Image"}, {6, "Script file"},
    {7, "Filesystem Image"}, {8, "Binary Flat Device Tree Blob"},
    {9, "Kirkwood Boot Image"}, {10, "Freescale IMXBoot Image"},
    {11, "Davinci UBL Image"}, {12, "TI OMAP Config Header Image"},
    {13, "TI Davinci AIS Image"}, {14, "OS Kernel Image"},
    {15, "Freescale PBL Boot Image"}, {16, "Freescale MXSBoot Image"},
    {17, "TI Keystone GPHeader Image"}, {18, "ATMEL ROM bootable Image"},
    {19, "Altera SOCFPGA CV/AV Preloader"}, {20, "x86 setup.bin Image"},
    {21, "x86 setup.bin Image"}, {22, "A list of typeless images"},
    {23, "Rockchip Boot Image"}, {24, "Rockchip SD card"},
    {25, "Rockchip SPI image"}, {26, "Xilinx Zynq Boot Image"},
    {27, "Xilinx ZynqMP Boot Image"}, {28, "Xilinx ZynqMP Boot Image (bif)"},
    {29, "FPGA Image"}, {30, "VYBRID .vyb Image"},
    {31, "Trusted Execution Environment OS Image"},
    {32, "Firmware Image with HABv4 IVT"},
    {33, "TI Power Management Micro-Controller Firmware"},
    {34, "STMicroelectronics STM32 Image"},
    {35, "Altera SOCFPGA A10 Preloader"},
    {36, "MediaTek BootROM loadable Image"},
    {37, "Freescale IMX8MBoot Image"}, {38, "Freescale IMX8Boot Image"},
    {39, "Coprocessor Image for remoteproc"},
    {40, "Allwinner eGON Boot Image"}, {41, "Allwinner TOC0 Boot Image"},
    {42, "Binary Flat Device Tree Blob in a Legacy Image"},
    {43, "Renesas SPKG image"}, {44, "StarFive SPL image"}
};

struct uimage_header {
    std::string name;
    std::uint32_t data_size = 0;
    std::uint32_t data_checksum = 0;
    std::uint32_t load_address = 0;
    std::uint32_t entry_point_address = 0;
    std::uint32_t timestamp = 0;
    const char* compression_type = nullptr;
    const char* cpu_type = nullptr;
    const char* os_type = nullptr;
    const char* image_type = nullptr;
    bool header_crc_valid = false;
};

[[nodiscard]] std::uint32_t uimage_header_checksum(byte_view data, std::size_t offset) {
    static const std::uint8_t zeroes[4] = {0, 0, 0, 0};
    auto crc = crc32_update(0, data.subview(offset, 4));
    crc = crc32_update(crc, byte_view(zeroes, 4));
    return crc32_update(crc, data.subview(offset + 8, uimage_header_size - 8));
}

[[nodiscard]] std::optional<uimage_header> inspect_uimage(byte_view data, std::size_t offset) {
    if(!data.contains(offset, uimage_header_size)) {
        return std::nullopt;
    }
    const binary_reader<byte_order::big> reader(data);

    const auto magic = reader.read<std::uint32_t>(offset);
    if(!magic || (*magic != uimage_magic_standard && *magic != uimage_magic_okli)) {
        return std::nullopt;
    }

    const auto stored_crc = reader.read<std::uint32_t>(offset + 4);
    const auto timestamp = reader.read<std::uint32_t>(offset + 8);
    const auto data_size = reader.read<std::uint32_t>(offset + 12);
    const auto load_address = reader.read<std::uint32_t>(offset + 16);
    const auto entry_point = reader.read<std::uint32_t>(offset + 20);
    const auto data_crc = reader.read<std::uint32_t>(offset + 24);
    if(!stored_crc || !timestamp || !data_size || !load_address || !entry_point || !data_crc) {
        return std::nullopt;
    }

    uimage_header header;
    header.os_type = lookup(uimage_os_table, static_cast<std::uint32_t>(data[offset + 28]));
    header.cpu_type = lookup(uimage_cpu_table, static_cast<std::uint32_t>(data[offset + 29]));
    header.image_type =
        lookup(uimage_image_type_table, static_cast<std::uint32_t>(data[offset + 30]));
    header.compression_type =
        lookup(uimage_compression_table, static_cast<std::uint32_t>(data[offset + 31]));
    if(header.os_type == nullptr || header.cpu_type == nullptr
        || header.image_type == nullptr || header.compression_type == nullptr) {
        return std::nullopt;
    }

    header.name = get_cstring(
        data, offset + uimage_name_offset, uimage_header_size - uimage_name_offset
    );
    header.data_size = *data_size;
    header.data_checksum = *data_crc;
    header.timestamp = *timestamp;
    header.load_address = *load_address;
    header.entry_point_address = *entry_point;
    header.header_crc_valid = uimage_header_checksum(data, offset) == *stored_crc;
    return header;
}

extraction_result extract_uimage(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string default_output_name = "uimage_data";

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    const auto header = inspect_uimage(data, offset);
    if(!header) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const std::uint64_t payload_start =
        static_cast<std::uint64_t>(offset) + uimage_header_size;
    const std::uint64_t payload_size = header->data_size;
    if(payload_start > static_cast<std::uint64_t>(data.size())
        || payload_size > static_cast<std::uint64_t>(data.size()) - payload_start) {

        result.failure = extraction_failure::invalid_data;
        return result;
    }

    const auto payload = data.subview(
        static_cast<std::size_t>(payload_start), static_cast<std::size_t>(payload_size)
    );

    result.success = true;
    result.size = uimage_header_size;

    const bool data_crc_valid = crc32(payload) == header->data_checksum;
    if(data_crc_valid) {

        result.size = uimage_header_size + payload_size;
    }

    if(!data_crc_valid || output_directory == nullptr) {
        return result;
    }

    std::string base_name = default_output_name;
    if(!header->name.empty()) {
        base_name = header->name;
        std::replace(base_name.begin(), base_name.end(), ' ', '_');
    }

    const chroot output(*output_directory);
    result.success = output.create_file(base_name + ".bin", payload);
    if(!result.success) {
        result.failure = extraction_failure::write_error;
    }
    return result;
}

constexpr std::uint8_t linux_symtab_magic[] = {
    0x00, 0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00, 0x34, 0x00,
    0x35, 0x00, 0x36, 0x00, 0x37, 0x00, 0x38, 0x00, 0x39, 0x00
};

[[nodiscard]] bool has_linux_symbol_table(byte_view data) noexcept {
    constexpr std::size_t magic_size = sizeof(linux_symtab_magic);
    if(data.size() < magic_size) {
        return false;
    }
    std::size_t match_count = 0;
    const std::size_t last = data.size() - magic_size;
    for(std::size_t index = 0; index <= last; ++index) {
        bool matched = true;
        for(std::size_t byte = 0; byte < magic_size; ++byte) {
            if(data[index + byte] != linux_symtab_magic[byte]) {
                matched = false;
                break;
            }
        }
        if(matched) {
            ++match_count;
            if(match_count > 1) {
                return false;
            }
        }
    }
    return match_count == 1;
}

extraction_result extract_linux_kernel(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    (void)data;
    (void)signature;
    (void)output_directory;
    extraction_result result;
    result.success = false;
    result.failure = extraction_failure::unsupported;
    return result;
}

constexpr std::size_t vxworks_symtab_entry_size = 16;
constexpr std::size_t vxworks_symtab_magic_offset = 8;
constexpr std::size_t vxworks_symtab_min_entries = 250;

[[nodiscard]] const char* vxworks_symbol_type(std::uint32_t type) noexcept {
    switch(type) {
        case 0x500: return "function";
        case 0x700: return "initialized data";
        case 0x900: return "uninitialized data";
        default: return nullptr;
    }
}

struct vxworks_entry {
    std::uint32_t name = 0;
    std::uint32_t value = 0;
    const char* symtype = nullptr;
};

template<byte_order Order>
[[nodiscard]] std::optional<vxworks_entry> parse_vxworks_entry(
    byte_view data,
    std::size_t offset
) noexcept {
    const binary_reader<Order> reader(data);
    const auto name_ptr = reader.template read<std::uint32_t>(offset);
    const auto value_ptr = reader.template read<std::uint32_t>(offset + 4);
    const auto type = reader.template read<std::uint32_t>(offset + 8);
    const auto group = reader.template read<std::uint32_t>(offset + 12);
    if(!name_ptr || !value_ptr || !type || !group) {
        return std::nullopt;
    }
    const auto* symtype = vxworks_symbol_type(*type);
    if(symtype == nullptr || *name_ptr == 0 || *value_ptr == 0) {
        return std::nullopt;
    }
    return vxworks_entry{*name_ptr, *value_ptr, symtype};
}

template<byte_order Order, typename Sink>
[[nodiscard]] std::size_t walk_vxworks_symtab(
    byte_view data,
    std::size_t offset,
    std::size_t& entry_count,
    Sink&& on_entry
) {
    const auto available = data.size();
    std::optional<std::size_t> previous_offset;
    std::size_t cursor = offset;
    entry_count = 0;
    while(is_offset_safe(available, cursor, previous_offset)) {
        const auto entry = parse_vxworks_entry<Order>(data, cursor);
        if(!entry) {
            break;
        }
        on_entry(*entry);
        ++entry_count;
        previous_offset = cursor;
        cursor += vxworks_symtab_entry_size;
    }
    return cursor;
}

void append_symtab_json_entry(std::string& text, const vxworks_entry& entry, bool first) {
    if(!first) {
        text += ',';
    }
    text += "\n  {\n    \"size\": ";
    text += std::to_string(vxworks_symtab_entry_size);
    text += ",\n    \"name\": ";
    text += std::to_string(entry.name);
    text += ",\n    \"value\": ";
    text += std::to_string(entry.value);
    text += ",\n    \"symtype\": \"";
    text += entry.symtype;
    text += "\"\n  }";
}

extraction_result extract_vxworks_symtab(
    byte_view data,
    const signature_result& signature,
    const std::string* output_directory
) {
    static const std::string outfile_name = "symtab.json";

    constexpr std::size_t flush_threshold = 64 * 1024;

    extraction_result result;
    if(signature.offset > static_cast<std::uint64_t>(data.size())) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const auto offset = static_cast<std::size_t>(signature.offset);

    if(!data.contains(offset, 10)) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }
    const bool big_endian = data[offset + 9] == 0;

    std::size_t entry_count = 0;
    const auto noop = [](const vxworks_entry&) {};
    const auto end_offset = big_endian
        ? walk_vxworks_symtab<byte_order::big>(data, offset, entry_count, noop)
        : walk_vxworks_symtab<byte_order::little>(data, offset, entry_count, noop);

    if(entry_count < vxworks_symtab_min_entries) {
        result.failure = extraction_failure::invalid_data;
        return result;
    }

    result.success = true;
    result.size = static_cast<std::uint64_t>(end_offset - offset);

    if(output_directory == nullptr) {
        return result;
    }

    const chroot output(*output_directory);
    bool write_ok = true;
    bool first = true;
    std::string buffer = "[";
    const auto flush = [&](bool force) {
        if(!write_ok) {

            buffer.clear();
            return;
        }
        if(!force && buffer.size() < flush_threshold) {
            return;
        }
        if(!buffer.empty()) {
            write_ok = output.append_to_file(
                outfile_name,
                byte_view(reinterpret_cast<const std::uint8_t*>(buffer.data()), buffer.size())
            );
            buffer.clear();
        }
    };
    const auto sink = [&](const vxworks_entry& entry) {
        if(!write_ok) {
            return;
        }
        append_symtab_json_entry(buffer, entry, first);
        first = false;
        flush(false);
    };

    std::size_t written_count = 0;
    if(big_endian) {
        (void)walk_vxworks_symtab<byte_order::big>(data, offset, written_count, sink);
    } else {
        (void)walk_vxworks_symtab<byte_order::little>(data, offset, written_count, sink);
    }
    buffer += "\n]";
    flush(true);

    result.success = write_ok;
    if(!write_ok) {
        result.failure = extraction_failure::write_error;
    }
    return result;
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>> ecos_magic_patterns() {
    return {
        {0x00, 0x68, 0x1A, 0x40, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x5A, 0x33},
        {0x00, 0x68, 0x1A, 0x40, 0x7F, 0x00, 0x5A, 0x33},
        {0x40, 0x1A, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x5A, 0x00, 0x7F},
        {0x40, 0x1A, 0x68, 0x00, 0x33, 0x5A, 0x00, 0x7F}
    };
}

}

template<>
struct format_traits<elf_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "elf"; }
    static std::string description() { return "ELF binary"; }
    static std::vector<std::vector<std::uint8_t>> magic() { return {{0x7F, 'E', 'L', 'F'}}; }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        const auto header = inspect_elf(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.confidence = confidence_medium;
        result.description = description() + ", " + header->bit_class + "-bit "
            + header->exe_type + ", " + header->machine + " for " + header->osabi
            + ", " + header->endianness + " endian";
        return result;
    }
};

template<>
struct format_traits<uimage_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "uimage"; }
    static std::string description() { return "uImage firmware image"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x27, 0x05, 0x19, 0x56}, {'O', 'K', 'L', 'I'}};
    }

    static binwalk::extractor extractor() {
        return {
            extractor_type::internal,
            "uimage_built_in",
            &extract_uimage,
            std::string{},
            std::string{},
            {},
            {},
            false
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        signature_result probe;
        probe.offset = offset;
        const auto dry_run = dry_run_extractor(&extract_uimage, data, probe);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }

        const auto header = inspect_uimage(data, offset);
        if(!header) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = *dry_run.size;
        result.confidence = confidence_high;

        result.extraction_declined = !header->header_crc_valid || header->data_size == 0;
        result.description = description()
            + ", header size: " + std::to_string(uimage_header_size) + " bytes"
            + ", data size: " + std::to_string(header->data_size) + " bytes"
            + ", compression: " + header->compression_type
            + ", CPU: " + header->cpu_type
            + ", OS: " + header->os_type
            + ", image type: " + header->image_type
            + ", load address: " + to_hex_upper(header->load_address)
            + ", entry point: " + to_hex_upper(header->entry_point_address)
            + ", creation time: " + epoch_to_string(header->timestamp)
            + ", image name: \"" + header->name + "\"";

        if(!header->header_crc_valid) {

            result.confidence = offset == 0 ? confidence_medium : confidence_low;
            result.description += ", invalid checksum";
        }
        return result;
    }
};

template<>
struct format_traits<linux_kernel_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;

    static constexpr bool always_display = true;

    static std::string name() { return "linux_kernel"; }
    static std::string description() { return "Linux kernel version"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'L', 'i', 'n', 'u', 'x', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', ' '}};
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal,
            "linux_kernel_built_in",
            &extract_linux_kernel,
            std::string{},
            std::string{},
            {},
            {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t minimum_file_size = 100 * 1024;
        constexpr std::size_t minimum_version_length = 75;
        constexpr std::size_t period_offset_1 = 15;
        constexpr std::size_t period_offset_2 = 17;
        constexpr std::size_t period_offset_3 = 18;

        if(data.size() <= minimum_file_size || offset >= data.size()) {
            return std::nullopt;
        }

        const auto version = get_cstring(data, offset, data.size() - offset);
        if(version.size() <= minimum_version_length) {
            return std::nullopt;
        }
        if(version.find("gcc ") == std::string::npos) {
            return std::nullopt;
        }
        if(version.find('@') == std::string::npos) {
            return std::nullopt;
        }
        if(version.back() != '\n') {
            return std::nullopt;
        }

        if(version[period_offset_1] != '.'
            || (version[period_offset_2] != '.' && version[period_offset_3] != '.')) {
            return std::nullopt;
        }

        const bool symbol_table_present = has_linux_symbol_table(data);

        signature_result result;
        result.confidence = confidence_low;
        if(symbol_table_present) {

            result.offset = 0;
            result.size = data.size();
        } else {
            result.offset = offset;
            result.size = version.size();
            result.extraction_declined = true;
        }
        result.description = trim_ascii(version) + ", has symbol table: "
            + (symbol_table_present ? "true" : "false");
        return result;
    }
};

template<>
struct format_traits<linux_boot_image_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "linux_boot_image"; }
    static std::string description() { return "Linux kernel boot image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{
            0xb8, 0xc0, 0x07, 0x8e, 0xd8, 0xb8, 0x00, 0x90,
            0x8e, 0xc0, 0xb9, 0x00, 0x01, 0x29, 0xf6, 0x29
        }};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t hdrs_offset = 514;
        static const std::vector<std::uint8_t> hdrs_expected = {'!', 'H', 'd', 'r', 'S'};

        if(!bytes_equal(data, offset + hdrs_offset, hdrs_expected)) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = 0;
        result.confidence = confidence_low;
        result.description = description();
        return result;
    }
};

template<>
struct format_traits<linux_arm_zimage_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "linux_arm_zimage"; }
    static std::string description() { return "Linux ARM boot executable zImage"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0x18, 0x28, 0x6F, 0x01}, {0x01, 0x6F, 0x28, 0x18}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t back_offset = 36;
        constexpr std::uint32_t nop_little = 0xE1A00000;
        constexpr std::uint32_t nop_big = 0x0000A0E1;
        constexpr std::size_t nop_count = 8;

        if(offset < back_offset) {
            return std::nullopt;
        }
        const auto start = offset - back_offset;

        const binary_reader<byte_order::little> reader(data);
        const auto first = reader.read<std::uint32_t>(start);
        if(!first) {
            return std::nullopt;
        }
        for(std::size_t index = 1; index < nop_count; ++index) {
            const auto nop = reader.read<std::uint32_t>(start + index * 4);
            if(!nop || *nop != *first) {
                return std::nullopt;
            }
        }

        const char* endianness = nullptr;
        if(*first == nop_little) {
            endianness = "little";
        } else if(*first == nop_big) {
            endianness = "big";
        } else {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start;
        result.size = 0;
        result.confidence = confidence_medium;
        result.description = description() + ", " + endianness + " endian";
        return result;
    }
};

template<>
struct format_traits<linux_arm64_boot_image_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;
    static constexpr bool always_display = false;

    static std::string name() { return "linux_arm64_boot_image"; }
    static std::string description() { return "Linux kernel ARM64 boot image"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{0, 0, 0, 0, 0, 0, 0, 0, 'A', 'R', 'M', 'd'}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t back_offset = 0x30;
        constexpr std::size_t header_size = 64;
        constexpr std::uint64_t flags_reserved_mask = ~static_cast<std::uint64_t>(0xF);
        constexpr std::uint64_t flags_endian_mask = 1;
        constexpr std::uint32_t arm64_magic = 0x644D5241;
        static const std::vector<std::uint8_t> pe_signature = {'P', 'E'};

        if(offset < back_offset) {
            return std::nullopt;
        }
        const auto start = offset - back_offset;
        if(!data.contains(start, header_size)) {
            return std::nullopt;
        }

        const binary_reader<byte_order::little> reader(data);
        const auto image_size = reader.read<std::uint64_t>(start + 16);
        const auto flags = reader.read<std::uint64_t>(start + 24);
        const auto reserved_1 = reader.read<std::uint64_t>(start + 32);
        const auto reserved_2 = reader.read<std::uint64_t>(start + 40);
        const auto reserved_3 = reader.read<std::uint64_t>(start + 48);
        const auto magic_field = reader.read<std::uint32_t>(start + 56);
        const auto pe_offset = reader.read<std::uint32_t>(start + 60);
        if(!image_size || !flags || !reserved_1 || !reserved_2 || !reserved_3
            || !magic_field || !pe_offset) {
            return std::nullopt;
        }

        if(*magic_field != arm64_magic) {
            return std::nullopt;
        }
        if(*reserved_1 != 0 || *reserved_2 != 0 || *reserved_3 != 0) {
            return std::nullopt;
        }
        if((*flags & flags_reserved_mask) != 0) {
            return std::nullopt;
        }

        const std::uint64_t pe_start = static_cast<std::uint64_t>(start) + *pe_offset;
        if(pe_start > static_cast<std::uint64_t>(data.size())) {
            return std::nullopt;
        }
        if(!bytes_equal(data, static_cast<std::size_t>(pe_start), pe_signature)) {
            return std::nullopt;
        }

        const char* endianness =
            (*flags & flags_endian_mask) == 1 ? "big" : "little";

        signature_result result;
        result.offset = start;

        result.size = header_size;
        result.confidence = confidence_medium;
        result.description = description() + ", " + endianness
            + " endian, effective image size: " + std::to_string(*image_size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<wind_kernel_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;

    static constexpr bool always_display = true;

    static std::string name() { return "wind_kernel"; }
    static std::string description() { return "VxWorks WIND kernel version"; }
    static std::vector<std::vector<std::uint8_t>> magic() {
        return {{'W', 'I', 'N', 'D', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', ' '}};
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t magic_size = 13;

        if(!data.contains(offset, magic_size)) {
            return std::nullopt;
        }
        const auto version_offset = offset + magic_size;
        if(version_offset >= data.size()) {
            return std::nullopt;
        }

        const auto version = get_cstring(data, version_offset, data.size() - version_offset);
        if(version.empty()) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = offset;
        result.size = magic_size + version.size();
        result.confidence = confidence_low;
        result.description = description() + " " + version;
        return result;
    }
};

template<>
struct format_traits<vxworks_symtab_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;

    static constexpr bool always_display = true;

    static std::string name() { return "vxworks_symtab"; }
    static std::string description() { return "VxWorks symbol table"; }

    static std::vector<std::vector<std::uint8_t>> magic() {
        return {
            {0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
        };
    }

    static binwalk::extractor extractor() {
        return binwalk::extractor{
            extractor_type::internal,
            "vxworks_symtab_built_in",
            &extract_vxworks_symtab,
            std::string{},
            std::string{},
            {},
            {},
            true
        };
    }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        constexpr std::size_t back_offset = vxworks_symtab_magic_offset;

        if(offset < back_offset) {
            return std::nullopt;
        }
        const auto start = offset - back_offset;

        signature_result probe;
        probe.offset = start;
        const auto dry_run = dry_run_extractor(&extract_vxworks_symtab, data, probe);
        if(!dry_run.success || !dry_run.size) {
            return std::nullopt;
        }

        signature_result result;
        result.offset = start;
        result.size = *dry_run.size;
        result.confidence = confidence_high;
        result.description =
            description() + ", total size: " + std::to_string(result.size) + " bytes";
        return result;
    }
};

template<>
struct format_traits<ecos_format> {
    static constexpr bool short_signature = false;
    static constexpr std::size_t magic_offset = 0;

    static constexpr bool always_display = true;

    static std::string name() { return "ecos"; }
    static std::string description() { return "eCos kernel exception handler"; }

    static std::vector<std::vector<std::uint8_t>> magic() { return ecos_magic_patterns(); }

    static std::optional<signature_result> parse(byte_view data, std::size_t offset) {
        static const auto patterns = ecos_magic_patterns();
        if(!any_pattern_at(data, offset, patterns)) {
            return std::nullopt;
        }

        const char* endianness = data[offset] == 0 ? "little" : "big";

        signature_result result;
        result.offset = offset;
        result.size = 0;
        result.confidence = confidence_low;
        result.description = description() + ", MIPS " + endianness + " endian";
        return result;
    }
};

namespace formats {

std::vector<signature> b10a_kernels_signatures() {
    return make_signatures(type_list<
        uimage_format,
        linux_kernel_format,
        linux_boot_image_format,
        linux_arm_zimage_format,
        elf_format,
        wind_kernel_format,
        vxworks_symtab_format,
        ecos_format,
        linux_arm64_boot_image_format
    >{});
}

}
}
