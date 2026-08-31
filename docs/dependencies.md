# Native dependency and extractor policy

This audit is scoped to upstream Binwalk commit
`26713972e3f9f52dc37d4a421c4554b0bd9e82ef`.

## Rules

- The source tree, build graph, library, CLI, and shipped tools must contain only C or C++.
- No Rust source, Cargo package, Rust binary dependency, or FFI to Rust is permitted.
- Permissively licensed native libraries may be linked into `binwalk::core` when this materially
  improves format compatibility.
- Copyleft or restricted utilities remain optional external processes unless their licensing is
  explicitly accepted for a separate component. They are not linked into the core library.
- Python-based upstream extractors are replaced by native C++ implementations.
- FetchContent dependencies are pinned and can be disabled in favor of `find_package`.

## Upstream external extractor audit

| Upstream command | Existing native implementation | Initial direction |
| --- | --- | --- |
| `7zz` | Official 7-Zip is C/C++; libarchive is C | Prefer libarchive for common 7z data; retain optional 7-Zip process for unsupported/encrypted cases |
| `cabextract` | libmspack and libarchive are C | Use a native library adapter |
| `dmg2img` | dmg2img is C, GPL-2.0 | Keep external and optional initially; implement UDIF handling in C++ for a permissive built-in path |
| `dumpifs` | Existing utility is C | Evaluate as an optional external C tool; port the required QNX IFS extraction logic into C++ |
| `jefferson` | Python | Forbidden dependency; implement JFFS2 extraction in C++ |
| `lz4` | Official implementation is C | Fetch/link the native library |
| `lzfse` | Official implementation is C, BSD-3-Clause | Fetch/link the native library |
| `lzop` | Native C utility and LZO libraries exist | Implement the lzop container in C++ over a native LZO backend |
| `sasquatch` | C, GPL-2.0 | Optional external only; investigate libsqfs/squashfs-tools-ng and a native format adapter |
| `sasquatch-v4be` | C, GPL-2.0 | Same policy as `sasquatch` |
| `srec_cat` | C++ | S-record extraction is small enough to implement directly in the core |
| `tar` | Multiple C implementations; libarchive is C | Use libarchive or a focused C++ tar reader |
| `tsk_recover` | The Sleuth Kit exposes C/C++ libraries | Prefer the library API behind an optional adapter |
| `ubireader_extract_files` | Python | Forbidden dependency; implement UBI/UBIFS parsing and extraction in C++ |
| `uefi-firmware-parser` | Python; UEFITool is C++/BSD-2-Clause | Evaluate a small UEFITool-derived adapter or implement the required UEFI structures directly |
| `unrar` | Native C++ source exists but has a restrictive license | Prefer libarchive where compatible; make the official external utility opt-in |
| `unyaffs` | Native C implementations exist | Audit source/license; otherwise implement YAFFS2 extraction in C++ |
| `vmlinux-to-elf` | Python | Forbidden dependency; port the Linux kernel reconstruction logic to C++ |
| `zstd` | Official implementation is C | Fetch/link the native library |

## Dependency layers

1. Foundation: C++17 standard library only. The signature scanner and public core types belong here.
2. Interface: CLI11 and nlohmann/json, both header-only C++ dependencies used by the CLI.
3. Compression: zlib, bzip2, xz/liblzma, zstd, LZ4, LZFSE, and an LZO implementation.
4. Archive/file-system adapters: libarchive, libmspack, The Sleuth Kit, and selectively
   evaluated native libraries.
5. Optional external tools: GPL or restricted native executables that cannot safely become core
   link dependencies.

GoogleTest is test-only. The upstream Rust executable may be run from a temporary development
directory as a behavioral oracle, but is never copied into this repository or referenced by its
build system.
