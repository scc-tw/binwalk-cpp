# binwalk-cpp

`binwalk-cpp` is a native C++17 firmware-analysis library and command-line
tool. It scans binary data for embedded file formats, reports their offsets and
sizes, extracts or carves recognized content, follows extracted files
recursively, and can generate entropy data and PNG graphs.

The signature registry is aligned with Binwalk v3 at upstream commit
[`26713972e3f9f52dc37d4a421c4554b0bd9e82ef`](https://github.com/ReFirmLabs/binwalk/commit/26713972e3f9f52dc37d4a421c4554b0bd9e82ef).
This is an independent C++ implementation: Rust and Python are not build-time
or run-time dependencies.

## Highlights

- All 111 signatures from the frozen upstream registry, represented by 251
  magic patterns.
- Aho-Corasick scanning with format-specific validation, confidence ranking,
  overlap filtering, include/exclude filters, and an all-offset search mode.
- Built-in extraction for common compression, archive, image, filesystem, boot,
  executable, and vendor firmware formats.
- Optional external extractors for formats handled by established native
  command-line tools.
- Recursive extraction, known/unknown carving, JSON logging, multithreaded
  recursive analysis, and entropy graphs with PNG output.
- A path-confined extraction layer that neutralizes traversal paths and unsafe
  symlinks before writing output.
- An installable CMake package exposing the `binwalk::core` target and public
  C++ API.

## Requirements

The base build requires:

- CMake 3.24 or newer;
- a C++17 compiler;
- a C compiler.

The recommended Linux workflow below additionally uses Ninja and mold. CMake
3.29 or newer is required for `CMAKE_LINKER_TYPE=MOLD`.

CMake looks for dependencies already installed on the system first. With
`BINWALK_FETCH_DEPENDENCIES=ON` (the default), missing C/C++ dependencies are
downloaded at pinned release tags through `FetchContent`. A first-time build
therefore needs network access unless every enabled dependency is available
locally.

## Build on Linux with Ninja and mold

Configure a Release build, compile it, and run the complete test suite:

```sh
cmake -S . -B build-linux -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_LINKER_TYPE=MOLD
cmake --build build-linux --parallel
ctest --test-dir build-linux --parallel --output-on-failure
```

The resulting command-line executable is:

```text
build-linux/cli/binwalk
```

To install into a staging prefix:

```sh
cmake --install build-linux --prefix "$PWD/stage"
```

This installs the CLI, public headers, the core library, and the CMake package
configuration. When the static build uses codecs fetched by CMake, their
archives are installed under `lib/binwalk/` and exported with the package;
system-provided codec dependencies are rediscovered for consumers.

## Build on Windows

With Visual Studio 2022:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## CMake options

| Option | Default | Purpose |
| --- | --- | --- |
| `BINWALK_BUILD_CLI` | `ON` | Build the `binwalk` command-line program. |
| `BINWALK_BUILD_TESTS` | `BUILD_TESTING` | Build the GoogleTest suite. |
| `BINWALK_FETCH_DEPENDENCIES` | `ON` | Fetch missing dependencies at pinned tags. |
| `BUILD_SHARED_LIBS` | `OFF` | Build `binwalk::core` as a shared rather than static library. |
| `BINWALK_WITH_ZLIB` | `ON` | Enable deflate, zlib, and gzip support through zlib. |
| `BINWALK_WITH_BZIP2` | `ON` | Enable the bzip2 backend. |
| `BINWALK_WITH_LZMA` | `ON` | Enable xz and LZMA support through liblzma. |
| `BINWALK_WITH_LZ4` | `ON` | Enable the LZ4 backend. |
| `BINWALK_WITH_ZSTD` | `ON` | Enable the Zstandard backend. |
| `BINWALK_WITH_LZFSE` | `ON` | Enable LZFSE and LZVN support. |
| `BINWALK_WITH_LZO` | `ON` | Enable the built-in LZO1X decoder. |

Every third-party codec is optional. For example, a dependency-minimal core can
be configured with the codec options disabled:

```sh
cmake -S . -B build-minimal -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_LINKER_TYPE=MOLD \
  -DBUILD_TESTING=OFF \
  -DBINWALK_BUILD_TESTS=OFF \
  -DBINWALK_BUILD_CLI=OFF \
  -DBINWALK_WITH_ZLIB=OFF \
  -DBINWALK_WITH_BZIP2=OFF \
  -DBINWALK_WITH_LZMA=OFF \
  -DBINWALK_WITH_LZ4=OFF \
  -DBINWALK_WITH_ZSTD=OFF \
  -DBINWALK_WITH_LZFSE=OFF \
  -DBINWALK_WITH_LZO=OFF
cmake --build build-minimal --parallel
```

Signatures remain available when a codec is disabled, but extraction paths that
need that backend report `unsupported`.

## Command-line usage

List the exact signatures and extraction routes available in the current build:

```sh
binwalk --list
```

Scan a firmware image:

```sh
binwalk firmware.bin
```

Read data from standard input:

```sh
cat firmware.bin | binwalk --stdin
```

Limit scanning to selected signature names or exclude noisy signatures. Names
are case-insensitive and may be comma- or space-separated:

```sh
binwalk --include gzip,squashfs firmware.bin
binwalk --exclude copyright aes_sbox firmware.bin
```

Enable signatures that are normally restricted to the start of a file and
continue searching inside validated regions:

```sh
binwalk --search-all firmware.bin
```

Extract recognized content into `extractions/`, or choose another directory:

```sh
binwalk --extract firmware.bin
binwalk --extract --directory output firmware.bin
```

Recursively scan files created by successful extractors. `--threads` controls
the number of recursive workers; when omitted it uses the available hardware
concurrency:

```sh
binwalk --extract --matryoshka --threads 8 --directory output firmware.bin
```

Carve the detected file map, including unknown gaps between known regions:

```sh
binwalk --carve --directory carved firmware.bin
```

Write structured results as a JSON array. Use `-` to send JSON to standard
output, normally together with `--quiet`:

```sh
binwalk --quiet --log results.json firmware.bin
binwalk --quiet --log - firmware.bin
```

Calculate block entropy and optionally render it as a PNG:

```sh
binwalk --entropy --png entropy.png --log entropy.json firmware.bin
```

Run `binwalk --help` for the complete option reference. Extraction and entropy
mode are mutually exclusive, as are include and exclude filters.

## Extraction backends

The core can extract many formats in-process. Compression support is provided by
optional zlib, bzip2, liblzma, LZ4, Zstandard, and LZFSE backends plus the
project's built-in LZO1X decoder.

Other formats use external utilities when installed. Depending on the detected
format, the current registry may invoke:

```text
7zz              cabextract       dmg2img          dumpifs
lz4              lzfse            lzop             sasquatch
sasquatch-v4be   srec_cat          tar              tsk_recover
unrar            unyaffs          zstd
```

These programs are optional and are not downloaded by CMake. Detection still
works without them; an attempted extraction reports `utility_not_found`.

`binwalk --list` is the authoritative mapping between signature names and their
configured built-in or external extractors.

## Current compatibility status

The registry and detection behavior target capability parity with the frozen
upstream revision. Detection offsets, sizes, validation, extraction success,
and extracted content are tested against committed golden data; human-readable
description wording is allowed to differ.

An extractor being listed as `Built-in` means that its route is implemented
inside the process. It does not necessarily mean that the underlying algorithm
has been ported yet. The following groups currently contain explicit
`unsupported` stubs:

- encrypted firmware handled upstream by unavailable decryption logic:
  `openssl`, `dlink_tlv`, `dlke`, `shrs`, `encrpted_img`, `dkbs`, and `encfw`;
- Linux kernel extraction for `linux_kernel`;
- `jffs2`, `ubi`, and `ubifs` filesystem extraction;
- `pchrom`, `uefi_pi_volume`, and `uefi_capsule` extraction.

Those formats are still detected and reported. The explicit failure prevents a
capability gap from appearing to succeed silently. Upstream routes that depend
on Python are intentionally not copied into this project; native replacements
are required before those gaps can be closed.

## Use as a C++ library

After installation, consume the exported CMake target:

```cmake
cmake_minimum_required(VERSION 3.24)
project(firmware_scanner LANGUAGES CXX)

find_package(binwalk CONFIG REQUIRED)

add_executable(firmware_scanner main.cpp)
target_compile_features(firmware_scanner PRIVATE cxx_std_17)
target_link_libraries(firmware_scanner PRIVATE binwalk::core)
```

Point `CMAKE_PREFIX_PATH` at a non-system installation when configuring the
consumer:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_PREFIX_PATH=/path/to/binwalk-prefix
cmake --build build
```

A minimal scan through the public API looks like this:

```cpp
#include <binwalk/binwalk.hpp>

#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    const std::vector<std::uint8_t> firmware{/* binary data */};
    const binwalk::scanner scanner;

    for(const auto& match : scanner.scan(binwalk::byte_view(firmware))) {
        std::cout << match.offset << "  " << match.name << "  "
                  << match.description << '\n';
    }
}
```

The umbrella header also exposes extraction, carving, entropy, codec, binary
reader, safe-write, process, result, and signature APIs.

## Verification

The test suite covers registry order and metadata, format parsing, malformed and
truncated input, extraction behavior, codec backends, recursive CLI behavior,
JSON output, path confinement, and platform-specific file handling. The
separate consumer project under `tests/package_consumer/` verifies the installed
CMake package.

The upstream Rust implementation is used only as a read-only behavior oracle.
It is never part of this repository's dependency graph. Golden observations are
committed under `tests/golden/`, while binary fixtures live under
`tests/fixtures/`.

Some extractor integration tests skip when their optional external utility is
not installed. A skipped external-tool test is distinct from a failed test.

## Repository layout

```text
cli/                 command-line frontend
cmake/               dependency and package configuration
include/binwalk/     installed public headers
lib/                 core library and format implementations
tests/               unit, integration, golden, fixture, and consumer tests
```

## License

`binwalk-cpp` is distributed under the MIT License. See [`LICENSE`](LICENSE).
