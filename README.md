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
- A scan that runs several automaton walks at once, over disjoint slices of the
  same window and across cores, and reads the image through a memory mapping
  rather than a copy. See [Performance](#performance).
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
| `BINWALK_BUILD_BENCH` | `OFF` | Build the throughput harnesses under `bench/`. |
| `BINWALK_PROFILE_COUNTERS` | `OFF` | Report scanner hot-path counters on exit. |
| `BINWALK_ENABLE_IPO` | `ON` | Link-time optimisation for optimised builds. |
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

## Performance

Measured on one machine (8-core Ryzen 7 PRO 6850U, MSVC Release), best of five,
using the CLI's own elapsed figure so process start-up is excluded. `baseline`
is this tree before the scanner was reworked; the corpus comes from
[`bench/make_corpus.py`](bench/make_corpus.py) and the harnesses are described
in [`bench/README.md`](bench/README.md). Times cover reading the file as well as
scanning it, and every corpus produces an identical file map either way.

The machine is a laptop that clocks down as it warms, so both columns were taken
with it otherwise idle. Repeating the run on a hot machine moves every absolute
figure by up to a fifth in either direction; the ratios hold.

| corpus                  | baseline | now    | throughput | speed-up |
| ----------------------- | -------- | ------ | ---------- | -------- |
| 4 MiB, high entropy     | 43 ms    | 5 ms   | 800 MiB/s  | 9x       |
| 4 MiB, all zeroes       | 39 ms    | 4 ms   | 1000 MiB/s | 10x      |
| 16 MiB, firmware-like   | 12.8 s   | 12 ms  | 1333 MiB/s | 1070x    |
| 64 MiB, high entropy    | 603 ms   | 25 ms  | 2560 MiB/s | 24x      |
| 64 MiB, firmware-like   | 45.5 s   | 45 ms  | 1422 MiB/s | 1010x    |
| 256 MiB, firmware-like  | 4.8 min  | 138 ms | 1855 MiB/s | 2090x    |

The three-figure speed-ups are not a faster search: they are a parser that no
longer walked the file, described below. The honest measure of the search
itself is the high-entropy row, where nothing matches and there is nothing to
parse — 24x — and the matcher microbenchmark, which puts the automaton walk at
500 MiB/s before and 1.9 GiB/s after on one thread.

Small inputs are dominated by fixed costs — building the registry, and on
Windows roughly 40 ms of process start-up that no scanner controls — so the
larger corpora are the ones that say anything about scanning.

### Where the time went

**A parser that walked the file.** The 16 MiB case above took 12.8 seconds
because `Linux version ` appears in firmware text thousands of times, and the
kernel-version parser copied everything from each hit to the next NUL byte
before testing anything. Over a text region that has no NUL bytes, that is the
whole region per hit, and the scan is quadratic in its length. The predicates
now run cheapest-first over the raw bytes — three byte compares reject nearly
everything — and the string is built only for a candidate that has survived all
of them. `--search-all` had the same shape in the S-record footer search, which
now skips between line terminators with `memchr` instead of testing every byte.

**Answering the same question repeatedly.** `get_cstring` walked to the
terminator one `push_back` at a time, then validated UTF-8, then copied again.
It now finds the terminator with `memchr` and builds the string once. On top of
that, a scan asks where a run ends at thousands of offsets inside the same run,
so `scanner::scan` arms a memo of the run it has already proven clean; the
answers are unchanged, but the work across a whole scan is linear rather than
quadratic. The memo is armed by a scope object rather than left permanently
live, which is what makes it sound: the scope pins the buffer its cached
pointers refer to.

**A search that waited on memory.** Walking an Aho-Corasick automaton is a chain
of dependent loads — the next state cannot be computed until the current one has
arrived — so a core spends most of every load's latency idle. The matcher now
runs eight walks at once over disjoint slices of the same 64 KiB window, which
fills those slots with work that does not depend on them; whole batches of
windows then go to a pool of threads, one per physical core. Two details make it
pay: the states are renumbered so that a reportable one is recognised by a
compare against a register rather than a second table load, and each slice is
reached through a compile-time displacement off a single cursor so all eight
walk states stay in registers. Alone the interleaving takes the matcher from
500 MiB/s to 1.9 GiB/s on this machine; the threads take match-free data past
6 GiB/s.

It is the same automaton over the same bytes in the same order, so it cannot
report anything the single walk would not — and the test suite holds both
backends to the same output, byte for byte, on random, repetitive and
match-dense inputs and at every window boundary.

**Restarting the search.** A confident result claims the bytes it covers, and
the scan used to restart the search after each one. Under a thread pool that
threw away a whole batch per result. Because a walk begun at an offset reports
exactly the matches that start at or after it, raising a floor over one
continuous walk gives the same answer for one pass instead of one per result.

**Reading the file.** The CLI read images a byte at a time through
`istreambuf_iterator`, at about 180 MiB/s. It now maps the file and tells the
kernel the access is sequential, which is both faster than a bulk read — no
copy — and does not need the image resident in the heap. A pipe, or anything the
platform will not map, still falls back to a single bulk read.

Smaller pieces: CRC-32 folds eight bytes per step through sliced tables instead
of one, the entropy histogram uses four interleaved tallies so that repeated
bytes do not serialise on one counter, and result identifiers are formatted
directly rather than through a string stream.

### Portability

Nothing above is tied to one processor. The vector work is what the compiler
and the C library already do (`memchr`, `memcmp`); the interleaving is ordinary
scalar code whose benefit comes from instruction-level parallelism, so it needs
no instruction-set baseline beyond the one the project already targets and
behaves the same on x86-64 and AArch64. Thread count is read from the topology
rather than assumed, and `scan_options::worker_threads` leaves the choice with
the caller: `0` or `1` keeps a scan entirely on the calling thread.

A scanner shared between threads lends its workers to one scan at a time, so a
caller already running a scan per file keeps its own parallelism and never
oversubscribes.

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
bench/               throughput harnesses and the corpus generator
cli/                 command-line frontend
cmake/               dependency and package configuration
include/binwalk/     installed public headers
lib/                 core library and format implementations
tests/               unit, integration, golden, fixture, and consumer tests
```

## License

`binwalk-cpp` is distributed under the MIT License. See [`LICENSE`](LICENSE).
