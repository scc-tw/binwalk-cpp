# binwalk-cpp

A native C++17 rewrite of Binwalk v3, frozen against upstream commit
`26713972e3f9f52dc37d4a421c4554b0bd9e82ef`.

The project contains no Rust code and has no Rust build-time or run-time dependency.

## Configure and build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Set `BUILD_SHARED_LIBS=ON` to build `binwalk::core` as a shared library. The CLI is a
separate executable that links the core target.

Dependencies needed by enabled components are discovered with `find_package` first.
When `BINWALK_FETCH_DEPENDENCIES=ON`, missing C/C++ dependencies are downloaded by
CMake FetchContent at pinned release tags.

## Status

Upstream registers 111 signatures. This port implements a growing subset of them,
and the supporting infrastructure is complete.

Run `binwalk --list` for the authoritative set of what this build detects and
which utility, if any, extracts each one.

**Infrastructure — complete.** CMake packaging and installable CMake package,
public API, template-based binary reader, trait-based format registry,
Aho-Corasick scanner, CLI, entropy analysis with PNG output, known/unknown
carving, a path-confined safe-write layer for extraction, real external-process
execution for third-party extraction utilities, and a compression codec facade
over zlib, bzip2, xz/liblzma, lz4, zstd, lzfse and a from-scratch LZO1X decoder.
Every third-party codec is optional: the tree builds and tests clean with all of
them disabled.

**Verification.** Behaviour is checked against the upstream Rust implementation
used as a read-only oracle, never as a dependency — it appears nowhere in this
repository or its build graph. Golden vectors captured from that oracle are
committed under `tests/golden/`. The bar is *capability* parity rather than
byte-identical output: detection offsets and sizes, extraction success, and
extracted content must match, while description wording is free.

Cases where this port deliberately behaves differently from upstream are noted in
the source beside the code that implements them. Several are places where upstream
has a defect — including two path-traversal weaknesses in its extraction write
path that this port does not share.

**Known gaps.** Upstream extracts JFFS2, UBI/UBIFS, UEFI volumes and Linux kernel
images by invoking Python tools. This project permits no Python dependency, so
those four are **detected but not yet extracted** until native implementations
land; they report an `unsupported` extraction failure rather than silently
appearing to succeed. Formats whose upstream extractor is a permissively
licensed native utility are invoked as optional external processes when that
utility is installed, and report `utility_not_found` when it is not.
