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

The CMake packaging, public API, template-based binary reader and format registry,
Aho-Corasick scanner, CLI shell, entropy analysis, known/unknown carving, internal
extraction framework, and GoogleTest harness are in place. The current native format
set is gzip, BMP, PDF, PNG, JPEG, RIFF, and MBR. Format and extractor compatibility is
being ported incrementally.
