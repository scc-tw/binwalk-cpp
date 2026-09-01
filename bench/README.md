# Benchmarks

Not part of the shipped build. Configure with `-DBINWALK_BUILD_BENCH=ON` to get
three harnesses:

| target                 | what it measures                                                     |
| ---------------------- | -------------------------------------------------------------------- |
| `binwalk_bench`        | `scan`, `entropy_blocks` and `crc32` over one file                     |
| `binwalk_bench_matcher`| the literal matcher alone, and that its backends agree byte for byte  |
| `binwalk_bench_io`     | the ways of getting a file in front of the scanner                    |

```sh
cmake -S . -B build -DBINWALK_BUILD_BENCH=ON
cmake --build build --config Release

python bench/make_corpus.py /tmp/binwalk-corpus

./build/bench/binwalk_bench          /tmp/binwalk-corpus/firmware_64m.bin 5 --threads=8
./build/bench/binwalk_bench_matcher  /tmp/binwalk-corpus/firmware_64m.bin 5
./build/bench/binwalk_bench_io       /tmp/binwalk-corpus/firmware_256m.bin 5
```

`binwalk_bench` takes `--threads=N` and `--search-all`, and `--patterns` on its
own prints the magic-length distribution the matcher is built from.

## The corpus

Real firmware cannot be committed, so `make_corpus.py` synthesises images from
the same ingredients: compressed payloads, long runs of zeroes, NUL-free text,
and real magic headers. Three cases matter and they behave differently:

- **firmware\_\*.bin** — the realistic mix. Exercises the parsers.
- **random_64m.bin** — high entropy, almost no magic hits. Isolates the matcher.
- **zeros_64m.bin** — the repetitive case, which is where a naive prefilter
  degenerates and where an automaton does not.

## Reading the numbers

`binwalk_bench` reports the best of N runs, because the interesting quantity is
what the machine can do rather than what the scheduler let it do on one try. The
CLI's own "Analyzed 1 file ... in N milliseconds" line covers everything after
`main` starts, so it includes reading the file but not process start-up, which
on Windows is around 40 ms on its own and swamps small inputs.

## Profiling

`-DBINWALK_PROFILE_COUNTERS=ON` makes the scanner report, on exit, how many
magic hits it saw and where the parser time went, ranked by signature:

```
[profile] matches=93341 parser_calls=93324 parser_ms=16.60
[profile]   linux_kernel      16.02 ms   92460 calls   0.173 us/call
```

That ranking is what to look at first. A magic that is common in text — a
version banner, a copyright line — is hit thousands of times per scan, so a
parser that walks the rest of the buffer before rejecting costs far more than
the search that found it.

## Comparing against another implementation

The comparison worth making is against upstream binwalk on the same file and
the same machine. Both print their own elapsed time, which keeps process
start-up out of it:

```sh
binwalk       /tmp/binwalk-corpus/firmware_256m.bin | tail -1   # upstream
./build/cli/binwalk /tmp/binwalk-corpus/firmware_256m.bin | tail -1
```

Compare file maps as well as times: a faster scanner that finds different
things has not been made faster.
