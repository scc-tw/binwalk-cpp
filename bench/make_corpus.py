#!/usr/bin/env python3
"""Builds the benchmark corpus the throughput numbers in bench/README.md refer to.

Real firmware cannot be committed, so the corpus is synthesised from the same
ingredients: high-entropy payloads, long runs of zeroes, NUL-free text, and real
magic headers at known offsets. It is deterministic apart from the payload
bytes, so repeated runs are comparable on one machine.

    python bench/make_corpus.py <output-directory>
"""

import os
import random
import struct
import sys
import zlib

NUL = bytes(1)

WORDS = [
    b"config", b"kernel", b"init", b"/bin/sh", b"root", b"eth0", b"password",
    b"BusyBox v1.31.1", b"Linux version 4.14.0", b"mtdblock", b"squashfs", b"jffs2",
]


def gzip_blob(rnd, payload):
    stream = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = stream.compress(payload) + stream.flush()
    head = bytes([0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03])
    return head + body + struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))


def squashfs(rnd, size):
    body = b"hsqs" + struct.pack("<IIII", 128, 0x5F000000, 16, 131072)
    body += struct.pack("<HHHHHH", 1, 17, 0, 4, 4, 0)
    body += struct.pack(
        "<QQQQQQQ", 1, size, size - 100, size - 200, size - 300, size - 400, size - 500
    )
    tail = max(0, size - len(body))
    return body + os.urandom(min(tail, 4096)) + NUL * max(0, tail - 4096)


def elf(rnd, size):
    header = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0]) + NUL * 8
    header += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    return header + os.urandom(max(0, size - len(header)))


def jpeg(rnd, size):
    header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + b"JFIF"
    header += bytes([0, 1, 1, 0, 0, 1, 0, 1, 0, 0])
    return header + os.urandom(max(0, size - len(header) - 2)) + bytes([0xFF, 0xD9])


def png(rnd, size):
    ihdr = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    out = bytes([0x89]) + b"PNG\r\n" + bytes([0x1A, 0x0A])
    out += struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr
    out += struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF)
    payload = zlib.compress(NUL * (64 * 64 * 3 + 64))
    out += struct.pack(">I", len(payload)) + b"IDAT" + payload
    out += struct.pack(">I", zlib.crc32(b"IDAT" + payload) & 0xFFFFFFFF)
    out += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    return out + os.urandom(max(0, size - len(out)))


def textish(rnd, size):
    buffer = bytearray()
    while len(buffer) < size:
        buffer += rnd.choice(WORDS) + b" "
        if rnd.random() < 0.1:
            buffer += b"\n"
    return bytes(buffer[:size])


def build(out_dir, total, name):
    rnd = random.Random(0xB19A1C)
    parts, produced = [], 0
    plain = [
        (0.42, lambda size: os.urandom(size)),
        (0.20, lambda size: NUL * size),
        (0.20, lambda size: textish(rnd, size)),
        (0.18, lambda size: (os.urandom(256) * (size // 256 + 1))[:size]),
    ]

    while produced < total:
        roll = rnd.random()
        if roll < 0.06:
            blob = gzip_blob(rnd, os.urandom(rnd.randint(2048, 65536)))
        elif roll < 0.10:
            blob = squashfs(rnd, rnd.randint(65536, 262144))
        elif roll < 0.13:
            blob = elf(rnd, rnd.randint(16384, 131072))
        elif roll < 0.15:
            blob = jpeg(rnd, rnd.randint(8192, 65536))
        elif roll < 0.17:
            blob = png(rnd, rnd.randint(8192, 65536))
        else:
            scaled, running, chosen = (roll - 0.17) / 0.83, 0.0, plain[0][1]
            for weight, maker in plain:
                running += weight
                if scaled <= running:
                    chosen = maker
                    break
            blob = chosen(rnd.randint(32768, 524288))
        parts.append(blob)
        produced += len(blob)

    path = os.path.join(out_dir, name)
    with open(path, "wb") as handle:
        handle.write(b"".join(parts)[:total])
    print(path, total)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    build(out_dir, 16 * 1024 * 1024, "firmware_16m.bin")
    build(out_dir, 64 * 1024 * 1024, "firmware_64m.bin")
    build(out_dir, 256 * 1024 * 1024, "firmware_256m.bin")

    for name, size, filler in (
        ("random_64m.bin", 64 * 1024 * 1024, os.urandom),
        ("zeros_64m.bin", 64 * 1024 * 1024, lambda n: NUL * n),
    ):
        with open(os.path.join(out_dir, name), "wb") as handle:
            handle.write(filler(size))
        print(os.path.join(out_dir, name), size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
