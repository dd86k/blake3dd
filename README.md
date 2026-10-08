# blake3dd

BLAKE3 in pure D, no C dependencies.

- `std.digest` compatible (template and OOP APIs, HMAC).
- Streaming input.
- Hash, keyed hash, and key derivation modes.
- Extendable output (XOF), any multiple of 8 bits.
- Optional multithreading via `std.parallelism`.
- Validated against the official test vectors.

Scalar only, no SIMD yet.

## Usage

```d
import blake3dd;
import std.digest : toHexString, LetterCase;

ubyte[32] hash = blake3_256_Of("abc");
writeln(toHexString!(LetterCase.lower)(hash));
// 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
```

Streaming:

```d
BLAKE3_256 b3;
b3.put(part1);
b3.put(part2);
ubyte[32] hash = b3.finish(); // also resets the state
```

### Modes

```d
BLAKE3_256 b3;

b3.key(key32);                          // keyed hash, ubyte[32]
b3.deriveKey("myapp 2026-10-08 session keys v1"); // key derivation
```

`start()` and `finish()` keep the mode and key.

### Output size

```d
BLAKE3!(1024) b3;               // 128-byte output
ubyte[128] output = b3.finish();
```

`BLAKE3_256` and `BLAKE3_512` are provided as aliases. Shorter outputs are
prefixes of longer ones.

Splitting one key derivation into several keys:

```d
BLAKE3!(76 * 8) kdf;
kdf.deriveKey("myapp 2026-10-08 file encryption v1");
kdf.put(masterKey);
ubyte[76] material = kdf.finish();

ubyte[32] encKey = material[0 .. 32];
ubyte[32] macKey = material[32 .. 64];
ubyte[12] nonce  = material[64 .. 76];
```

Runtime length, read in pieces or from any offset with `output()`. It leaves
the state untouched, so more input can follow; `start()` resets it:

```d
BLAKE3_256 b3;
b3.put(data);

ubyte[] stream = new ubyte[length];
b3.output(stream);

ubyte[64] window;
b3.output(window, 1 << 20); // bytes 1 MiB .. 1 MiB + 64
```

### Threading

```d
BLAKE3_256 b3;
b3.threads = 0; // 0 = all taskPool workers + caller, default is 1
foreach (ubyte[] buffer; File(path, "rb").byChunk(16 << 20))
    b3.put(buffer);
ubyte[32] hash = b3.finish();
```

Threads only help when a single `put()` call receives a large buffer, at
least 16 KiB per thread. Small reads stay single-threaded. Memory-mapping
the file (`std.mmfile`) and passing it whole works well too.

The shared `taskPool` is used. To cap it program-wide, set
`std.parallelism.defaultPoolThreads` before its first use.

### OOP

```d
Digest d = new BLAKE3_256Digest();
d.put(data);
ubyte[] hash = d.finish();
```

Cast back to `BLAKE3_256Digest` to reach the struct's members:

```d
BLAKE3_256Digest b3 = cast(BLAKE3_256Digest)d;
b3.threads = 0;
b3.key(key32);
b3.output(buffer);
```

## Performance

512 MiB, LDC `-O3 -release -mcpu=native`, 32 cores (Ryzen 9 5950X):

| Threads | 1   | 2    | 4    | 8    | 16   | 32    |
|---------|-----|------|------|------|------|-------|
| MiB/s   | 739 | 1298 | 2312 | 4010 | 6603 | 10155 |

Prefer LDC. Single-threaded, GDC reaches ~640 MiB/s and DMD ~240 MiB/s.

To reproduce:

```sh
dub run :benchmark -b release-native --compiler=ldc2
dub run :benchmark -b release-native --compiler=ldc2 -- --size 1024 --threads 1,8,0
```

`--threads 0` uses all available cores. Digests are compared across thread counts,
so the benchmark doubles as a consistency check.

## License

Boost Software License 1.0.
