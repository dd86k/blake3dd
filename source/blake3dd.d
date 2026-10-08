/// Computes BLAKE3 hashes of arbitrary data.
/// Reference: $(LINK2 https://github.com/BLAKE3-team/BLAKE3, BLAKE3)
/// License: $(LINK2 https://www.boost.org/LICENSE_1_0.txt, Boost License 1.0)
/// Authors: $(LINK2 https://github.com/dd86k, dd86k)
module blake3dd;

private import std.digest;
private import core.bitop : ror;

/// blake3dd library version string.
public enum BLAKE3DD_VERSION_STRING = "0.1.0";

/// BLAKE3 hasher, conforming to the Digest API.
///
/// The final chunk is always kept buffered until finish() since it may be
/// the root node; only chunks followed by more input are compressed early.
/// Params: digestSize = Output size in bits (extendable-output, XOF).
struct BLAKE3(uint digestSize)
{
    @safe:

    static assert(digestSize > 0, "Digest size cannot be zero");
    static assert(digestSize % 8 == 0, "Digest size must be a multiple of 8");

    /// Block size in bits, used by HMAC.
    enum blockSize = BlockLength * 8;

    /// Number of threads used to hash whole chunks. 0 uses all workers of
    /// std.parallelism's taskPool plus the calling thread. Threads only help
    /// when put() receives large buffers (at least 16 KiB per thread).
    uint threads = 1;

    /// Reset the state of the instance, keeping the key, mode, and threads.
    void start()
    {
        cv = keyWords;
        chunkCounter = 0;
        blockLength = 0;
        blocksCompressed = 0;
        stackSize = 0;
    }

    /// Switch to keyed hash mode and reset the state.
    void key(scope const(ubyte)[32] input)
    {
        keyWords = bytesToWords(input)[0 .. 8];
        flags = Flag.keyedHash;
        start();
    }

    /// Switch to key derivation mode and reset the state. The context should
    /// be hardcoded, globally unique, and application-specific.
    void deriveKey(scope const(char)[] context)
    {
        BLAKE3!256 ctx;
        ctx.flags = Flag.deriveKeyContext;
        ctx.put(cast(const(ubyte)[])context);
        ubyte[32] contextKey = ctx.finish();
        keyWords = bytesToWords(contextKey)[0 .. 8];
        flags = Flag.deriveKeyMaterial;
        start();
    }

    /// Feed the algorithm with data.
    /// Also implements the $(REF isOutputRange, std,range,primitives)
    /// interface for `ubyte` and `const(ubyte)[]`.
    /// Params: input = Input data to digest
    void put(scope const(ubyte)[] input...)
    {
        while (input.length)
        {
            if (chunkLength == ChunkLength)
            {
                uint[16] m = bytesToWords(block);
                uint[8] chunkCV = compress(cv, m, BlockLength, chunkCounter,
                    flags | Flag.chunkEnd)[0 .. 8];
                pushCV(chunkCV);
                cv = keyWords;
                blockLength = 0;
                blocksCompressed = 0;
            }

            // Bypass the block buffer for whole chunks, keeping the last
            // one buffered since it could be the root.
            if (chunkLength == 0 && input.length > ChunkLength)
            {
                size_t count = (input.length - 1) / ChunkLength; // @suppress(dscanner.suspicious.length_subtraction)
                if (count > MaxBatch)
                    count = MaxBatch;

                hashBatch(input[0 .. count * ChunkLength]);
                input = input[count * ChunkLength .. $];
                continue;
            }

            size_t chunkWant = ChunkLength - chunkLength;
            size_t take = input.length < chunkWant ? input.length : chunkWant;
            updateChunk(input[0 .. take]);
            input = input[take .. $];
        }
    }

    /// Returns the digest and resets the state.
    ubyte[digestSize / 8] finish()
    {
        ubyte[digestSize / 8] digest = void;
        output(digest);
        start();
        return digest;
    }

    /// Writes extended output of any length, starting at a byte offset,
    /// without modifying the state. Can be called repeatedly to read the
    /// output stream in pieces.
    void output(scope ubyte[] buffer, ulong offset = 0) const
    {
        uint[8] inputCV = cv;
        uint[16] m = bytesToWords(block[0 .. blockLength]);
        uint length = blockLength;
        ulong counter = chunkCounter;
        uint f = flags | Flag.chunkEnd | (blocksCompressed == 0 ? Flag.chunkStart : 0);

        foreach_reverse (ref const(uint[8]) left; stack[0 .. stackSize])
        {
            uint[8] right = compress(inputCV, m, length, counter, f)[0 .. 8];
            m[0 .. 8] = left;
            m[8 .. 16] = right;
            inputCV = keyWords;
            length = BlockLength;
            counter = 0;
            f = flags | Flag.parent;
        }

        // Each root block yields 64 bytes of output, indexed by the counter.
        counter = offset / BlockLength;
        size_t skip = offset % BlockLength;
        while (buffer.length)
        {
            uint[16] words = compress(inputCV, m, length, counter++, f | Flag.root);
            size_t available = BlockLength - skip;
            size_t n = buffer.length < available ? buffer.length : available;
            foreach (i; 0 .. n)
                buffer[i] = cast(ubyte)(words[(skip + i) / 4] >> (8 * ((skip + i) % 4)));
            buffer = buffer[n .. $];
            skip = 0;
        }
    }

private:

    /// Enough for 2^64 bytes of input.
    enum MaxDepth = 54;
    /// Chunks hashed per put() iteration when bypassing the buffer.
    enum MaxBatch = 16 * 1024;
    /// Bounds the subtrees per batch; must exceed 64 + 2 * log2(MaxBatch).
    enum MaxPieces = 128;
    /// Avoids waking threads for less work than a dispatch costs.
    enum MinChunksPerThread = 16;

    uint[8] keyWords = IV;
    uint flags;

    /// Current chunk
    uint[8] cv = IV;
    ulong chunkCounter;
    ubyte[BlockLength] block;
    uint blockLength;
    uint blocksCompressed;

    /// Chaining values of completed subtrees
    uint[8][MaxDepth] stack;
    uint stackSize;

    size_t chunkLength() const
    {
        return blocksCompressed * BlockLength + blockLength;
    }

    void updateChunk(scope const(ubyte)[] input)
    {
        while (input.length)
        {
            if (blockLength == BlockLength)
            {
                uint[16] m = bytesToWords(block);
                cv = compress(cv, m, BlockLength, chunkCounter,
                    flags | (blocksCompressed == 0 ? Flag.chunkStart : 0))[0 .. 8];
                blocksCompressed++;
                blockLength = 0;
            }

            size_t blockWant = BlockLength - blockLength;
            size_t take = input.length < blockWant ? input.length : blockWant;
            block[blockLength .. blockLength + take] = input[0 .. take];
            blockLength += take;
            input = input[take .. $];
        }
    }

    /// Adds a subtree of 2^level chunks and merges every subtree it completes,
    /// which is the number of trailing zero bits in the chunk count above
    /// level. The chunk counter must be a multiple of the subtree size.
    void pushCV(uint[8] newCV, uint level = 0)
    {
        chunkCounter += 1UL << level;
        for (ulong total = chunkCounter >> level; (total & 1) == 0; total >>= 1)
        {
            uint[16] m = void;
            m[0 .. 8] = stack[--stackSize];
            m[8 .. 16] = newCV;
            newCV = compress(keyWords, m, BlockLength, 0, flags | Flag.parent)[0 .. 8];
        }
        stack[stackSize++] = newCV;
    }

    /// The parent merges too and only the subtree roots are pushed serially.
    void hashBatch(scope const(ubyte)[] input) nothrow
    {
        size_t count = input.length / ChunkLength;

        size_t parts = threads;
        if (parts != 1)
        {
            if (parts == 0)
            {
                try
                    parts = poolSize();
                catch (Exception)
                    parts = 1;
            }
            size_t maxParts = count / MinChunksPerThread;
            if (parts > maxParts)
                parts = maxParts;
        }
        if (parts == 0)
            parts = 1;

        uint maxLevel;
        while ((2UL << maxLevel) <= count / parts)
            maxLevel++;
        while ((count >> maxLevel) > 64)
            maxLevel++;

        Piece[MaxPieces] pieces = void;
        size_t n;
        for (size_t offset; offset < count; n++)
        {
            uint level = maxLevel;
            while ((1UL << level) > count - offset ||
                ((chunkCounter + offset) & ((1UL << level) - 1)) != 0)
                level--;
            pieces[n].offset = offset;
            pieces[n].level = level;
            offset += 1UL << level;
        }

        bool done;
        if (parts > 1)
        {
            // Thread creation failures should not lose the hash.
            try
            {
                hashPiecesParallel(input, pieces[0 .. n], keyWords, chunkCounter, flags);
                done = true;
            }
            catch (Exception) {}
        }
        if (done == false)
        {
            foreach (ref Piece piece; pieces[0 .. n])
                hashPiece(input, piece, keyWords, chunkCounter, flags);
        }

        foreach (ref const(Piece) piece; pieces[0 .. n])
            pushCV(piece.cv, piece.level);
    }

}

/// Alias for BLAKE3-256.
alias BLAKE3_256 = BLAKE3!(256);
/// Alias for BLAKE3-512, an extended output of BLAKE3-256.
alias BLAKE3_512 = BLAKE3!(512);

/// Convenience alias using the BLAKE3 implementation.
auto blake3_256_Of(T...)(T data)
{
    return digest!(BLAKE3_256, T)(data);
}

/// OOP BLAKE3 digest. Exposes the struct's threads, modes, and output()
/// through alias this, reachable by casting a `Digest` back to this class.
class BLAKE3Digest(uint digestSize) : WrapperDigest!(BLAKE3!digestSize)
{
    ref inout(BLAKE3!digestSize) state() inout return @safe pure nothrow @nogc
    {
        return _digest;
    }
    alias state this;
}

/// Alias for an OOP BLAKE3-256 digest.
alias BLAKE3_256Digest = BLAKE3Digest!256;

private: @safe:

enum BlockLength = 64;
enum ChunkLength = 1024;

enum Flag : uint
{
    chunkStart          = 1,
    chunkEnd            = 2,
    parent              = 4,
    root                = 8,
    keyedHash           = 16,
    deriveKeyContext    = 32,
    deriveKeyMaterial   = 64,
}

immutable uint[8] IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

/// Message word order for each round, replacing the per-round permutation.
enum ubyte[16][7] schedule = [
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
    [ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 ],
    [ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 ],
    [ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 ],
    [ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 ],
    [ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 ],
    [ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 ],
];

struct Piece
{
    size_t offset; // in chunks
    uint level;
    uint[8] cv;
}

/// Hashes whole chunks as aligned power-of-two subtrees, so workers do

size_t poolSize() @trusted
{
    import std.parallelism : taskPool;
    return taskPool.size + 1;
}

void hashPiecesParallel(scope const(ubyte)[] input, scope Piece[] pieces,
    const ref uint[8] key, ulong counter, uint flags) @trusted
{
    import std.parallelism : taskPool;

    uint[8] k = key;
    foreach (ref Piece piece; taskPool.parallel(pieces, 1))
        hashPiece(input, piece, k, counter, flags);
}

void hashPiece(scope const(ubyte)[] input, ref Piece piece,
    const ref uint[8] key, ulong counter, uint flags)
    pure nothrow @nogc
{
    size_t start = piece.offset * ChunkLength;
    size_t end = start + (ChunkLength << piece.level);
    piece.cv = subtreeCV(input[start .. end], key, counter + piece.offset, flags);
}

uint[8] subtreeCV(scope const(ubyte)[] input,
    const ref uint[8] key, ulong counter, uint flags)
    pure nothrow @nogc
{
    if (input.length == ChunkLength)
        return chunkCV(input, key, counter, flags);

    size_t half = input.length / 2;
    uint[16] m = void;
    m[0 .. 8] = subtreeCV(input[0 .. half], key, counter, flags);
    m[8 .. 16] = subtreeCV(input[half .. $], key, counter + half / ChunkLength, flags);
    return compress(key, m, BlockLength, 0, flags | Flag.parent)[0 .. 8];
}

uint[8] chunkCV(scope const(ubyte)[] chunk,
    const ref uint[8] key, ulong counter, uint flags)
    pure nothrow @nogc
{
    uint[8] chainingValue = key;
    foreach (b; 0 .. ChunkLength / BlockLength)
    {
        uint f = flags;
        if (b == 0)
            f |= Flag.chunkStart;
        if (b == ChunkLength / BlockLength - 1)
            f |= Flag.chunkEnd;
        uint[16] m = bytesToWords(chunk[b * BlockLength .. (b + 1) * BlockLength]);
        chainingValue = compress(chainingValue, m, BlockLength, counter, f)[0 .. 8];
    }
    return chainingValue;
}

void g(ref uint a, ref uint b, ref uint c, ref uint d, uint m1, uint m2)
    pure nothrow @nogc
{
    a = a + b + m1; d = ror(d ^ a, 16);
    c = c + d;      b = ror(b ^ c, 12);
    a = a + b + m2; d = ror(d ^ a, 8);
    c = c + d;      b = ror(b ^ c, 7);
}

uint[16] compress(const ref uint[8] chainingValue, const ref uint[16] m,
    uint length, ulong counter, uint f)
    pure nothrow @nogc
{
    uint[16] s = void;
    s[0 .. 8] = chainingValue;
    s[8 .. 12] = IV[0 .. 4];
    s[12] = cast(uint)counter;
    s[13] = cast(uint)(counter >> 32);
    s[14] = length;
    s[15] = f;

    static foreach (r; 0 .. 7)
    {
        g(s[0], s[4], s[8],  s[12], m[schedule[r][0]],  m[schedule[r][1]]);
        g(s[1], s[5], s[9],  s[13], m[schedule[r][2]],  m[schedule[r][3]]);
        g(s[2], s[6], s[10], s[14], m[schedule[r][4]],  m[schedule[r][5]]);
        g(s[3], s[7], s[11], s[15], m[schedule[r][6]],  m[schedule[r][7]]);
        g(s[0], s[5], s[10], s[15], m[schedule[r][8]],  m[schedule[r][9]]);
        g(s[1], s[6], s[11], s[12], m[schedule[r][10]], m[schedule[r][11]]);
        g(s[2], s[7], s[8],  s[13], m[schedule[r][12]], m[schedule[r][13]]);
        g(s[3], s[4], s[9],  s[14], m[schedule[r][14]], m[schedule[r][15]]);
    }

    foreach (i; 0 .. 8)
    {
        s[i] ^= s[i + 8];
        s[i + 8] ^= chainingValue[i];
    }
    return s;
}

/// Input is zero-padded to a full block.
uint[16] bytesToWords(scope const(ubyte)[] input)
    pure nothrow @nogc
{
    uint[16] words;
    foreach (i, ubyte b; input)
        words[i / 4] |= cast(uint)b << (8 * (i % 4));
    return words;
}

/// This module conforms to the Digest API.
unittest
{
    static assert(isDigest!BLAKE3_256);
    static assert(hasBlockSize!BLAKE3_256);
    static assert(BLAKE3_256.blockSize == 512);
}

/// Hashing a large buffer on all cores.
unittest
{
    BLAKE3_256 b3;
    b3.threads = 0;
    b3.put(new ubyte[4 << 20]);
    ubyte[32] hash = b3.finish();
}

unittest
{
    assert(toHexString!(LetterCase.lower)(blake3_256_Of("")) ==
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "blake3-256('') failed");
    assert(toHexString!(LetterCase.lower)(blake3_256_Of("abc")) ==
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        "blake3-256('abc') failed");
    assert(toHexString!(LetterCase.lower)(blake3_256_Of("abcdef")) ==
        "b34b56076712fd7fb9c067245a6c85e16174b3ef2e35df7b56b7f164e5c36446",
        "blake3-256('abcdef') failed");
    assert(toHexString!(LetterCase.lower)(blake3_256_Of("The quick brown fox jumps over the lazy dog.")) ==
        "4c9bd68d7f0baa2e167cef98295eb1ec99a3ec8f0656b33dbae943b387f31d5d",
        "blake3-256('The quick brown fox jumps over the lazy dog.') failed");
}

// Test one million 'a'
unittest
{
    char[] onemila = new char[1_000_000];
    onemila[] = 'a';
    BLAKE3_256 b3;
    b3.put(cast(ubyte[])onemila);
    assert(toHexString!(LetterCase.lower)(b3.finish()) ==
        "616f575a1b58d4c9797d4217b9730ae5e6eb319d76edef6549b46f4efe31ff8b",
        "One million 'a' failed");
}

// Test past chunk size and streamability
unittest
{
    char[] twomila = new char[2_000_000];
    twomila[] = 'a';
    BLAKE3_256 b3;
    b3.put(cast(ubyte[])twomila);
    assert(toHexString!(LetterCase.lower)(b3.finish()) ==
        "d6e5100fe1829150ea9aaf9adc79b3cb3b1d6f243457d1576f0783e6e8611ea3",
        "Two million 'a' failed");

    ubyte[] part1 = cast(ubyte[])twomila[0..1_000_000];
    ubyte[] part2 = cast(ubyte[])twomila[1_000_000..$];
    b3.put(part1); b3.put(part2);
    assert(toHexString!(LetterCase.lower)(b3.finish()) ==
        "d6e5100fe1829150ea9aaf9adc79b3cb3b1d6f243457d1576f0783e6e8611ea3",
        "Two million 'a' failed");
}

version (unittest)
{
    /// Repeating 0..250 sequence used by the official test vectors.
    ubyte[] testInput(size_t length)
    {
        ubyte[] ret = new ubyte[length];
        foreach (i, ref x; ret)
            x = cast(ubyte)(i % 251);
        return ret;
    }

    immutable ubyte[32] testKey = cast(immutable(ubyte)[32])"whats the Elvish word for friend";
    enum testContext = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    struct Vector
    {
        size_t length;
        string hash, keyed, derived;
    }

    // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    // Truncated to 32 bytes.
    static immutable Vector[] vectors = [
        Vector(0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        Vector(1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
            "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        Vector(2,
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
            "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
            "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
        Vector(3,
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
            "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
            "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"),
        Vector(4,
            "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
            "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070",
            "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060"),
        Vector(5,
            "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2",
            "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461",
            "1f24eda69dbcb752847ec3ebb5dd42836d86e58500c7c98d906ecd82ed9ae47f"),
        Vector(6,
            "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844",
            "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6d",
            "be96b30b37919fe4379dfbe752ae77b4f7e2ab92f7ff27435f76f2f065f6a5f4"),
        Vector(7,
            "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe",
            "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a",
            "dc3b6485f9d94935329442916b0d059685ba815a1fa2a14107217453a7fc9f0e"),
        Vector(8,
            "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
            "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600",
            "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940"),
        Vector(63,
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
            "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
            "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
        Vector(64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
            "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
            "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        Vector(65,
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
            "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
            "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        Vector(127,
            "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
            "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818",
            "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3"),
        Vector(128,
            "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
            "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec",
            "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225"),
        Vector(129,
            "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
            "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f",
            "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1"),
        Vector(1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
            "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
            "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        Vector(1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
            "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
        Vector(1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
            "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
        Vector(2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
            "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
        Vector(2049,
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
            "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
            "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
        Vector(3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
            "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770",
            "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"),
        Vector(3073,
            "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
            "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a",
            "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081"),
        Vector(4096,
            "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
            "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0",
            "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9"),
        Vector(4097,
            "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
            "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc",
            "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8"),
        Vector(5120,
            "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833",
            "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20",
            "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f60"),
        Vector(5121,
            "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff",
            "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024",
            "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c34"),
        Vector(6144,
            "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205",
            "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1d",
            "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a15"),
        Vector(6145,
            "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f",
            "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539",
            "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5"),
        Vector(7168,
            "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a",
            "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fc",
            "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae2237"),
        Vector(7169,
            "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817",
            "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa511",
            "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d9"),
        Vector(8192,
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
            "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
            "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"),
        Vector(8193,
            "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
            "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5",
            "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1"),
        Vector(16384,
            "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
            "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d",
            "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1"),
        Vector(31744,
            "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
            "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
            "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"),
        Vector(102400,
            "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
            "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
            "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"),
    ];

    // Full 131-byte hash mode outputs.
    static immutable Vector[] xof = [
        Vector(0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
            ~ "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
            ~ "26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda"
            ~ "7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421"
            ~ "cce14d"),
        Vector(1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
            ~ "f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bf"
            ~ "e332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e562"
            ~ "7be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff1280"
            ~ "0ab67a"),
        Vector(102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"
            ~ "e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6"
            ~ "745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4a"
            ~ "b1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204"
            ~ "f45f8e"),
    ];
}

// Official test vectors, all modes
unittest
{
    foreach (ref immutable(Vector) v; vectors)
    {
        ubyte[] input = testInput(v.length);

        BLAKE3_256 b3;
        b3.put(input);
        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.hash);

        b3.key(testKey);
        b3.put(input);
        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.keyed);
        b3.put(input);
        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.keyed,
            "finish() must keep the key");

        b3.deriveKey(testContext);
        b3.put(input);
        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.derived);
    }
}

// Extended output
unittest
{
    foreach (ref immutable(Vector) v; xof)
    {
        BLAKE3!(131 * 8) b3;
        b3.put(testInput(v.length));
        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.hash);
    }

    BLAKE3_512 b512;
    assert(toHexString!(LetterCase.lower)(b512.finish()) == xof[0].hash[0 .. 128]);
}

// Runtime-length output, in pieces and at offsets
unittest
{
    foreach (ref immutable(Vector) v; xof)
    {
        BLAKE3_256 b3;
        b3.put(testInput(v.length));

        ubyte[131] full;
        b3.output(full);
        assert(toHexString!(LetterCase.lower)(full) == v.hash);

        foreach (size_t split; [ 0, 1, 63, 64, 65, 100, 131 ])
        {
            ubyte[131] pieces;
            b3.output(pieces[0 .. split]);
            b3.output(pieces[split .. $], split);
            assert(pieces == full);
        }

        assert(toHexString!(LetterCase.lower)(b3.finish()) == v.hash[0 .. 64],
            "output() must not modify the state");
    }
}

// OOP digest exposes the struct through a cast
unittest
{
    Digest d = new BLAKE3_256Digest();
    BLAKE3_256Digest b3 = cast(BLAKE3_256Digest)d;
    b3.threads = 0;
    b3.key(testKey);
    d.put(testInput(102_400));

    ubyte[131] extended;
    b3.output(extended);
    assert(toHexString!(LetterCase.lower)(d.finish()) == vectors[$-1].keyed);
    assert(toHexString!(LetterCase.lower)(extended[0 .. 32]) == vectors[$-1].keyed);
}

// Threaded and streamed inputs must match the single-threaded result
unittest
{
    ubyte[] input = testInput((MaxBatchTest + 1037) * 1024 + 123);

    BLAKE3_256 b3;
    b3.put(input);
    ubyte[32] expected = b3.finish();

    foreach (uint threads; [ 0, 2, 3, 4, 7 ])
    {
        b3.threads = threads;
        b3.put(input);
        assert(b3.finish() == expected);

        foreach (size_t step; [ 63, 64, 1000, 1024, 1025, 50_000 ])
        {
            for (size_t i; i < input.length; i += step)
                b3.put(input[i .. i + step < input.length ? i + step : $]);
            assert(b3.finish() == expected);
        }
    }

    // Covers the batch path across a parallel boundary
    BLAKE3_256 b3t;
    b3t.threads = 0;
    b3t.put(testInput(102_400));
    assert(toHexString!(LetterCase.lower)(b3t.finish()) == vectors[$-1].hash);
}

version (unittest) private enum MaxBatchTest = BLAKE3_256.MaxBatch;
