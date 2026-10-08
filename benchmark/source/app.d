/// Measures blake3dd throughput across thread counts.
module app;

import blake3dd;
import core.cpuid : processor;
import std.datetime.stopwatch : StopWatch, AutoStart;
import std.digest : toHexString, LetterCase;
import std.format : format;
import std.getopt;
import std.parallelism : totalCPUs;
import std.stdio;
import std.string : strip;

int main(string[] args)
{
    uint sizeMiB = 512;
    uint runs = 3;
    uint[] threadCounts;

    arraySep = ",";
    GetoptResult res = getopt(args,
        "size|s", "Input size in MiB (default: 512)", &sizeMiB,
        "runs|r", "Runs per thread count, best is kept (default: 3)", &runs,
        "threads|t", "Thread counts, comma-separated (default: 1,2,4,.. cores)", &threadCounts);
    if (res.helpWanted)
    {
        defaultGetoptPrinter("Usage: benchmark [options]", res.options);
        return 0;
    }

    if (threadCounts.length == 0)
    {
        for (uint t = 1; t < totalCPUs; t *= 2)
            threadCounts ~= t;
        threadCounts ~= 0;
    }

    // Non-zero so pages are actually committed before timing.
    ubyte[] data = new ubyte[cast(size_t)sizeMiB << 20];
    foreach (i, ref ubyte b; data)
        b = cast(ubyte)(i % 251);

    writefln("CPU      : %s (%d logical cores)", strip(processor()), totalCPUs);
    writefln("Compiler : %s (frontend %d.%03d)", __VENDOR__, __VERSION__ / 1000, __VERSION__ % 1000);
    writefln("Input    : %d MiB, best of %d runs", sizeMiB, runs);
    writeln();
    writeln("| Threads |     MiB/s | Digest");
    writeln("|---------|-----------|-----------------");

    ubyte[32] reference;
    foreach (size_t n, uint threads; threadCounts)
    {
        double best = double.infinity;
        ubyte[32] hash;
        foreach (r; 0 .. runs)
        {
            BLAKE3_256 b3;
            b3.threads = threads;
            StopWatch sw = StopWatch(AutoStart.yes);
            b3.put(data);
            hash = b3.finish();
            double seconds = sw.peek.total!"hnsecs" / 1e7;
            if (seconds < best)
                best = seconds;
        }

        if (n == 0)
            reference = hash;
        else if (hash != reference)
        {
            stderr.writefln("error: digest mismatch at %d threads", threads);
            return 1;
        }

        writefln("| %7s | %9.1f | %s", threads == 0 ? "all" : format("%d", threads),
            sizeMiB / best, toHexString!(LetterCase.lower)(hash)[0 .. 16]);
    }
    return 0;
}
