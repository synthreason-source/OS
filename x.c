/*
    ================================================================
                8-REGION SHA-256 ZERO-BIT PROOF OF WORK
                         COMPLETE C++17 PROGRAM
    ================================================================

    SHA-256 produces 256 bits.

    This program divides the digest into exactly 8 independent
    32-bit regions:

        Region 0 = bits   0 - 31
        Region 1 = bits  32 - 63
        Region 2 = bits  64 - 95
        Region 3 = bits  96 - 127
        Region 4 = bits 128 - 159
        Region 5 = bits 160 - 191
        Region 6 = bits 192 - 223
        Region 7 = bits 224 - 255

    Each region has its own leading-zero-bit requirement.

    Example:

        {1,1,1,1,1,1,1,1}

    requires at least one leading zero bit in every region.

    Example:

        {4,4,4,4,4,4,4,4}

    requires at least four leading zero bits in every region.

    The program:

        1. Builds a block header.
        2. Changes the nonce.
        3. Computes SHA-256.
        4. Splits the digest into 8 regions.
        5. Counts leading zero bits in every region.
        6. Checks all eight requirements.
        7. Stops when all eight pass.
        8. Prints the winning hash and zero profile.
        9. Links each block to the previous block hash.
       10. Reports hash rate and total work.

    This is an educational SHA-256 PoW system.
    It is NOT Bitcoin's exact PoW rule.

    ------------------------------------------------
    COMPILE
    ------------------------------------------------

    Linux / WSL:

        g++ -O3 -march=native -std=c++17 zero_pow.cpp -o zero_pow

    Windows MinGW:

        g++ -O3 -march=native -std=c++17 zero_pow.cpp -o zero_pow.exe

    Run:

        ./zero_pow

    or Windows:

        zero_pow.exe

    ================================================================
*/

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <limits>
#include <cmath>

// ================================================================
// CONFIGURATION
// ================================================================

constexpr std::size_t NUM_REGIONS = 8;
constexpr std::size_t REGION_BITS = 32;

/*
    ================================================================
    PER-REGION DIFFICULTY
    ================================================================

    QUICK TEST:

        1,1,1,1,1,1,1,1

    MEDIUM:

        2,2,2,2,2,2,2,2

    HARD:

        4,4,4,4,4,4,4,4

    VERY HARD:

        8,8,8,8,8,8,8,8

    You can also make every region different:

        1,2,3,4,5,6,7,8

    Each value must be <= 32.
*/

constexpr std::array<unsigned, NUM_REGIONS>
REQUIRED_ZERO_BITS = {
    1, 1, 1, 1,
    1, 1, 1, 1
};


// Number of blocks to mine.
constexpr std::uint32_t TOTAL_BLOCKS = 5;


// ------------------------------------------------
// DISPLAY OPTIONS
// ------------------------------------------------

// Print every attempted hash.
constexpr bool SHOW_ALL_HASHES = true;

// Maximum number of failed hashes printed.
// Does not affect mining.
// UINT64_MAX means unlimited.
constexpr std::uint64_t MAX_PRINTED_HASHES = 500;


// Print progress every N hashes.
constexpr bool SHOW_PROGRESS = true;

constexpr std::uint64_t PROGRESS_INTERVAL = 100000;


// ================================================================
// SHA-256 CONSTANTS
// ================================================================

static constexpr std::uint32_t K[64] = {

    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,

    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,

    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,

    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,

    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,

    0x983e5152,
    0xa831c66d,
    0xbf597fc7,

    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,

    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,

    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,

    0xa2bfe8a1,
    0xa81c66d,
    0xc24b8b70,
    0xc76c51a3,

    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,

    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,

    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,

    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,

    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
};


// ================================================================
// SHA-256 FUNCTIONS
// ================================================================

static inline std::uint32_t rotr(
    std::uint32_t x,
    unsigned n)
{
    return (x >> n) | (x << (32 - n));
}


static inline std::uint32_t Ch(
    std::uint32_t x,
    std::uint32_t y,
    std::uint32_t z)
{
    return (x & y) ^ (~x & z);
}


static inline std::uint32_t Maj(
    std::uint32_t x,
    std::uint32_t y,
    std::uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}


static inline std::uint32_t BigSigma0(
    std::uint32_t x)
{
    return rotr(x, 2) ^
           rotr(x, 13) ^
           rotr(x, 22);
}


static inline std::uint32_t BigSigma1(
    std::uint32_t x)
{
    return rotr(x, 6) ^
           rotr(x, 11) ^
           rotr(x, 25);
}


static inline std::uint32_t SmallSigma0(
    std::uint32_t x)
{
    return rotr(x, 7) ^
           rotr(x, 18) ^
           (x >> 3);
}


static inline std::uint32_t SmallSigma1(
    std::uint32_t x)
{
    return rotr(x, 17) ^
           rotr(x, 19) ^
           (x >> 10);
}


// ================================================================
// BIG-ENDIAN LOAD
// ================================================================

static inline std::uint32_t load_be32(
    const std::uint8_t* p)
{
    return
        (static_cast<std::uint32_t>(p[0]) << 24) |
        (static_cast<std::uint32_t>(p[1]) << 16) |
        (static_cast<std::uint32_t>(p[2]) << 8) |
        (static_cast<std::uint32_t>(p[3]));
}


// ================================================================
// BIG-ENDIAN STORE
// ================================================================

static inline void store_be32(
    std::uint8_t* p,
    std::uint32_t x)
{
    p[0] =
        static_cast<std::uint8_t>(x >> 24);

    p[1] =
        static_cast<std::uint8_t>(x >> 16);

    p[2] =
        static_cast<std::uint8_t>(x >> 8);

    p[3] =
        static_cast<std::uint8_t>(x);
}


// ================================================================
// SHA-256 FOR 44-BYTE BLOCK HEADER
// ================================================================
//
// Header:
//
//      4 bytes  block index
//     32 bytes  previous hash
//      8 bytes  nonce
//
// Total:
//
//     44 bytes
//
// SHA-256 padding makes this exactly one 64-byte block.
//
// No heap allocation occurs during mining.
// ================================================================

static inline void sha256_header(
    const std::uint8_t header[44],
    std::uint8_t digest[32])
{
    std::uint32_t w[64];

    // 44-byte message = 11 words.
    for (int i = 0; i < 11; ++i)
    {
        w[i] =
            load_be32(
                header + i * 4);
    }

    // SHA-256 padding.
    w[11] = 0x80000000U;

    // Remaining padding words.
    w[12] = 0;
    w[13] = 0;

    // High 32 bits of message length.
    w[14] = 0;

    // 44 bytes * 8 = 352 bits.
    w[15] = 352;

    // Message schedule.
    for (int i = 16; i < 64; ++i)
    {
        w[i] =
            SmallSigma1(w[i - 2]) +
            w[i - 7] +
            SmallSigma0(w[i - 15]) +
            w[i - 16];
    }

    // Initial SHA-256 state.
    std::uint32_t a = 0x6a09e667;
    std::uint32_t b = 0xbb67ae85;
    std::uint32_t c = 0x3c6ef372;
    std::uint32_t d = 0xa54ff53a;
    std::uint32_t e = 0x510e527f;
    std::uint32_t f = 0x9b05688c;
    std::uint32_t g = 0x1f83d9ab;
    std::uint32_t h = 0x5be0cd19;

    // Compression.
    for (int i = 0; i < 64; ++i)
    {
        const std::uint32_t t1 =
            h +
            BigSigma1(e) +
            Ch(e, f, g) +
            K[i] +
            w[i];

        const std::uint32_t t2 =
            BigSigma0(a) +
            Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add initial state.
    a += 0x6a09e667;
    b += 0xbb67ae85;
    c += 0x3c6ef372;
    d += 0xa54ff53a;
    e += 0x510e527f;
    f += 0x9b05688c;
    g += 0x1f83d9ab;
    h += 0x5be0cd19;

    // Produce digest.
    store_be32(digest + 0,  a);
    store_be32(digest + 4,  b);
    store_be32(digest + 8,  c);
    store_be32(digest + 12, d);
    store_be32(digest + 16, e);
    store_be32(digest + 20, f);
    store_be32(digest + 24, g);
    store_be32(digest + 28, h);
}


// ================================================================
// COUNT LEADING ZERO BITS
// ================================================================

static inline unsigned count_leading_zero_bits(
    std::uint32_t x)
{
    if (x == 0)
        return 32;

#if defined(__GNUC__) || defined(__clang__)

    return static_cast<unsigned>(
        __builtin_clz(x));

#elif defined(_MSC_VER)

    unsigned long index;

    #include <intrin.h>

    _BitScanReverse(
        &index,
        x);

    return 31U - index;

#else

    unsigned count = 0;

    for (int bit = 31; bit >= 0; --bit)
    {
        if (x & (1U << bit))
            break;

        ++count;
    }

    return count;

#endif
}


// ================================================================
// ZERO PROFILE
// ================================================================

struct ZeroProfile
{
    std::array<unsigned, NUM_REGIONS>
        zeros{};

    unsigned total = 0;

    bool success = false;
};


// ================================================================
// CHECK POW
// ================================================================
//
// Fast path:
//     profile == nullptr
//
// In that case we stop immediately at the first failing region.
//
// This is the hot mining path.
//
// ================================================================

static inline bool check_pow(
    const std::uint8_t digest[32],
    ZeroProfile* profile = nullptr)
{
    bool success = true;

    unsigned total = 0;

    for (std::size_t region = 0;
         region < NUM_REGIONS;
         ++region)
    {
        const std::uint32_t value =
            load_be32(
                digest + region * 4);

        const unsigned zeros =
            count_leading_zero_bits(value);

        if (profile)
        {
            profile->zeros[region] =
                zeros;
        }

        total += zeros;

        if (zeros <
            REQUIRED_ZERO_BITS[region])
        {
            success = false;

            // Fast rejection.
            if (!profile)
                return false;
        }
    }

    if (profile)
    {
        profile->total = total;
        profile->success = success;
    }

    return success;
}


// ================================================================
// HASH TO HEX
// ================================================================

static constexpr char HEX[] =
    "0123456789abcdef";


static void hash_to_hex(
    const std::uint8_t hash[32],
    char output[65])
{
    for (int i = 0; i < 32; ++i)
    {
        output[i * 2] =
            HEX[hash[i] >> 4];

        output[i * 2 + 1] =
            HEX[hash[i] & 0x0f];
    }

    output[64] = '\0';
}


// ================================================================
// MAKE HEADER
// ================================================================

static inline void make_header(
    std::uint32_t block_index,
    const std::array<std::uint8_t, 32>& previous_hash,
    std::uint64_t nonce,
    std::uint8_t header[44])
{
    // Block index.
    header[0] =
        static_cast<std::uint8_t>(
            block_index >> 24);

    header[1] =
        static_cast<std::uint8_t>(
            block_index >> 16);

    header[2] =
        static_cast<std::uint8_t>(
            block_index >> 8);

    header[3] =
        static_cast<std::uint8_t>(
            block_index);

    // Previous block hash.
    std::memcpy(
        header + 4,
        previous_hash.data(),
        32);

    // Nonce.
    for (int i = 0; i < 8; ++i)
    {
        header[36 + i] =
            static_cast<std::uint8_t>(
                nonce >> (56 - i * 8));
    }
}


// ================================================================
// BLOCK
// ================================================================

struct Block
{
    std::uint32_t index = 0;

    std::array<std::uint8_t, 32>
        previous_hash{};

    std::uint64_t nonce = 0;

    std::array<std::uint8_t, 32>
        hash{};

    ZeroProfile profile;
};


// ================================================================
// PRINT HASH ATTEMPT
// ================================================================

static void print_attempt(
    std::uint32_t block,
    std::uint64_t nonce,
    const std::uint8_t digest[32],
    const ZeroProfile& profile)
{
    char hash_string[65];

    hash_to_hex(
        digest,
        hash_string);

    std::cout
        << "\n------------------------------------------------------------\n";

    std::cout
        << "BLOCK : "
        << block
        << '\n';

    std::cout
        << "NONCE : "
        << nonce
        << '\n';

    std::cout
        << "HASH  : "
        << hash_string
        << '\n';

    std::cout
        << "\nREGIONS\n";

    for (std::size_t region = 0;
         region < NUM_REGIONS;
         ++region)
    {
        const std::size_t first_bit =
            region * REGION_BITS;

        const std::size_t last_bit =
            first_bit + REGION_BITS - 1;

        std::cout
            << "Region "
            << region
            << " ["
            << first_bit
            << "-"
            << last_bit
            << "]  "
            << std::setw(2)
            << profile.zeros[region]
            << " / "
            << std::setw(2)
            << REQUIRED_ZERO_BITS[region];

        if (profile.zeros[region] >=
            REQUIRED_ZERO_BITS[region])
        {
            std::cout
                << "  PASS";
        }
        else
        {
            std::cout
                << "  FAIL";
        }

        std::cout << '\n';
    }

    std::cout
        << "TOTAL ZERO BITS: "
        << profile.total
        << '\n';

    std::cout
        << "RESULT: "
        << (profile.success
            ? "POW SUCCESS"
            : "FAIL")
        << '\n';

    std::cout
        << "------------------------------------------------------------\n";
}


// ================================================================
// MINE ONE BLOCK
// ================================================================

static Block mine_block(
    std::uint32_t block_index,
    const std::array<std::uint8_t, 32>& previous_hash,
    std::uint64_t& total_hashes,
    std::uint64_t& printed_hashes)
{
    Block block;

    block.index =
        block_index;

    block.previous_hash =
        previous_hash;

    // ------------------------------------------------------------
    // Header is initialized once.
    // Only bytes 36..43 change during mining.
    // ------------------------------------------------------------

    std::uint8_t header[44];

    make_header(
        block_index,
        previous_hash,
        0,
        header);


    std::uint8_t digest[32];


    const auto start =
        std::chrono::steady_clock::now();


    std::uint64_t nonce = 0;


    while (true)
    {
        // --------------------------------------------------------
        // Update nonce only.
        // --------------------------------------------------------

        header[36] =
            static_cast<std::uint8_t>(
                nonce >> 56);

        header[37] =
            static_cast<std::uint8_t>(
                nonce >> 48);

        header[38] =
            static_cast<std::uint8_t>(
                nonce >> 40);

        header[39] =
            static_cast<std::uint8_t>(
                nonce >> 32);

        header[40] =
            static_cast<std::uint8_t>(
                nonce >> 24);

        header[41] =
            static_cast<std::uint8_t>(
                nonce >> 16);

        header[42] =
            static_cast<std::uint8_t>(
                nonce >> 8);

        header[43] =
            static_cast<std::uint8_t>(
                nonce);


        // --------------------------------------------------------
        // SHA-256
        // --------------------------------------------------------

        sha256_header(
            header,
            digest);

        ++total_hashes;


        // --------------------------------------------------------
        // FAST POW TEST
        // --------------------------------------------------------

        if (check_pow(
                digest,
                nullptr))
        {
            // Winning hash.
            ZeroProfile profile;

            check_pow(
                digest,
                &profile);

            block.nonce =
                nonce;

            std::memcpy(
                block.hash.data(),
                digest,
                32);

            block.profile =
                profile;

            return block;
        }


        // --------------------------------------------------------
        // OPTIONAL HASH DISPLAY
        // --------------------------------------------------------

        if (SHOW_ALL_HASHES &&
            printed_hashes <
                MAX_PRINTED_HASHES)
        {
            ZeroProfile profile;

            check_pow(
                digest,
                &profile);

            print_attempt(
                block_index,
                nonce,
                digest,
                profile);

            ++printed_hashes;
        }


        // --------------------------------------------------------
        // PROGRESS
        // --------------------------------------------------------

        if (SHOW_PROGRESS &&
            total_hashes > 0 &&
            total_hashes %
                PROGRESS_INTERVAL == 0)
        {
            const auto now =
                std::chrono::steady_clock::now();

            const double seconds =
                std::chrono::duration<double>(
                    now - start)
                    .count();

            const double rate =
                seconds > 0.0
                ? static_cast<double>(
                      total_hashes) /
                      seconds
                : 0.0;

            std::cout
                << "\rBlock "
                << block_index
                << " | hashes = "
                << total_hashes
                << " | nonce = "
                << nonce
                << " | "
                << std::fixed
                << std::setprecision(2)
                << rate
                << " H/s"
                << std::flush;
        }


        // --------------------------------------------------------
        // NEXT NONCE
        // --------------------------------------------------------

        ++nonce;


        // Detect uint64 overflow.
        if (nonce == 0)
        {
            std::cerr
                << "\nNonce space exhausted.\n";

            std::exit(EXIT_FAILURE);
        }
    }
}


// ================================================================
// DIFFICULTY DISPLAY
// ================================================================

static unsigned calculate_total_required()
{
    unsigned total = 0;

    for (std::size_t i = 0;
         i < NUM_REGIONS;
         ++i)
    {
        if (REQUIRED_ZERO_BITS[i] > 32)
        {
            std::cerr
                << "ERROR: Region "
                << i
                << " requires "
                << REQUIRED_ZERO_BITS[i]
                << " zero bits.\n";

            std::cerr
                << "Maximum is 32.\n";

            std::exit(EXIT_FAILURE);
        }

        total +=
            REQUIRED_ZERO_BITS[i];
    }

    return total;
}


static void print_configuration()
{
    const unsigned total_required =
        calculate_total_required();

    std::cout
        << "============================================================\n";

    std::cout
        << "       8-REGION SHA-256 ZERO-BIT PROOF OF WORK\n";

    std::cout
        << "============================================================\n\n";

    std::cout
        << "SHA-256 bits       : 256\n";

    std::cout
        << "Regions            : 8\n";

    std::cout
        << "Bits per region    : 32\n";

    std::cout
        << "Blocks             : "
        << TOTAL_BLOCKS
        << "\n\n";


    std::cout
        << "ZERO-BIT TARGETS\n";

    for (std::size_t i = 0;
         i < NUM_REGIONS;
         ++i)
    {
        std::cout
            << "  Region "
            << i
            << " : "
            << REQUIRED_ZERO_BITS[i]
            << '\n';
    }


    std::cout
        << "\nTotal constrained bits: "
        << total_required
        << '\n';


    // For independent random digest bits,
    // approximate success probability = 2^-total.
    if (total_required < 63)
    {
        const double expected =
            std::ldexp(
                1.0,
                static_cast<int>(
                    total_required));

        std::cout
            << "Approx. expected hashes/block: "
            << std::fixed
            << std::setprecision(0)
            << expected
            << '\n';
    }
    else
    {
        std::cout
            << "Approx. expected hashes/block: "
            << ">= 2^63\n";
    }


    std::cout
        << "\nHash printing       : "
        << (SHOW_ALL_HASHES
            ? "ON"
            : "OFF")
        << '\n';


    if (SHOW_ALL_HASHES)
    {
        std::cout
            << "Print limit         : ";

        if (MAX_PRINTED_HASHES ==
            std::numeric_limits<
                std::uint64_t>::max())
        {
            std::cout
                << "UNLIMITED\n";
        }
        else
        {
            std::cout
                << MAX_PRINTED_HASHES
                << '\n';
        }
    }


    std::cout
        << "\n============================================================\n";
}


// ================================================================
// RUN BLOCKCHAIN POW
// ================================================================

static void run_pow()
{
    print_configuration();


    // ------------------------------------------------------------
    // Genesis previous hash.
    // ------------------------------------------------------------

    std::array<std::uint8_t, 32>
        previous_hash{};


    std::array<Block, TOTAL_BLOCKS>
        chain{};


    std::uint64_t total_hashes = 0;

    std::uint64_t printed_hashes = 0;


    const auto global_start =
        std::chrono::steady_clock::now();


    // ============================================================
    // MINE BLOCKS
    // ============================================================

    for (std::uint32_t block_index = 0;
         block_index < TOTAL_BLOCKS;
         ++block_index)
    {
        std::cout
            << "\n\n############################################################\n";

        std::cout
            << "                    MINING BLOCK "
            << block_index
            << '\n';

        std::cout
            << "############################################################\n";


        Block block =
            mine_block(
                block_index,
                previous_hash,
                total_hashes,
                printed_hashes);


        chain[block_index] =
            block;


        previous_hash =
            block.hash;


        char winning_hash[65];

        hash_to_hex(
            block.hash.data(),
            winning_hash);


        // --------------------------------------------------------
        // WINNER
        // --------------------------------------------------------

        std::cout
            << "\n\n*** BLOCK SOLVED ***\n";

        std::cout
            << "Block : "
            << block.index
            << '\n';

        std::cout
            << "Nonce : "
            << block.nonce
            << '\n';

        std::cout
            << "Hash  : "
            << winning_hash
            << '\n';


        std::cout
            << "\nZero profile:\n";


        for (std::size_t region = 0;
             region < NUM_REGIONS;
             ++region)
        {
            std::cout
                << "  Region "
                << region
                << " = "
                << block.profile.zeros[region]
                << " / "
                << REQUIRED_ZERO_BITS[region]
                << " zero bits\n";
        }


        std::cout
            << "Total leading-zero bits = "
            << block.profile.total
            << '\n';
    }


    // ============================================================
    // VERIFY CHAIN
    // ============================================================

    bool chain_valid = true;


    for (std::size_t i = 1;
         i < TOTAL_BLOCKS;
         ++i)
    {
        if (chain[i].previous_hash !=
            chain[i - 1].hash)
        {
            chain_valid = false;
            break;
        }
    }


    // ============================================================
    // PERFORMANCE
    // ============================================================

    const auto global_end =
        std::chrono::steady_clock::now();


    const double elapsed =
        std::chrono::duration<double>(
            global_end - global_start)
            .count();


    const double hash_rate =
        elapsed > 0.0
        ? static_cast<double>(
              total_hashes) /
              elapsed
        : 0.0;


    // ============================================================
    // FINAL SUMMARY
    // ============================================================

    std::cout
        << "\n\n============================================================\n";

    std::cout
        << "                       FINAL SUMMARY\n";

    std::cout
        << "============================================================\n";


    std::cout
        << "Blocks mined        : "
        << TOTAL_BLOCKS
        << '\n';


    std::cout
        << "Total SHA-256 hashes: "
        << total_hashes
        << '\n';


    std::cout
        << "Elapsed time        : "
        << std::fixed
        << std::setprecision(4)
        << elapsed
        << " seconds\n";


    std::cout
        << "Hash rate           : "
        << std::fixed
        << std::setprecision(2)
        << hash_rate
        << " H/s\n";


    if (TOTAL_BLOCKS > 0)
    {
        std::cout
            << "Average hashes/block: "
            << std::fixed
            << std::setprecision(2)
            << static_cast<double>(
                   total_hashes) /
                   static_cast<double>(
                       TOTAL_BLOCKS)
            << '\n';
    }


    std::cout
        << "Chain linkage       : "
        << (chain_valid
            ? "VALID"
            : "INVALID")
        << '\n';


    std::cout
        << "\n============================================================\n";


    // ------------------------------------------------------------
    // Print final chain.
    // ------------------------------------------------------------

    std::cout
        << "\nFINAL CHAIN\n";


    for (std::size_t i = 0;
         i < TOTAL_BLOCKS;
         ++i)
    {
        char hash_hex[65];

        hash_to_hex(
            chain[i].hash.data(),
            hash_hex);


        std::cout
            << "\nBlock "
            << chain[i].index
            << '\n';

        std::cout
            << "Nonce: "
            << chain[i].nonce
            << '\n';

        std::cout
            << "Hash : "
            << hash_hex
            << '\n';

        std::cout
            << "Zeros: ";


        for (std::size_t r = 0;
             r < NUM_REGIONS;
             ++r)
        {
            std::cout
                << chain[i]
                       .profile
                       .zeros[r];

            if (r + 1 <
                NUM_REGIONS)
            {
                std::cout
                    << ',';
            }
        }

        std::cout
            << '\n';
    }
}


// ================================================================
// MAIN
// ================================================================

int main()
{
    run_pow();

    return 0;
}