// factor_cuda.cu
//
// GPU-assisted prime factorisation using CUDA.
//
// Compile examples:
//
//   nvcc -O3 -std=c++17 -arch=sm_75 factor_cuda.cu -o factor_cuda
//   nvcc -O3 -std=c++17 -arch=sm_86 factor_cuda.cu -o factor_cuda
//   nvcc -O3 -std=c++17 -arch=sm_89 factor_cuda.cu -o factor_cuda
//
// Run:
//
//   ./factor_cuda 360
//   ./factor_cuda 8051
//   ./factor_cuda 10000300057
//   ./factor_cuda benchmark
//
// Notes:
//
//   - uint64_t inputs are supported.
//   - Miller-Rabin is deterministic for unsigned 64-bit integers.
//   - Complete factorisation is verified exactly.
//   - The GPU searches many Pollard-Rho trajectories in parallel.
//   - The CPU recursively processes factors returned by the GPU.
//

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>


// ============================================================
// CUDA ERROR HANDLING
// ============================================================

#define CUDA_CHECK(call)                                      \
    do {                                                      \
        cudaError_t error__ = (call);                        \
        if (error__ != cudaSuccess) {                         \
            std::ostringstream message__;                     \
            message__                                           \
                << "CUDA error at " << __FILE__                \
                << ":" << __LINE__ << ": "                    \
                << cudaGetErrorString(error__);               \
            throw std::runtime_error(message__.str());        \
        }                                                     \
    } while (false)


// ============================================================
// CONSTANTS
// ============================================================

constexpr int DEFAULT_BLOCKS = 256;
constexpr int DEFAULT_THREADS = 256;
constexpr int DEFAULT_ROUNDS = 4096;
constexpr int DEFAULT_RESTARTS = 32;

constexpr uint64_t SMALL_PRIMES[] = {
    2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL,
    19ULL, 23ULL, 29ULL, 31ULL, 37ULL, 41ULL, 43ULL, 47ULL
};

constexpr uint64_t MILLER_RABIN_BASES[] = {
    2ULL,
    325ULL,
    9375ULL,
    28178ULL,
    450775ULL,
    9780504ULL,
    1795265022ULL
};


// ============================================================
// HOST AND DEVICE ARITHMETIC
// ============================================================

__host__ __device__
uint64_t add_mod_u64(
    uint64_t a,
    uint64_t b,
    uint64_t modulus
) {
    // Assumes a < modulus and b < modulus.
    if (a >= modulus - b) {
        return a - (modulus - b);
    }

    return a + b;
}


__host__ __device__
uint64_t mul_mod_u64(
    uint64_t a,
    uint64_t b,
    uint64_t modulus
) {
#if defined(__CUDA_ARCH__)
    // CUDA's 128-bit integer support is not consistently available
    // across all device compilation targets, so use repeated doubling.
    uint64_t result = 0;
    a %= modulus;

    while (b > 0) {
        if (b & 1ULL) {
            result = add_mod_u64(
                result,
                a,
                modulus
            );
        }

        b >>= 1;

        if (b > 0) {
            a = add_mod_u64(
                a,
                a,
                modulus
            );
        }
    }

    return result;
#else
    #if defined(__SIZEOF_INT128__)
        using uint128_t = unsigned __int128;

        return static_cast<uint64_t>(
            (static_cast<uint128_t>(a) * b) % modulus
        );
    #else
        uint64_t result = 0;
        a %= modulus;

        while (b > 0) {
            if (b & 1ULL) {
                result = add_mod_u64(
                    result,
                    a,
                    modulus
                );
            }

            b >>= 1;

            if (b > 0) {
                a = add_mod_u64(
                    a,
                    a,
                    modulus
                );
            }
        }

        return result;
    #endif
#endif
}


__host__ __device__
uint64_t pow_mod_u64(
    uint64_t base,
    uint64_t exponent,
    uint64_t modulus
) {
    uint64_t result = 1ULL % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1ULL) {
            result = mul_mod_u64(
                result,
                base,
                modulus
            );
        }

        exponent >>= 1;

        if (exponent > 0) {
            base = mul_mod_u64(
                base,
                base,
                modulus
            );
        }
    }

    return result;
}


__host__ __device__
uint64_t gcd_u64(
    uint64_t a,
    uint64_t b
) {
    while (b != 0) {
        uint64_t remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}


__host__ __device__
uint64_t abs_difference_u64(
    uint64_t a,
    uint64_t b
) {
    return a >= b ? a - b : b - a;
}


__host__ __device__
uint64_t rho_function(
    uint64_t x,
    uint64_t c,
    uint64_t n
) {
    return add_mod_u64(
        mul_mod_u64(x, x, n),
        c,
        n
    );
}


// ============================================================
// MILLER-RABIN
// ============================================================

__host__ __device__
bool is_probable_prime_u64(
    uint64_t n
) {
    if (n < 2ULL) {
        return false;
    }

    for (uint64_t prime : SMALL_PRIMES) {
        if (n == prime) {
            return true;
        }

        if (n % prime == 0ULL) {
            return false;
        }
    }

    uint64_t d = n - 1ULL;
    unsigned int s = 0;

    while ((d & 1ULL) == 0ULL) {
        d >>= 1;
        ++s;
    }

    for (uint64_t base : MILLER_RABIN_BASES) {
        uint64_t a = base % n;

        if (a == 0ULL) {
            continue;
        }

        uint64_t x = pow_mod_u64(
            a,
            d,
            n
        );

        if (x == 1ULL || x == n - 1ULL) {
            continue;
        }

        bool witness = true;

        for (unsigned int r = 1; r < s; ++r) {
            x = mul_mod_u64(
                x,
                x,
                n
            );

            if (x == n - 1ULL) {
                witness = false;
                break;
            }
        }

        if (witness) {
            return false;
        }
    }

    return true;
}


// ============================================================
// DEVICE RANDOM GENERATOR
// ============================================================

__device__
uint64_t splitmix64_device(
    uint64_t& state
) {
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);

    z = (z ^ (z >> 30))
        * 0xBF58476D1CE4E5B9ULL;

    z = (z ^ (z >> 27))
        * 0x94D049BB133111EBULL;

    return z ^ (z >> 31);
}


__device__
uint64_t random_below_device(
    uint64_t& state,
    uint64_t n
) {
    if (n == 0ULL) {
        return 0ULL;
    }

    return splitmix64_device(state) % n;
}


// ============================================================
// GPU POLLARD-RHO KERNEL
// ============================================================

__global__
void pollard_rho_kernel(
    uint64_t n,
    int rounds,
    uint64_t seed,
    unsigned long long* result
) {
    const uint64_t thread_id =
        static_cast<uint64_t>(
            blockIdx.x
        )
        * blockDim.x
        + threadIdx.x;

    uint64_t state =
        seed
        ^ (thread_id * 0x9E3779B97F4A7C15ULL);

    if (n < 4ULL) {
        return;
    }

    if ((n & 1ULL) == 0ULL) {
        atomicCAS(
            result,
            0ULL,
            2ULL
        );
        return;
    }

    if (n % 3ULL == 0ULL) {
        atomicCAS(
            result,
            0ULL,
            3ULL
        );
        return;
    }

    if (n % 5ULL == 0ULL) {
        atomicCAS(
            result,
            0ULL,
            5ULL
        );
        return;
    }

    uint64_t c =
        1ULL
        + random_below_device(
            state,
            n - 1ULL
        );

    uint64_t x =
        2ULL
        + random_below_device(
            state,
            n - 2ULL
        );

    uint64_t y = x;

    for (int iteration = 0; iteration < rounds; ++iteration) {
        if (*result != 0ULL) {
            return;
        }

        x = rho_function(
            x,
            c,
            n
        );

        y = rho_function(
            y,
            c,
            n
        );

        y = rho_function(
            y,
            c,
            n
        );

        uint64_t distance = abs_difference_u64(x, y);
        uint64_t divisor = gcd_u64(distance, n);

        if (divisor > 1ULL && divisor < n) {
            atomicCAS(
                result,
                0ULL,
                static_cast<unsigned long long>(divisor)
            );
            return;
        }

        if (divisor == n) {
            return;
        }
    }
}


// ============================================================
// CUDA GPU FACTOR FINDER
// ============================================================

class CudaFactorFinder {
public:
    CudaFactorFinder(
        int blocks = DEFAULT_BLOCKS,
        int threads = DEFAULT_THREADS,
        int rounds = DEFAULT_ROUNDS
    )
        : blocks_(blocks),
          threads_(threads),
          rounds_(rounds) {
        if (blocks_ <= 0 || threads_ <= 0 || rounds_ <= 0) {
            throw std::invalid_argument(
                "CUDA launch parameters must be positive"
            );
        }

        CUDA_CHECK(
            cudaMalloc(
                reinterpret_cast<void**>(&device_result_),
                sizeof(unsigned long long)
            )
        );
    }

    ~CudaFactorFinder() {
        if (device_result_ != nullptr) {
            cudaFree(device_result_);
        }
    }

    CudaFactorFinder(
        const CudaFactorFinder&
    ) = delete;

    CudaFactorFinder& operator=(
        const CudaFactorFinder&
    ) = delete;

    uint64_t find_factor(
        uint64_t n,
        int restarts = DEFAULT_RESTARTS
    ) {
        if (n < 2ULL) {
            return 0ULL;
        }

        if (n % 2ULL == 0ULL) {
            return 2ULL;
        }

        if (n % 3ULL == 0ULL) {
            return 3ULL;
        }

        if (n % 5ULL == 0ULL) {
            return 5ULL;
        }

        if (is_probable_prime_u64(n)) {
            return n;
        }

        for (int restart = 0; restart < restarts; ++restart) {
            unsigned long long zero = 0ULL;

            CUDA_CHECK(
                cudaMemcpy(
                    device_result_,
                    &zero,
                    sizeof(unsigned long long),
                    cudaMemcpyHostToDevice
                )
            );

            uint64_t seed =
                static_cast<uint64_t>(
                    std::chrono::high_resolution_clock::now()
                        .time_since_epoch()
                        .count()
                )
                ^ static_cast<uint64_t>(restart)
                ^ n;

            pollard_rho_kernel<<<
                blocks_,
                threads_
            >>>(
                n,
                rounds_,
                seed,
                device_result_
            );

            CUDA_CHECK(cudaGetLastError());
            CUDA_CHECK(cudaDeviceSynchronize());

            unsigned long long host_result = 0ULL;

            CUDA_CHECK(
                cudaMemcpy(
                    &host_result,
                    device_result_,
                    sizeof(unsigned long long),
                    cudaMemcpyDeviceToHost
                )
            );

            uint64_t factor =
                static_cast<uint64_t>(host_result);

            if (
                factor > 1ULL
                && factor < n
                && n % factor == 0ULL
            ) {
                return factor;
            }
        }

        return 0ULL;
    }

private:
    int blocks_;
    int threads_;
    int rounds_;

    unsigned long long* device_result_ = nullptr;
};


// ============================================================
// RESULT OBJECT
// ============================================================

struct FactorResult {
    uint64_t n = 0ULL;
    uint64_t factor = 0ULL;
    uint64_t cofactor = 0ULL;
    std::string method;
    double elapsed_seconds = 0.0;
    bool verified = false;

    bool success() const {
        return verified
            && factor > 1ULL
            && cofactor > 1ULL
            && factor * cofactor == n;
    }
};


// ============================================================
// FACTOR HELPERS
// ============================================================

std::pair<uint64_t, uint64_t> normalize_factor_pair(
    uint64_t n,
    uint64_t factor
) {
    if (factor > n / factor) {
        factor = n / factor;
    }

    return {
        factor,
        n / factor
    };
}


bool exact_factor_check(
    uint64_t n,
    uint64_t factor
) {
    if (factor <= 1ULL || factor >= n) {
        return false;
    }

    return n % factor == 0ULL;
}


bool is_square_u64(
    uint64_t n
) {
    uint64_t root =
        static_cast<uint64_t>(
            sqrt(
                static_cast<long double>(n)
            )
        );

    while (
        root < std::numeric_limits<uint64_t>::max()
        && (root + 1ULL) <= n / (root + 1ULL)
    ) {
        ++root;
    }

    while (root > n / root) {
        --root;
    }

    return root * root == n;
}


// ============================================================
// GPU ONE-SPLIT FACTORISATION
// ============================================================

FactorResult factor_integer_cuda(
    uint64_t n,
    CudaFactorFinder& finder
) {
    const auto start =
        std::chrono::high_resolution_clock::now();

    FactorResult result;
    result.n = n;

    if (n < 2ULL) {
        result.method = "invalid";
        result.verified = false;
        return result;
    }

    if (is_probable_prime_u64(n)) {
        result.factor = n;
        result.cofactor = 1ULL;
        result.method = "prime-input";
        result.verified = true;

        const auto finish =
            std::chrono::high_resolution_clock::now();

        result.elapsed_seconds =
            std::chrono::duration<double>(
                finish - start
            ).count();

        return result;
    }

    for (uint64_t prime : SMALL_PRIMES) {
        if (n % prime == 0ULL) {
            result.factor = prime;
            result.cofactor = n / prime;
            result.method = "small-prime";
            result.verified =
                result.factor * result.cofactor == n;

            const auto finish =
                std::chrono::high_resolution_clock::now();

            result.elapsed_seconds =
                std::chrono::duration<double>(
                    finish - start
                ).count();

            return result;
        }
    }

    uint64_t factor = finder.find_factor(n);

    if (factor == 0ULL) {
        result.method = "cuda-pollard-rho-failed";
        result.verified = false;

        const auto finish =
            std::chrono::high_resolution_clock::now();

        result.elapsed_seconds =
            std::chrono::duration<double>(
                finish - start
            ).count();

        return result;
    }

    auto pair = normalize_factor_pair(
        n,
        factor
    );

    result.factor = pair.first;
    result.cofactor = pair.second;
    result.method = "cuda-pollard-rho";
    result.verified =
        result.factor > 1ULL
        && result.cofactor > 1ULL
        && result.factor * result.cofactor == n;

    const auto finish =
        std::chrono::high_resolution_clock::now();

    result.elapsed_seconds =
        std::chrono::duration<double>(
            finish - start
        ).count();

    return result;
}


// ============================================================
// COMPLETE PRIME FACTORISATION
// ============================================================

void factor_complete_recursive(
    uint64_t n,
    CudaFactorFinder& finder,
    std::vector<uint64_t>& factors
) {
    if (n < 2ULL) {
        return;
    }

    if (is_probable_prime_u64(n)) {
        factors.push_back(n);
        return;
    }

    FactorResult result =
        factor_integer_cuda(
            n,
            finder
        );

    if (!result.success()) {
        throw std::runtime_error(
            "CUDA failed to factor " + std::to_string(n)
        );
    }

    factor_complete_recursive(
        result.factor,
        finder,
        factors
    );

    factor_complete_recursive(
        result.cofactor,
        finder,
        factors
    );
}


std::vector<uint64_t> factor_complete(
    uint64_t n,
    CudaFactorFinder& finder
) {
    std::vector<uint64_t> factors;

    factor_complete_recursive(
        n,
        finder,
        factors
    );

    std::sort(
        factors.begin(),
        factors.end()
    );

    return factors;
}


// ============================================================
// VERIFICATION
// ============================================================

bool verify_complete_factorisation(
    uint64_t n,
    const std::vector<uint64_t>& factors
) {
    if (n < 2ULL) {
        return factors.empty();
    }

    if (factors.empty()) {
        return false;
    }

    uint64_t remaining = n;

    for (uint64_t factor : factors) {
        if (!is_probable_prime_u64(factor)) {
            return false;
        }

        if (factor < 2ULL || remaining % factor != 0ULL) {
            return false;
        }

        remaining /= factor;
    }

    return remaining == 1ULL;
}


// ============================================================
// FORMATTING
// ============================================================

std::string format_factorisation(
    const std::vector<uint64_t>& factors
) {
    if (factors.empty()) {
        return "1";
    }

    std::ostringstream output;

    for (std::size_t i = 0; i < factors.size();) {
        uint64_t factor = factors[i];
        std::size_t count = 0;

        while (
            i + count < factors.size()
            && factors[i + count] == factor
        ) {
            ++count;
        }

        if (i > 0) {
            output << " * ";
        }

        output << factor;

        if (count > 1) {
            output << "^" << count;
        }

        i += count;
    }

    return output.str();
}


std::string result_to_string(
    const FactorResult& result
) {
    std::ostringstream output;

    output << "N=" << result.n << "\n";
    output << "factor=" << result.factor << "\n";
    output << "cofactor=" << result.cofactor << "\n";
    output << "method=" << result.method << "\n";
    output << "verified="
           << (result.verified ? "true" : "false")
           << "\n";
    output << std::fixed
           << std::setprecision(6)
           << "time="
           << result.elapsed_seconds
           << "s";

    return output.str();
}


// ============================================================
// DEVICE INFORMATION
// ============================================================

void print_cuda_device_information() {
    int device_count = 0;

    CUDA_CHECK(
        cudaGetDeviceCount(&device_count)
    );

    if (device_count == 0) {
        throw std::runtime_error(
            "No CUDA devices detected"
        );
    }

    cudaDeviceProp properties{};

    CUDA_CHECK(
        cudaGetDeviceProperties(
            &properties,
            0
        )
    );

    std::cout
        << "CUDA device: "
        << properties.name
        << "\n";

    std::cout
        << "Compute capability: "
        << properties.major
        << "."
        << properties.minor
        << "\n";

    std::cout
        << "Global memory: "
        << (
            static_cast<double>(
                properties.totalGlobalMem
            ) / (1024.0 * 1024.0 * 1024.0)
        )
        << " GiB\n";
}


// ============================================================
// SINGLE SOLVE
// ============================================================

void solve_number(
    uint64_t n,
    CudaFactorFinder& finder
) {
    std::cout << "\n";
    std::cout << "N = " << n << "\n";

    FactorResult split =
        factor_integer_cuda(
            n,
            finder
        );

    std::cout << "\n";
    std::cout << result_to_string(split) << "\n";

    std::vector<uint64_t> factors =
        factor_complete(
            n,
            finder
        );

    bool verified =
        verify_complete_factorisation(
            n,
            factors
        );

    std::cout << "\n";
    std::cout << "Prime factors: [";

    for (std::size_t i = 0; i < factors.size(); ++i) {
        if (i > 0) {
            std::cout << ", ";
        }

        std::cout << factors[i];
    }

    std::cout << "]\n";

    std::cout
        << "Prime factorisation: "
        << format_factorisation(factors)
        << "\n";

    std::cout
        << "Complete verification: "
        << (verified ? "true" : "false")
        << "\n";
}


// ============================================================
// BENCHMARK
// ============================================================

void benchmark(
    CudaFactorFinder& finder
) {
    const std::vector<uint64_t> numbers = {
        2ULL,
        13ULL,
        360ULL,
        8051ULL,
        10403ULL,
        1009ULL * 1013ULL,
        10007ULL * 10009ULL,
        100003ULL * 100019ULL,
        1000003ULL * 1000033ULL,
        2305843009213693951ULL
    };

    std::cout << "\n";
    std::cout << "CUDA FACTORISATION BENCHMARK\n";
    std::cout << "============================\n";

    for (uint64_t n : numbers) {
        const auto start =
            std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> factors =
            factor_complete(
                n,
                finder
            );

        const auto finish =
            std::chrono::high_resolution_clock::now();

        double seconds =
            std::chrono::duration<double>(
                finish - start
            ).count();

        bool verified =
            verify_complete_factorisation(
                n,
                factors
            );

        std::cout << "\n";
        std::cout << "N = " << n << "\n";
        std::cout
            << "Factorisation = "
            << format_factorisation(factors)
            << "\n";
        std::cout
            << "Verified = "
            << (verified ? "true" : "false")
            << "\n";
        std::cout
            << "Time = "
            << std::fixed
            << std::setprecision(6)
            << seconds
            << " s\n";
    }
}


// ============================================================
// STRING PARSING
// ============================================================

uint64_t parse_uint64(
    const std::string& text
) {
    if (text.empty()) {
        throw std::invalid_argument(
            "Empty integer"
        );
    }

    std::size_t position = 0;

    unsigned long long value =
        std::stoull(
            text,
            &position,
            10
        );

    if (position != text.size()) {
        throw std::invalid_argument(
            "Invalid characters in integer"
        );
    }

    return static_cast<uint64_t>(value);
}


// ============================================================
// INTERACTIVE MODE
// ============================================================

void interactive(
    CudaFactorFinder& finder
) {
    std::cout << "\n";
    std::cout << "CUDA PRIME FACTORISATION\n";
    std::cout << "=======================\n";
    std::cout << "Enter an unsigned 64-bit integer.\n";
    std::cout << "Commands: quit, benchmark\n";

    while (true) {
        std::cout << "\nN> ";

        std::string input;

        if (!std::getline(std::cin, input)) {
            break;
        }

        if (
            input == "quit"
            || input == "exit"
            || input == "q"
        ) {
            break;
        }

        if (input == "benchmark") {
            try {
                benchmark(finder);
            }
            catch (const std::exception& error) {
                std::cerr
                    << "Benchmark error: "
                    << error.what()
                    << "\n";
            }

            continue;
        }

        try {
            uint64_t n =
                parse_uint64(input);

            if (n < 2ULL) {
                std::cout
                    << "N must be at least 2.\n";
                continue;
            }

            solve_number(
                n,
                finder
            );
        }
        catch (const std::exception& error) {
            std::cerr
                << "Error: "
                << error.what()
                << "\n";
        }
    }
}


// ============================================================
// MAIN
// ============================================================

int main(
    int argc,
    char** argv
) {
    try {
        print_cuda_device_information();

        CudaFactorFinder finder(
            DEFAULT_BLOCKS,
            DEFAULT_THREADS,
            DEFAULT_ROUNDS
        );

        if (argc > 1) {
            std::string argument = argv[1];

            if (argument == "benchmark") {
                benchmark(finder);
                return 0;
            }

            uint64_t n =
                parse_uint64(argument);

            if (n < 2ULL) {
                throw std::invalid_argument(
                    "N must be at least 2"
                );
            }

            solve_number(
                n,
                finder
            );

            return 0;
        }

        interactive(finder);
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }

    return 0;
}