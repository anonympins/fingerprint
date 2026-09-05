#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <cstdint>

namespace Fingerprint::Utils {

// Simule la multiplication 32-bit de JavaScript `Math.imul`
inline int32_t imul(int32_t a, int32_t b) {
    return static_cast<int32_t>(static_cast<uint32_t>(a) * static_cast<uint32_t>(b));
}

uint64_t cyrb53(const std::string& str, uint32_t seed = 0);

int32_t solve_cpu_target(const uint8_t* base_block, int base_block_len, const char* target_hex);
int32_t solve_memory_challenge(const char* seed, int difficulty_mb);

} // namespace Fingerprint::Utils
#endif // UTILS_HPP