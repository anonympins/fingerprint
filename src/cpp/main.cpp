#include <emscripten.h>
#include <string>
#include "utils.hpp"

/**
 * Bridges C++ and JavaScript via WebAssembly.
 * Functions marked with EMSCRIPTEN_KEEPALIVE are exported to JavaScript.
 */

extern "C" {

/**
 * Exposes cyrb53 hash function to JavaScript.
 * Primitive types and C string pointers are handled natively by Emscripten.
 */
EMSCRIPTEN_KEEPALIVE
uint64_t hash_string(const char* str) {
    return Fingerprint::Utils::cyrb53(std::string(str));
}

EMSCRIPTEN_KEEPALIVE
int32_t solve_cpu_target(const uint8_t* base_block, int base_block_len, const char* target_hex) {
    return Fingerprint::Utils::solve_cpu_target(base_block, base_block_len, target_hex);
}

EMSCRIPTEN_KEEPALIVE
int32_t solve_memory_challenge(const char* seed, int difficulty_mb) {
    return Fingerprint::Utils::solve_memory_challenge(seed, difficulty_mb);
}

EMSCRIPTEN_KEEPALIVE
void generate_gpu_pow_trajectory(const char* seed, int iterations, float* output) {
    Fingerprint::Utils::generate_gpu_pow_trajectory(std::string(seed), iterations, output);
}

} // extern "C"