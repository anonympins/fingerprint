#include <emscripten.h>
#include <string>
#include "utils.hpp"

/**
 * Ce fichier sert de pont entre le C++ et JavaScript.
 * Les fonctions déclarées ici avec EMSCRIPTEN_KEEPALIVE seront exportées
 * et pourront être appelées depuis le code JavaScript.
 */

extern "C" {

/**
 * Expose la fonction cyrb53 à JavaScript.
 * Note : Les types de base comme les nombres et les pointeurs de chaînes C
 * sont gérés nativement par Emscripten.
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

} // extern "C"