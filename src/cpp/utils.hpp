#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <cstdint>

namespace Fingerprint::Utils {

// Simule la multiplication 32-bit de JavaScript `Math.imul`
inline int32_t imul(int32_t a, int32_t b) {
    return a * b;
}

uint64_t cyrb53(const std::string& str, uint32_t seed = 0);

} // namespace Fingerprint::Utils
#endif // UTILS_HPP