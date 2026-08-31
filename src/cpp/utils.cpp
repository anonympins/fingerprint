#include "utils.hpp"

namespace Fingerprint::Utils {

uint64_t cyrb53(const std::string& str, uint32_t seed) {
    int32_t h1 = 0xdeadbeef ^ seed;
    int32_t h2 = 0x41c6ce57 ^ seed;

    for (char ch : str) {
        h1 = imul(h1 ^ ch, -1640531535); // 2654435761 en int32
        h2 = imul(h2 ^ ch, 1597334677);
    }

    h1 = imul(h1 ^ (h1 >> 16), -2048144789) ^ imul(h2 ^ (h2 >> 13), -1028477387); // 2246822507 et 3266489909 en int32
    h2 = imul(h2 ^ (h2 >> 16), -2048144789) ^ imul(h1 ^ (h1 >> 13), -1028477387);

    // Combine les deux hash 32-bit en un hash 64-bit (similaire à la version JS)
    // Note : La conversion en uint64_t est importante pour correspondre au résultat non signé de JS.
    uint64_t result = static_cast<uint64_t>(static_cast<uint32_t>(2097151 & h2)) * 4294967296;
    result += static_cast<uint32_t>(h1);

    return result;
}

} // namespace Fingerprint::Utils