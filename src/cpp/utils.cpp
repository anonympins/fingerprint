#include "utils.hpp"
#include <vector>
#include <cstring>
#include <string>

namespace Fingerprint::Utils {

namespace {

class SHA256 {
public:
    SHA256() { reset(); }

    void update(const uint8_t* data, size_t len) {
        size_t remaining = len;

        if (m_buffer_len > 0) {
            size_t space = 64 - m_buffer_len;
            size_t copy_len = (remaining < space) ? remaining : space;
            std::memcpy(m_buffer + m_buffer_len, data, copy_len);
            m_buffer_len += copy_len;
            remaining -= copy_len;
            data += copy_len;
            m_total_len += copy_len;

            if (m_buffer_len == 64) {
                transform(m_buffer);
                m_buffer_len = 0;
            }
        }

        while (remaining >= 64) {
            transform(data);
            remaining -= 64;
            data += 64;
            m_total_len += 64;
        }

        if (remaining > 0) {
            std::memcpy(m_buffer, data, remaining);
            m_buffer_len = remaining;
            m_total_len += remaining;
        }
    }

    void finalize(uint8_t digest[32]) {
        uint64_t total_bits = m_total_len * 8;
        uint8_t padding[64];
        std::memset(padding, 0, 64);
        padding[0] = 0x80;

        size_t pad_len = (m_buffer_len < 56) ? (56 - m_buffer_len) : (120 - m_buffer_len);
        update(padding, pad_len);

        uint8_t len_bytes[8];
        for (int i = 0; i < 8; ++i) {
            len_bytes[i] = static_cast<uint8_t>(total_bits >> (56 - i * 8));
        }
        update(len_bytes, 8);

        for (int i = 0; i < 8; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>(m_state[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(m_state[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(m_state[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(m_state[i]);
        }
    }

private:
    void reset() {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
        m_buffer_len = 0;
        m_total_len = 0;
    }

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }

    static inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    static inline uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline uint32_t gam0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline uint32_t gam1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = gam1(w[i - 2]) + w[i - 7] + gam0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76ca1422,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sig1(e) + choose(e, f, g) + k[i] + w[i];
            uint32_t t2 = sig0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

    uint32_t m_state[8];
    uint8_t m_buffer[64];
    size_t m_buffer_len;
    uint64_t m_total_len;
};

static inline uint8_t hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void parse_hex_to_bytes(const char* hex, uint8_t* bytes) {
    size_t len = std::strlen(hex);
    std::memset(bytes, 0, 32);
    int byte_idx = 31;
    for (int i = static_cast<int>(len) - 1; i >= 0 && byte_idx >= 0; i -= 2) {
        uint8_t low = hex_char_to_val(hex[i]);
        uint8_t high = (i > 0) ? hex_char_to_val(hex[i - 1]) : 0;
        bytes[byte_idx--] = (high << 4) | low;
    }
}

} // namespace

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

int32_t solve_cpu_target(const uint8_t* base_block, int base_block_len, const char* target_hex) {
    uint8_t target_bytes[32];
    parse_hex_to_bytes(target_hex, target_bytes);

    int32_t cpu_solution = 0;
    uint8_t hash[32];

    while (true) {
        std::string sol_str = std::to_string(cpu_solution);
        size_t sol_len = sol_str.length();

        SHA256 sha;
        sha.update(base_block, base_block_len);
        sha.update(reinterpret_cast<const uint8_t*>(sol_str.c_str()), sol_len);
        sha.finalize(hash);

        bool is_less = false;
        for (int i = 0; i < 32; ++i) {
            if (hash[i] < target_bytes[i]) {
                is_less = true;
                break;
            } else if (hash[i] > target_bytes[i]) {
                break;
            }
        }

        if (is_less) {
            break;
        }
        cpu_solution++;
    }
    return cpu_solution;
}

int32_t solve_memory_challenge(const char* seed, int difficulty_mb) {
    size_t size = static_cast<size_t>(difficulty_mb) * 1024 * 1024;
    size_t buffer_len = size / 4;
    if (buffer_len == 0) return 0;

    std::vector<uint32_t> buffer(buffer_len);
    int32_t h = 0;
    for (int i = 0; seed[i] != '\0'; ++i) {
        h += static_cast<uint8_t>(seed[i]);
    }

    for (size_t i = 0; i < buffer_len; ++i) {
        h = imul(h ^ static_cast<int32_t>(i), 1597334677);
        buffer[i] = static_cast<uint32_t>(h);
    }

    int32_t solution = 0;
    size_t iterations = size / 16;
    size_t addr = buffer[0] % buffer_len;

    for (size_t i = 0; i < iterations; ++i) {
        addr = buffer[addr] % buffer_len;
        solution ^= static_cast<int32_t>(addr);
    }

    return solution;
}

} // namespace Fingerprint::Utils