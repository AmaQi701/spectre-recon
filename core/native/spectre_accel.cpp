// SPECTRE Native C++17 Accelerator Engine (Linux epoll + OpenSSL HMAC + Fast Hashing)
// Compiled with: g++ -O3 -std=c++17 -shared -fPIC spectre_accel.cpp -o libspectre_accel.so -lssl -lcrypto

#include <arpa/inet.h>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <chrono>

extern "C" {

uint32_t spectre_mmh3_32(const uint8_t* data, size_t len, uint32_t seed) {
    const uint32_t c1 = 0xcc9e2d51U;
    const uint32_t c2 = 0x1b873593U;
    uint32_t h1 = seed;
    const size_t nblocks = len / 4;
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t k1;
        std::memcpy(&k1, data + i * 4, sizeof(uint32_t));
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64U;
    }
    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= static_cast<uint32_t>(tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= static_cast<uint32_t>(tail[1]) << 8;  [[fallthrough]];
        case 1:
            k1 ^= static_cast<uint32_t>(tail[0]);
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >> 17);
            k1 *= c2;
            h1 ^= k1;
    }
    h1 ^= static_cast<uint32_t>(len);
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6bU;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35U;
    h1 ^= h1 >> 16;
    return h1;
}

double spectre_shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }
    double ent = 0.0;
    const double inv_len = 1.0 / static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) * inv_len;
            ent -= p * std::log2(p);
        }
    }
    return ent;
}

uint64_t spectre_simhash64(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0ULL;
    int32_t v[64] = {0};
    uint64_t rolling = 14695981039346656037ULL;
    size_t tok_len = 0;
    auto flush_token = [&](uint64_t h) {
        for (int b = 0; b < 64; ++b) {
            v[b] += ((h >> b) & 1ULL) ? 1 : -1;
        }
    };
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        bool is_alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '<' || c == '/';
        if (is_alnum) {
            if (c >= 'A' && c <= 'Z') c += 32;
            rolling ^= static_cast<uint64_t>(c);
            rolling *= 1099511628211ULL;
            tok_len++;
        } else if (tok_len >= 2) {
            flush_token(rolling);
            rolling = 14695981039346656037ULL;
            tok_len = 0;
        } else {
            rolling = 14695981039346656037ULL;
            tok_len = 0;
        }
    }
    if (tok_len >= 2) flush_token(rolling);
    uint64_t out = 0ULL;
    for (int b = 0; b < 64; ++b) {
        if (v[b] > 0) out |= (1ULL << b);
    }
    return out;
}

int spectre_jwt_verify_wordlist(
    const uint8_t* signing_input,
    size_t signing_len,
    const uint8_t* target_sig,
    size_t sig_len,
    int alg_bits,
    const char* wordlist_nl,
    char* matched_out,
    size_t matched_cap
) {
    if (!signing_input || !target_sig || !wordlist_nl || !matched_out || matched_cap < 2) return 0;
    const EVP_MD* md = EVP_sha256();
    if (alg_bits == 384) md = EVP_sha384();
    else if (alg_bits == 512) md = EVP_sha512();

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    const char* p = wordlist_nl;
    while (*p) {
        const char* nl = std::strchr(p, '\n');
        size_t wlen = nl ? static_cast<size_t>(nl - p) : std::strlen(p);
        if (wlen > 0 && p[wlen - 1] == '\r') wlen--;
        HMAC(md, p, static_cast<int>(wlen), signing_input, signing_len, digest, &digest_len);
        if (digest_len == sig_len && CRYPTO_memcmp(digest, target_sig, sig_len) == 0) {
            size_t copy_n = wlen < (matched_cap - 1) ? wlen : (matched_cap - 1);
            std::memcpy(matched_out, p, copy_n);
            matched_out[copy_n] = '\0';
            return 1;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

int spectre_epoll_tcp_probe(
    const char* ip_str,
    const int* ports,
    size_t num_ports,
    int timeout_ms,
    char* out_buf,
    size_t out_cap
) {
    if (!ip_str || !ports || num_ports == 0 || !out_buf || out_cap < 32) return 0;
    out_buf[0] = '\0';
    struct in_addr addr4{};
    if (inet_pton(AF_INET, ip_str, &addr4) != 1) return 0;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) return 0;

    struct Slot { int fd; int port; bool connected; bool done; std::string hex_banner; };
    std::vector<Slot> slots;
    slots.reserve(num_ports);

    for (size_t i = 0; i < num_ports && i < 512; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(static_cast<uint16_t>(ports[i]));
        sa.sin_addr = addr4;
        int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd);
            continue;
        }
        int idx = static_cast<int>(slots.size());
        slots.push_back({fd, ports[i], rc == 0, false, ""});
        struct epoll_event ev{};
        ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
        ev.data.u32 = static_cast<uint32_t>(idx);
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    }

    auto t_start = std::chrono::steady_clock::now();
    std::vector<struct epoll_event> events(64);
    size_t remaining = slots.size();

    while (remaining > 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_start
        ).count();
        int left_ms = timeout_ms - static_cast<int>(elapsed);
        if (left_ms <= 0) break;
        int n = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), left_ms > 80 ? 80 : left_ms);
        if (n <= 0) continue;
        for (int i = 0; i < n; ++i) {
            Slot& s = slots[events[i].data.u32];
            if (s.done) continue;
            uint32_t ev = events[i].events;
            if (ev & (EPOLLERR | EPOLLHUP)) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                if (err != 0) { s.done = true; remaining--; continue; }
            }
            if (!s.connected && (ev & EPOLLOUT)) {
                int err = 0; socklen_t elen = sizeof(err);
                if (getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                    s.connected = true;
                } else {
                    s.done = true; remaining--; continue;
                }
            }
            if (s.connected && (ev & EPOLLIN)) {
                uint8_t buf[256];
                ssize_t r = recv(s.fd, buf, sizeof(buf), MSG_DONTWAIT);
                if (r > 0) {
                    static const char* hx = "0123456789abcdef";
                    for (ssize_t k = 0; k < r && s.hex_banner.size() < 256; ++k) {
                        s.hex_banner.push_back(hx[(buf[k] >> 4) & 0xF]);
                        s.hex_banner.push_back(hx[buf[k] & 0xF]);
                    }
                    s.done = true; remaining--;
                }
            }
        }
    }

    std::string res;
    int open_cnt = 0;
    for (auto& s : slots) {
        if (s.connected && s.hex_banner.empty()) {
            uint8_t buf[128];
            ssize_t r = recv(s.fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (r > 0) {
                static const char* hx = "0123456789abcdef";
                for (ssize_t k = 0; k < r; ++k) {
                    s.hex_banner.push_back(hx[(buf[k] >> 4) & 0xF]);
                    s.hex_banner.push_back(hx[buf[k] & 0xF]);
                }
            }
        }
        close(s.fd);
        if (s.connected) {
            open_cnt++;
            res += std::to_string(s.port) + ":" + s.hex_banner + "\n";
        }
    }
    close(epfd);
    size_t cn = res.size() < (out_cap - 1) ? res.size() : (out_cap - 1);
    std::memcpy(out_buf, res.data(), cn);
    out_buf[cn] = '\0';
    return open_cnt;
}

} // extern "C"
