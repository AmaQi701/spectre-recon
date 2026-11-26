// SPECTRE Native C++17 Accelerator Engine (Linux epoll + OpenSSL HMAC + Fast Hashing)
// Compiled with: g++ -O3 -std=c++17 -shared -fPIC spectre_accel.cpp -o libspectre_accel.so -lssl -lcrypto

#include <arpa/inet.h>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
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
    if (!data) len = 0;
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
    const uint8_t* tail = data ? (data + nblocks * 4) : nullptr;
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
            OPENSSL_cleanse(digest, sizeof(digest));
            return 1;
        }
        if (!nl) break;
        p = nl + 1;
    }
    OPENSSL_cleanse(digest, sizeof(digest));
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
    struct in6_addr addr6{};
    bool is_v6 = false;
    if (inet_pton(AF_INET, ip_str, &addr4) != 1) {
        if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
            is_v6 = true;
        } else {
            return 0;
        }
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) return 0;

    struct Slot { int fd; int port; bool connected; bool done; std::string hex_banner; };
    std::vector<Slot> slots;
    slots.reserve(num_ports);

    for (size_t i = 0; i < num_ports && i < 512; ++i) {
        int domain = is_v6 ? AF_INET6 : AF_INET;
        int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        int rc = -1;
        if (is_v6) {
            struct sockaddr_in6 sa6{};
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(static_cast<uint16_t>(ports[i]));
            sa6.sin6_addr = addr6;
            rc = connect(fd, reinterpret_cast<struct sockaddr*>(&sa6), sizeof(sa6));
        } else {
            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(static_cast<uint16_t>(ports[i]));
            sa.sin_addr = addr4;
            rc = connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        }
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

static inline bool match_ci(const uint8_t* p, size_t rem, const char* lit, size_t n) {
    if (rem < n) return false;
    for (size_t k = 0; k < n; ++k) {
        uint8_t c = p[k];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != static_cast<uint8_t>(lit[k])) return false;
    }
    return true;
}

uint32_t spectre_js_token_mask(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0U;
    uint32_t mask = 0U;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        const uint8_t* p = data + i;
        const size_t rem = len - i;
        switch (c) {
            case '/':
                if (!(mask & 1U)) {
                    if (match_ci(p, rem, "/api/", 5) || match_ci(p, rem, "/v1/", 4) ||
                        match_ci(p, rem, "/v2/", 4) || match_ci(p, rem, "/v3/", 4) ||
                        match_ci(p, rem, "/graphql", 8) || match_ci(p, rem, "/auth/", 6) ||
                        match_ci(p, rem, "/admin/", 7) || match_ci(p, rem, "/internal/", 10) ||
                        match_ci(p, rem, "/live/", 6) || match_ci(p, rem, "/stream/", 8) ||
                        match_ci(p, rem, "/news/", 6) || match_ci(p, rem, "/tv/", 4) ||
                        match_ci(p, rem, "/radio/", 7) || match_ci(p, rem, "/channels/", 10)) {
                        mask |= 1U;
                    }
                }
                if (!(mask & 8U) && match_ci(p, rem, "/assets/", 8)) {
                    mask |= 8U;
                }
                break;
            case '.':
                if (!(mask & 1U)) {
                    if (match_ci(p, rem, ".get", 4) || match_ci(p, rem, ".post", 5) ||
                        match_ci(p, rem, ".put", 4) || match_ci(p, rem, ".delete", 7) ||
                        match_ci(p, rem, ".patch", 6)) {
                        mask |= 1U;
                    }
                }
                break;
            case 'h':
                if (!(mask & 1U) && (match_ci(p, rem, "http://", 7) || match_ci(p, rem, "https://", 8))) {
                    mask |= 1U;
                }
                break;
            case 'w':
                if (!(mask & 1U) && (match_ci(p, rem, "ws://", 5) || match_ci(p, rem, "wss://", 6))) {
                    mask |= 1U;
                }
                break;
            case 'i':
                if (!(mask & 2U) && match_ci(p, rem, "innerhtml", 9)) mask |= 2U;
                break;
            case 'o':
                if (!(mask & 2U) && match_ci(p, rem, "outerhtml", 9)) mask |= 2U;
                break;
            case 'd':
                if (!(mask & 2U) && (match_ci(p, rem, "document.write", 14) || match_ci(p, rem, "dangerouslysetinnerhtml", 23))) {
                    mask |= 2U;
                }
                break;
            case 'e':
                if (!(mask & 2U) && match_ci(p, rem, "eval", 4)) mask |= 2U;
                break;
            case 'p':
                if (!(mask & 2U) && match_ci(p, rem, "postmessage", 11)) mask |= 2U;
                break;
            case 's':
                if (!(mask & 2U) && match_ci(p, rem, "settimeout", 10)) mask |= 2U;
                if (!(mask & 4U) && (match_ci(p, rem, "secret_key", 10) || match_ci(p, rem, "secretkey", 9) || match_ci(p, rem, "secret-key", 10))) {
                    mask |= 4U;
                }
                if (!(mask & 8U) && match_ci(p, rem, "static/js/", 10)) mask |= 8U;
                if (!(mask & 16U) && match_ci(p, rem, "sourcemappingurl=", 17)) mask |= 16U;
                break;
            case 'a':
                if (!(mask & 4U)) {
                    if (match_ci(p, rem, "api_key", 7) || match_ci(p, rem, "apikey", 6) || match_ci(p, rem, "api-key", 7) ||
                        match_ci(p, rem, "access_token", 12) || match_ci(p, rem, "accesstoken", 11) || match_ci(p, rem, "access-token", 12) ||
                        match_ci(p, rem, "authorization", 13)) {
                        mask |= 4U;
                    }
                }
                if (!(mask & 8U) && match_ci(p, rem, "assets/", 7)) mask |= 8U;
                break;
            case 'b':
                if (!(mask & 4U) && (match_ci(p, rem, "base_url", 8) || match_ci(p, rem, "baseurl", 7) || match_ci(p, rem, "bearer ", 7))) {
                    mask |= 4U;
                }
                break;
            case 'v':
                if (!(mask & 4U) && match_ci(p, rem, "vite_", 5)) mask |= 4U;
                break;
            case '"':
                if (!(mask & 16U) && match_ci(p, rem, "\"sourcescontent\"", 16)) mask |= 16U;
                break;
            default:
                break;
        }
        if (mask == 0x1FU) break;
    }
    return mask;
}

int spectre_hamming64(uint64_t a, uint64_t b) {
    return __builtin_popcountll(a ^ b);
}

uint64_t spectre_structural_hash(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0ULL;
    size_t pos = 0;
    while (pos < len && data[pos] <= 0x20) pos++;
    if (pos >= len) return 0ULL;

    uint64_t h = 14695981039346656037ULL;
    auto mix = [&](uint8_t b) {
        h ^= static_cast<uint64_t>(b);
        h *= 1099511628211ULL;
    };

    uint8_t first = data[pos];
    if (first == '{' || first == '[') {
        bool in_str = false;
        bool esc = false;
        uint8_t key_buf[48];
        size_t key_len = 0;
        for (size_t i = pos; i < len; ++i) {
            uint8_t c = data[i];
            if (in_str) {
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    in_str = false;
                    size_t k = i + 1;
                    while (k < len && data[k] <= 0x20) k++;
                    if (k < len && data[k] == ':') {
                        mix('"');
                        for (size_t m = 0; m < key_len; ++m) mix(key_buf[m]);
                        mix(':');
                    }
                    key_len = 0;
                } else if (key_len < sizeof(key_buf)) {
                    if (c >= 'A' && c <= 'Z') c += 32;
                    key_buf[key_len++] = c;
                }
            } else {
                if (c == '"') {
                    in_str = true;
                    key_len = 0;
                } else if (c == '{' || c == '}' || c == '[' || c == ']') {
                    mix(c);
                }
            }
        }
        return h;
    }

    bool has_lt = false;
    size_t scan_lim = len < 512 ? len : 512;
    for (size_t i = pos; i < scan_lim; ++i) {
        if (data[i] == '<') { has_lt = true; break; }
    }
    if (has_lt) {
        for (size_t i = pos; i < len; ++i) {
            if (data[i] == '<' && i + 1 < len) {
                size_t k = i + 1;
                bool closing = false;
                if (data[k] == '/') { closing = true; k++; }
                if (k < len && ((data[k] >= 'a' && data[k] <= 'z') || (data[k] >= 'A' && data[k] <= 'Z'))) {
                    mix('<');
                    if (closing) mix('/');
                    size_t tlen = 0;
                    while (k < len && tlen < 24) {
                        uint8_t tc = data[k];
                        bool ok = (tc >= 'a' && tc <= 'z') || (tc >= 'A' && tc <= 'Z') || (tc >= '0' && tc <= '9');
                        if (!ok) break;
                        if (tc >= 'A' && tc <= 'Z') tc += 32;
                        mix(tc);
                        k++;
                        tlen++;
                    }
                    while (k < len && data[k] != '>') k++;
                    i = k;
                }
            }
        }
        return h;
    }

    for (size_t i = pos; i < len; ++i) {
        uint8_t c = data[i];
        if (c == '\n' || c == ':' || c == '=' || c == '[' || c == ']') mix(c);
    }
    return h;
}

static inline bool match_cs(const uint8_t* p, size_t rem, const char* lit, size_t n) {
    if (rem < n) return false;
    return std::memcmp(p, lit, n) == 0;
}

uint32_t spectre_secret_prefilter_mask(const uint8_t* data, size_t len) {
    if (!data || len < 4) return 0U;
    uint32_t mask = 0U;
    for (size_t i = 0; i + 3 < len; ++i) {
        const uint8_t* p = data + i;
        const size_t rem = len - i;
        switch (p[0]) {
            case 'A':
                if (!(mask & 1U) && (match_cs(p, rem, "AKIA", 4) || match_cs(p, rem, "ASIA", 4) || match_cs(p, rem, "AIza", 4))) {
                    mask |= 1U;
                }
                break;
            case 'g':
                if (!(mask & 2U) && (match_cs(p, rem, "ghp_", 4) || match_cs(p, rem, "github_pat_", 11) || match_cs(p, rem, "glpat-", 6))) {
                    mask |= 2U;
                }
                if (!(mask & 8U) && match_cs(p, rem, "gsk_", 4)) {
                    mask |= 8U;
                }
                break;
            case 'n':
                if (!(mask & 2U) && match_cs(p, rem, "npm_", 4)) mask |= 2U;
                break;
            case 's':
                if (!(mask & 4U) && match_cs(p, rem, "sk_live_", 8)) mask |= 4U;
                if (!(mask & 8U) && (match_cs(p, rem, "sk-ant-", 7) || match_cs(p, rem, "sk-proj-", 8))) mask |= 8U;
                break;
            case 'r':
                if (!(mask & 4U) && match_cs(p, rem, "rk_live_", 8)) mask |= 4U;
                break;
            case 'x':
                if (!(mask & 4U) && (match_cs(p, rem, "xoxb-", 5) || match_cs(p, rem, "xoxp-", 5))) mask |= 4U;
                break;
            case 'S':
                if (!(mask & 4U) && match_cs(p, rem, "SG.", 3) && rem >= 24) mask |= 4U;
                break;
            case 'h':
                if (!(mask & 8U) && match_cs(p, rem, "hf_", 3) && rem >= 24) mask |= 8U;
                break;
            case '-':
                if (!(mask & 16U) && match_cs(p, rem, "-----BEGIN ", 11)) mask |= 16U;
                break;
            case 'e':
                if (!(mask & 16U) && match_cs(p, rem, "eyJ", 3) && rem >= 24) mask |= 16U;
                break;
            default:
                break;
        }
        if (mask == 0x1FU) break;
    }
    return mask;
}

uint32_t spectre_cpp_abi_version() {
    return 950U;
}

uint64_t spectre_fnv1a64_ci(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0ULL;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

int spectre_dual_baseline_threshold(int base_len, int base_jitter) {
    int j4 = base_jitter > 0 ? (base_jitter * 4) : 0;
    int pct12 = base_len > 0 ? static_cast<int>(base_len * 0.12) : 0;
    int thr = 500;
    if (j4 > thr) thr = j4;
    if (pct12 > thr) thr = pct12;
    return thr;
}

uint32_t spectre_nvt_body_sig_mask(const uint8_t* data, size_t len) {
    if (!data || len < 4) return 0U;
    uint32_t mask = 0U;
    for (size_t i = 0; i + 3 < len; ++i) {
        const uint8_t* p = data + i;
        const size_t rem = len - i;
        uint8_t c = p[0];
        if (c >= 'A' && c <= 'Z') c += 32;
        switch (c) {
            case '"':
                if (!(mask & 1U) && (match_ci(p, rem, "\"beans\"", 7) || match_ci(p, rem, "\"propertysources\"", 17))) mask |= 1U;
                if (!(mask & 4U) && (match_ci(p, rem, "\"__schema\"", 10) || match_ci(p, rem, "\"openapi\"", 9) || match_ci(p, rem, "\"swagger\"", 9))) mask |= 4U;
                if (!(mask & 8U) && (match_ci(p, rem, "\"models\"", 8) || match_ci(p, rem, "\"jsonrpc\"", 9) || match_ci(p, rem, "\"collections\"", 13))) mask |= 8U;
                break;
            case 'r':
                if (!(mask & 2U) && match_ci(p, rem, "ref: refs/heads/", 16)) mask |= 2U;
                break;
            case '[':
                if (!(mask & 2U) && match_ci(p, rem, "[core]", 6)) mask |= 2U;
                break;
            case 'd':
                if (!(mask & 2U) && match_ci(p, rem, "db_password", 11)) mask |= 2U;
                break;
            case 'a':
                if (!(mask & 2U) && (match_ci(p, rem, "app_key=", 8) || match_ci(p, rem, "aws_secret", 10))) mask |= 2U;
                if (!(mask & 16U) && match_ci(p, rem, "active connections:", 19)) mask |= 16U;
                break;
            case 'p':
                if (!(mask & 1U) && match_ci(p, rem, "process_cpu_seconds_total", 25)) mask |= 1U;
                if (!(mask & 16U) && match_ci(p, rem, "phpinfo()", 9)) mask |= 16U;
                break;
            case '#':
                if (!(mask & 1U) && match_ci(p, rem, "# help ", 7)) mask |= 1U;
                break;
            case 'o':
                if (!(mask & 8U) && match_ci(p, rem, "ollama", 6)) mask |= 8U;
                break;
            case 'w':
                if (!(mask & 16U) && match_ci(p, rem, "werkzeug", 8)) mask |= 16U;
                break;
            case 't':
                if (!(mask & 16U) && match_ci(p, rem, "traceback", 9)) mask |= 16U;
                break;
            case 's':
                if (!(mask & 16U) && match_ci(p, rem, "server-status", 13)) mask |= 16U;
                break;
            default:
                break;
        }
        if (mask == 0x1FU) break;
    }
    return mask;
}

} // extern "C"
