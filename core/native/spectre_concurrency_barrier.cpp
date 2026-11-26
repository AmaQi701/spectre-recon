// SPECTRE C++17 Deterministic Thread Barrier & Telemetry Kernel (ABI v950)
// SPDX-License-Identifier: Apache-2.0
// Provides generation-safe POSIX/C++17 thread barrier synchronization and
// robust multi-sample latency dispersion (MAD / IQR) for QA benchmarking.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

namespace {

class GenerationBarrier {
public:
    explicit GenerationBarrier(size_t parties)
        : total_(parties == 0 ? 1 : parties), waiting_(0), gen_(0) {}

    bool arrive_and_wait(int timeout_ms) {
        std::unique_lock<std::mutex> lk(mu_);
        const uint64_t my_gen = gen_;
        if (++waiting_ >= total_) {
            waiting_ = 0;
            ++gen_;
            lk.unlock();
            cv_.notify_all();
            return true;
        }
        const auto dur = std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 1000);
        const bool ok = cv_.wait_for(lk, dur, [&] { return gen_ != my_gen; });
        if (!ok && waiting_ > 0) {
            --waiting_;
        }
        return ok;
    }

private:
    size_t total_;
    size_t waiting_;
    uint64_t gen_;
    std::mutex mu_;
    std::condition_variable cv_;
};

} // namespace

extern "C" {

int spectre_cpp_barrier_selftest(int worker_count, int timeout_ms, int64_t* out_spread_us) {
    if (worker_count < 1) {
        return 0;
    }
    const size_t n = static_cast<size_t>(worker_count > 32 ? 32 : worker_count);
    GenerationBarrier barrier(n);
    std::vector<int64_t> wake_ns(n, 0);
    std::vector<int> passed(n, 0);
    std::vector<std::thread> pool;
    pool.reserve(n);

    const auto t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < n; ++i) {
        pool.emplace_back([&, i]() {
            if (barrier.arrive_and_wait(timeout_ms)) {
                const auto dt = std::chrono::steady_clock::now() - t0;
                wake_ns[i] = std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count();
                passed[i] = 1;
            }
        });
    }
    for (auto& th : pool) {
        if (th.joinable()) {
            th.join();
        }
    }

    int ok_total = 0;
    int64_t min_ns = INT64_MAX;
    int64_t max_ns = 0;
    for (size_t i = 0; i < n; ++i) {
        if (passed[i]) {
            ++ok_total;
            if (wake_ns[i] < min_ns) min_ns = wake_ns[i];
            if (wake_ns[i] > max_ns) max_ns = wake_ns[i];
        }
    }
    if (out_spread_us) {
        *out_spread_us = (ok_total >= 2 && max_ns >= min_ns) ? ((max_ns - min_ns) / 1000) : 0;
    }
    return ok_total;
}

double spectre_cpp_mad_latency_us(const int64_t* samples_us, size_t count) {
    if (!samples_us || count < 2) {
        return 0.0;
    }
    const size_t cap = count > 4096 ? 4096 : count;
    std::vector<double> vals(cap);
    for (size_t i = 0; i < cap; ++i) {
        vals[i] = static_cast<double>(samples_us[i] < 0 ? 0 : samples_us[i]);
    }
    std::sort(vals.begin(), vals.end());
    const double median = (cap % 2 == 1)
        ? vals[cap / 2]
        : 0.5 * (vals[(cap / 2) - 1] + vals[cap / 2]);

    std::vector<double> devs(cap);
    for (size_t i = 0; i < cap; ++i) {
        devs[i] = std::fabs(vals[i] - median);
    }
    std::sort(devs.begin(), devs.end());
    const double mad = (cap % 2 == 1)
        ? devs[cap / 2]
        : 0.5 * (devs[(cap / 2) - 1] + devs[cap / 2]);
    return mad * 1.4826;
}

int spectre_cpp_idempotency_drift_score(
    const int* status_codes,
    const int* body_lengths,
    size_t count
) {
    if (!status_codes || !body_lengths || count < 2) {
        return 0;
    }
    const size_t cap = count > 512 ? 512 : count;
    int ok_2xx = 0;
    int conflict_4xx = 0;
    int server_5xx = 0;
    int min_len = body_lengths[0] < 0 ? 0 : body_lengths[0];
    int max_len = min_len;

    for (size_t i = 0; i < cap; ++i) {
        const int sc = status_codes[i];
        const int bl = body_lengths[i] < 0 ? 0 : body_lengths[i];
        if (sc >= 200 && sc < 300) {
            ++ok_2xx;
        } else if (sc == 409 || sc == 429 || sc == 400 || sc == 422) {
            ++conflict_4xx;
        } else if (sc >= 500 && sc < 600) {
            ++server_5xx;
        }
        if (bl < min_len) min_len = bl;
        if (bl > max_len) max_len = bl;
    }

    if (ok_2xx >= 2 && conflict_4xx >= 1) {
        return 85;
    }
    if (ok_2xx >= 1 && server_5xx >= 1) {
        return 75;
    }
    if (ok_2xx == static_cast<int>(cap) && (max_len - min_len) > 512) {
        return 60;
    }
    return 0;
}

} // extern "C"
