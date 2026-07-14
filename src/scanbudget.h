#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <utility>

struct ScanBudgetProfile {
    int targetDeadlineMs = 2000;
    int pingAttempts = 1;
    int pingTimeoutSeconds = 1;
    int serviceAttempts = 1;
    int serviceTimeoutMs = 280;
};

constexpr int kProcessCleanupReserveMs = 50;
constexpr int kEstimatePerTargetAllowanceMs = 300;

inline ScanBudgetProfile scanBudgetProfile(int accuracyLevel)
{
    switch (std::clamp(accuracyLevel, 0, 3)) {
    case 0: return {1000, 1, 1, 1, 180};
    case 1: return {2000, 1, 1, 1, 280};
    case 2: return {4000, 2, 1, 1, 300};
    case 3: return {8000, 2, 2, 2, 600};
    default: return {2000, 1, 1, 1, 280};
    }
}

inline std::int64_t estimatedScanUpperBoundMs(int targetCount,
                                              int workerCount,
                                              int targetDeadlineMs,
                                              int perTargetAllowanceMs = kEstimatePerTargetAllowanceMs)
{
    if (targetCount <= 0 || workerCount <= 0 || targetDeadlineMs <= 0 ||
        perTargetAllowanceMs < 0) {
        return 0;
    }
    const std::int64_t waves =
        (static_cast<std::int64_t>(targetCount) + workerCount - 1) / workerCount;
    return waves * (static_cast<std::int64_t>(targetDeadlineMs) + perTargetAllowanceMs);
}

class TargetBudget {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using NowFunction = std::function<TimePoint()>;

    explicit TargetBudget(int deadlineMs, NowFunction now = []() { return Clock::now(); })
        : deadlineMs_(std::max(0, deadlineMs)), now_(std::move(now)), started_(now_())
    {
    }

    int remainingMs() const
    {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(now_() - started_).count();
        return std::max(0, deadlineMs_ - static_cast<int>(elapsed));
    }

    bool expired() const { return remainingMs() == 0; }
    int clampTimeout(int requestedMs, int reserveMs = 0) const
    {
        const int available = std::max(0, remainingMs() - std::max(0, reserveMs));
        return std::min(std::max(0, requestedMs), available);
    }

private:
    int deadlineMs_;
    NowFunction now_;
    TimePoint started_;
};
