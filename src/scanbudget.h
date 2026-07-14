#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <utility>

struct ScanBudgetProfile {
    int targetDeadlineMs = 8000;
    int pingAttempts = 1;
    int pingTimeoutSeconds = 1;
    int serviceAttempts = 1;
    int serviceTimeoutMs = 1000;
};

constexpr int kProcessCleanupReserveMs = 50;
constexpr int kEstimatePerTargetAllowanceMs = 300;
constexpr int kPingProcessStartupAllowanceMs = 500;

enum class AliveHostStage {
    Services,
    MacAddress,
    Vendor,
    Hostname,
    NormalizeIdentity,
    Details
};

inline constexpr std::array<AliveHostStage, 6> kAliveHostStageOrder = {
    AliveHostStage::Services,
    AliveHostStage::MacAddress,
    AliveHostStage::Vendor,
    AliveHostStage::Hostname,
    AliveHostStage::NormalizeIdentity,
    AliveHostStage::Details
};

constexpr int pingAttemptWaitMs(int timeoutSeconds)
{
    return timeoutSeconds > 0 ? timeoutSeconds * 1000 + kPingProcessStartupAllowanceMs : 0;
}

inline ScanBudgetProfile scanBudgetProfile(int accuracyLevel)
{
    switch (std::clamp(accuracyLevel, 0, 3)) {
    case 0: return {3000, 1, 1, 1, 350};
    case 1: return {8000, 1, 1, 1, 1000};
    case 2: return {15000, 2, 1, 1, 1500};
    case 3: return {30000, 2, 2, 2, 2000};
    default: return {8000, 1, 1, 1, 1000};
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
