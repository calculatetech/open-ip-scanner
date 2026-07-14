#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <utility>

struct ScanBudgetProfile {
    int targetDeadlineMs = 11000;
    int pingAttempts = 2;
    int pingTimeoutSeconds = 1;
    int serviceAttempts = 2;
    int serviceTimeoutMs = 750;
};

constexpr int kProcessCleanupReserveMs = 50;
constexpr int kEstimatePerTargetAllowanceMs = 300;
constexpr int kPingProcessStartupAllowanceMs = 500;
constexpr int kNonServiceStageReserveMs = 2000;

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
    case 0: return {5000, 1, 1, 1, 350};
    case 1: return {11000, 2, 1, 2, 750};
    case 2: return {25000, 3, 2, 3, 1250};
    case 3: return {50000, 4, 3, 4, 2000};
    default: return {11000, 2, 1, 2, 750};
    }
}

inline int targetDeadlineForProfile(const ScanBudgetProfile &profile, int enabledServiceCount)
{
    if (enabledServiceCount <= 0) {
        return profile.targetDeadlineMs;
    }
    const std::int64_t pingWork =
        static_cast<std::int64_t>(profile.pingAttempts) *
        pingAttemptWaitMs(profile.pingTimeoutSeconds);
    const std::int64_t serviceWork =
        static_cast<std::int64_t>(enabledServiceCount) * profile.serviceAttempts *
        profile.serviceTimeoutMs;
    const std::int64_t required = pingWork + serviceWork + kNonServiceStageReserveMs;
    return static_cast<int>(std::min<std::int64_t>(
        std::max<std::int64_t>(profile.targetDeadlineMs, required),
        std::numeric_limits<int>::max()));
}

inline const char *scanBudgetProfileSummary(int accuracyLevel)
{
    switch (std::clamp(accuracyLevel, 0, 3)) {
    case 0: return "1 attempt; 1 s ping / 350 ms port wait";
    case 1: return "2 attempts; 1 s ping / 750 ms port wait";
    case 2: return "3 attempts; 2 s ping / 1.25 s port wait";
    case 3: return "4 attempts; 3 s ping / 2 s port wait";
    default: return "2 attempts; 1 s ping / 750 ms port wait";
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
