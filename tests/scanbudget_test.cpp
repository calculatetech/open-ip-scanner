#include "scanbudget.h"

#include <cstdlib>

namespace {

void require(bool condition)
{
    if (!condition) {
        std::abort();
    }
}

} // namespace

int main()
{
    const ScanBudgetProfile fast = scanBudgetProfile(0);
    const ScanBudgetProfile balanced = scanBudgetProfile(1);
    const ScanBudgetProfile high = scanBudgetProfile(2);
    const ScanBudgetProfile maximum = scanBudgetProfile(3);

    require(fast.targetDeadlineMs == 3000 && fast.pingAttempts == 1 &&
            fast.pingTimeoutSeconds == 1 && fast.serviceAttempts == 1 &&
            fast.serviceTimeoutMs == 350);
    require(balanced.targetDeadlineMs == 8000 && balanced.pingAttempts == 1 &&
            balanced.pingTimeoutSeconds == 1 && balanced.serviceAttempts == 1 &&
            balanced.serviceTimeoutMs == 1000);
    require(high.targetDeadlineMs == 15000 && high.pingAttempts == 2 &&
            high.pingTimeoutSeconds == 1 && high.serviceAttempts == 1 &&
            high.serviceTimeoutMs == 1500);
    require(maximum.targetDeadlineMs == 30000 && maximum.pingAttempts == 2 &&
            maximum.pingTimeoutSeconds == 2 && maximum.serviceAttempts == 2 &&
            maximum.serviceTimeoutMs == 2000);
    require(scanBudgetProfile(-1).targetDeadlineMs == fast.targetDeadlineMs);
    require(scanBudgetProfile(99).targetDeadlineMs == maximum.targetDeadlineMs);

    require(estimatedScanUpperBoundMs(4096, 4, maximum.targetDeadlineMs) == 31027200);
    require(estimatedScanUpperBoundMs(5, 4, balanced.targetDeadlineMs) == 16600);
    require(estimatedScanUpperBoundMs(0, 4, balanced.targetDeadlineMs) == 0);
    require(estimatedScanUpperBoundMs(5, 0, balanced.targetDeadlineMs) == 0);
    require(estimatedScanUpperBoundMs(-1, 4, balanced.targetDeadlineMs) == 0);
    require(estimatedScanUpperBoundMs(5, 4, -1) == 0);
    require(estimatedScanUpperBoundMs(5, 4, balanced.targetDeadlineMs, -1) == 0);

    require(kAliveHostStageOrder.front() == AliveHostStage::Services);
    require(kAliveHostStageOrder[1] == AliveHostStage::MacAddress);
    require(kAliveHostStageOrder[2] == AliveHostStage::Vendor);
    require(kAliveHostStageOrder[3] == AliveHostStage::Hostname);
    require(kAliveHostStageOrder[4] == AliveHostStage::NormalizeIdentity);
    require(kAliveHostStageOrder.back() == AliveHostStage::Details);
    require(pingAttemptWaitMs(1) == 1500);
    require(pingAttemptWaitMs(2) == 2500);
    require(pingAttemptWaitMs(0) == 0);

    TargetBudget::TimePoint now{};
    TargetBudget budget(100, [&]() { return now; });
    require(!budget.expired());
    require(budget.clampTimeout(1000) == 100);
    require(budget.clampTimeout(1000, 50) == 50);
    require(budget.clampTimeout(-1) == 0);
    now += std::chrono::milliseconds(100);
    require(budget.expired());
    require(budget.clampTimeout(1000) == 0);
    return EXIT_SUCCESS;
}
