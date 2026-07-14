#include "scanbudget.h"

#include <cstdlib>
#include <string_view>

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

    require(fast.targetDeadlineMs == 5000 && fast.pingAttempts == 1 &&
            fast.pingTimeoutSeconds == 1 && fast.serviceAttempts == 1 &&
            fast.serviceTimeoutMs == 350);
    require(balanced.targetDeadlineMs == 11000 && balanced.pingAttempts == 2 &&
            balanced.pingTimeoutSeconds == 1 && balanced.serviceAttempts == 2 &&
            balanced.serviceTimeoutMs == 750);
    require(high.targetDeadlineMs == 25000 && high.pingAttempts == 3 &&
            high.pingTimeoutSeconds == 2 && high.serviceAttempts == 3 &&
            high.serviceTimeoutMs == 1250);
    require(maximum.targetDeadlineMs == 50000 && maximum.pingAttempts == 4 &&
            maximum.pingTimeoutSeconds == 3 && maximum.serviceAttempts == 4 &&
            maximum.serviceTimeoutMs == 2000);
    require(scanBudgetProfile(-1).targetDeadlineMs == fast.targetDeadlineMs);
    require(scanBudgetProfile(99).targetDeadlineMs == maximum.targetDeadlineMs);

    require(estimatedScanUpperBoundMs(4096, 4, maximum.targetDeadlineMs) == 51507200);
    require(estimatedScanUpperBoundMs(5, 4, balanced.targetDeadlineMs) == 22600);
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
    require(std::string_view(scanBudgetProfileSummary(0)).find("1 attempt") == 0);
    require(std::string_view(scanBudgetProfileSummary(1)).find("2 attempts") == 0);
    require(std::string_view(scanBudgetProfileSummary(2)).find("3 attempts") == 0);
    require(std::string_view(scanBudgetProfileSummary(3)).find("4 attempts") == 0);

    require(targetDeadlineForProfile(fast, 0) == 5000);
    require(targetDeadlineForProfile(fast, 4) == 5000);
    require(targetDeadlineForProfile(fast, 10) == 7000);
    require(targetDeadlineForProfile(balanced, 4) == 11000);
    require(targetDeadlineForProfile(balanced, 10) == 20000);
    require(targetDeadlineForProfile(high, 4) == 25000);
    require(targetDeadlineForProfile(high, 10) == 47000);
    require(targetDeadlineForProfile(maximum, 4) == 50000);
    require(targetDeadlineForProfile(maximum, 10) == 96000);

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
