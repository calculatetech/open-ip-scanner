#pragma once

#include "scanresult.h"

#include <atomic>
#include <functional>
#include <memory>

bool isDebugScanFixtureTarget(const QString &targetText);
int debugScanFixtureResultCount();
int debugScanFixtureIntervalMs(int accuracyLevel);
ScanResult debugScanFixtureResult(int index);
QList<ScanResult> runDebugScanFixture(
    int accuracyLevel,
    const std::shared_ptr<std::atomic_bool> &cancellation,
    const std::function<void(int, int)> &onProgress,
    const std::function<void(const ScanResult &)> &onResult);
