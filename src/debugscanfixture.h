#pragma once

#include "scanresult.h"

bool isDebugScanFixtureTarget(const QString &targetText);
int debugScanFixtureResultCount();
int debugScanFixtureIntervalMs(int accuracyLevel);
ScanResult debugScanFixtureResult(int index);
