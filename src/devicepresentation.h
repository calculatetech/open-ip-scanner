#pragma once

#include "scanresult.h"

#include <QString>

enum MacDisplayFormat {
    MacColonUpper = 0,
    MacColonLower = 1,
    MacHyphenUpper = 2,
    MacHyphenLower = 3,
    MacCiscoDot = 4,
    MacPlainUpper = 5,
    MacPlainLower = 6
};

QString normalizeMacHex12(const QString &mac);
QString formatMacAddress(const QString &mac, int displayFormat);
QString deviceDetailsHtml(const ScanResult &result, int macDisplayFormat);
