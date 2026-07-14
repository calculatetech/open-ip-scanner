#pragma once

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

// Value-owned policy and data captured on the UI thread before a scan starts.
// Scan workers receive this object as const data and never consult mutable
// ScannerWindow settings.
struct ScanOptions {
    int accuracyLevel = 1;
    int maxParallelProbes = 4;

    QString interfaceName;
    QString interfaceLabel;
    QString localIp;
    QString localMac;
    QStringList dnsSuffixes;

    int pingAttempts = 2;
    int pingTimeoutSeconds = 1;
    int serviceAttempts = 2;
    int serviceTimeoutMs = 750;
    int neighborConfirmationMs = 5500;
    int targetDeadlineMs = 11000;
    int macDisplayFormat = 0;

    QSet<QString> enabledServiceIds;
    QHash<QString, QString> builtInOuiVendors;
    QHash<QString, QString> customOuiVendors;
};
