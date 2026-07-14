#pragma once

#include "hostnameevidence.h"
#include "serviceevidence.h"

#include <QList>
#include <QString>

struct ServiceHit {
    QString id;
    QString label;
    int port = 0;
    bool isWeb = false;
    ServiceEvidenceLevel evidence = ServiceEvidenceLevel::OpenPort;
};

struct ScanResult {
    QString ip;
    QString interfaceName;
    QString mac;
    QString vendor;
    QString hostname;
    HostnameQuality hostnameQuality = HostnameQuality::Unknown;
    QList<ServiceHit> services;
    QString detailsText;
};
