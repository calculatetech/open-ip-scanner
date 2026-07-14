#pragma once

#include "hostnameevidence.h"
#include "resolverdiagnostics.h"
#include "serviceevidence.h"

#include <QList>
#include <QString>

struct ScanResult {
    QString ip;
    QString interfaceName;
    QString mac;
    QString vendor;
    QString hostname;
    HostnameSource hostnameSource = HostnameSource::Unknown;
    QList<HostnameEvidence> hostnameEvidence;
    QList<ResolverEvent> resolverEvents;
    QList<ServiceHit> services;
    QString detailsText;
};
