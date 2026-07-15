#pragma once

#include "hostnameevidence.h"
#include "resolverdiagnostics.h"
#include "serviceevidence.h"

#include <QList>
#include <QString>

enum class DiscoveryMethod {
    Unknown,
    Local,
    Gateway,
    Ping,
    Service,
    Neighbor
};

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
    DiscoveryMethod discoveryMethod = DiscoveryMethod::Unknown;
};

QString discoveryMethodLabel(DiscoveryMethod method);
