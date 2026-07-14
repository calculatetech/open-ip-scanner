#pragma once

#include <QList>
#include <QString>
#include <QStringList>

enum class HostnameSource : int {
    Unknown = 0,
    Preliminary = 100,
    AvahiMdns = 300,
    SystemResolver = 400,
    DnsPtr = 500,
    LocalHost = 600
};

struct HostnameEvidence {
    QString hostname;
    HostnameSource source = HostnameSource::Unknown;
};

struct HostnameDisplayRow {
    QString hostname;
    QStringList sourceLabels;
    bool preferred = false;
};

QString normalizedHostnameKey(const QString &hostname);
QString hostnameSourceLabel(HostnameSource source);
QString qualifyHostname(const QString &hostname, const QString &dnsSuffix);
QString preferredPtrHostname(const QStringList &hostnames,
                             const QStringList &adapterDnsSuffixes);
QList<HostnameEvidence> mergeHostnameEvidence(
    const QList<HostnameEvidence> &current,
    const HostnameEvidence &candidate);
QList<HostnameEvidence> canonicalHostnameEvidence(
    const QList<HostnameEvidence> &evidence);
HostnameEvidence preferredHostname(const QList<HostnameEvidence> &evidence);
HostnameEvidence preferredHostname(const HostnameEvidence &current,
                                   const HostnameEvidence &candidate);
QList<HostnameDisplayRow> hostnameDisplayRows(
    const QList<HostnameEvidence> &evidence);
QString ipv4PtrQueryName(const QString &address);
