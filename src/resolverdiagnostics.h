#pragma once

#include <QList>
#include <QString>

enum class ResolverKind {
    Mdns,
    DnsPtr,
    System
};

enum class ResolverOutcome {
    Resolved,
    NoRecord,
    TimedOut,
    Cancelled,
    BackendUnavailable,
    DaemonUnavailable,
    MulticastUnavailable,
    InvalidResponse
};

struct ResolverEvent {
    ResolverKind resolver = ResolverKind::Mdns;
    ResolverOutcome outcome = ResolverOutcome::BackendUnavailable;
};

bool operator==(const ResolverEvent &left, const ResolverEvent &right);
QList<ResolverEvent> mergeResolverEvents(const QList<ResolverEvent> &current,
                                         const ResolverEvent &candidate);
QString resolverDiagnosticsText(const QList<ResolverEvent> &events);
QByteArray resolverSupportBundleJson(const QList<ResolverEvent> &events,
                                     const QString &applicationVersion,
                                     const QString &platformName);
