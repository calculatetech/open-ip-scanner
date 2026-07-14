#include "resolverdiagnostics.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>

namespace {

QString resolverKey(ResolverKind resolver)
{
    switch (resolver) {
    case ResolverKind::Mdns: return "mdns";
    case ResolverKind::DnsPtr: return "ptr";
    case ResolverKind::System: return "system";
    }
    return "unknown";
}

QString resolverLabel(ResolverKind resolver)
{
    switch (resolver) {
    case ResolverKind::Mdns: return "mDNS";
    case ResolverKind::DnsPtr: return "PTR";
    case ResolverKind::System: return "System";
    }
    return "Unknown";
}

QString outcomeKey(ResolverOutcome outcome)
{
    switch (outcome) {
    case ResolverOutcome::Resolved: return "resolved";
    case ResolverOutcome::NoRecord: return "no_record";
    case ResolverOutcome::TimedOut: return "timeout";
    case ResolverOutcome::Cancelled: return "cancelled";
    case ResolverOutcome::BackendUnavailable: return "backend_unavailable";
    case ResolverOutcome::DaemonUnavailable: return "daemon_unavailable";
    case ResolverOutcome::MulticastUnavailable: return "multicast_unavailable";
    case ResolverOutcome::InvalidResponse: return "invalid_response";
    }
    return "unknown";
}

QString outcomeLabel(ResolverOutcome outcome)
{
    switch (outcome) {
    case ResolverOutcome::Resolved: return "Resolved";
    case ResolverOutcome::NoRecord: return "No record";
    case ResolverOutcome::TimedOut: return "Timeout";
    case ResolverOutcome::Cancelled: return "Cancelled";
    case ResolverOutcome::BackendUnavailable: return "Backend unavailable";
    case ResolverOutcome::DaemonUnavailable: return "Daemon unavailable";
    case ResolverOutcome::MulticastUnavailable: return "Multicast unavailable";
    case ResolverOutcome::InvalidResponse: return "Invalid response";
    }
    return "Unknown";
}

QMap<QString, int> countsFor(const QList<ResolverEvent> &events)
{
    QMap<QString, int> counts;
    for (const ResolverEvent &event : events) {
        const QString key = resolverKey(event.resolver) + "." + outcomeKey(event.outcome);
        counts[key] = counts.value(key) + 1;
    }
    return counts;
}

QString mdnsHealth(const QMap<QString, int> &counts)
{
    if (counts.value("mdns.daemon_unavailable") > 0) {
        return "Daemon unavailable";
    }
    if (counts.value("mdns.multicast_unavailable") > 0) {
        return "Multicast unavailable";
    }
    if (counts.value("mdns.backend_unavailable") > 0) {
        return "Backend unavailable";
    }
    if (counts.value("mdns.resolved") > 0 ||
        counts.value("mdns.no_record") > 0 ||
        counts.value("mdns.invalid_response") > 0) {
        return "Available";
    }
    if (counts.value("mdns.timeout") > 0) {
        return "Unresponsive";
    }
    return "Not observed";
}

} // namespace

bool operator==(const ResolverEvent &left, const ResolverEvent &right)
{
    return left.resolver == right.resolver && left.outcome == right.outcome;
}

QList<ResolverEvent> mergeResolverEvents(const QList<ResolverEvent> &current,
                                         const ResolverEvent &candidate)
{
    QList<ResolverEvent> merged = current;
    if (!merged.contains(candidate)) {
        merged.append(candidate);
    }
    return merged;
}

QString resolverDiagnosticsText(const QList<ResolverEvent> &events)
{
    const QMap<QString, int> counts = countsFor(events);
    QStringList lines;
    lines << "Hostname enrichment";
    lines << QString("mDNS backend: %1").arg(mdnsHealth(counts));
    lines << "mDNS client: Built-in Qt D-Bus";
    if (counts.isEmpty()) {
        lines << "No resolver observations recorded.";
        return lines.join('\n');
    }
    lines << QString();
    const QList<ResolverKind> resolverOrder = {
        ResolverKind::Mdns, ResolverKind::DnsPtr, ResolverKind::System};
    const QList<ResolverOutcome> outcomeOrder = {
        ResolverOutcome::Resolved,
        ResolverOutcome::NoRecord,
        ResolverOutcome::TimedOut,
        ResolverOutcome::Cancelled,
        ResolverOutcome::DaemonUnavailable,
        ResolverOutcome::MulticastUnavailable,
        ResolverOutcome::BackendUnavailable,
        ResolverOutcome::InvalidResponse};
    for (ResolverKind resolver : resolverOrder) {
        for (ResolverOutcome outcome : outcomeOrder) {
            const int count = counts.value(resolverKey(resolver) + "." + outcomeKey(outcome));
            if (count > 0) {
                lines << QString("%1 %2: %3")
                             .arg(resolverLabel(resolver), outcomeLabel(outcome))
                             .arg(count);
            }
        }
    }
    if (counts.value("mdns.daemon_unavailable") > 0) {
        lines << QString() << "Remediation: Start or install avahi-daemon.";
    } else if (counts.value("mdns.multicast_unavailable") > 0) {
        lines << QString() << "Remediation: Check adapter multicast support and firewall rules.";
    }
    return lines.join('\n');
}

QByteArray resolverSupportBundleJson(const QList<ResolverEvent> &events,
                                     const QString &applicationVersion,
                                     const QString &platformName)
{
    const QMap<QString, int> counts = countsFor(events);
    QJsonObject countObject;
    for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
        countObject.insert(it.key(), it.value());
    }
    QJsonObject enrichment;
    enrichment.insert("mdns_backend", mdnsHealth(counts));
    enrichment.insert("mdns_client", "Qt D-Bus");
    enrichment.insert("counts", countObject);

    QJsonObject root;
    root.insert("application", "Open IP Scanner");
    root.insert("version", applicationVersion);
    root.insert("platform", platformName);
    root.insert("hostname_enrichment", enrichment);
    return QJsonDocument(root).toJson(QJsonDocument::Indented);
}
