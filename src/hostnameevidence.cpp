#include "hostnameevidence.h"

#include <QHostAddress>
#include <QMap>
#include <QSet>

#include <algorithm>

namespace {

bool isUsable(const HostnameEvidence &evidence)
{
    return !normalizedHostnameKey(evidence.hostname).isEmpty();
}

} // namespace

QString normalizedHostnameKey(const QString &hostname)
{
    QString normalized = hostname.trimmed();
    while (normalized.endsWith('.')) {
        normalized.chop(1);
    }
    if (normalized.isEmpty() || normalized.compare("Unknown", Qt::CaseInsensitive) == 0) {
        return {};
    }
    return normalized.toCaseFolded();
}

QString hostnameSourceLabel(HostnameSource source)
{
    switch (source) {
    case HostnameSource::LocalHost: return "Local";
    case HostnameSource::DnsPtr: return "PTR";
    case HostnameSource::SystemResolver: return "System";
    case HostnameSource::AvahiMdns: return "mDNS";
    case HostnameSource::Preliminary: return "Preliminary";
    case HostnameSource::Unknown: return "Unknown";
    }
    return "Unknown";
}

QList<HostnameEvidence> mergeHostnameEvidence(
    const QList<HostnameEvidence> &current,
    const HostnameEvidence &candidate)
{
    QList<HostnameEvidence> merged = current;
    const QString key = normalizedHostnameKey(candidate.hostname);
    if (key.isEmpty()) {
        return merged;
    }
    const auto duplicate = std::find_if(
        merged.cbegin(), merged.cend(), [&](const HostnameEvidence &existing) {
            return normalizedHostnameKey(existing.hostname) == key &&
                   existing.source == candidate.source;
        });
    if (duplicate == merged.cend()) {
        HostnameEvidence normalized = candidate;
        normalized.hostname = candidate.hostname.trimmed();
        while (normalized.hostname.endsWith('.')) {
            normalized.hostname.chop(1);
        }
        merged.append(normalized);
    }
    return merged;
}

HostnameEvidence preferredHostname(const QList<HostnameEvidence> &evidence)
{
    HostnameEvidence best;
    for (const HostnameEvidence &candidate : evidence) {
        if (!isUsable(candidate)) {
            continue;
        }
        if (!isUsable(best) || static_cast<int>(candidate.source) >
                                   static_cast<int>(best.source)) {
            best = candidate;
        }
    }
    return best;
}

HostnameEvidence preferredHostname(const HostnameEvidence &current,
                                   const HostnameEvidence &candidate)
{
    return preferredHostname(mergeHostnameEvidence({current}, candidate));
}

QList<HostnameDisplayRow> hostnameDisplayRows(
    const QList<HostnameEvidence> &evidence)
{
    const HostnameEvidence preferred = preferredHostname(evidence);
    const QString preferredKey = normalizedHostnameKey(preferred.hostname);
    QMap<QString, HostnameDisplayRow> grouped;
    QMap<QString, QSet<QString>> labels;
    for (const HostnameEvidence &item : evidence) {
        const QString key = normalizedHostnameKey(item.hostname);
        if (key.isEmpty()) {
            continue;
        }
        if (!grouped.contains(key)) {
            grouped.insert(key, {item.hostname, {}, key == preferredKey});
        }
        labels[key].insert(hostnameSourceLabel(item.source));
    }

    QList<HostnameDisplayRow> rows;
    rows.reserve(grouped.size());
    for (auto it = grouped.cbegin(); it != grouped.cend(); ++it) {
        HostnameDisplayRow row = it.value();
        if (row.preferred) {
            row.hostname = preferred.hostname;
        }
        QStringList ordered;
        const QList<HostnameSource> sourceOrder = {
            HostnameSource::LocalHost,
            HostnameSource::DnsPtr,
            HostnameSource::SystemResolver,
            HostnameSource::AvahiMdns,
            HostnameSource::Preliminary};
        for (HostnameSource source : sourceOrder) {
            const QString label = hostnameSourceLabel(source);
            if (labels.value(it.key()).contains(label)) {
                ordered.append(label);
            }
        }
        row.sourceLabels = ordered;
        rows.append(row);
    }
    std::stable_sort(rows.begin(), rows.end(), [](const HostnameDisplayRow &left,
                                                   const HostnameDisplayRow &right) {
        if (left.preferred != right.preferred) {
            return left.preferred;
        }
        return QString::compare(left.hostname, right.hostname, Qt::CaseInsensitive) < 0;
    });
    return rows;
}

QString ipv4PtrQueryName(const QString &address)
{
    QHostAddress parsed;
    if (!parsed.setAddress(address) ||
        parsed.protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }
    const quint32 value = parsed.toIPv4Address();
    return QString("%1.%2.%3.%4.in-addr.arpa")
        .arg(value & 0xffu)
        .arg((value >> 8) & 0xffu)
        .arg((value >> 16) & 0xffu)
        .arg((value >> 24) & 0xffu);
}
