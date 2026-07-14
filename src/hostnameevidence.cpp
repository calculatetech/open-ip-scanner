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

QString shortHostnameKey(const QString &hostname)
{
    return normalizedHostnameKey(hostname).section('.', 0, 0);
}

bool isQualifiedHostname(const QString &hostname)
{
    return normalizedHostnameKey(hostname).contains('.');
}

bool inheritsObservedSuffix(HostnameSource source)
{
    return source == HostnameSource::LocalHost ||
           source == HostnameSource::SystemResolver;
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

QString qualifyHostname(const QString &hostname, const QString &dnsSuffix)
{
    QString normalized = hostname.trimmed();
    while (normalized.endsWith('.')) {
        normalized.chop(1);
    }
    QString suffix = dnsSuffix.trimmed();
    while (suffix.startsWith('.')) {
        suffix.remove(0, 1);
    }
    while (suffix.endsWith('.')) {
        suffix.chop(1);
    }
    if (normalizedHostnameKey(normalized).isEmpty() ||
        normalizedHostnameKey(suffix).isEmpty() ||
        isQualifiedHostname(normalized)) {
        return normalized;
    }
    return normalized + '.' + suffix;
}

QString preferredPtrHostname(const QStringList &hostnames,
                             const QStringList &adapterDnsSuffixes)
{
    QString best;
    int bestScore = -1;
    for (const QString &value : hostnames) {
        QString hostname = value.trimmed();
        while (hostname.endsWith('.')) {
            hostname.chop(1);
        }
        if (normalizedHostnameKey(hostname).isEmpty()) {
            continue;
        }

        int score = isQualifiedHostname(hostname) ? 100 : 0;
        QString selected = hostname;
        for (int index = 0; index < adapterDnsSuffixes.size(); ++index) {
            const QString suffix = normalizedHostnameKey(
                adapterDnsSuffixes.at(index));
            if (suffix.isEmpty()) {
                continue;
            }
            const QString key = normalizedHostnameKey(hostname);
            if (key == suffix ||
                key.endsWith(QStringLiteral(".") + suffix)) {
                score = 300 - index;
                break;
            }
            if (!isQualifiedHostname(hostname) && score < 200 - index) {
                score = 200 - index;
                selected = qualifyHostname(hostname, suffix);
            }
        }
        if (score > bestScore ||
            (score == bestScore && QString::compare(
                                      selected, best, Qt::CaseInsensitive) < 0)) {
            best = selected;
            bestScore = score;
        }
    }
    return best;
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

QList<HostnameEvidence> canonicalHostnameEvidence(
    const QList<HostnameEvidence> &evidence)
{
    QMap<QString, HostnameEvidence> qualifiedByShortName;
    for (const HostnameEvidence &item : evidence) {
        if (item.source != HostnameSource::DnsPtr ||
            !isQualifiedHostname(item.hostname)) {
            continue;
        }
        const QString shortKey = shortHostnameKey(item.hostname);
        const HostnameEvidence current = qualifiedByShortName.value(shortKey);
        if (!isUsable(current) || static_cast<int>(item.source) >
                                      static_cast<int>(current.source)) {
            qualifiedByShortName.insert(shortKey, item);
        }
    }

    QList<HostnameEvidence> canonical;
    canonical.reserve(evidence.size());
    for (HostnameEvidence item : evidence) {
        if (!isQualifiedHostname(item.hostname) &&
            inheritsObservedSuffix(item.source)) {
            const HostnameEvidence donor = qualifiedByShortName.value(
                shortHostnameKey(item.hostname));
            if (isUsable(donor)) {
                item.hostname = donor.hostname;
            }
        }
        const QString itemKey = normalizedHostnameKey(item.hostname);
        const auto existing = std::find_if(
            canonical.cbegin(), canonical.cend(), [&](const HostnameEvidence &value) {
                return value.source == item.source &&
                       normalizedHostnameKey(value.hostname) == itemKey;
            });
        if (existing == canonical.cend()) {
            canonical.append(item);
        }
    }
    return canonical;
}

HostnameEvidence preferredHostname(const QList<HostnameEvidence> &evidence)
{
    HostnameEvidence best;
    for (const HostnameEvidence &candidate : canonicalHostnameEvidence(evidence)) {
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
    const QList<HostnameEvidence> canonical = canonicalHostnameEvidence(evidence);
    const HostnameEvidence preferred = preferredHostname(canonical);
    const QString preferredKey = normalizedHostnameKey(preferred.hostname);
    QMap<QString, HostnameDisplayRow> grouped;
    QMap<QString, QSet<QString>> labels;
    for (const HostnameEvidence &item : canonical) {
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
