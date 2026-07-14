#include "targetparser.h"

#include <QAbstractSocket>
#include <QSet>

#include <algorithm>

namespace {
bool parseIpv4(const QString &text, quint32 *value)
{
    QHostAddress address;
    if (!address.setAddress(text) ||
        address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    *value = address.toIPv4Address();
    return true;
}

QString limitError(int maximumHosts)
{
    return QString("Too many targets (%1 max). Narrow the range.").arg(maximumHosts);
}

bool appendRange(quint32 start,
                 quint32 end,
                 int maximumHosts,
                 QSet<quint32> *unique,
                 QString *error)
{
    if (start > end) {
        std::swap(start, end);
    }
    const quint64 count = static_cast<quint64>(end) - start + 1ULL;
    if (count > static_cast<quint64>(maximumHosts)) {
        *error = limitError(maximumHosts);
        return false;
    }
    for (quint32 value = start; value <= end; ++value) {
        unique->insert(value);
        if (unique->size() > maximumHosts) {
            *error = limitError(maximumHosts);
            return false;
        }
        if (value == 0xFFFFFFFFu) {
            break;
        }
    }
    return true;
}
} // namespace

TargetParseResult TargetParser::parse(const QString &text, int maximumHosts)
{
    TargetParseResult result;
    if (maximumHosts < 1) {
        result.error = "The target limit must be positive.";
        return result;
    }

    const QStringList tokens = text.split(',', Qt::SkipEmptyParts);
    if (tokens.isEmpty()) {
        result.error = "Enter at least one target (CIDR, range, or IP).";
        return result;
    }

    QSet<quint32> unique;
    for (const QString &rawToken : tokens) {
        const QString token = rawToken.trimmed();
        if (token.isEmpty()) {
            continue;
        }

        if (token.contains('/')) {
            const QStringList parts = token.split('/');
            bool prefixValid = false;
            const int prefix = parts.size() == 2 ? parts[1].toInt(&prefixValid) : 0;
            quint32 address = 0;
            if (parts.size() != 2 || !prefixValid || prefix < 1 || prefix > 32 ||
                !parseIpv4(parts[0], &address)) {
                result.error = QString("Invalid CIDR: %1").arg(token);
                return result;
            }

            const int hostBits = 32 - prefix;
            const quint32 mask = prefix == 32 ? 0xFFFFFFFFu
                                               : (0xFFFFFFFFu << hostBits);
            const quint32 network = address & mask;
            const quint64 addressCount = 1ULL << hostBits;
            const quint32 start = prefix >= 31 ? network : network + 1;
            const quint32 end = prefix == 32
                                    ? network
                                    : prefix == 31
                                          ? network + 1
                                          : network + static_cast<quint32>(addressCount) - 2;
            if (!appendRange(start, end, maximumHosts, &unique, &result.error)) {
                return result;
            }
            continue;
        }

        if (token.contains('-')) {
            const QStringList parts = token.split('-');
            if (parts.size() != 2) {
                result.error = QString("Invalid range: %1").arg(token);
                return result;
            }
            const QString left = parts[0].trimmed();
            const QString right = parts[1].trimmed();
            quint32 start = 0;
            if (!parseIpv4(left, &start)) {
                result.error = QString("Invalid range start: %1").arg(left);
                return result;
            }
            quint32 end = 0;
            if (right.contains('.')) {
                if (!parseIpv4(right, &end)) {
                    result.error = QString("Invalid range end: %1").arg(right);
                    return result;
                }
            } else {
                bool octetValid = false;
                const int octet = right.toInt(&octetValid);
                if (!octetValid || octet < 0 || octet > 255) {
                    result.error = QString("Invalid range end: %1").arg(right);
                    return result;
                }
                end = (start & 0xFFFFFF00u) | static_cast<quint32>(octet);
            }
            if (!appendRange(start, end, maximumHosts, &unique, &result.error)) {
                return result;
            }
            continue;
        }

        quint32 address = 0;
        if (!parseIpv4(token, &address)) {
            result.error = QString("Invalid IP address: %1").arg(token);
            return result;
        }
        unique.insert(address);
        if (unique.size() > maximumHosts) {
            result.error = limitError(maximumHosts);
            return result;
        }
    }

    if (unique.isEmpty()) {
        result.error = "Enter at least one target (CIDR, range, or IP).";
        return result;
    }

    QList<quint32> addresses = unique.values();
    std::sort(addresses.begin(), addresses.end());
    result.hosts.reserve(addresses.size());
    for (const quint32 address : addresses) {
        result.hosts.append(QHostAddress(address));
    }
    return result;
}
