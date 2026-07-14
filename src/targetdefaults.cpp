#include "targetdefaults.h"

#include <QHostAddress>
#include <QHash>
#include <QMap>
#include <QSet>

#include <algorithm>

namespace {

QString addressText(quint32 value)
{
    return QHostAddress(value).toString();
}

QList<QPair<quint32, quint32>> contiguousIntervals(
    const QSet<quint32> &accepted)
{
    QList<quint32> addresses = accepted.values();
    std::sort(addresses.begin(), addresses.end());
    QList<QPair<quint32, quint32>> intervals;
    for (int index = 0; index < addresses.size();) {
        const quint32 first = addresses[index];
        quint32 last = first;
        ++index;
        while (index < addresses.size() && last != 0xFFFFFFFFu &&
               addresses[index] == last + 1) {
            last = addresses[index];
            ++index;
        }
        intervals.append({first, last});
    }
    return intervals;
}

QString serializeRanges(const QSet<quint32> &accepted)
{
    QStringList ranges;
    for (const auto &interval : contiguousIntervals(accepted)) {
        ranges.append(interval.first == interval.second
                          ? addressText(interval.first)
                          : QString("%1-%2")
                                .arg(addressText(interval.first),
                                     addressText(interval.second)));
    }
    return ranges.join(", ");
}

QString serializeCidrs(const QSet<quint32> &accepted)
{
    QStringList cidrs;
    for (const auto &interval : contiguousIntervals(accepted)) {
        quint64 current = interval.first;
        const quint64 last = interval.second;
        while (current <= last) {
            int selectedPrefix = 32;
            quint64 selectedNetwork = current;
            quint64 selectedLast = current;

            if (current > 0) {
                const quint64 candidateNetwork = current - 1;
                for (int prefix = 1; prefix <= 30; ++prefix) {
                    const int hostBits = 32 - prefix;
                    const quint64 blockSize = quint64{1} << hostBits;
                    if (candidateNetwork % blockSize != 0) {
                        continue;
                    }
                    const quint64 candidateLast =
                        candidateNetwork + blockSize - 2;
                    if (candidateLast <= last) {
                        selectedPrefix = prefix;
                        selectedNetwork = candidateNetwork;
                        selectedLast = candidateLast;
                        break;
                    }
                }
            }
            if (selectedPrefix == 32 && current % 2 == 0 &&
                current + 1 <= last) {
                selectedPrefix = 31;
                selectedLast = current + 1;
            }

            cidrs.append(QString("%1/%2")
                             .arg(addressText(static_cast<quint32>(selectedNetwork)))
                             .arg(selectedPrefix));
            current = selectedLast + 1;
        }
    }
    return cidrs.join(", ");
}

struct TextMeasure {
    int tokenCharacters = 0;
    int tokenCount = 0;

    int joinedCharacters() const
    {
        return tokenCount == 0 ? 0
                               : tokenCharacters + 2 * (tokenCount - 1);
    }
};

int decimalLength(quint32 value)
{
    if (value >= 100) {
        return 3;
    }
    if (value >= 10) {
        return 2;
    }
    return 1;
}

int addressLength(quint32 value)
{
    return decimalLength((value >> 24) & 0xFFu) +
           decimalLength((value >> 16) & 0xFFu) +
           decimalLength((value >> 8) & 0xFFu) +
           decimalLength(value & 0xFFu) + 3;
}

QPair<TextMeasure, TextMeasure> intervalMeasures(quint32 first,
                                                 quint32 last)
{
    TextMeasure range;
    range.tokenCount = 1;
    range.tokenCharacters = first == last
                                ? addressLength(first)
                                : addressLength(first) + 1 +
                                      addressLength(last);

    TextMeasure cidr;
    quint64 current = first;
    while (current <= last) {
        int selectedPrefix = 32;
        quint64 selectedNetwork = current;
        quint64 selectedLast = current;
        if (current > 0) {
            const quint64 candidateNetwork = current - 1;
            for (int prefix = 1; prefix <= 30; ++prefix) {
                const quint64 blockSize = quint64{1} << (32 - prefix);
                if (candidateNetwork % blockSize == 0 &&
                    candidateNetwork + blockSize - 2 <= last) {
                    selectedPrefix = prefix;
                    selectedNetwork = candidateNetwork;
                    selectedLast = candidateNetwork + blockSize - 2;
                    break;
                }
            }
        }
        if (selectedPrefix == 32 && current % 2 == 0 &&
            current + 1 <= last) {
            selectedPrefix = 31;
            selectedLast = current + 1;
        }
        ++cidr.tokenCount;
        cidr.tokenCharacters +=
            addressLength(static_cast<quint32>(selectedNetwork)) + 1 +
            decimalLength(static_cast<quint32>(selectedPrefix));
        current = selectedLast + 1;
    }
    return {range, cidr};
}

int maximumFittingPrefix(const QList<quint32> &acceptedOrder,
                         int maxTextCharacters)
{
    QMap<quint32, quint32> intervals;
    TextMeasure rangeTotal;
    TextMeasure cidrTotal;
    int bestCount = 0;
    const auto apply = [](TextMeasure *total,
                          const TextMeasure &measure,
                          int direction) {
        total->tokenCharacters += direction * measure.tokenCharacters;
        total->tokenCount += direction * measure.tokenCount;
    };

    for (int index = 0; index < acceptedOrder.size(); ++index) {
        const quint32 address = acceptedOrder[index];
        auto next = intervals.lowerBound(address);
        const bool joinsNext = next != intervals.end() &&
                               quint64{address} + 1 == next.key();
        auto previous = next;
        const bool hasPrevious = previous != intervals.begin();
        if (hasPrevious) {
            --previous;
        }
        const bool joinsPrevious = hasPrevious &&
                                   quint64{previous.value()} + 1 == address;

        quint32 first = address;
        quint32 last = address;
        if (joinsPrevious) {
            first = previous.key();
            const auto measures = intervalMeasures(previous.key(),
                                                   previous.value());
            apply(&rangeTotal, measures.first, -1);
            apply(&cidrTotal, measures.second, -1);
            intervals.remove(previous.key());
        }
        if (joinsNext) {
            last = next.value();
            const auto measures = intervalMeasures(next.key(), next.value());
            apply(&rangeTotal, measures.first, -1);
            apply(&cidrTotal, measures.second, -1);
            intervals.remove(next.key());
        }

        intervals.insert(first, last);
        const auto measures = intervalMeasures(first, last);
        apply(&rangeTotal, measures.first, 1);
        apply(&cidrTotal, measures.second, 1);
        if (rangeTotal.joinedCharacters() <= maxTextCharacters &&
            cidrTotal.joinedCharacters() <= maxTextCharacters) {
            bestCount = index + 1;
        }
    }
    return bestCount;
}

void appendOmittedInterface(DefaultTargetPlan *plan, const QString &label)
{
    if (!label.isEmpty() && !plan->omittedInterfaces.contains(label)) {
        plan->omittedInterfaces.append(label);
    }
}

} // namespace

DefaultTargetPlan buildDefaultTargetPlan(const QList<DefaultNetworkInput> &networks,
                                         int maxHosts,
                                         int maxTextCharacters,
                                         TargetTextFormat format)
{
    DefaultTargetPlan plan;
    if (maxHosts <= 0 || maxTextCharacters <= 0) {
        return plan;
    }

    QSet<quint32> accepted;
    QList<quint32> acceptedOrder;
    QHash<quint32, QString> acceptedLabels;
    for (const DefaultNetworkInput &input : networks) {
        if (input.prefixLength < 1 || input.prefixLength > 32) {
            continue;
        }

        const int boundedPrefix = input.prefixLength <= 19 ? 24 : input.prefixLength;
        const int hostBits = 32 - boundedPrefix;
        const quint32 mask = boundedPrefix == 32 ? 0xFFFFFFFFu
                                                 : (0xFFFFFFFFu << hostBits);
        const quint32 network = input.localAddress & mask;
        quint32 first = network;
        quint32 last = network;
        if (boundedPrefix == 31) {
            last = network + 1;
        } else if (boundedPrefix < 31) {
            first = network + 1;
            last = network + ((1u << hostBits) - 2u);
        }

        bool omittedUniqueHost = false;
        for (quint64 value = first; value <= last; ++value) {
            const quint32 address = static_cast<quint32>(value);
            if (accepted.contains(address)) {
                continue;
            }
            if (accepted.size() >= maxHosts) {
                omittedUniqueHost = true;
                continue;
            }
            accepted.insert(address);
            acceptedOrder.append(address);
            acceptedLabels.insert(address,
                                  input.interfaceLabel.isEmpty() ? input.interfaceName
                                                                 : input.interfaceLabel);
        }
        if (omittedUniqueHost) {
            const QString label = input.interfaceLabel.isEmpty() ? input.interfaceName
                                                                  : input.interfaceLabel;
            appendOmittedInterface(&plan, label);
        }
    }

    QString rangeText = serializeRanges(accepted);
    QString cidrText = serializeCidrs(accepted);
    if (rangeText.size() > maxTextCharacters ||
        cidrText.size() > maxTextCharacters) {
        const int keepCount =
            maximumFittingPrefix(acceptedOrder, maxTextCharacters);
        QSet<quint32> bounded;
        bounded.reserve(keepCount);
        for (int index = 0; index < keepCount; ++index) {
            bounded.insert(acceptedOrder[index]);
        }
        rangeText = serializeRanges(bounded);
        cidrText = serializeCidrs(bounded);
        for (qsizetype index = acceptedOrder.size() - 1;
             index >= static_cast<qsizetype>(keepCount);
             --index) {
            appendOmittedInterface(
                &plan, acceptedLabels.value(acceptedOrder[index]));
        }
        accepted = std::move(bounded);
    }
    plan.targetText = format == TargetTextFormat::Cidr ? cidrText : rangeText;
    plan.uniqueHostCount = static_cast<int>(accepted.size());
    return plan;
}
