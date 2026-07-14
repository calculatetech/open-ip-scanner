#include "targetdefaults.h"

#include <QHostAddress>
#include <QHash>
#include <QSet>

#include <algorithm>

namespace {

QString addressText(quint32 value)
{
    return QHostAddress(value).toString();
}

QString serializeAddresses(const QSet<quint32> &accepted)
{
    QList<quint32> addresses = accepted.values();
    std::sort(addresses.begin(), addresses.end());
    QStringList ranges;
    for (int index = 0; index < addresses.size();) {
        const quint32 first = addresses[index];
        quint32 last = first;
        ++index;
        while (index < addresses.size() && addresses[index] == last + 1) {
            last = addresses[index];
            ++index;
        }
        ranges.append(first == last ? addressText(first)
                                    : QString("%1-%2").arg(addressText(first), addressText(last)));
    }
    return ranges.join(", ");
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
                                         int maxTextCharacters)
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

    plan.targetText = serializeAddresses(accepted);
    while (plan.targetText.size() > maxTextCharacters && !acceptedOrder.isEmpty()) {
        const quint32 address = acceptedOrder.takeLast();
        accepted.remove(address);
        appendOmittedInterface(&plan, acceptedLabels.value(address));
        plan.targetText = serializeAddresses(accepted);
    }
    plan.uniqueHostCount = accepted.size();
    return plan;
}
