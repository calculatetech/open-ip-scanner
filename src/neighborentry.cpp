#include "neighborentry.h"

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSet>

namespace {

NeighborState parseStateName(const QString &name)
{
    const QString state = name.trimmed().toUpper();
    if (state == "INCOMPLETE") return NeighborState::Incomplete;
    if (state == "REACHABLE") return NeighborState::Reachable;
    if (state == "STALE") return NeighborState::Stale;
    if (state == "DELAY") return NeighborState::Delay;
    if (state == "PROBE") return NeighborState::Probe;
    if (state == "FAILED") return NeighborState::Failed;
    if (state == "NOARP") return NeighborState::NoArp;
    if (state == "PERMANENT") return NeighborState::Permanent;
    return NeighborState::None;
}

NeighborState parseState(const QJsonValue &value)
{
    if (value.isString()) {
        return parseStateName(value.toString());
    }
    if (!value.isArray()) {
        return NeighborState::None;
    }
    for (const QJsonValue &item : value.toArray()) {
        const NeighborState state = parseStateName(item.toString());
        if (state != NeighborState::None) {
            return state;
        }
    }
    return NeighborState::None;
}

QString normalizedUnicastMac(const QString &value)
{
    static const QRegularExpression macPattern(
        "^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$");
    const QString mac = value.trimmed();
    if (!macPattern.match(mac).hasMatch()) {
        return {};
    }

    const QString normalized = mac.toUpper();
    if (normalized == "00:00:00:00:00:00" || normalized == "FF:FF:FF:FF:FF:FF") {
        return {};
    }
    bool ok = false;
    const int firstOctet = normalized.left(2).toInt(&ok, 16);
    if (!ok || (firstOctet & 0x01) != 0) {
        return {};
    }
    return normalized;
}

bool stateSuppliesMac(NeighborState state)
{
    return state == NeighborState::Reachable || state == NeighborState::Stale ||
           state == NeighborState::Delay || state == NeighborState::Probe ||
           state == NeighborState::Permanent;
}

bool stateEstablishesLiveness(NeighborState state)
{
    return state == NeighborState::Reachable;
}

} // namespace

QString neighborIdentityKey(const QString &interfaceName, const QString &ip)
{
    return interfaceName + QChar('\n') + ip;
}

QString NeighborObservation::identityKey() const
{
    return neighborIdentityKey(interfaceName, ip);
}

bool NeighborObservation::suppliesMacMetadata() const
{
    return !mac.isEmpty() && stateSuppliesMac(state);
}

bool NeighborObservation::establishesLiveness() const
{
    return suppliesMacMetadata() && stateEstablishesLiveness(state);
}

QList<NeighborObservation> parseLinuxNeighborJson(const QByteArray &json,
                                                  const QString &expectedInterface,
                                                  QString *error)
{
    if (error != nullptr) {
        error->clear();
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isArray()) {
        if (error != nullptr) {
            *error = QString("Invalid ip-neighbor JSON: %1").arg(parseError.errorString());
        }
        return {};
    }

    QList<NeighborObservation> observations;
    QSet<QString> seenIdentities;
    for (const QJsonValue &value : document.array()) {
        if (!value.isObject()) {
            continue;
        }
        const QJsonObject object = value.toObject();
        const QString ip = object.value("dst").toString().trimmed();
        const QString reportedInterface = object.value("dev").toString().trimmed();
        const QString interfaceName = reportedInterface.isEmpty() ? expectedInterface
                                                                   : reportedInterface;
        QHostAddress address;
        if (!address.setAddress(ip) || address.protocol() != QAbstractSocket::IPv4Protocol ||
            interfaceName.isEmpty() ||
            (!expectedInterface.isEmpty() && !reportedInterface.isEmpty() &&
             reportedInterface != expectedInterface)) {
            continue;
        }

        NeighborObservation observation;
        observation.ip = address.toString();
        observation.interfaceName = interfaceName;
        observation.mac = normalizedUnicastMac(object.value("lladdr").toString());
        observation.state = parseState(object.value("state"));
        if (!stateSuppliesMac(observation.state)) {
            observation.mac.clear();
        }

        const QString key = observation.identityKey();
        if (!seenIdentities.contains(key)) {
            observations.append(observation);
            seenIdentities.insert(key);
        }
    }
    return observations;
}
