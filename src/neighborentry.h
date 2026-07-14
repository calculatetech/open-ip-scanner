#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

enum class NeighborState {
    None,
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    NoArp,
    Permanent
};

struct NeighborObservation {
    QString ip;
    QString interfaceName;
    QString mac;
    NeighborState state = NeighborState::None;

    QString identityKey() const;
    bool suppliesMacMetadata() const;
    bool establishesLiveness() const;
};

QString neighborIdentityKey(const QString &interfaceName, const QString &ip);
QList<NeighborObservation> parseLinuxNeighborJson(const QByteArray &json,
                                                  const QString &expectedInterface,
                                                  QString *error = nullptr);
