#pragma once

#include <QList>
#include <QString>
#include <QStringList>

struct DefaultNetworkInput {
    quint32 localAddress = 0;
    int prefixLength = 24;
    QString interfaceName;
    QString interfaceLabel;
};

struct DefaultTargetPlan {
    QString targetText;
    QStringList omittedInterfaces;
    int uniqueHostCount = 0;
};

DefaultTargetPlan buildDefaultTargetPlan(const QList<DefaultNetworkInput> &networks,
                                         int maxHosts = 4096,
                                         int maxTextCharacters = 2048);
