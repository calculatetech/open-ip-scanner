#pragma once

#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

enum class TargetTextFormat {
    Cidr,
    Range
};

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
                                         int maxTextCharacters = 2048,
                                         TargetTextFormat format = TargetTextFormat::Cidr);
