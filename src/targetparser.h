#pragma once

#include <QHostAddress>
#include <QList>
#include <QString>

struct TargetParseResult {
    QList<QHostAddress> hosts;
    QString error;

    bool isValid() const { return error.isEmpty(); }
};

class TargetParser {
public:
    static TargetParseResult parse(const QString &text, int maximumHosts = 4096);
};
