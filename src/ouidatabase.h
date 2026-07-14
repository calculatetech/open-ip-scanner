#pragma once

#include <QHash>
#include <QString>

class OuiDatabase {
public:
    static QString normalizePrefix(const QString &prefix);
    static bool parseOverrides(const QString &text,
                               QHash<QString, QString> *vendors,
                               QString *error = nullptr);
    static QString lookup(const QString &mac,
                          const QHash<QString, QString> &customVendors,
                          const QHash<QString, QString> &builtInVendors);
};
