#include "ouidatabase.h"

#include <QRegularExpression>

namespace {
bool safeVendorName(const QString &text)
{
    if (text.size() > 120) {
        return false;
    }
    for (const QChar ch : text) {
        if (ch == QChar::Null || ch.category() == QChar::Other_Control) {
            return false;
        }
    }
    return true;
}
} // namespace

QString OuiDatabase::normalizePrefix(const QString &prefix)
{
    QString normalized = prefix.toUpper();
    normalized.remove(':');
    normalized.remove('-');
    normalized.remove('.');
    static const QRegularExpression hexPattern("^[0-9A-F]+$");
    if (normalized.size() < 6 || !hexPattern.match(normalized).hasMatch()) {
        return {};
    }
    return normalized.left(6);
}

bool OuiDatabase::parseOverrides(const QString &text,
                                 QHash<QString, QString> *vendors,
                                 QString *error)
{
    if (vendors == nullptr) {
        if (error != nullptr) {
            *error = "No destination was provided for the OUI overrides.";
        }
        return false;
    }
    QHash<QString, QString> parsedVendors;
    const QStringList lines = text.split('\n');
    for (int index = 0; index < lines.size(); ++index) {
        const QString line = lines[index].trimmed();
        if (line.isEmpty() || line.startsWith('#')) {
            continue;
        }
        const qsizetype separator = line.indexOf('=');
        if (separator <= 0 || separator != line.lastIndexOf('=')) {
            if (error != nullptr) {
                *error = QString("Line %1 must use PREFIX=Vendor.").arg(index + 1);
            }
            return false;
        }
        QString rawPrefix = line.left(separator).trimmed().toUpper();
        rawPrefix.remove(':');
        rawPrefix.remove('-');
        rawPrefix.remove('.');
        static const QRegularExpression exactPrefixPattern("^[0-9A-F]{6}$");
        const QString prefix = exactPrefixPattern.match(rawPrefix).hasMatch()
                                   ? rawPrefix
                                   : QString{};
        const QString vendor = line.mid(separator + 1).trimmed();
        if (prefix.isEmpty()) {
            if (error != nullptr) {
                *error = QString("Line %1 has an invalid 24-bit hexadecimal OUI prefix.")
                             .arg(index + 1);
            }
            return false;
        }
        if (vendor.isEmpty() || !safeVendorName(vendor)) {
            if (error != nullptr) {
                *error = QString("Line %1 has an empty or invalid vendor name.")
                             .arg(index + 1);
            }
            return false;
        }
        parsedVendors.insert(prefix, vendor);
    }
    *vendors = parsedVendors;
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

QString OuiDatabase::lookup(const QString &mac,
                            const QHash<QString, QString> &customVendors,
                            const QHash<QString, QString> &builtInVendors)
{
    const QString prefix = normalizePrefix(mac);
    if (prefix.isEmpty()) {
        return "Unknown";
    }
    if (customVendors.contains(prefix)) {
        return customVendors.value(prefix);
    }
    return builtInVendors.value(prefix, "Unknown");
}
