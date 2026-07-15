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

QString OuiDatabase::normalizeAssignmentPrefix(const QString &prefix)
{
    QString normalized = prefix.trimmed().toUpper();
    normalized.remove(':');
    normalized.remove('-');
    normalized.remove('.');
    static const QRegularExpression hexPattern("^[0-9A-F]+$");
    if ((normalized.size() != 6 && normalized.size() != 7 &&
         normalized.size() != 9) ||
        !hexPattern.match(normalized).hasMatch()) {
        return {};
    }
    return normalized;
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
        const QString prefix = normalizeAssignmentPrefix(line.left(separator));
        const QString vendor = line.mid(separator + 1).trimmed();
        if (prefix.isEmpty()) {
            if (error != nullptr) {
                *error = QString("Line %1 must have a 24-, 28-, or 36-bit hexadecimal prefix.")
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
    QString normalized = mac.trimmed().toUpper();
    normalized.remove(':');
    normalized.remove('-');
    normalized.remove('.');
    static const QRegularExpression macPattern("^[0-9A-F]{12}$");
    if (!macPattern.match(normalized).hasMatch() ||
        normalized == "000000000000" || normalized == "FFFFFFFFFFFF") {
        return "Unknown";
    }
    bool firstByteOk = false;
    const int firstByte = normalized.left(2).toInt(&firstByteOk, 16);
    if (!firstByteOk || (firstByte & 0x01) != 0) {
        return "Unknown";
    }
    if ((firstByte & 0x02) != 0) {
        return "Private / randomized";
    }
    for (const int digits : {9, 7, 6}) {
        const QString prefix = normalized.left(digits);
        if (customVendors.contains(prefix)) {
            return customVendors.value(prefix);
        }
    }
    for (const int digits : {9, 7, 6}) {
        const QString prefix = normalized.left(digits);
        if (builtInVendors.contains(prefix)) {
            return builtInVendors.value(prefix);
        }
    }
    return "Unknown";
}

bool OuiDatabase::loadTsv(QIODevice &input,
                          QHash<QString, QString> *vendors,
                          QString *error)
{
    if (vendors == nullptr) {
        if (error != nullptr) {
            *error = "No destination was provided for vendor assignments.";
        }
        return false;
    }
    QHash<QString, QString> parsed;
    int lineNumber = 0;
    while (!input.atEnd()) {
        ++lineNumber;
        const QString line = QString::fromUtf8(input.readLine()).trimmed();
        if (lineNumber == 1 && line == "prefix_bits\tprefix\torganization") {
            continue;
        }
        if (line.isEmpty()) {
            continue;
        }
        const QStringList fields = line.split('\t');
        if (fields.size() != 3) {
            if (error != nullptr) {
                *error = QString("Vendor data line %1 has an invalid field count.")
                             .arg(lineNumber);
            }
            return false;
        }
        const QString prefix = normalizeAssignmentPrefix(fields[1]);
        const int expectedBits = static_cast<int>(prefix.size()) * 4;
        bool bitsOk = false;
        const int declaredBits = fields[0].toInt(&bitsOk);
        const QString vendor = fields[2].trimmed();
        if (prefix.isEmpty() || !bitsOk || declaredBits != expectedBits ||
            vendor.isEmpty() || !safeVendorName(vendor) || parsed.contains(prefix)) {
            if (error != nullptr) {
                *error = QString("Vendor data line %1 is invalid or duplicated.")
                             .arg(lineNumber);
            }
            return false;
        }
        parsed.insert(prefix, vendor);
    }
    if (parsed.isEmpty()) {
        if (error != nullptr) {
            *error = "Vendor data contains no assignments.";
        }
        return false;
    }
    *vendors = parsed;
    if (error != nullptr) {
        error->clear();
    }
    return true;
}
