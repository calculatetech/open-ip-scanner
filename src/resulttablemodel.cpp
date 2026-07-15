#include "resulttablemodel.h"

#include "neighborentry.h"

#include <QFontDatabase>
#include <QHostAddress>

#include <algorithm>

namespace {

bool sameHostnameEvidence(const QList<HostnameEvidence> &left,
                          const QList<HostnameEvidence> &right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (int index = 0; index < left.size(); ++index) {
        if (left.at(index).hostname != right.at(index).hostname ||
            left.at(index).source != right.at(index).source) {
            return false;
        }
    }
    return true;
}

bool sameServices(const QList<ServiceHit> &left, const QList<ServiceHit> &right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (int index = 0; index < left.size(); ++index) {
        const ServiceHit &lhs = left.at(index);
        const ServiceHit &rhs = right.at(index);
        if (lhs.id != rhs.id || lhs.label != rhs.label || lhs.port != rhs.port ||
            lhs.isWeb != rhs.isWeb || lhs.evidence != rhs.evidence) {
            return false;
        }
    }
    return true;
}

bool sameResult(const ScanResult &left, const ScanResult &right)
{
    return left.ip == right.ip && left.interfaceName == right.interfaceName &&
           left.mac == right.mac && left.vendor == right.vendor &&
           left.hostname == right.hostname &&
           left.hostnameSource == right.hostnameSource &&
           sameHostnameEvidence(left.hostnameEvidence, right.hostnameEvidence) &&
           left.resolverEvents == right.resolverEvents &&
           sameServices(left.services, right.services) &&
           left.detailsText == right.detailsText &&
           left.discoveryMethod == right.discoveryMethod;
}

} // namespace

ResultTableModel::ResultTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int ResultTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int ResultTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ResultTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rows_.size() ||
        index.column() < 0 || index.column() >= ColumnCount) {
        return {};
    }
    const ScanResult &result = rows_.at(index.row());
    if (role == IdentityRole) {
        return identityFor(result);
    }
    if (role == SortRole) {
        return sortValue(result, index.column());
    }
    if (role == ServiceTagsRole && index.column() == Services) {
        QStringList tags;
        for (const ServiceHit &service : result.services) {
            tags.append(serviceEvidenceText(service.label, service.port, service.evidence));
        }
        return tags;
    }
    if (role == ServiceKindsRole && index.column() == Services) {
        QStringList kinds;
        for (const ServiceHit &service : result.services) {
            kinds.append(service.evidence == ServiceEvidenceLevel::VerifiedProtocol
                             ? service.id
                             : QString());
        }
        return kinds;
    }
    if (role == Qt::FontRole && (index.column() == Ip || index.column() == Mac)) {
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case Ip: return result.ip;
    case Hostname: return tableHostname(result);
    case Mac:
        return macFormatter_ ? macFormatter_(result.mac)
                             : (result.mac.trimmed().isEmpty() ? QString("Unknown") : result.mac);
    case Vendor: return result.vendor.trimmed().isEmpty() ? QString("Unknown") : result.vendor;
    case Services: return servicesText(result.services);
    default: return {};
    }
}

QVariant ResultTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    static const QStringList headers = {
        "IP Address", "Hostname", "MAC Address", "Vendor", "Services"};
    return section >= 0 && section < headers.size() ? headers.at(section) : QVariant();
}

void ResultTableModel::clear()
{
    if (rows_.isEmpty()) {
        return;
    }
    beginRemoveRows({}, 0, static_cast<int>(rows_.size()) - 1);
    rows_.clear();
    identityRows_.clear();
    endRemoveRows();
}

bool ResultTableModel::upsertResult(const ScanResult &result)
{
    if (result.ip.isEmpty()) {
        return false;
    }
    const QString identity = identityFor(result);
    const int existing = identityRows_.value(identity, -1);
    if (existing >= 0) {
        if (sameResult(rows_.at(existing), result)) {
            return false;
        }
        rows_[existing] = result;
        emit dataChanged(index(existing, 0), index(existing, ColumnCount - 1));
        return true;
    }
    const int row = insertionRow(result);
    beginInsertRows({}, row, row);
    rows_.insert(row, result);
    endInsertRows();
    if (row == rows_.size() - 1) {
        identityRows_.insert(identity, row);
    } else {
        for (int shiftedRow = row; shiftedRow < rows_.size(); ++shiftedRow) {
            identityRows_.insert(identityFor(rows_.at(shiftedRow)), shiftedRow);
        }
    }
    return true;
}

void ResultTableModel::setMacFormatter(std::function<QString(const QString &)> formatter)
{
    macFormatter_ = std::move(formatter);
}

void ResultTableModel::notifyMacFormatChanged()
{
    if (!rows_.isEmpty()) {
        emit dataChanged(index(0, Mac), index(static_cast<int>(rows_.size()) - 1, Mac),
                         {Qt::DisplayRole, SortRole});
    }
}

QString ResultTableModel::identityAt(int row) const
{
    return row >= 0 && row < rows_.size() ? identityFor(rows_.at(row)) : QString();
}

int ResultTableModel::rowForIdentity(const QString &identity) const
{
    return identityRows_.value(identity, -1);
}

ScanResult ResultTableModel::resultAt(int row) const
{
    return row >= 0 && row < rows_.size() ? rows_.at(row) : ScanResult();
}

ScanResult ResultTableModel::resultForIdentity(const QString &identity) const
{
    return resultAt(rowForIdentity(identity));
}

bool ResultTableModel::matchesSearch(int row,
                                     const QString &query,
                                     const QString &scope) const
{
    if (row < 0 || row >= rows_.size()) {
        return false;
    }
    const QString normalizedQuery = normalizedText(query);
    if (normalizedQuery.isEmpty()) {
        return true;
    }

    const ScanResult &result = rows_.at(row);
    const QString normalizedHostnameQuery = normalizedHostnameKey(query);
    if (scope == "ip") {
        return textContains(result.ip, normalizedQuery);
    }
    if (scope == "hostname") {
        return hostnameContains(result, normalizedHostnameQuery);
    }
    if (scope == "vendor") {
        return evidenceTextContains(result.vendor, normalizedQuery);
    }
    if (scope == "services") {
        return servicesContain(result, normalizedQuery);
    }
    if (scope == "mac") {
        return macContains(result.mac, query, normalizedQuery);
    }
    if (scope == "oui") {
        const QString compactQuery = normalizedMacSearchText(query);
        const QString compactMac = normalizedMacSearchText(result.mac);
        return !compactQuery.isEmpty() && compactQuery.size() <= 12 &&
               compactMac.startsWith(compactQuery);
    }

    return textContains(result.ip, normalizedQuery) ||
           hostnameContains(result, normalizedHostnameQuery) ||
           evidenceTextContains(result.vendor, normalizedQuery) ||
           servicesContain(result, normalizedQuery) ||
           macContains(result.mac, query, normalizedQuery);
}

QString ResultTableModel::identityFor(const ScanResult &result)
{
    return neighborIdentityKey(result.interfaceName, result.ip);
}

QString ResultTableModel::normalizedText(const QString &value)
{
    return value.trimmed().toCaseFolded();
}

QString ResultTableModel::normalizedMacSearchText(const QString &value)
{
    QString normalized;
    normalized.reserve(value.size());
    for (const QChar character : value.trimmed()) {
        if (character == ':' || character == '.' || character == '-' ||
            character.isSpace()) {
            continue;
        }
        const QChar folded = character.toLower();
        if (!folded.isDigit() && (folded < 'a' || folded > 'f')) {
            return {};
        }
        normalized.append(folded);
    }
    return normalized;
}

bool ResultTableModel::textContains(const QString &value,
                                    const QString &normalizedQuery)
{
    return normalizedText(value).contains(normalizedQuery);
}

bool ResultTableModel::evidenceTextContains(const QString &value,
                                            const QString &normalizedQuery)
{
    const QString normalized = normalizedText(value);
    return !normalized.isEmpty() && normalized != QStringLiteral("unknown") &&
           normalized.contains(normalizedQuery);
}

bool ResultTableModel::macContains(const QString &mac,
                                   const QString &query,
                                   const QString &normalizedQuery)
{
    if (evidenceTextContains(mac, normalizedQuery)) {
        return true;
    }
    const QString compactQuery = normalizedMacSearchText(query);
    return !compactQuery.isEmpty() &&
           normalizedMacSearchText(mac).contains(compactQuery);
}

bool ResultTableModel::hostnameContains(const ScanResult &result,
                                        const QString &normalizedQuery)
{
    if (normalizedQuery.isEmpty()) {
        return false;
    }
    if (normalizedHostnameKey(result.hostname).contains(normalizedQuery)) {
        return true;
    }
    if (result.hostnameEvidence.isEmpty()) {
        return false;
    }
    const QList<HostnameEvidence> canonical =
        canonicalHostnameEvidence(result.hostnameEvidence);
    return std::any_of(canonical.cbegin(), canonical.cend(),
                       [&normalizedQuery](const HostnameEvidence &evidence) {
                           return normalizedHostnameKey(evidence.hostname)
                               .contains(normalizedQuery);
                       });
}

bool ResultTableModel::servicesContain(const ScanResult &result,
                                       const QString &normalizedQuery)
{
    return std::any_of(
        result.services.cbegin(), result.services.cend(),
        [&normalizedQuery](const ServiceHit &service) {
            if (QString::number(service.port).contains(normalizedQuery)) {
                return true;
            }
            if (service.evidence != ServiceEvidenceLevel::VerifiedProtocol) {
                return false;
            }
            return normalizedText(service.label).contains(normalizedQuery) ||
                   normalizedText(service.id).contains(normalizedQuery);
        });
}

QString ResultTableModel::tableHostname(const ScanResult &result)
{
    const QString hostname = result.hostname.trimmed();
    if (hostname.isEmpty()) {
        return "Unknown";
    }
    if (result.hostnameSource == HostnameSource::AvahiMdns) {
        return hostname;
    }
    const QString shortName = hostname.section('.', 0, 0);
    return shortName.isEmpty() ? hostname : shortName;
}

QString ResultTableModel::servicesText(const QList<ServiceHit> &services)
{
    QStringList parts;
    for (const ServiceHit &service : services) {
        parts.append(serviceEvidenceText(service.label, service.port, service.evidence));
    }
    return parts.join(", ");
}

qulonglong ResultTableModel::ipKey(const QString &ip)
{
    return QHostAddress(ip).toIPv4Address();
}

QVariant ResultTableModel::macKey(const QString &mac)
{
    QString hex = mac.toUpper();
    hex.remove(':');
    hex.remove('-');
    hex.remove('.');
    bool ok = false;
    const qulonglong value = hex.toULongLong(&ok, 16);
    return ok && hex.size() == 12 ? QVariant(value) : QVariant();
}

QVariant ResultTableModel::sortValue(const ScanResult &result, int column) const
{
    switch (column) {
    case Ip: return ipKey(result.ip);
    case Hostname: return normalizedText(tableHostname(result));
    case Mac: return macKey(result.mac);
    case Vendor: return normalizedText(result.vendor);
    case Services: return normalizedText(servicesText(result.services));
    default: return {};
    }
}

bool ResultTableModel::lessThan(const ScanResult &left, const ScanResult &right) const
{
    const QVariant lhs = sortValue(left, sortColumn_);
    const QVariant rhs = sortValue(right, sortColumn_);
    int comparison = 0;
    if (lhs.userType() == QMetaType::ULongLong && rhs.userType() == QMetaType::ULongLong) {
        comparison = lhs.toULongLong() < rhs.toULongLong() ? -1
                     : lhs.toULongLong() > rhs.toULongLong() ? 1 : 0;
    } else {
        comparison = QString::compare(lhs.toString(), rhs.toString(), Qt::CaseInsensitive);
    }
    if (comparison == 0) {
        comparison = QString::compare(identityFor(left), identityFor(right), Qt::CaseSensitive);
    }
    return sortOrder_ == Qt::AscendingOrder ? comparison < 0 : comparison > 0;
}

int ResultTableModel::insertionRow(const ScanResult &result) const
{
    const auto it = std::lower_bound(rows_.cbegin(), rows_.cend(), result,
                                     [this](const ScanResult &left, const ScanResult &right) {
                                         return lessThan(left, right);
                                     });
    return static_cast<int>(std::distance(rows_.cbegin(), it));
}

void ResultTableModel::sort(int column, Qt::SortOrder order)
{
    if (column < 0 || column >= ColumnCount) {
        return;
    }
    sortColumn_ = column;
    sortOrder_ = order;
    if (rows_.size() < 2) {
        return;
    }
    emit layoutAboutToBeChanged({}, QAbstractItemModel::VerticalSortHint);
    const QModelIndexList oldPersistent = persistentIndexList();
    QStringList identities;
    QList<int> columns;
    identities.reserve(oldPersistent.size());
    columns.reserve(oldPersistent.size());
    for (const QModelIndex &oldIndex : oldPersistent) {
        identities.append(identityAt(oldIndex.row()));
        columns.append(oldIndex.column());
    }
    std::stable_sort(rows_.begin(), rows_.end(),
                     [this](const ScanResult &left, const ScanResult &right) {
                         return lessThan(left, right);
                     });
    rebuildIdentityRows();
    QModelIndexList newPersistent;
    newPersistent.reserve(oldPersistent.size());
    for (int i = 0; i < identities.size(); ++i) {
        newPersistent.append(index(rowForIdentity(identities.at(i)), columns.at(i)));
    }
    changePersistentIndexList(oldPersistent, newPersistent);
    emit layoutChanged({}, QAbstractItemModel::VerticalSortHint);
}

void ResultTableModel::rebuildIdentityRows()
{
    identityRows_.clear();
    for (int row = 0; row < rows_.size(); ++row) {
        identityRows_.insert(identityFor(rows_.at(row)), row);
    }
}
