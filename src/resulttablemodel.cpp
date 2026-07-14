#include "resulttablemodel.h"

#include "neighborentry.h"

#include <QFontDatabase>
#include <QHostAddress>

#include <algorithm>

ResultTableModel::ResultTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int ResultTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : rows_.size();
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
    if (role == Qt::FontRole && (index.column() == Ip || index.column() == Mac)) {
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case Ip: return result.ip;
    case Hostname: return result.hostname.trimmed().isEmpty() ? QString("Unknown") : result.hostname;
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
    beginRemoveRows({}, 0, rows_.size() - 1);
    rows_.clear();
    identityRows_.clear();
    endRemoveRows();
}

void ResultTableModel::upsertResult(const ScanResult &result)
{
    if (result.ip.isEmpty()) {
        return;
    }
    const QString identity = identityFor(result);
    const int existing = identityRows_.value(identity, -1);
    if (existing >= 0) {
        if (mergeResult(&rows_[existing], result)) {
            emit dataChanged(index(existing, 0), index(existing, ColumnCount - 1));
        }
        return;
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
}

void ResultTableModel::setMacFormatter(std::function<QString(const QString &)> formatter)
{
    macFormatter_ = std::move(formatter);
}

void ResultTableModel::notifyMacFormatChanged()
{
    if (!rows_.isEmpty()) {
        emit dataChanged(index(0, Mac), index(rows_.size() - 1, Mac),
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

QString ResultTableModel::identityFor(const ScanResult &result)
{
    return neighborIdentityKey(result.interfaceName, result.ip);
}

QString ResultTableModel::normalizedText(const QString &value)
{
    return value.trimmed().toCaseFolded();
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
    case Hostname: return normalizedText(result.hostname);
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

bool ResultTableModel::mergeResult(ScanResult *current, const ScanResult &incoming)
{
    bool changed = false;
    const auto upgrade = [&changed](QString *value, const QString &incomingValue) {
        if ((value->isEmpty() || *value == "Unknown") && !incomingValue.isEmpty() &&
            incomingValue != "Unknown") {
            *value = incomingValue;
            changed = true;
        }
    };
    upgrade(&current->hostname, incoming.hostname);
    upgrade(&current->mac, incoming.mac);
    upgrade(&current->vendor, incoming.vendor);
    if (current->services.isEmpty() && !incoming.services.isEmpty()) {
        current->services = incoming.services;
        changed = true;
    }
    if (current->detailsText.isEmpty() && !incoming.detailsText.isEmpty()) {
        current->detailsText = incoming.detailsText;
        changed = true;
    }
    return changed;
}
