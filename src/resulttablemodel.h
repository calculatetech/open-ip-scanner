#pragma once

#include "scanresult.h"

#include <QAbstractTableModel>
#include <QHash>

#include <functional>

class ResultTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column { Ip = 0, Hostname, Mac, Vendor, Services, ColumnCount };
    enum Role {
        IdentityRole = Qt::UserRole + 1,
        SortRole,
        ServiceTagsRole,
        ServiceKindsRole
    };

    explicit ResultTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section,
                        Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    void clear();
    bool upsertResult(const ScanResult &result);
    void setMacFormatter(std::function<QString(const QString &)> formatter);
    void notifyMacFormatChanged();

    QString identityAt(int row) const;
    int rowForIdentity(const QString &identity) const;
    ScanResult resultAt(int row) const;
    ScanResult resultForIdentity(const QString &identity) const;
    bool matchesSearch(int row,
                       const QString &query,
                       const QString &scope = QStringLiteral("all")) const;
    int activeSortColumn() const { return sortColumn_; }
    Qt::SortOrder activeSortOrder() const { return sortOrder_; }

private:
    static QString identityFor(const ScanResult &result);
    static QString normalizedText(const QString &value);
    static QString normalizedMacSearchText(const QString &value);
    static bool textContains(const QString &value, const QString &normalizedQuery);
    static bool evidenceTextContains(const QString &value,
                                     const QString &normalizedQuery);
    static bool macContains(const QString &mac,
                            const QString &query,
                            const QString &normalizedQuery);
    static bool hostnameContains(const ScanResult &result,
                                 const QString &normalizedQuery);
    static bool servicesContain(const ScanResult &result,
                                const QString &normalizedQuery);
    static QString tableHostname(const ScanResult &result);
    static QString servicesText(const QList<ServiceHit> &services);
    static qulonglong ipKey(const QString &ip);
    static QVariant macKey(const QString &mac);
    QVariant sortValue(const ScanResult &result, int column) const;
    bool lessThan(const ScanResult &left, const ScanResult &right) const;
    int insertionRow(const ScanResult &result) const;
    void rebuildIdentityRows();

    QList<ScanResult> rows_;
    QHash<QString, int> identityRows_;
    std::function<QString(const QString &)> macFormatter_;
    int sortColumn_ = Ip;
    Qt::SortOrder sortOrder_ = Qt::AscendingOrder;
};
