#pragma once

#include <QIODevice>
#include <QString>
#include <QStringList>
#include <QVector>

struct CsvExportData {
    QStringList headers;
    QVector<QStringList> rows;
};

enum class CsvExportStatus {
    Success,
    Cancelled,
    OpenFailed,
    WriteFailed,
    CommitFailed
};

struct CsvExportOutcome {
    CsvExportStatus status = CsvExportStatus::Success;
    QString error;
};

class CsvExportSink {
public:
    virtual ~CsvExportSink() = default;

    virtual bool open() = 0;
    virtual QIODevice *device() = 0;
    virtual bool flush() = 0;
    virtual bool commit() = 0;
    virtual void cancel() = 0;
    virtual QString errorString() const = 0;
};

class CsvExporter {
public:
    static CsvExportData selectTable(
        const QStringList &headers,
        const QVector<QStringList> &rows,
        const QVector<bool> &rowVisible,
        const QVector<int> &visibleColumnsInDisplayOrder,
        bool filteredRowsOnly);
    static CsvExportOutcome exportFile(const QString &path,
                                       const CsvExportData &data);
    static CsvExportOutcome exportToSink(CsvExportSink &sink,
                                         const CsvExportData &data);
    static QString escapeCell(const QString &text);
};
