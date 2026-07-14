#include "csvexporter.h"

#include <QSaveFile>
#include <QTextStream>

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QStringConverter>
#endif

namespace {
class SaveFileSink final : public CsvExportSink {
public:
    explicit SaveFileSink(const QString &path)
        : file_(path)
    {
    }

    bool open() override
    {
        return file_.open(QIODevice::WriteOnly | QIODevice::Text);
    }

    QIODevice *device() override
    {
        return &file_;
    }

    bool flush() override
    {
        return file_.flush();
    }

    bool commit() override
    {
        return file_.commit();
    }

    void cancel() override
    {
        file_.cancelWriting();
    }

    QString errorString() const override
    {
        return file_.errorString();
    }

private:
    QSaveFile file_;
};

QString failureText(const QString &prefix, const QString &detail)
{
    return detail.isEmpty() ? prefix : QString("%1: %2").arg(prefix, detail);
}
} // namespace

CsvExportData CsvExporter::selectTable(
    const QStringList &headers,
    const QVector<QStringList> &rows,
    const QVector<bool> &rowVisible,
    const QVector<int> &visibleColumnsInDisplayOrder,
    bool filteredRowsOnly)
{
    CsvExportData selected;
    for (int column : visibleColumnsInDisplayOrder) {
        if (column >= 0 && column < headers.size()) {
            selected.headers.append(headers[column]);
        }
    }
    for (int row = 0; row < rows.size(); ++row) {
        if (filteredRowsOnly &&
            (row >= rowVisible.size() || !rowVisible[row])) {
            continue;
        }
        QStringList fields;
        for (int column : visibleColumnsInDisplayOrder) {
            if (column >= 0 && column < rows[row].size()) {
                fields.append(rows[row][column]);
            }
        }
        selected.rows.append(fields);
    }
    return selected;
}

CsvExportOutcome CsvExporter::exportFile(const QString &path,
                                         const CsvExportData &data)
{
    if (path.isEmpty()) {
        return {CsvExportStatus::Cancelled, {}};
    }

    SaveFileSink sink(path);
    return exportToSink(sink, data);
}

CsvExportOutcome CsvExporter::exportToSink(CsvExportSink &sink,
                                           const CsvExportData &data)
{
    if (!sink.open()) {
        return {CsvExportStatus::OpenFailed,
                failureText("Could not open the destination", sink.errorString())};
    }

    QTextStream stream(sink.device());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    stream.setEncoding(QStringConverter::Utf8);
#else
    stream.setCodec("UTF-8");
#endif

    auto writeRecord = [&stream](const QStringList &record) {
        QStringList fields;
        fields.reserve(record.size());
        for (const QString &cell : record) {
            fields.append(CsvExporter::escapeCell(cell));
        }
        stream << fields.join(',') << '\n';
        return stream.status() == QTextStream::Ok;
    };

    bool writeOk = writeRecord(data.headers);
    for (const QStringList &row : data.rows) {
        if (!writeOk) {
            break;
        }
        writeOk = writeRecord(row);
    }
    stream.flush();
    writeOk = writeOk && stream.status() == QTextStream::Ok && sink.flush();
    if (!writeOk) {
        const QString detail = sink.errorString();
        sink.cancel();
        return {CsvExportStatus::WriteFailed,
                failureText("Could not write the complete CSV", detail)};
    }

    if (!sink.commit()) {
        const QString detail = sink.errorString();
        sink.cancel();
        return {CsvExportStatus::CommitFailed,
                failureText("Could not atomically replace the destination", detail)};
    }
    return {CsvExportStatus::Success, {}};
}

QString CsvExporter::escapeCell(const QString &text)
{
    QString safe = text;
    if (!safe.isEmpty()) {
        const QChar first = safe.front();
        if (first == '=' || first == '+' || first == '-' || first == '@' ||
            first == '\t' || first == '\r') {
            safe.prepend('\'');
        }
    }
    safe.replace('"', "\"\"");
    return QString("\"%1\"").arg(safe);
}
