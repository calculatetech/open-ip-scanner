#include "csvexporter.h"

#include <QBuffer>
#include <QFile>
#include <QSaveFile>
#include <QTemporaryDir>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "CSV exporter requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

class MemorySink final : public CsvExportSink {
public:
    bool open() override
    {
        if (openFails) {
            error = "injected open failure";
            return false;
        }
        return buffer.open(QIODevice::WriteOnly);
    }

    QIODevice *device() override { return &buffer; }

    bool flush() override
    {
        if (flushFails) {
            error = "injected disk-full failure";
            return false;
        }
        return true;
    }

    bool commit() override
    {
        if (commitFails) {
            error = "injected commit failure";
            return false;
        }
        committed = true;
        return true;
    }

    void cancel() override { cancelled = true; }
    QString errorString() const override { return error; }

    QBuffer buffer;
    QString error;
    bool openFails = false;
    bool flushFails = false;
    bool commitFails = false;
    bool committed = false;
    bool cancelled = false;
};

class FailingSaveSink final : public CsvExportSink {
public:
    explicit FailingSaveSink(const QString &path) : file(path) {}

    bool open() override
    {
        return file.open(QIODevice::WriteOnly | QIODevice::Text);
    }
    QIODevice *device() override { return &file; }
    bool flush() override
    {
        error = "simulated disk full";
        return false;
    }
    bool commit() override { return false; }
    void cancel() override { file.cancelWriting(); }
    QString errorString() const override { return error; }

    QSaveFile file;
    QString error;
};

QByteArray readFile(const QString &path)
{
    QFile file(path);
    REQUIRE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}

} // namespace

int main()
{
    const QStringList headers{"IP", "Hidden", "Hostname"};
    const QVector<QStringList> rows{
        {"10.0.0.2", "secret-a", "second"},
        {"10.0.0.1", "secret-b", "first"},
        {"10.0.0.3", "secret-c", "third"}};
    const QVector<bool> visible{true, false, true};
    const QVector<int> columns{2, 0};

    const CsvExportData filtered = CsvExporter::selectTable(
        headers, rows, visible, columns, true);
    REQUIRE(filtered.headers == QStringList({"Hostname", "IP"}));
    REQUIRE(filtered.rows == QVector<QStringList>({
        {"second", "10.0.0.2"}, {"third", "10.0.0.3"}}));

    const CsvExportData all = CsvExporter::selectTable(
        headers, rows, visible, columns, false);
    REQUIRE(all.rows == QVector<QStringList>({
        {"second", "10.0.0.2"},
        {"first", "10.0.0.1"},
        {"third", "10.0.0.3"}}));

    CsvExportData escaping;
    escaping.headers = {"value", "unicode"};
    escaping.rows = {
        {"comma, quote \" and\nline", QString::fromUtf8("café 東京")},
        {"=cmd", "+sum"},
        {"-value", "@link"},
        {"\ttab", "\rcarriage"}};
    MemorySink success;
    const CsvExportOutcome successOutcome =
        CsvExporter::exportToSink(success, escaping);
    REQUIRE(successOutcome.status == CsvExportStatus::Success);
    REQUIRE(success.committed && !success.cancelled);
    const QByteArray output = success.buffer.data();
    REQUIRE(output.startsWith("\"value\",\"unicode\"\n"));
    REQUIRE(output.contains("\"comma, quote \"\" and\nline\""));
    REQUIRE(output.contains(QString::fromUtf8("café 東京").toUtf8()));
    for (const QByteArray &token : {QByteArray("'=cmd"), QByteArray("'+sum"),
                                    QByteArray("'-value"), QByteArray("'@link"),
                                    QByteArray("'\ttab"), QByteArray("'\rcarriage")}) {
        REQUIRE(output.contains(token));
    }

    REQUIRE(CsvExporter::exportFile({}, escaping).status ==
            CsvExportStatus::Cancelled);

    MemorySink openFailure;
    openFailure.openFails = true;
    REQUIRE(CsvExporter::exportToSink(openFailure, escaping).status ==
            CsvExportStatus::OpenFailed);

    MemorySink flushFailure;
    flushFailure.flushFails = true;
    REQUIRE(CsvExporter::exportToSink(flushFailure, escaping).status ==
            CsvExportStatus::WriteFailed);
    REQUIRE(flushFailure.cancelled && !flushFailure.committed);

    MemorySink commitFailure;
    commitFailure.commitFails = true;
    REQUIRE(CsvExporter::exportToSink(commitFailure, escaping).status ==
            CsvExportStatus::CommitFailed);
    REQUIRE(commitFailure.cancelled && !commitFailure.committed);

    QTemporaryDir directory;
    REQUIRE(directory.isValid());
    const QString destination = directory.filePath("results.csv");
    {
        QFile existing(destination);
        REQUIRE(existing.open(QIODevice::WriteOnly));
        REQUIRE(existing.write("old destination") == 15);
    }
    FailingSaveSink diskFull(destination);
    REQUIRE(CsvExporter::exportToSink(diskFull, escaping).status ==
            CsvExportStatus::WriteFailed);
    REQUIRE(readFile(destination) == "old destination");

    REQUIRE(CsvExporter::exportFile(destination, escaping).status ==
            CsvExportStatus::Success);
    REQUIRE(readFile(destination) == output);
    return EXIT_SUCCESS;
}
