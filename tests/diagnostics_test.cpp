#include "diagnostics.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

#include <iostream>
#include <atomic>
#include <thread>
#include <vector>

namespace {
void require(bool condition, const char *message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}
}

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    DiagnosticsStore &store = DiagnosticsStore::instance();
    store.clear();
    store.setLoggingEnabled(false);
    for (int index = 0; index < 510; ++index) {
        store.record(diagnosticEvent(
            DiagnosticSeverity::Error,
            "ping.failed",
            "discovery",
            "Install iputils-ping.",
            "10.33.0.27 secret-host.local SSH-2.0-private-banner",
            127,
            true));
    }
    require(store.events().size() == 500, "diagnostic ring must remain bounded");
    require(store.counts().value("ping.failed") == 510,
            "aggregate counts must survive ring eviction");

    const QByteArray bundle = diagnosticsSupportBundleJson(
        store.events(),
        store.counts(),
        {{"ping", false}, {"ip", true}},
        "0.6.3",
        "0.6.3",
        "Test Linux");
    require(bundle.contains("ping.failed"), "support bundle lost stable code");
    require(bundle.contains("Install iputils-ping"), "support bundle lost remediation");
    require(bundle.contains("\"exit_status\": 127"), "support bundle lost exit status");
    require(!bundle.contains("10.33.0.27"), "support bundle leaked target address");
    require(!bundle.contains("secret-host.local"), "support bundle leaked hostname");
    require(!bundle.contains("SSH-2.0-private-banner"), "support bundle leaked banner");
    require(!bundle.contains("message"), "support bundle exported raw message field");

    const QString summary = diagnosticsSummaryText(
        store.latestEvents(),
        store.counts(),
        {{"ping", false}, {"ip", true}});
    require(summary.contains("ping: Unavailable"), "summary lost capability state");
    require(summary.contains("Fix: Install iputils-ping."),
            "summary lost remediation");

    QStandardPaths::setTestModeEnabled(true);
    QDir logDirectory(store.logDirectory());
    logDirectory.removeRecursively();

    store.clear();
    store.setLoggingEnabled(true);
    std::atomic<int> concurrentProgress{0};
    std::vector<std::thread> writers;
    for (int writer = 0; writer < 4; ++writer) {
        writers.emplace_back([&store, &concurrentProgress, writer]() {
            for (int index = 0; index < 400; ++index) {
                store.record(diagnosticEvent(
                    DiagnosticSeverity::Warning,
                    QString("concurrent.%1").arg(writer),
                    "test",
                    "Retry."));
                concurrentProgress.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    std::thread disabler([&store, &concurrentProgress]() {
        while (concurrentProgress.load(std::memory_order_relaxed) < 100) {
            std::this_thread::yield();
        }
        store.setLoggingEnabled(false);
    });
    for (std::thread &writer : writers) {
        writer.join();
    }
    disabler.join();
    require(store.events().size() == 500,
            "concurrent diagnostic ring exceeded its bound");
    int concurrentTotal = 0;
    const QMap<QString, int> concurrentCounts = store.counts();
    for (auto it = concurrentCounts.cbegin(); it != concurrentCounts.cend(); ++it) {
        concurrentTotal += it.value();
    }
    require(concurrentTotal == 1600, "concurrent diagnostics lost aggregate counts");
    require(store.loggingHealthy(),
            "concurrent enqueue/drain/disable damaged logger health");

    store.clear();
    store.record(diagnosticEvent(DiagnosticSeverity::Warning,
                                 "dns_suffix.query_failed",
                                 "adapter_discovery",
                                 "Repair resolver configuration."));
    for (int index = 0; index < 700; ++index) {
        store.record(diagnosticEvent(DiagnosticSeverity::Error,
                                     "scan.failure",
                                     "scan",
                                     "Retry."));
    }
    require(store.failureCountsByStage().value("scan") == 700,
            "stage aggregates were capped with the event ring");
    store.beginScan();
    require(store.counts().value("dns_suffix.query_failed") == 1 &&
                store.failureCountsByStage().value("adapter_discovery") == 1 &&
                !store.counts().contains("scan.failure"),
            "scan reset did not retain adapter diagnostics exclusively");

    logDirectory.removeRecursively();
    store.clear();
    store.setLoggingEnabled(true);
    for (int index = 0; index < 7000; ++index) {
        store.record(diagnosticEvent(
            DiagnosticSeverity::Warning,
            "resolver.failed",
            "hostname",
            "Check resolver configuration.",
            "secret-host.local at 10.33.0.27 returned bounded error text"));
    }
    store.setLoggingEnabled(false);
    logDirectory.refresh();
    const QStringList logs = logDirectory.entryList(
        {"diagnostics.log*"}, QDir::Files, QDir::Name);
    require(logs.size() >= 2 && logs.size() <= 3,
            "diagnostic logs did not rotate into a three-file bound");
    const QFileDevice::Permissions directoryPermissions =
        QFileInfo(logDirectory.absolutePath()).permissions();
    require((directoryPermissions &
             (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
              QFileDevice::ExeGroup | QFileDevice::ReadOther |
              QFileDevice::WriteOther | QFileDevice::ExeOther)) == 0,
            "diagnostic directory permissions are not owner-only");
    for (const QString &name : logs) {
        QFile file(logDirectory.filePath(name));
        const QFileDevice::Permissions permissions = QFileInfo(file).permissions();
        require((permissions &
                 (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
                  QFileDevice::ExeGroup | QFileDevice::ReadOther |
                  QFileDevice::WriteOther | QFileDevice::ExeOther)) == 0,
                "diagnostic log permissions are not owner-only");
        require(file.open(QIODevice::ReadOnly), "could not inspect diagnostic log");
        const QByteArray content = file.readAll();
        require(!content.contains("secret-host.local"), "diagnostic log leaked hostname");
        require(!content.contains("10.33.0.27"), "diagnostic log leaked address");
        require(content.contains("bounded error text"),
                "diagnostic log lost bounded error context");
    }
    logDirectory.removeRecursively();

    store.clear();
    store.setMaximumPendingLogLinesForTesting(1);
    store.setLogWriterPausedForTesting(true);
    store.setLoggingEnabled(true);
    store.record(diagnosticEvent(DiagnosticSeverity::Warning,
                                 "fixture.in_flight",
                                 "test",
                                 "Retry."));
    for (int attempts = 0;
         attempts < 100000 && !store.logWriterWritingForTesting();
         ++attempts) {
        std::this_thread::yield();
    }
    require(store.logWriterWritingForTesting(),
            "paused writer did not accept the in-flight fixture batch");
    store.record(diagnosticEvent(DiagnosticSeverity::Warning,
                                 "fixture.queued",
                                 "test",
                                 "Retry."));
    store.record(diagnosticEvent(DiagnosticSeverity::Warning,
                                 "fixture.overflow",
                                 "test",
                                 "Retry."));
    require(!store.loggingEnabled() && !store.loggingHealthy() &&
                store.counts().value("diagnostic.log_queue_overflow") == 1,
            "bounded log queue overflow did not fail logging truthfully");
    store.setLogWriterPausedForTesting(false);
    store.setLoggingEnabled(false);
    require(!store.loggingHealthy(),
            "older in-flight write erased a newer overflow failure");
    for (int index = 0; index < 600; ++index) {
        store.record(diagnosticEvent(DiagnosticSeverity::Info,
                                     QString("fixture.noise.%1").arg(index),
                                     "test",
                                     "None."));
    }
    store.beginScan();
    require(store.counts().value("diagnostic.log_queue_overflow") == 1,
            "scan reset discarded active logger recovery guidance");
    const QByteArray failedBundle = diagnosticsSupportBundleJson(
        store.latestEvents(), store.counts(), {}, "0.6.3", "0.6.3", "Test");
    require(failedBundle.contains("diagnostic.log_queue_overflow") &&
                failedBundle.contains("verify storage performance"),
            "support output lost an evicted active logger failure");
    store.setMaximumPendingLogLinesForTesting(8192);
    store.setLoggingEnabled(true);
    store.record(diagnosticEvent(DiagnosticSeverity::Info,
                                 "fixture.recovery",
                                 "test",
                                 "None."));
    store.setLoggingEnabled(false);
    require(store.loggingHealthy() && store.loggingStatusText() == "Disabled",
            "successful retry did not recover logger health");
    store.beginScan();
    require(!store.counts().contains("diagnostic.log_queue_overflow"),
            "recovered logger failure survived the next scan reset");

    const auto requireInjectedFailure = [&store, &logDirectory](
                                            int failurePoint,
                                            const QString &expectedCode) {
        logDirectory.removeRecursively();
        store.clear();
        store.setLogFailurePointForTesting(failurePoint);
        store.setLoggingEnabled(true);
        store.record(diagnosticEvent(DiagnosticSeverity::Warning,
                                     "fixture.injected_failure",
                                     "test",
                                     "Retry."));
        store.setLoggingEnabled(false);
        require(!store.loggingHealthy() &&
                    store.counts().value(expectedCode) == 1,
                "injected log I/O failure did not surface failed health");
        store.setLogFailurePointForTesting(0);
        store.setLoggingEnabled(true);
        store.record(diagnosticEvent(DiagnosticSeverity::Info,
                                     "fixture.injected_recovery",
                                     "test",
                                     "None."));
        store.setLoggingEnabled(false);
        require(store.loggingHealthy(),
                "logger did not recover after injected I/O failure");
    };
    requireInjectedFailure(1, "diagnostic.log_permissions_failed");
    requireInjectedFailure(2, "diagnostic.log_open_failed");
    requireInjectedFailure(3, "diagnostic.log_write_failed");
    logDirectory.removeRecursively();

    QFile directoryBlocker(logDirectory.absolutePath());
    require(QDir().mkpath(QFileInfo(directoryBlocker).path()),
            "could not prepare log-directory failure fixture");
    require(directoryBlocker.open(QIODevice::WriteOnly),
            "could not create log-directory failure fixture");
    directoryBlocker.close();
    store.clear();
    store.setLoggingEnabled(true);
    store.record(diagnosticEvent(DiagnosticSeverity::Error,
                                 "fixture.failure",
                                 "test",
                                 "Retry."));
    store.setLoggingEnabled(false);
    require(!store.loggingHealthy() &&
                store.loggingStatusText() == "Failed" &&
                store.counts().value("diagnostic.log_directory_failed") == 1,
            "log-directory failure was not surfaced as failed health");
    require(QFile::remove(logDirectory.absolutePath()),
            "could not remove log-directory failure fixture");

    require(QDir().mkpath(logDirectory.absolutePath()),
            "could not prepare rotation failure fixture");
    QFile activeLog(logDirectory.filePath("diagnostics.log"));
    require(activeLog.open(QIODevice::WriteOnly),
            "could not create active rotation fixture");
    require(activeLog.resize(1024 * 1024),
            "could not size active rotation fixture");
    activeLog.close();
    require(QDir().mkdir(logDirectory.filePath("diagnostics.log.2")),
            "could not create blocked rotation fixture");
    store.clear();
    store.setLoggingEnabled(true);
    store.record(diagnosticEvent(DiagnosticSeverity::Error,
                                 "fixture.rotation",
                                 "test",
                                 "Retry."));
    store.setLoggingEnabled(false);
    require(!store.loggingHealthy() &&
                store.counts().value("diagnostic.log_rotation_failed") == 1,
            "rotation failure was not surfaced as failed health");
    logDirectory.removeRecursively();

    {
        DiagnosticsStore shutdownStore;
        shutdownStore.setLoggingEnabled(true);
        for (int index = 0; index < 300; ++index) {
            shutdownStore.record(diagnosticEvent(DiagnosticSeverity::Info,
                                                 "fixture.shutdown_flush",
                                                 "test",
                                                 "None."));
        }
    }
    QFile shutdownLog(logDirectory.filePath("diagnostics.log"));
    require(shutdownLog.open(QIODevice::ReadOnly),
            "enabled logger destruction did not create its log");
    const QByteArray shutdownContent = shutdownLog.readAll();
    require(shutdownContent.count("fixture.shutdown_flush") == 300,
            "enabled logger destruction lost pending records");
    shutdownLog.close();
    logDirectory.removeRecursively();
    return 0;
}
