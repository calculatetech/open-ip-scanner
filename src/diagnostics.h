#pragma once

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QString>

#include <condition_variable>
#include <atomic>
#include <mutex>
#include <thread>

enum class DiagnosticSeverity {
    Info,
    Warning,
    Error
};

struct DiagnosticEvent {
    qint64 timestampMsUtc = 0;
    DiagnosticSeverity severity = DiagnosticSeverity::Warning;
    QString code;
    QString stage;
    QString remediation;
    QString message;
    int exitStatus = 0;
    bool hasExitStatus = false;
};

class DiagnosticsStore {
public:
    DiagnosticsStore() = default;
    static DiagnosticsStore &instance();

    ~DiagnosticsStore();

    void clear();
    void beginScan();
    void record(DiagnosticEvent event);
    QList<DiagnosticEvent> events() const;
    QList<DiagnosticEvent> latestEvents() const;
    QMap<QString, int> counts() const;
    QMap<QString, int> failureCountsByStage() const;

    void setLoggingEnabled(bool enabled);
    bool loggingEnabled() const;
    bool loggingHealthy() const;
    QString loggingStatusText() const;
    QString logDirectory() const;
    void setLogFailurePointForTesting(int failurePoint);
    void setMaximumPendingLogLinesForTesting(int maximumLines);
    void setLogWriterPausedForTesting(bool paused);
    bool logWriterWritingForTesting() const;

private:
    void ensureLogWriterLocked();
    void logWriterLoop();
    void recordLocked(const DiagnosticEvent &event, bool queueForLog);
    void recordLogFailureLocked(const QString &code, const QString &message);
    bool appendLogLine(const QByteArray &line, QString *code, QString *message);
    bool rotateLogsIfNeeded(const QString &directory,
                            qint64 incomingBytes,
                            QString *message);

    mutable std::mutex mutex_;
    QList<DiagnosticEvent> events_;
    QMap<QString, DiagnosticEvent> latestEvents_;
    QMap<QString, int> counts_;
    QMap<QString, int> failureCountsByStage_;
    bool loggingEnabled_ = false;
    bool loggingHealthy_ = true;
    bool logWriterStopping_ = false;
    bool logWriterWriting_ = false;
    quint64 logGeneration_ = 0;
    QList<QByteArray> pendingLogLines_;
    QString activeLogDirectory_;
    std::condition_variable logWriterWake_;
    std::condition_variable logWriterDrained_;
    std::thread logWriter_;
    std::atomic<int> injectedLogFailurePoint_{0};
    std::atomic<int> maximumPendingLogLines_{8192};
    std::atomic_bool logWriterPausedForTesting_{false};
};

DiagnosticEvent diagnosticEvent(DiagnosticSeverity severity,
                                const QString &code,
                                const QString &stage,
                                const QString &remediation,
                                const QString &message = {},
                                int exitStatus = 0,
                                bool hasExitStatus = false);
QString diagnosticsSummaryText(const QList<DiagnosticEvent> &events,
                               const QMap<QString, int> &counts,
                               const QMap<QString, bool> &capabilities);
QByteArray diagnosticsSupportBundleJson(
    const QList<DiagnosticEvent> &events,
    const QMap<QString, int> &counts,
    const QMap<QString, bool> &capabilities,
    const QString &applicationVersion,
    const QString &buildVersion,
    const QString &platformName);
