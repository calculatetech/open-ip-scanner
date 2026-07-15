#include "diagnostics.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>

#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr int kMaximumEvents = 500;
constexpr int kMaximumFieldLength = 240;
constexpr qint64 kMaximumLogBytes = 1024 * 1024;

QString bounded(QString value, int maximum = kMaximumFieldLength)
{
    value.replace('\r', ' ');
    value.replace('\n', ' ');
    return value.left(maximum);
}

QString sanitizedMessage(QString value)
{
    value.replace(QRegularExpression(
                      R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"),
                  "[address]");
    value.replace(QRegularExpression(
                      R"(\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b)"),
                  "[hardware-address]");
    value.replace(QRegularExpression(
                      R"(\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}\b)"),
                  "[hostname]");
    return bounded(value);
}

QString severityKey(DiagnosticSeverity severity)
{
    switch (severity) {
    case DiagnosticSeverity::Info: return "info";
    case DiagnosticSeverity::Warning: return "warning";
    case DiagnosticSeverity::Error: return "error";
    }
    return "warning";
}

QJsonObject redactedEventObject(const DiagnosticEvent &event)
{
    QJsonObject object;
    object.insert("timestamp_utc",
                  QDateTime::fromMSecsSinceEpoch(event.timestampMsUtc).toUTC()
                      .toString(Qt::ISODateWithMs));
    object.insert("severity", severityKey(event.severity));
    object.insert("code", bounded(event.code, 80));
    object.insert("stage", bounded(event.stage, 80));
    object.insert("remediation", bounded(event.remediation));
    if (event.hasExitStatus) {
        object.insert("exit_status", event.exitStatus);
    }
    // Error text is intentionally omitted from default support output. It can
    // contain executable- or system-supplied data even after basic scrubbing.
    return object;
}

QByteArray localLogLine(const DiagnosticEvent &event)
{
    QJsonObject object = redactedEventObject(event);
    if (!event.message.isEmpty()) {
        object.insert("message", event.message);
    }
    return QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n';
}
} // namespace

DiagnosticsStore &DiagnosticsStore::instance()
{
    static DiagnosticsStore store;
    return store;
}

DiagnosticsStore::~DiagnosticsStore()
{
    logWriterPausedForTesting_.store(false, std::memory_order_relaxed);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        loggingEnabled_ = false;
        logWriterStopping_ = true;
        logWriterWake_.notify_all();
    }
    if (logWriter_.joinable()) {
        logWriter_.join();
    }
}

void DiagnosticsStore::clear()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
    latestEvents_.clear();
    counts_.clear();
    failureCountsByStage_.clear();
}

void DiagnosticsStore::beginScan()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const bool retainLoggerFailure = !loggingHealthy_;
    QList<DiagnosticEvent> retained;
    QMap<QString, DiagnosticEvent> retainedLatest;
    QMap<QString, int> retainedCounts;
    QMap<QString, int> retainedStages;
    for (const DiagnosticEvent &event : events_) {
        if (event.stage == "adapter_discovery" ||
            (retainLoggerFailure && event.stage == "diagnostics")) {
            retained.append(event);
        }
    }
    for (auto it = latestEvents_.cbegin(); it != latestEvents_.cend(); ++it) {
        if (it.value().stage == "adapter_discovery" ||
            (retainLoggerFailure && it.value().stage == "diagnostics")) {
            retainedLatest.insert(it.key(), it.value());
            retainedCounts.insert(it.key(), counts_.value(it.key()));
        }
    }
    if (!retainedCounts.isEmpty()) {
        for (const QString &stage : {QString("adapter_discovery"),
                                     QString("diagnostics")}) {
            if (failureCountsByStage_.contains(stage) &&
                (stage != "diagnostics" || retainLoggerFailure)) {
                retainedStages.insert(stage, failureCountsByStage_.value(stage));
            }
        }
    }
    events_ = retained;
    latestEvents_ = retainedLatest;
    counts_ = retainedCounts;
    failureCountsByStage_ = retainedStages;
}

void DiagnosticsStore::record(DiagnosticEvent event)
{
    if (event.timestampMsUtc <= 0) {
        event.timestampMsUtc = QDateTime::currentMSecsSinceEpoch();
    }
    event.code = bounded(event.code, 80);
    event.stage = bounded(event.stage, 80);
    event.remediation = bounded(event.remediation);
    event.message = sanitizedMessage(event.message);

    const std::lock_guard<std::mutex> lock(mutex_);
    recordLocked(event, true);
}

void DiagnosticsStore::recordLocked(const DiagnosticEvent &event,
                                    bool queueForLog)
{
    counts_[event.code] = counts_.value(event.code) + 1;
    if (event.severity != DiagnosticSeverity::Info) {
        failureCountsByStage_[event.stage] =
            failureCountsByStage_.value(event.stage) + 1;
    }
    latestEvents_[event.code] = event;
    events_.append(event);
    while (events_.size() > kMaximumEvents) {
        events_.removeFirst();
    }
    if (queueForLog && loggingEnabled_) {
        if (pendingLogLines_.size() >=
            maximumPendingLogLines_.load(std::memory_order_relaxed)) {
            loggingEnabled_ = false;
            loggingHealthy_ = false;
            ++logGeneration_;
            pendingLogLines_.clear();
            DiagnosticEvent failure = diagnosticEvent(
                DiagnosticSeverity::Error,
                "diagnostic.log_queue_overflow",
                "diagnostics",
                "Disable diagnostic logging, verify storage performance, then re-enable it.",
                "The bounded diagnostic log queue filled before it could be written.");
            failure.message = sanitizedMessage(failure.message);
            recordLocked(failure, false);
            logWriterDrained_.notify_all();
            return;
        }
        pendingLogLines_.append(localLogLine(event));
        logWriterWake_.notify_one();
    }
}

void DiagnosticsStore::recordLogFailureLocked(const QString &code,
                                              const QString &message)
{
    loggingEnabled_ = false;
    loggingHealthy_ = false;
    ++logGeneration_;
    pendingLogLines_.clear();
    DiagnosticEvent failure = diagnosticEvent(
        DiagnosticSeverity::Error,
        code,
        "diagnostics",
        "Choose a writable local data location, verify free space and permissions, then re-enable diagnostic logging.",
        message);
    failure.message = sanitizedMessage(failure.message);
    recordLocked(failure, false);
}

QList<DiagnosticEvent> DiagnosticsStore::events() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

QList<DiagnosticEvent> DiagnosticsStore::latestEvents() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return latestEvents_.values();
}

QMap<QString, int> DiagnosticsStore::counts() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return counts_;
}

QMap<QString, int> DiagnosticsStore::failureCountsByStage() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return failureCountsByStage_;
}

void DiagnosticsStore::setLoggingEnabled(bool enabled)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (enabled && !loggingEnabled_) {
        ++logGeneration_;
    }
    loggingEnabled_ = enabled;
    if (enabled) {
        ensureLogWriterLocked();
        logWriterWake_.notify_one();
        return;
    }
    while (!pendingLogLines_.isEmpty() || logWriterWriting_) {
        logWriterWake_.notify_one();
        logWriterDrained_.wait(lock);
    }
}

bool DiagnosticsStore::loggingEnabled() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return loggingEnabled_;
}

bool DiagnosticsStore::loggingHealthy() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return loggingHealthy_;
}

QString DiagnosticsStore::loggingStatusText() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!loggingHealthy_) {
        return loggingEnabled_ ? "Retrying" : "Failed";
    }
    return loggingEnabled_ ? "Enabled" : "Disabled";
}

void DiagnosticsStore::setLogFailurePointForTesting(int failurePoint)
{
    injectedLogFailurePoint_.store(failurePoint, std::memory_order_relaxed);
}

void DiagnosticsStore::setMaximumPendingLogLinesForTesting(int maximumLines)
{
    maximumPendingLogLines_.store(maximumLines, std::memory_order_relaxed);
}

void DiagnosticsStore::setLogWriterPausedForTesting(bool paused)
{
    logWriterPausedForTesting_.store(paused, std::memory_order_relaxed);
}

bool DiagnosticsStore::logWriterWritingForTesting() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return logWriterWriting_;
}

QString DiagnosticsStore::logDirectory() const
{
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) +
           "/diagnostics";
}

void DiagnosticsStore::ensureLogWriterLocked()
{
    if (logWriter_.joinable()) {
        return;
    }
    activeLogDirectory_ = logDirectory();
    logWriter_ = std::thread([this]() { logWriterLoop(); });
}

void DiagnosticsStore::logWriterLoop()
{
    while (true) {
        QByteArray batch;
        quint64 batchGeneration = 0;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            while (pendingLogLines_.isEmpty() && !logWriterStopping_) {
                logWriterWake_.wait(lock);
            }
            if (pendingLogLines_.isEmpty() && logWriterStopping_) {
                logWriterDrained_.notify_all();
                return;
            }
            constexpr int kMaximumBatchLines = 100;
            int batchLines = 0;
            while (!pendingLogLines_.isEmpty() &&
                   batchLines < kMaximumBatchLines) {
                batch.append(pendingLogLines_.takeFirst());
                ++batchLines;
            }
            logWriterWriting_ = true;
            batchGeneration = logGeneration_;
        }
        while (logWriterPausedForTesting_.load(std::memory_order_relaxed)) {
            std::this_thread::yield();
        }
        QString failureCode;
        QString failureMessage;
        const bool written = appendLogLine(batch, &failureCode, &failureMessage);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            logWriterWriting_ = false;
            if (!written) {
                recordLogFailureLocked(failureCode, failureMessage);
            } else if (batchGeneration == logGeneration_) {
                loggingHealthy_ = true;
            }
            if (pendingLogLines_.isEmpty()) {
                logWriterDrained_.notify_all();
            }
        }
    }
}

bool DiagnosticsStore::appendLogLine(const QByteArray &line,
                                     QString *code,
                                     QString *message)
{
    const QString directory = activeLogDirectory_;
    const int failurePoint =
        injectedLogFailurePoint_.load(std::memory_order_relaxed);
    const QFileInfo directoryInfo(directory);
    if (!QDir().mkpath(directoryInfo.path())) {
        *code = "diagnostic.log_directory_failed";
        *message = "Could not create the diagnostic log parent directory.";
        return false;
    }
    const QByteArray encodedDirectory = QFile::encodeName(directory);
    if (::mkdir(encodedDirectory.constData(), S_IRWXU) != 0 && errno != EEXIST) {
        *code = "diagnostic.log_directory_failed";
        *message = "Could not create the diagnostic log directory.";
        return false;
    }
    if (!QFileInfo(directory).isDir()) {
        *code = "diagnostic.log_directory_failed";
        *message = "The diagnostic log location is not a directory.";
        return false;
    }
    if (failurePoint == 1 ||
        ::chmod(encodedDirectory.constData(), S_IRWXU) != 0) {
        *code = "diagnostic.log_permissions_failed";
        *message = "Could not restrict diagnostic log directory permissions.";
        return false;
    }
    if (!rotateLogsIfNeeded(directory, line.size(), message)) {
        *code = "diagnostic.log_rotation_failed";
        return false;
    }
    const QByteArray encodedFile = QFile::encodeName(
        directory + "/diagnostics.log");
    const int descriptor = failurePoint == 2
                               ? -1
                               : ::open(encodedFile.constData(),
                                        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                                        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        *code = "diagnostic.log_open_failed";
        *message = "Could not open the diagnostic log file.";
        return false;
    }
    if (::fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
        ::close(descriptor);
        *code = "diagnostic.log_permissions_failed";
        *message = "Could not restrict diagnostic log file permissions.";
        return false;
    }
    QFile file;
    if (!file.open(descriptor,
                   QIODevice::WriteOnly | QIODevice::Append,
                   QFileDevice::AutoCloseHandle)) {
        ::close(descriptor);
        *code = "diagnostic.log_open_failed";
        *message = "Could not attach the diagnostic log file for writing.";
        return false;
    }
    if (failurePoint == 3 || file.write(line) != line.size() || !file.flush()) {
        *code = "diagnostic.log_write_failed";
        *message = "Could not write or flush the diagnostic log file.";
        return false;
    }
    return true;
}

bool DiagnosticsStore::rotateLogsIfNeeded(const QString &directory,
                                          qint64 incomingBytes,
                                          QString *message)
{
    const QString current = directory + "/diagnostics.log";
    if (QFileInfo(current).size() + incomingBytes <= kMaximumLogBytes) {
        return true;
    }
    const QString oldest = directory + "/diagnostics.log.2";
    const QString previous = directory + "/diagnostics.log.1";
    if (QFileInfo::exists(oldest) && !QFile::remove(oldest)) {
        *message = "Could not remove the oldest rotated diagnostic log.";
        return false;
    }
    if (QFileInfo::exists(previous) && !QFile::rename(previous, oldest)) {
        *message = "Could not rotate the previous diagnostic log.";
        return false;
    }
    if (!QFile::rename(current, previous)) {
        *message = "Could not rotate the active diagnostic log.";
        return false;
    }
    return true;
}

DiagnosticEvent diagnosticEvent(DiagnosticSeverity severity,
                                const QString &code,
                                const QString &stage,
                                const QString &remediation,
                                const QString &message,
                                int exitStatus,
                                bool hasExitStatus)
{
    return {QDateTime::currentMSecsSinceEpoch(),
            severity,
            code,
            stage,
            remediation,
            message,
            exitStatus,
            hasExitStatus};
}

QString diagnosticsSummaryText(const QList<DiagnosticEvent> &events,
                               const QMap<QString, int> &counts,
                               const QMap<QString, bool> &capabilities)
{
    QStringList lines{"Local diagnostics", "No target history or service payloads are collected."};
    if (!capabilities.isEmpty()) {
        lines << QString();
        for (auto it = capabilities.cbegin(); it != capabilities.cend(); ++it) {
            lines << QString("%1: %2").arg(it.key(), it.value() ? "Available" : "Unavailable");
        }
    }
    QMap<QString, DiagnosticEvent> latest;
    for (const DiagnosticEvent &event : events) {
        latest[event.code] = event;
    }
    if (counts.isEmpty()) {
        lines << QString() << "No failures recorded in the current session.";
        return lines.join('\n');
    }
    lines << QString() << "Events";
    for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
        lines << QString("%1: %2").arg(it.key()).arg(it.value());
        const QString remediation = latest.value(it.key()).remediation;
        if (!remediation.isEmpty()) {
            lines << QString("  Fix: %1").arg(remediation);
        }
    }
    return lines.join('\n');
}

QByteArray diagnosticsSupportBundleJson(
    const QList<DiagnosticEvent> &events,
    const QMap<QString, int> &counts,
    const QMap<QString, bool> &capabilities,
    const QString &applicationVersion,
    const QString &buildVersion,
    const QString &platformName)
{
    QJsonObject countObject;
    for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
        countObject.insert(it.key(), it.value());
    }
    QJsonObject capabilityObject;
    for (auto it = capabilities.cbegin(); it != capabilities.cend(); ++it) {
        capabilityObject.insert(it.key(), it.value());
    }
    QJsonArray eventArray;
    for (const DiagnosticEvent &event : events) {
        eventArray.append(redactedEventObject(event));
    }
    QJsonObject root;
    root.insert("application", "Open IP Scanner");
    root.insert("application_version", applicationVersion);
    root.insert("build_version", buildVersion);
    root.insert("platform", platformName);
    root.insert("capabilities", capabilityObject);
    root.insert("counts", countObject);
    root.insert("events", eventArray);
    root.insert("privacy", "Targets, hostnames, service payloads, and raw error text omitted");
    return QJsonDocument(root).toJson(QJsonDocument::Indented);
}
