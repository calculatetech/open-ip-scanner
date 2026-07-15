#include "linuxpingprobe.h"

#include "cancellablewait.h"
#include "diagnostics.h"

#include <QProcess>
#include <QStandardPaths>

bool LinuxPingProbe::ping(const QHostAddress &address,
                          const QString &interfaceName,
                          int attempts,
                          int timeoutSeconds,
                          const TargetBudget &budget,
                          const Cancellation &cancellation) const
{
#ifdef Q_OS_LINUX
    const QString executable = QStandardPaths::findExecutable("ping");
    const QString program = executable.isEmpty() ? QStringLiteral("ping") : executable;
    if (executable.isEmpty()) {
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Error,
            "ping.missing",
            "discovery",
            "Install the iputils-ping package and retry the scan.",
            "The ping executable was not found."));
        return false;
    }
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (cancellable::isCancelled(cancellation) || budget.expired()) {
            return false;
        }
        QStringList arguments{
            "-n", "-c", "1", "-W", QString::number(timeoutSeconds)};
        if (!interfaceName.isEmpty()) {
            arguments << "-I" << interfaceName;
        }
        arguments << address.toString();

        QProcess process;
        process.start(program, arguments);
        const int waitMs = budget.clampTimeout(
            pingAttemptWaitMs(timeoutSeconds), kProcessCleanupReserveMs);
        const cancellable::WaitResult waitResult = cancellable::waitForProcess(
                process,
                waitMs,
                cancellation,
                [&budget]() { return budget.remainingMs(); });
        if (waitResult != cancellable::WaitResult::Completed) {
            if (waitResult == cancellable::WaitResult::Failed) {
                DiagnosticsStore::instance().record(diagnosticEvent(
                    DiagnosticSeverity::Error,
                    "ping.start_failed",
                    "discovery",
                    "Verify that ping is installed and executable.",
                    process.errorString()));
            }
            continue;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) {
            return true;
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() > 1) {
            const QString standardError = QString::fromLocal8Bit(
                process.readAllStandardError()).trimmed();
            DiagnosticsStore::instance().record(diagnosticEvent(
                DiagnosticSeverity::Warning,
                process.exitStatus() == QProcess::NormalExit
                    ? "ping.failed"
                    : "ping.crashed",
                "discovery",
                "Verify the installed ping command works outside the application.",
                standardError.isEmpty() ? process.errorString() : standardError,
                process.exitCode(),
                true));
        }
    }
#else
    Q_UNUSED(address)
    Q_UNUSED(interfaceName)
    Q_UNUSED(attempts)
    Q_UNUSED(timeoutSeconds)
    Q_UNUSED(budget)
    Q_UNUSED(cancellation)
#endif
    return false;
}
