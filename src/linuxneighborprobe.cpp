#include "linuxneighborprobe.h"

#include "cancellablewait.h"
#include "diagnostics.h"

#include <QElapsedTimer>
#include <QProcess>
#include <QStandardPaths>

#include <algorithm>
#include <utility>

LinuxNeighborProbe::LinuxNeighborProbe(LookupOverride lookupOverride)
    : lookupOverride_(std::move(lookupOverride))
{
}

NeighborObservation LinuxNeighborProbe::lookup(
    const QString &ip,
    const QString &interfaceName,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    if (cancellable::isCancelled(cancellation) || budget.expired()) {
        return {};
    }
    return lookupOverride_
               ? lookupOverride_(ip, interfaceName, budget, cancellation)
               : lookupProduction(ip, interfaceName, budget, cancellation);
}

NeighborObservation LinuxNeighborProbe::lookupProduction(
    const QString &ip,
    const QString &interfaceName,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
#ifdef Q_OS_LINUX
    const QString executable = QStandardPaths::findExecutable("ip");
    if (executable.isEmpty()) {
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Error,
            "ip.missing",
            "neighbor",
            "Install the iproute2 package and retry the scan.",
            "The ip executable was not found."));
        return {};
    }
    QProcess process;
    QStringList arguments{"-j", "neigh", "show", ip};
    if (!interfaceName.isEmpty()) {
        arguments << "dev" << interfaceName;
    }
    process.start(executable, arguments);
    const cancellable::WaitResult waitResult = cancellable::waitForProcess(
            process,
            budget.clampTimeout(1000, kProcessCleanupReserveMs),
            cancellation,
            [&budget]() { return budget.remainingMs(); });
    if (waitResult == cancellable::WaitResult::Completed &&
        process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) {
        const QByteArray output = process.readAllStandardOutput();
        QString parseError;
        const QList<NeighborObservation> observations = parseLinuxNeighborJson(
            output, interfaceName, &parseError);
        if (!parseError.isEmpty()) {
            DiagnosticsStore::instance().record(diagnosticEvent(
                DiagnosticSeverity::Warning,
                "ip.invalid_response",
                "neighbor",
                "Verify that the installed iproute2 tool supports JSON output.",
                parseError));
        }
        const QString expectedKey = neighborIdentityKey(interfaceName, ip);
        for (const NeighborObservation &observation : observations) {
            if (interfaceName.isEmpty() ? observation.ip == ip
                                        : observation.identityKey() == expectedKey) {
                return observation;
            }
        }
    } else if (waitResult == cancellable::WaitResult::Failed) {
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Error,
            "ip.start_failed",
            "neighbor",
            "Verify that iproute2 is installed and executable.",
            process.errorString()));
    } else if (waitResult == cancellable::WaitResult::TimedOut) {
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Warning,
            "ip.timeout",
            "neighbor",
            "Check system load and retry the scan."));
    } else if (waitResult == cancellable::WaitResult::Completed) {
        const QString standardError = QString::fromLocal8Bit(
            process.readAllStandardError()).trimmed();
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Warning,
            "ip.failed",
            "neighbor",
            "Run 'ip neigh show' to verify the local neighbor-cache tool.",
            standardError.isEmpty() ? process.errorString() : standardError,
            process.exitCode(),
            true));
    }
#else
    Q_UNUSED(ip)
    Q_UNUSED(interfaceName)
    Q_UNUSED(budget)
    Q_UNUSED(cancellation)
#endif
    return {};
}

NeighborObservation LinuxNeighborProbe::confirmLiveness(
    const NeighborObservation &initial,
    const QString &ip,
    const QString &interfaceName,
    int confirmationTimeoutMs,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    NeighborObservation latest = initial;
    if (!latest.suppliesMacMetadata() || latest.establishesLiveness() ||
        confirmationTimeoutMs <= 0 || budget.expired()) {
        return latest;
    }

    QElapsedTimer confirmation;
    confirmation.start();
    while (confirmation.elapsed() < confirmationTimeoutMs &&
           !budget.expired()) {
        const int confirmationRemaining = confirmationTimeoutMs -
                                          static_cast<int>(confirmation.elapsed());
        const int waitMs = std::min(
            {250, confirmationRemaining, budget.remainingMs()});
        if (waitMs <= 0 ||
            cancellable::waitForDelay(waitMs, cancellation) !=
                cancellable::WaitResult::Completed) {
            break;
        }
        const NeighborObservation candidate = lookup(
            ip, interfaceName, budget, cancellation);
        if (candidate.suppliesMacMetadata()) {
            latest = candidate;
        }
        if (candidate.establishesLiveness()) {
            return candidate;
        }
    }
    return latest;
}
