#include "linuxpingprobe.h"

#include "cancellablewait.h"

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
        if (cancellable::waitForProcess(
                process,
                waitMs,
                cancellation,
                [&budget]() { return budget.remainingMs(); }) !=
            cancellable::WaitResult::Completed) {
            continue;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) {
            return true;
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
