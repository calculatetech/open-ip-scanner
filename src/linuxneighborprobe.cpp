#include "linuxneighborprobe.h"

#include "cancellablewait.h"

#include <QElapsedTimer>
#include <QProcess>

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
    QProcess process;
    QStringList arguments{"-j", "neigh", "show", ip};
    if (!interfaceName.isEmpty()) {
        arguments << "dev" << interfaceName;
    }
    process.start("ip", arguments);
    if (cancellable::waitForProcess(
            process,
            budget.clampTimeout(1000, kProcessCleanupReserveMs),
            cancellation,
            [&budget]() { return budget.remainingMs(); }) ==
            cancellable::WaitResult::Completed &&
        process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) {
        const QList<NeighborObservation> observations = parseLinuxNeighborJson(
            process.readAllStandardOutput(), interfaceName);
        const QString expectedKey = neighborIdentityKey(interfaceName, ip);
        for (const NeighborObservation &observation : observations) {
            if (interfaceName.isEmpty() ? observation.ip == ip
                                        : observation.identityKey() == expectedKey) {
                return observation;
            }
        }
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
