#include "linuxneighborprobe.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

namespace {

class EnvironmentGuard {
public:
    explicit EnvironmentGuard(const char *name)
        : name_(name), wasSet_(qEnvironmentVariableIsSet(name)), value_(qgetenv(name))
    {
    }

    ~EnvironmentGuard()
    {
        if (wasSet_) {
            qputenv(name_.constData(), value_);
        } else {
            qunsetenv(name_.constData());
        }
    }

private:
    QByteArray name_;
    bool wasSet_;
    QByteArray value_;
};

bool productionLookupContract(const QString &ip, const QString &interfaceName)
{
#ifndef Q_OS_LINUX
    Q_UNUSED(ip)
    Q_UNUSED(interfaceName)
    return true;
#else
    QTemporaryDir tools;
    if (!tools.isValid()) {
        return false;
    }
    const QString argumentsPath = tools.filePath("arguments");
    QFile fakeIp(tools.filePath("ip"));
    if (!fakeIp.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    fakeIp.write(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$OIS_NEIGH_ARGS\"\n"
        "case \"$OIS_NEIGH_MODE\" in\n"
        "  success) printf '%s\\n' '[{\"dst\":\"192.0.2.99\",\"dev\":\"fixture0\",\"lladdr\":\"02:00:00:00:00:99\",\"state\":\"REACHABLE\"},{\"dst\":\"192.0.2.55\",\"dev\":\"wrong0\",\"lladdr\":\"02:00:00:00:00:66\",\"state\":\"REACHABLE\"},{\"dst\":\"192.0.2.55\",\"dev\":\"fixture0\",\"lladdr\":\"02:00:00:00:00:55\",\"state\":\"REACHABLE\"}]' ;;\n"
        "  wrong-ip) printf '%s\\n' '[{\"dst\":\"192.0.2.99\",\"dev\":\"fixture0\",\"lladdr\":\"02:00:00:00:00:99\",\"state\":\"REACHABLE\"}]' ;;\n"
        "  malformed) printf '%s\\n' 'not-json' ;;\n"
        "  nonzero) exit 7 ;;\n"
        "  slow) sleep 5 ;;\n"
        "esac\n");
    fakeIp.close();
    if (!fakeIp.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                               QFileDevice::ExeOwner)) {
        return false;
    }

    EnvironmentGuard pathGuard("PATH");
    EnvironmentGuard argsGuard("OIS_NEIGH_ARGS");
    EnvironmentGuard modeGuard("OIS_NEIGH_MODE");
    qputenv("PATH", tools.path().toUtf8() + ':' + qgetenv("PATH"));
    qputenv("OIS_NEIGH_ARGS", argumentsPath.toUtf8());
    const LinuxNeighborProbe productionProbe;

    qputenv("OIS_NEIGH_MODE", "success");
    const NeighborObservation selected = productionProbe.lookup(
        ip, interfaceName, TargetBudget(1200), {});
    QFile arguments(argumentsPath);
    if (!arguments.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }
    const QByteArray actualArguments = arguments.readAll();
    if (actualArguments !=
            "-j\nneigh\nshow\n192.0.2.55\ndev\nfixture0\n" ||
        selected.ip != ip || selected.interfaceName != interfaceName ||
        selected.mac != "02:00:00:00:00:55" ||
        !selected.establishesLiveness()) {
        return false;
    }

    qputenv("OIS_NEIGH_MODE", "wrong-ip");
    const NeighborObservation wrongIp = productionProbe.lookup(
        ip, interfaceName, TargetBudget(1200), {});
    qputenv("OIS_NEIGH_MODE", "malformed");
    const NeighborObservation malformed = productionProbe.lookup(
        ip, interfaceName, TargetBudget(1200), {});
    qputenv("OIS_NEIGH_MODE", "nonzero");
    const NeighborObservation nonzero = productionProbe.lookup(
        ip, interfaceName, TargetBudget(1200), {});
    if (!wrongIp.ip.isEmpty() || !malformed.ip.isEmpty() ||
        !nonzero.ip.isEmpty()) {
        return false;
    }

    qputenv("OIS_NEIGH_MODE", "slow");
    QElapsedTimer deadlineTimer;
    deadlineTimer.start();
    const NeighborObservation deadline = productionProbe.lookup(
        ip, interfaceName, TargetBudget(120), {});
    if (!deadline.ip.isEmpty() || deadlineTimer.elapsed() >= 1000) {
        return false;
    }

    const auto cancellation = std::make_shared<std::atomic_bool>(false);
    std::thread canceler([cancellation]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        cancellation->store(true);
    });
    QElapsedTimer cancellationTimer;
    cancellationTimer.start();
    const NeighborObservation canceled = productionProbe.lookup(
        ip, interfaceName, TargetBudget(1200), cancellation);
    canceler.join();
    return canceled.ip.isEmpty() && cancellationTimer.elapsed() < 1000;
#endif
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const QString ip = "192.0.2.55";
    const QString interfaceName = "fixture0";
    NeighborObservation initial{
        ip, interfaceName, "02:00:00:00:00:55", NeighborState::Delay};
    const int confirmationTimeoutMs = 700;
    std::atomic<int> lookupCalls{0};
    LinuxNeighborProbe probe(
        [&](const QString &candidateIp,
            const QString &candidateInterface,
            const TargetBudget &,
            const LinuxNeighborProbe::Cancellation &) {
            lookupCalls.fetch_add(1);
            NeighborObservation observation = initial;
            if (candidateIp == ip && candidateInterface == interfaceName) {
                observation.state = NeighborState::Reachable;
            }
            return observation;
        });
    const NeighborObservation confirmed = probe.confirmLiveness(
        initial, ip, interfaceName, confirmationTimeoutMs, TargetBudget(1200), {});
    if (!confirmed.establishesLiveness() || confirmed.mac != initial.mac ||
        lookupCalls.load() != 1) {
        std::cerr << "delayed scoped confirmation contract failed\n";
        return 1;
    }

    lookupCalls.store(0);
    NeighborObservation reachable = initial;
    reachable.state = NeighborState::Reachable;
    const NeighborObservation alreadyReachable = probe.confirmLiveness(
        reachable, ip, interfaceName, confirmationTimeoutMs, TargetBudget(1200), {});
    if (!alreadyReachable.establishesLiveness() || lookupCalls.load() != 0) {
        std::cerr << "already-reachable cutoff contract failed\n";
        return 1;
    }

    lookupCalls.store(0);
    const NeighborObservation fast = probe.confirmLiveness(
        initial, ip, interfaceName, 0, TargetBudget(1200), {});
    if (fast.state != NeighborState::Delay || lookupCalls.load() != 0) {
        std::cerr << "fast confirmation cutoff contract failed\n";
        return 1;
    }

    lookupCalls.store(0);
    const auto cancellation = std::make_shared<std::atomic_bool>(true);
    const NeighborObservation canceled = probe.confirmLiveness(
        initial,
        ip,
        interfaceName,
        confirmationTimeoutMs,
        TargetBudget(1200),
        cancellation);
    if (canceled.state != NeighborState::Delay || lookupCalls.load() != 0) {
        std::cerr << "confirmation cancellation contract failed\n";
        return 1;
    }

    lookupCalls.store(0);
    NeighborObservation invalid;
    invalid.ip = ip;
    invalid.interfaceName = interfaceName;
    const NeighborObservation ignored = probe.confirmLiveness(
        invalid,
        ip,
        interfaceName,
        confirmationTimeoutMs,
        TargetBudget(1200),
        {});
    if (ignored.suppliesMacMetadata() || lookupCalls.load() != 0) {
        std::cerr << "non-evidentiary cutoff contract failed\n";
        return 1;
    }

    const NeighborObservation canceledLookup = probe.lookup(
        ip, interfaceName, TargetBudget(1200), cancellation);
    const NeighborObservation expiredLookup = probe.lookup(
        ip, interfaceName, TargetBudget(0), {});
    if (!canceledLookup.ip.isEmpty() || !expiredLookup.ip.isEmpty() ||
        lookupCalls.load() != 0) {
        std::cerr << "lookup cancellation or budget cutoff contract failed\n";
        return 1;
    }
    if (!productionLookupContract(ip, interfaceName)) {
        std::cerr << "production command, identity, or cutoff contract failed\n";
        return 1;
    }
    return 0;
}
