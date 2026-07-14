#include "linuxpingprobe.h"

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

int invocationCount(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return 0;
    }
    int count = 0;
    for (const QByteArray &line : file.readAll().split('\n')) {
        if (!line.isEmpty()) {
            ++count;
        }
    }
    return count;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
#ifndef Q_OS_LINUX
    return 0;
#else
    QTemporaryDir tools;
    if (!tools.isValid()) {
        return 1;
    }
    const QString callsPath = tools.filePath("calls");
    const QString counterPath = tools.filePath("counter");
    QFile fakePing(tools.filePath("ping"));
    if (!fakePing.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return 1;
    }
    fakePing.write(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$OIS_PING_CALLS\"\n"
        "case \"$OIS_PING_MODE\" in\n"
        "  success) exit 0 ;;\n"
        "  fail) exit 1 ;;\n"
        "  second) count=0; test -f \"$OIS_PING_COUNTER\" && count=$(cat \"$OIS_PING_COUNTER\"); count=$((count + 1)); printf '%s' \"$count\" > \"$OIS_PING_COUNTER\"; test \"$count\" -ge 2 ;;\n"
        "  slow) exec sleep 5 ;;\n"
        "esac\n");
    fakePing.close();
    if (!fakePing.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                 QFileDevice::ExeOwner)) {
        return 1;
    }

    EnvironmentGuard pathGuard("PATH");
    EnvironmentGuard callsGuard("OIS_PING_CALLS");
    EnvironmentGuard counterGuard("OIS_PING_COUNTER");
    EnvironmentGuard modeGuard("OIS_PING_MODE");
    qputenv("PATH", tools.path().toUtf8() + ':' + qgetenv("PATH"));
    qputenv("OIS_PING_CALLS", callsPath.toUtf8());
    qputenv("OIS_PING_COUNTER", counterPath.toUtf8());

    const LinuxPingProbe probe;
    const QHostAddress address("192.0.2.55");
    qputenv("OIS_PING_MODE", "success");
    if (!probe.ping(address, "fixture0", 3, 2, TargetBudget(4000), {})) {
        std::cerr << "successful scoped ping failed\n";
        return 1;
    }
    QFile calls(callsPath);
    if (!calls.open(QIODevice::ReadOnly | QIODevice::Text) ||
        calls.readAll() != "-n -c 1 -W 2 -I fixture0 192.0.2.55\n") {
        std::cerr << "production ping arguments failed\n";
        return 1;
    }

    QFile::remove(callsPath);
    qputenv("OIS_PING_MODE", "second");
    if (!probe.ping(address, {}, 3, 1, TargetBudget(4000), {}) ||
        invocationCount(callsPath) != 2) {
        std::cerr << "retry success contract failed\n";
        return 1;
    }

    QFile::remove(callsPath);
    qputenv("OIS_PING_MODE", "fail");
    if (probe.ping(address, {}, 3, 1, TargetBudget(4000), {}) ||
        invocationCount(callsPath) != 3) {
        std::cerr << "attempt limit contract failed\n";
        return 1;
    }

    QFile::remove(callsPath);
    qputenv("OIS_PING_MODE", "slow");
    QElapsedTimer deadlineTimer;
    deadlineTimer.start();
    if (probe.ping(address, {}, 1, 2, TargetBudget(120), {}) ||
        deadlineTimer.elapsed() >= 1000) {
        std::cerr << "deadline contract failed\n";
        return 1;
    }

    const auto cancellation = std::make_shared<std::atomic_bool>(false);
    std::thread canceler([cancellation]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        cancellation->store(true);
    });
    QElapsedTimer cancellationTimer;
    cancellationTimer.start();
    const bool canceledResult = probe.ping(
        address, {}, 1, 2, TargetBudget(2000), cancellation);
    canceler.join();
    if (canceledResult || cancellationTimer.elapsed() >= 1000) {
        std::cerr << "cancellation contract failed\n";
        return 1;
    }

    QFile::remove(callsPath);
    const auto alreadyCanceled = std::make_shared<std::atomic_bool>(true);
    if (probe.ping(address, {}, 2, 1, TargetBudget(2000), alreadyCanceled) ||
        probe.ping(address, {}, 2, 1, TargetBudget(0), {}) ||
        invocationCount(callsPath) != 0) {
        std::cerr << "immediate cutoff contract failed\n";
        return 1;
    }
    return 0;
#endif
}
