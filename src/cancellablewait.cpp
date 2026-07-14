#include "cancellablewait.h"

#include <QAbstractSocket>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QProcess>
#include <QTcpSocket>
#include <QTimer>

#include <algorithm>

namespace {

constexpr int kPollIntervalMs = 25;

template <typename WaitFunction, typename FinishedFunction, typename FailedFunction>
cancellable::WaitResult waitInSlices(int timeoutMs,
                                      const cancellable::Flag &flag,
                                      WaitFunction wait,
                                      FinishedFunction finished,
                                      FailedFunction failed)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < timeoutMs) {
        if (cancellable::isCancelled(flag)) {
            return cancellable::WaitResult::Cancelled;
        }
        if (finished()) {
            return cancellable::WaitResult::Completed;
        }
        if (failed()) {
            return cancellable::WaitResult::Failed;
        }
        const int remaining = timeoutMs - static_cast<int>(elapsed.elapsed());
        wait(std::min(kPollIntervalMs, remaining));
    }
    if (cancellable::isCancelled(flag)) {
        return cancellable::WaitResult::Cancelled;
    }
    if (finished()) {
        return cancellable::WaitResult::Completed;
    }
    return failed() ? cancellable::WaitResult::Failed : cancellable::WaitResult::TimedOut;
}

class QtProcessControl final : public cancellable::ProcessControl {
public:
    explicit QtProcessControl(QProcess &process) : process_(process) {}

    bool waitForFinished(int timeoutMs) override { return process_.waitForFinished(timeoutMs); }
    void kill() override { process_.kill(); }
    QProcess::ProcessState state() const override { return process_.state(); }
    QProcess::ProcessError error() const override { return process_.error(); }

private:
    QProcess &process_;
};

} // namespace

namespace cancellable {

bool isCancelled(const Flag &flag)
{
    return flag && flag->load();
}

WaitResult waitForProcess(ProcessControl &process, int timeoutMs, const Flag &flag)
{
    const WaitResult result = waitInSlices(
        timeoutMs,
        flag,
        [&](int sliceMs) { process.waitForFinished(sliceMs); },
        [&]() { return process.state() == QProcess::NotRunning; },
        [&]() {
            return process.state() == QProcess::NotRunning &&
                   process.error() == QProcess::FailedToStart;
        });
    if (result == WaitResult::Cancelled || result == WaitResult::TimedOut) {
        process.kill();
        if (!process.waitForFinished(250) || process.state() != QProcess::NotRunning) {
            return WaitResult::Failed;
        }
    }
    if (result == WaitResult::Completed && process.error() == QProcess::FailedToStart) {
        return WaitResult::Failed;
    }
    return result;
}

WaitResult waitForProcess(QProcess &process, int timeoutMs, const Flag &flag)
{
    QtProcessControl control(process);
    return waitForProcess(control, timeoutMs, flag);
}

WaitResult waitForConnected(QTcpSocket &socket, int timeoutMs, const Flag &flag)
{
    const WaitResult result = waitInSlices(
        timeoutMs,
        flag,
        [&](int sliceMs) { socket.waitForConnected(sliceMs); },
        [&]() { return socket.state() == QAbstractSocket::ConnectedState; },
        [&]() {
            return socket.state() == QAbstractSocket::UnconnectedState &&
                   socket.error() != QAbstractSocket::UnknownSocketError;
        });
    if (result != WaitResult::Completed) {
        socket.abort();
    }
    return result;
}

WaitResult waitForBytesWritten(QTcpSocket &socket, int timeoutMs, const Flag &flag)
{
    return waitInSlices(
        timeoutMs,
        flag,
        [&](int sliceMs) { socket.waitForBytesWritten(sliceMs); },
        [&]() { return socket.bytesToWrite() == 0; },
        [&]() {
            return socket.state() == QAbstractSocket::UnconnectedState ||
                   socket.error() == QAbstractSocket::RemoteHostClosedError;
        });
}

WaitResult waitForReadyRead(QTcpSocket &socket, int timeoutMs, const Flag &flag)
{
    return waitInSlices(
        timeoutMs,
        flag,
        [&](int sliceMs) { socket.waitForReadyRead(sliceMs); },
        [&]() { return socket.bytesAvailable() > 0; },
        [&]() {
            return socket.state() == QAbstractSocket::UnconnectedState ||
                   socket.error() == QAbstractSocket::RemoteHostClosedError;
        });
}

QHostInfo lookupHost(const QString &address, int timeoutMs, const Flag &flag, WaitResult *result)
{
    if (isCancelled(flag)) {
        if (result) {
            *result = WaitResult::Cancelled;
        }
        return QHostInfo();
    }

    QEventLoop loop;
    QHostInfo answer;
    bool completed = false;
    const int lookupId = QHostInfo::lookupHost(address, &loop, [&](const QHostInfo &info) {
        answer = info;
        completed = true;
        loop.quit();
    });

    QElapsedTimer elapsed;
    elapsed.start();
    QTimer poll;
    poll.setInterval(kPollIntervalMs);
    QObject::connect(&poll, &QTimer::timeout, &loop, [&]() {
        if (isCancelled(flag) || elapsed.elapsed() >= timeoutMs) {
            QHostInfo::abortHostLookup(lookupId);
            loop.quit();
        }
    });
    poll.start();
    loop.exec();

    const WaitResult outcome = completed
                                   ? WaitResult::Completed
                                   : (isCancelled(flag) ? WaitResult::Cancelled : WaitResult::TimedOut);
    if (result) {
        *result = outcome;
    }
    return answer;
}

} // namespace cancellable
