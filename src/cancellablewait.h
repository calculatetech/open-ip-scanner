#pragma once

#include <QHostInfo>
#include <QProcess>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>

class QTcpSocket;

namespace cancellable {

using Flag = std::shared_ptr<std::atomic_bool>;
using RemainingTime = std::function<int()>;

enum class WaitResult {
    Completed,
    Cancelled,
    TimedOut,
    Failed
};

bool isCancelled(const Flag &flag);

class ProcessControl {
public:
    virtual ~ProcessControl() = default;
    virtual bool waitForFinished(int timeoutMs) = 0;
    virtual void kill() = 0;
    virtual QProcess::ProcessState state() const = 0;
    virtual QProcess::ProcessError error() const = 0;
};

WaitResult waitForProcess(ProcessControl &process,
                          int timeoutMs,
                          const Flag &flag,
                          const RemainingTime &cleanupRemaining = {});
WaitResult waitForProcess(QProcess &process,
                          int timeoutMs,
                          const Flag &flag,
                          const RemainingTime &cleanupRemaining = {});
WaitResult waitForConnected(QTcpSocket &socket, int timeoutMs, const Flag &flag);
WaitResult waitForBytesWritten(QTcpSocket &socket, int timeoutMs, const Flag &flag);
WaitResult waitForReadyRead(QTcpSocket &socket, int timeoutMs, const Flag &flag);
WaitResult waitForDelay(int timeoutMs, const Flag &flag);
QHostInfo lookupHost(const QString &address,
                     int timeoutMs,
                     const Flag &flag,
                     WaitResult *result = nullptr);

} // namespace cancellable
