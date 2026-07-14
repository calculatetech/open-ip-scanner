#include "cancellablewait.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QNetworkProxy>
#include <QProcess>
#include <QTcpServer>
#include <QTcpSocket>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

class UnstoppableProcess final : public cancellable::ProcessControl {
public:
    bool waitForFinished(int) override { return false; }
    void kill() override { killed = true; }
    QProcess::ProcessState state() const override { return QProcess::Running; }
    QProcess::ProcessError error() const override { return QProcess::UnknownError; }

    bool killed = false;
};

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

template <typename Function>
cancellable::WaitResult cancelAfter(Function function, qint64 *elapsedMs)
{
    const auto flag = std::make_shared<std::atomic_bool>(false);
    std::thread canceller([flag]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
        flag->store(true);
    });
    QElapsedTimer timer;
    timer.start();
    const cancellable::WaitResult result = function(flag);
    *elapsedMs = timer.elapsed();
    canceller.join();
    return result;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);

#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    REQUIRE(cancellable::isDnsLookupTimeoutError(QDnsLookup::TimeoutError));
#endif
    REQUIRE(!cancellable::isDnsLookupTimeoutError(QDnsLookup::NoError));

    qint64 elapsedMs = 0;
    QProcess process;
    process.start("sleep", {"10"});
    REQUIRE(cancelAfter(
                [&](const cancellable::Flag &flag) {
                    return cancellable::waitForProcess(process, 10000, flag);
                },
                &elapsedMs) == cancellable::WaitResult::Cancelled);
    REQUIRE(elapsedMs < 500);
    REQUIRE(process.state() == QProcess::NotRunning);

    UnstoppableProcess unstoppable;
    const auto alreadyCancelled = std::make_shared<std::atomic_bool>(true);
    REQUIRE(cancellable::waitForProcess(unstoppable, 10000, alreadyCancelled) ==
            cancellable::WaitResult::Failed);
    REQUIRE(unstoppable.killed);

    QTcpServer server;
    REQUIRE(server.listen(QHostAddress::LocalHost, 0));
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    REQUIRE(socket.waitForConnected(500));
    REQUIRE(server.waitForNewConnection(500));
    QTcpSocket *silentPeer = server.nextPendingConnection();
    REQUIRE(silentPeer != nullptr);
    REQUIRE(cancelAfter(
                [&](const cancellable::Flag &flag) {
                    return cancellable::waitForReadyRead(socket, 10000, flag);
                },
                &elapsedMs) == cancellable::WaitResult::Cancelled);
    REQUIRE(elapsedMs < 500);
    delete silentPeer;

    QTcpSocket disconnectedSocket;
    disconnectedSocket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    REQUIRE(disconnectedSocket.waitForConnected(500));
    REQUIRE(server.waitForNewConnection(500));
    QTcpSocket *peer = server.nextPendingConnection();
    REQUIRE(peer != nullptr);
    peer->disconnectFromHost();
    if (peer->state() != QAbstractSocket::UnconnectedState) {
        REQUIRE(peer->waitForDisconnected(500));
    }
    delete peer;
    REQUIRE(cancellable::waitForReadyRead(disconnectedSocket, 1000, {}) ==
            cancellable::WaitResult::Failed);

    QTcpServer unusedPort;
    REQUIRE(unusedPort.listen(QHostAddress::LocalHost, 0));
    const quint16 refusedPort = unusedPort.serverPort();
    unusedPort.close();
    QTcpSocket refusedSocket;
    refusedSocket.connectToHost(QHostAddress::LocalHost, refusedPort);
    QElapsedTimer refusedTimer;
    refusedTimer.start();
    REQUIRE(cancellable::waitForConnected(refusedSocket, 1000, {}) ==
            cancellable::WaitResult::Failed);
    REQUIRE(refusedTimer.elapsed() < 500);

    const auto cancelled = std::make_shared<std::atomic_bool>(true);
    cancellable::WaitResult lookupResult = cancellable::WaitResult::Failed;
    cancellable::lookupHost("example.invalid", 10000, cancelled, &lookupResult);
    REQUIRE(lookupResult == cancellable::WaitResult::Cancelled);

    const cancellable::DnsPtrLookupResult cancelledPtr =
        cancellable::lookupPtr("192.0.2.10", 10000, cancelled);
    REQUIRE(cancelledPtr.waitResult == cancellable::WaitResult::Cancelled);
    const cancellable::DnsPtrLookupResult expiredPtr =
        cancellable::lookupPtr("192.0.2.10", 0, {});
    REQUIRE(expiredPtr.waitResult == cancellable::WaitResult::TimedOut);
    const cancellable::DnsPtrLookupResult invalidPtr =
        cancellable::lookupPtr("not-an-ip", 100, {});
    REQUIRE(invalidPtr.waitResult == cancellable::WaitResult::Failed);

    QTcpSocket preCancelledSocket;
    preCancelledSocket.connectToHost(QHostAddress("192.0.2.1"), 65000);
    REQUIRE(cancellable::waitForConnected(preCancelledSocket, 10000, cancelled) ==
            cancellable::WaitResult::Cancelled);
    REQUIRE(cancelAfter(
                [&](const cancellable::Flag &flag) {
                    return cancellable::waitForDelay(10000, flag);
                },
                &elapsedMs) == cancellable::WaitResult::Cancelled);
    REQUIRE(elapsedMs < 500);
    return EXIT_SUCCESS;
}
