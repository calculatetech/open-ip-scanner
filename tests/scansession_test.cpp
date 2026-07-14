#include "scansession.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>
#include <QTimer>

#include <chrono>
#include <iostream>
#include <thread>

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    ScanSession session;
    const QThread *ownerThread = QThread::currentThread();
    int progressCount = 0;
    int resultCount = 0;
    int completionCount = 0;
    bool callbackThreadCorrect = true;
    bool completionCanceled = true;
    QList<ScanResult> completedResults;
    QEventLoop completed;

    QObject::connect(&session, &ScanSession::progressChanged,
                     [&](int current, int total) {
                         callbackThreadCorrect = callbackThreadCorrect &&
                                                 QThread::currentThread() == ownerThread;
                         if (current == 1 && total == 2) {
                             ++progressCount;
                         }
                     });
    QObject::connect(&session, &ScanSession::resultReady,
                     [&](const ScanResult &) {
                         callbackThreadCorrect = callbackThreadCorrect &&
                                                 QThread::currentThread() == ownerThread;
                         ++resultCount;
                     });
    QObject::connect(&session, &ScanSession::completed,
                     [&](const QList<ScanResult> &results, bool canceled) {
                         callbackThreadCorrect = callbackThreadCorrect &&
                                                 QThread::currentThread() == ownerThread;
                         ++completionCount;
                         completionCanceled = canceled;
                         completedResults = results;
                         completed.quit();
                     });

    const bool started = session.start(
        [](const ScanSession::Cancellation &,
           const ScanSession::ProgressCallback &progress,
           const ScanSession::ResultCallback &result) {
            ScanResult first;
            first.ip = "192.0.2.1";
            ScanResult second;
            second.ip = "192.0.2.2";
            result(first);
            progress(1, 2);
            result(second);
            progress(2, 2);
            return QList<ScanResult>{first, second};
        });
    const bool refusedOverlap = !session.start(
        [](const ScanSession::Cancellation &,
           const ScanSession::ProgressCallback &,
           const ScanSession::ResultCallback &) { return QList<ScanResult>{}; });
    QTimer::singleShot(2000, &completed, &QEventLoop::quit);
    completed.exec();
    if (!started || !refusedOverlap || session.isRunning() ||
        completionCount != 1 || completionCanceled || completedResults.size() != 2 ||
        resultCount != 2 || progressCount != 1 || !callbackThreadCorrect) {
        std::cerr << "normal scan-session lifecycle contract failed\n";
        return 1;
    }

    int resultCountAtCancellation = 0;
    bool canceledCompletion = false;
    QEventLoop canceled;
    QObject::connect(&session, &ScanSession::resultReady,
                     [&](const ScanResult &) { ++resultCountAtCancellation; });
    QObject::connect(&session, &ScanSession::completed,
                     [&](const QList<ScanResult> &, bool wasCanceled) {
                         canceledCompletion = wasCanceled;
                         canceled.quit();
                     });
    QElapsedTimer cancellationTime;
    cancellationTime.start();
    if (!session.start(
            [](const ScanSession::Cancellation &cancellation,
               const ScanSession::ProgressCallback &progress,
               const ScanSession::ResultCallback &result) {
                QList<ScanResult> results;
                for (int index = 0; index < 200; ++index) {
                    ScanResult scanResult;
                    scanResult.ip = QString("198.51.100.%1").arg(index + 1);
                    if (cancellation->load()) {
                        result(scanResult);
                        progress(index + 1, 200);
                        break;
                    }
                    results.append(scanResult);
                    result(scanResult);
                    progress(index + 1, 200);
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                return results;
            })) {
        return 1;
    }
    QTimer::singleShot(25, &session, &ScanSession::cancel);
    QTimer::singleShot(2000, &canceled, &QEventLoop::quit);
    canceled.exec();
    const int countWhenCompleted = resultCountAtCancellation;
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    if (!canceledCompletion || session.isRunning() || cancellationTime.elapsed() >= 500 ||
        resultCountAtCancellation != countWhenCompleted || countWhenCompleted >= 200 ||
        completionCount != 2) {
        std::cerr << "scan-session cancellation contract failed\n";
        return 1;
    }
    return 0;
}
