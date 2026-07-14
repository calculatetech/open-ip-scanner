#include "scansession.h"

#include <QMetaObject>

#include <system_error>

ScanSession::ScanSession(QObject *parent)
    : QObject(parent)
{
}

ScanSession::~ScanSession()
{
    cancel();
    waitForFinished();
}

bool ScanSession::start(Work work)
{
    if (!work || running_.load()) {
        return false;
    }

    if (worker_.joinable()) {
        worker_.join();
    }

    cancellation_ = std::make_shared<std::atomic_bool>(false);
    const Cancellation cancellation = cancellation_;
    running_.store(true);
    const auto progress = [this, cancellation](int current, int total) {
        if (cancellation->load()) {
            return;
        }
        QMetaObject::invokeMethod(
            this,
            [this, cancellation, current, total]() {
                if (!cancellation->load()) {
                    emit progressChanged(current, total);
                }
            },
            Qt::QueuedConnection);
    };
    const auto result = [this, cancellation](const ScanResult &scanResult) {
        if (cancellation->load()) {
            return;
        }
        QMetaObject::invokeMethod(
            this,
            [this, cancellation, scanResult]() {
                if (!cancellation->load()) {
                    emit resultReady(scanResult);
                }
            },
            Qt::QueuedConnection);
    };

    try {
        worker_ = std::thread(
            [this, work = std::move(work), cancellation, progress, result]() {
                const QList<ScanResult> results = work(cancellation, progress, result);
                const bool canceled = cancellation->load();
                QMetaObject::invokeMethod(
                    this,
                    [this, cancellation, results, canceled]() {
                        if (worker_.joinable()) {
                            worker_.join();
                        }
                        running_.store(false);
                        cancellation_.reset();
                        emit completed(results, canceled);
                    },
                    Qt::QueuedConnection);
            });
    } catch (const std::system_error &) {
        running_.store(false);
        cancellation_.reset();
        return false;
    }
    return true;
}

void ScanSession::cancel()
{
    if (cancellation_) {
        cancellation_->store(true);
    }
}

void ScanSession::waitForFinished()
{
    if (worker_.joinable()) {
        worker_.join();
    }
    running_.store(false);
}

bool ScanSession::isRunning() const
{
    return running_.load();
}
