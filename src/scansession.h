#pragma once

#include "scanresult.h"

#include <QObject>

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

class QTimer;

class ScanSession : public QObject {
    Q_OBJECT

public:
    using Cancellation = std::shared_ptr<std::atomic_bool>;
    using ProgressCallback = std::function<void(int, int)>;
    using ResultCallback = std::function<void(const ScanResult &)>;
    using Work = std::function<QList<ScanResult>(
        const Cancellation &, const ProgressCallback &, const ResultCallback &)>;

    explicit ScanSession(QObject *parent = nullptr);
    ~ScanSession() override;

    bool start(Work work);
    void cancel();
    void waitForFinished();
    bool isRunning() const;

signals:
    void progressChanged(int current, int total);
    void resultReady(const ScanResult &result);
    void completed(const QList<ScanResult> &results, bool canceled);

private:
    struct DeliveryQueue;
    void drainDeliveries();

    std::thread worker_;
    std::atomic_bool running_{false};
    Cancellation cancellation_;
    std::shared_ptr<DeliveryQueue> deliveries_;
    QTimer *deliveryTimer_ = nullptr;
    int idlePollIntervalMs_ = 1;
};
