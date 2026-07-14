#include "scansession.h"

#include <QTimer>

#include <algorithm>
#include <deque>
#include <mutex>
#include <system_error>
#include <utility>

struct ScanSession::DeliveryQueue {
    enum class Kind {
        Progress,
        Result,
        Completion
    };

    struct Delivery {
        Kind kind = Kind::Progress;
        Cancellation cancellation;
        int current = 0;
        int total = 0;
        ScanResult result;
        QList<ScanResult> results;
        bool canceled = false;
    };

    void push(Delivery delivery)
    {
        const std::lock_guard<std::mutex> locker(mutex);
        pending.push_back(std::move(delivery));
    }

    std::deque<Delivery> takeBatch(std::size_t maximum, bool *hasMore)
    {
        const std::lock_guard<std::mutex> locker(mutex);
        std::deque<Delivery> taken;
        while (!pending.empty() && taken.size() < maximum) {
            taken.push_back(std::move(pending.front()));
            pending.pop_front();
        }
        if (hasMore != nullptr) {
            *hasMore = !pending.empty();
        }
        return taken;
    }

    void clear()
    {
        const std::lock_guard<std::mutex> locker(mutex);
        pending.clear();
    }

    std::mutex mutex;
    std::deque<Delivery> pending;
};

ScanSession::ScanSession(QObject *parent)
    : QObject(parent),
      deliveries_(std::make_shared<DeliveryQueue>()),
      deliveryTimer_(new QTimer(this))
{
    deliveryTimer_->setInterval(1);
    connect(deliveryTimer_, &QTimer::timeout, this, &ScanSession::drainDeliveries);
}

ScanSession::~ScanSession()
{
    cancel();
    waitForFinished();
    deliveryTimer_->stop();
    deliveries_->clear();
}

bool ScanSession::start(Work work)
{
    if (!work || running_.load()) {
        return false;
    }

    if (worker_.joinable()) {
        worker_.join();
    }
    deliveries_->clear();

    cancellation_ = std::make_shared<std::atomic_bool>(false);
    const Cancellation cancellation = cancellation_;
    const std::shared_ptr<DeliveryQueue> deliveries = deliveries_;
    running_.store(true);
    idlePollIntervalMs_ = 1;
    deliveryTimer_->setInterval(idlePollIntervalMs_);
    deliveryTimer_->start();
    const auto progress = [deliveries, cancellation](int current, int total) {
        if (cancellation->load()) {
            return;
        }
        DeliveryQueue::Delivery delivery;
        delivery.kind = DeliveryQueue::Kind::Progress;
        delivery.cancellation = cancellation;
        delivery.current = current;
        delivery.total = total;
        deliveries->push(std::move(delivery));
    };
    const auto result = [deliveries, cancellation](const ScanResult &scanResult) {
        if (cancellation->load()) {
            return;
        }
        DeliveryQueue::Delivery delivery;
        delivery.kind = DeliveryQueue::Kind::Result;
        delivery.cancellation = cancellation;
        delivery.result = scanResult;
        deliveries->push(std::move(delivery));
    };

    try {
        worker_ = std::thread(
            [work = std::move(work), cancellation, deliveries, progress, result]() {
                DeliveryQueue::Delivery delivery;
                delivery.results = work(cancellation, progress, result);
                delivery.canceled = cancellation->load();
                delivery.kind = DeliveryQueue::Kind::Completion;
                delivery.cancellation = cancellation;
                deliveries->push(std::move(delivery));
            });
    } catch (const std::system_error &) {
        deliveryTimer_->stop();
        running_.store(false);
        cancellation_.reset();
        return false;
    }
    return true;
}

void ScanSession::drainDeliveries()
{
    constexpr std::size_t maximumDeliveriesPerTurn = 128;
    constexpr int maximumIdlePollIntervalMs = 25;
    bool hasMore = false;
    std::deque<DeliveryQueue::Delivery> pending = deliveries_->takeBatch(
        maximumDeliveriesPerTurn, &hasMore);
    if (pending.empty()) {
        idlePollIntervalMs_ = std::min(
            maximumIdlePollIntervalMs, idlePollIntervalMs_ * 2);
        deliveryTimer_->setInterval(idlePollIntervalMs_);
        return;
    }
    idlePollIntervalMs_ = 1;
    deliveryTimer_->setInterval(hasMore ? 0 : idlePollIntervalMs_);
    for (const DeliveryQueue::Delivery &delivery : pending) {
        if (cancellation_ != delivery.cancellation) {
            continue;
        }
        switch (delivery.kind) {
        case DeliveryQueue::Kind::Progress:
            if (!delivery.cancellation->load()) {
                emit progressChanged(delivery.current, delivery.total);
            }
            break;
        case DeliveryQueue::Kind::Result:
            if (!delivery.cancellation->load()) {
                emit resultReady(delivery.result);
            }
            break;
        case DeliveryQueue::Kind::Completion:
            if (worker_.joinable()) {
                worker_.join();
            }
            deliveryTimer_->stop();
            running_.store(false);
            cancellation_.reset();
            emit completed(delivery.results, delivery.canceled);
            break;
        }
    }
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
