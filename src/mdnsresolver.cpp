#include "mdnsresolver.h"

#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QHostAddress>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QRegularExpression>
#include <QSet>
#include <QThread>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace {

constexpr int kAvahiIpv4Protocol = 0;
constexpr quint32 kAvahiLookupUseMulticast = 2;
constexpr int kCancellationPollMs = 25;
constexpr int kBackendDeadlineMs = 2000;
constexpr int kObservationCacheMs = 250;

constexpr auto kAvahiTimeoutError = "org.freedesktop.Avahi.TimeoutError";

QString normalizedIpv4(const QString &address)
{
    QHostAddress parsed;
    if (!parsed.setAddress(address) ||
        parsed.protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }
    return parsed.toString();
}

QString normalizedHostname(const QString &hostname)
{
    QString normalized = hostname.trimmed();
    if (normalized.endsWith('.')) {
        normalized.chop(1);
    }
    static const QRegularExpression validName(
        "^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)*"
        "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
    return validName.match(normalized).hasMatch() ? normalized : QString();
}

struct CacheEntry {
    std::mutex mutex;
    std::condition_variable changed;
    bool completed = false;
    MdnsLookupResult result;
    std::chrono::steady_clock::time_point completedAt;
};

bool isCacheableObservation(const MdnsLookupResult &result)
{
    return result.status == MdnsLookupStatus::Resolved ||
           result.status == MdnsLookupStatus::NoRecord;
}

} // namespace

MdnsLookupStatus mdnsStatusForDbusError(const QDBusError &error)
{
    if (error.type() == QDBusError::NoReply ||
        error.type() == QDBusError::Timeout) {
        return MdnsLookupStatus::TimedOut;
    }
    if (error.name() == QLatin1String(kAvahiTimeoutError) ||
        error.name().contains("NotFound", Qt::CaseInsensitive)) {
        return MdnsLookupStatus::NoRecord;
    }
    return MdnsLookupStatus::BackendUnavailable;
}

namespace {

class AvahiDbusBackend final : public MdnsLookupBackend {
public:
    AvahiDbusBackend()
    {
        dispatcher_ = new QObject;
        dispatcher_->moveToThread(&thread_);
        QObject::connect(&thread_, &QThread::finished,
                         dispatcher_, &QObject::deleteLater);
        thread_.start();
    }

    ~AvahiDbusBackend() override
    {
        cancelAll();
        thread_.quit();
        thread_.wait();
        dispatcher_ = nullptr;
    }

    void resolve(int interfaceIndex,
                 const QString &address,
                 int timeoutMs,
        Callback callback) override
    {
        if (stopping_.load()) {
            MdnsBackendReply cancelled;
            cancelled.status = MdnsLookupStatus::Cancelled;
            callback(cancelled);
            return;
        }
        QMetaObject::invokeMethod(
            dispatcher_,
            [this, interfaceIndex, address, timeoutMs, callback = std::move(callback)]() {
                if (stopping_.load()) {
                    MdnsBackendReply cancelled;
                    cancelled.status = MdnsLookupStatus::Cancelled;
                    callback(cancelled);
                    return;
                }
                QDBusMessage message = QDBusMessage::createMethodCall(
                    "org.freedesktop.Avahi",
                    "/",
                    "org.freedesktop.Avahi.Server",
                    "ResolveAddress");
                message.setArguments({interfaceIndex,
                                      kAvahiIpv4Protocol,
                                      address,
                                      kAvahiLookupUseMulticast});
                auto *watcher = new QDBusPendingCallWatcher(
                    QDBusConnection::systemBus().asyncCall(message, timeoutMs), dispatcher_);
                {
                    QMutexLocker locker(&watchersMutex_);
                    watchers_.insert(watcher);
                }
                QObject::connect(
                    watcher,
                    &QDBusPendingCallWatcher::finished,
                    dispatcher_,
                    [this, watcher, callback = std::move(callback)]() {
                        {
                            QMutexLocker locker(&watchersMutex_);
                            watchers_.remove(watcher);
                        }
                        QDBusPendingReply<int, int, int, QString, QString, quint32> reply =
                            *watcher;
                        MdnsBackendReply result;
                        if (reply.isError()) {
                            result.status = mdnsStatusForDbusError(reply.error());
                        } else {
                            result.status = MdnsLookupStatus::Resolved;
                            result.interfaceIndex = reply.argumentAt<0>();
                            result.lookupProtocol = reply.argumentAt<1>();
                            result.addressProtocol = reply.argumentAt<2>();
                            result.address = reply.argumentAt<3>();
                            result.hostname = reply.argumentAt<4>();
                        }
                        watcher->deleteLater();
                        if (!stopping_.load()) {
                            callback(result);
                        }
                    });
            },
            Qt::QueuedConnection);
    }

    void cancelAll() override
    {
        if (stopping_.exchange(true) || !thread_.isRunning()) {
            return;
        }
        QMetaObject::invokeMethod(
            dispatcher_,
            [this]() {
                QSet<QDBusPendingCallWatcher *> pending;
                {
                    QMutexLocker locker(&watchersMutex_);
                    pending = watchers_;
                    watchers_.clear();
                }
                for (QDBusPendingCallWatcher *watcher : pending) {
                    QObject::disconnect(watcher, nullptr, dispatcher_, nullptr);
                    delete watcher;
                }
            },
            Qt::BlockingQueuedConnection);
    }

private:
    QThread thread_;
    QObject *dispatcher_ = nullptr;
    QMutex watchersMutex_;
    QSet<QDBusPendingCallWatcher *> watchers_;
    std::atomic_bool stopping_{false};
};

} // namespace

struct ScanMdnsResolver::SharedState {
    std::mutex mutex;
    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> cache;
    std::atomic_bool cancelled{false};
};

ScanMdnsResolver::ScanMdnsResolver(int interfaceIndex,
                                   cancellable::Flag cancellation,
                                   std::unique_ptr<MdnsLookupBackend> backend)
    : interfaceIndex_(interfaceIndex),
      cancellation_(std::move(cancellation)),
      backend_(std::move(backend)),
      state_(std::make_shared<SharedState>())
{
}

ScanMdnsResolver::~ScanMdnsResolver()
{
    cancel();
}

MdnsLookupResult ScanMdnsResolver::resolve(const QString &address, int timeoutMs)
{
    const QString normalizedAddress = normalizedIpv4(address);
    if (interfaceIndex_ <= 0 || normalizedAddress.isEmpty() || backend_ == nullptr) {
        return {MdnsLookupStatus::InvalidResponse, {}};
    }
    if (timeoutMs <= 0) {
        return {MdnsLookupStatus::TimedOut, {}};
    }
    if (cancellable::isCancelled(cancellation_) || state_->cancelled.load()) {
        cancel();
        return {MdnsLookupStatus::Cancelled, {}};
    }

    std::shared_ptr<CacheEntry> entry;
    bool shouldStart = false;
    const std::string key = QString("%1|%2").arg(interfaceIndex_).arg(normalizedAddress)
                                .toStdString();
    while (true) {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            const auto found = state_->cache.find(key);
            if (found == state_->cache.end()) {
                entry = std::make_shared<CacheEntry>();
                state_->cache.emplace(key, entry);
                shouldStart = true;
                break;
            }
            entry = found->second;
        }

        bool expired = false;
        {
            std::lock_guard<std::mutex> entryLock(entry->mutex);
            expired = entry->completed &&
                      (!isCacheableObservation(entry->result) ||
                       std::chrono::steady_clock::now() - entry->completedAt >=
                           std::chrono::milliseconds(kObservationCacheMs));
        }
        if (!expired) {
            break;
        }

        std::lock_guard<std::mutex> lock(state_->mutex);
        const auto current = state_->cache.find(key);
        if (current != state_->cache.end() && current->second == entry) {
            entry = std::make_shared<CacheEntry>();
            current->second = entry;
            shouldStart = true;
            break;
        }
    }

    if (shouldStart) {
        backend_->resolve(
            interfaceIndex_, normalizedAddress,
            std::min(timeoutMs, kBackendDeadlineMs),
            [entry, sharedState = state_, expectedInterface = interfaceIndex_, normalizedAddress](
                const MdnsBackendReply &reply) {
                MdnsLookupResult result;
                result.status = reply.status;
                if (sharedState->cancelled.load()) {
                    result.status = MdnsLookupStatus::Cancelled;
                } else if (reply.status == MdnsLookupStatus::Resolved) {
                    const QString replyAddress = normalizedIpv4(reply.address);
                    const QString replyHostname = normalizedHostname(reply.hostname);
                    if (reply.interfaceIndex != expectedInterface ||
                        reply.lookupProtocol != kAvahiIpv4Protocol ||
                        reply.addressProtocol != kAvahiIpv4Protocol ||
                        replyAddress != normalizedAddress || replyHostname.isEmpty() ||
                        replyHostname == normalizedAddress) {
                        result.status = MdnsLookupStatus::InvalidResponse;
                    } else {
                        result.hostname = replyHostname;
                    }
                }
                {
                    std::lock_guard<std::mutex> lock(entry->mutex);
                    entry->result = result;
                    entry->completed = true;
                    entry->completedAt = std::chrono::steady_clock::now();
                }
                entry->changed.notify_all();
            });
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    std::unique_lock<std::mutex> lock(entry->mutex);
    while (!entry->completed) {
        if (cancellable::isCancelled(cancellation_) || state_->cancelled.load()) {
            lock.unlock();
            cancel();
            return {MdnsLookupStatus::Cancelled, {}};
        }
        if (entry->changed.wait_for(lock, std::chrono::milliseconds(kCancellationPollMs)) ==
                std::cv_status::timeout &&
            std::chrono::steady_clock::now() >= deadline) {
            return {MdnsLookupStatus::TimedOut, {}};
        }
    }
    if (cancellable::isCancelled(cancellation_) || state_->cancelled.load()) {
        lock.unlock();
        cancel();
        return {MdnsLookupStatus::Cancelled, {}};
    }
    return entry->result;
}

void ScanMdnsResolver::cancel()
{
    if (!state_ || state_->cancelled.exchange(true)) {
        return;
    }
    if (backend_) {
        backend_->cancelAll();
    }
    std::lock_guard<std::mutex> cacheLock(state_->mutex);
    for (const auto &item : state_->cache) {
        const std::shared_ptr<CacheEntry> &entry = item.second;
        {
            std::lock_guard<std::mutex> entryLock(entry->mutex);
            if (!entry->completed) {
                entry->result = {MdnsLookupStatus::Cancelled, {}};
                entry->completed = true;
                entry->completedAt = std::chrono::steady_clock::now();
            }
        }
        entry->changed.notify_all();
    }
}

std::unique_ptr<MdnsLookupBackend> createAvahiDbusBackend()
{
    return std::make_unique<AvahiDbusBackend>();
}
