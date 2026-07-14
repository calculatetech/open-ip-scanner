#include "hostnameevidence.h"
#include "mdnsresolver.h"

#include <QCoreApplication>
#include <QDBusError>
#include <QDBusMessage>
#include <QElapsedTimer>
#include <QNetworkInterface>
#include <QStringList>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <utility>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "mDNS resolver requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

class FakeBackend final : public MdnsLookupBackend {
public:
    explicit FakeBackend(MdnsBackendReply reply, int delayMs = 0)
        : reply_(std::move(reply)), delayMs_(delayMs)
    {
    }

    ~FakeBackend() override { cancelAll(); }

    void resolve(int, const QString &, int timeoutMs, Callback callback) override
    {
        requestCount.fetch_add(1);
        receivedTimeoutMs.store(timeoutMs);
        if (delayMs_ <= 0) {
            callback(reply_);
            return;
        }
        worker_ = std::thread([this, callback = std::move(callback)]() {
            std::unique_lock<std::mutex> lock(mutex_);
            const bool cancelled = changed_.wait_for(
                lock,
                std::chrono::milliseconds(delayMs_),
                [this]() { return cancelled_; });
            lock.unlock();
            if (!cancelled) {
                callback(reply_);
            }
        });
    }

    void cancelAll() override
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelled_ = true;
        }
        changed_.notify_all();
        if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
            worker_.join();
        }
        cancelCount.fetch_add(1);
    }

    std::atomic<int> requestCount{0};
    std::atomic<int> cancelCount{0};
    std::atomic<int> receivedTimeoutMs{0};

private:
    MdnsBackendReply reply_;
    int delayMs_ = 0;
    std::mutex mutex_;
    std::condition_variable changed_;
    bool cancelled_ = false;
    std::thread worker_;
};

class SequenceBackend final : public MdnsLookupBackend {
public:
    explicit SequenceBackend(QList<MdnsBackendReply> replies)
        : replies_(std::move(replies))
    {
    }

    void resolve(int, const QString &, int, Callback callback) override
    {
        const int request = requestCount.fetch_add(1);
        callback(replies_.at(
            std::min(request, static_cast<int>(replies_.size()) - 1)));
    }

    void cancelAll() override { }

    std::atomic<int> requestCount{0};

private:
    QList<MdnsBackendReply> replies_;
};

std::unique_ptr<FakeBackend> resolvedBackend(int delayMs = 0)
{
    MdnsBackendReply reply;
    reply.status = MdnsLookupStatus::Resolved;
    reply.interfaceIndex = 7;
    reply.lookupProtocol = 0;
    reply.addressProtocol = 0;
    reply.address = "192.0.2.10";
    reply.hostname = "fixture.local.";
    return std::make_unique<FakeBackend>(reply, delayMs);
}

std::unique_ptr<FakeBackend> resolvedBackendFor(int interfaceIndex,
                                                const QString &address,
                                                const QString &hostname)
{
    MdnsBackendReply reply;
    reply.status = MdnsLookupStatus::Resolved;
    reply.interfaceIndex = interfaceIndex;
    reply.lookupProtocol = 0;
    reply.addressProtocol = 0;
    reply.address = address;
    reply.hostname = hostname;
    return std::make_unique<FakeBackend>(reply);
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (QCoreApplication::arguments().contains("--live")) {
        const int loopbackIndex = QNetworkInterface::interfaceIndexFromName("lo");
        ScanMdnsResolver resolver(loopbackIndex, {}, createAvahiDbusBackend());
        const MdnsLookupResult result = resolver.resolve("127.0.0.1", 2000);
        REQUIRE(result.status == MdnsLookupStatus::Resolved);
        REQUIRE(result.hostname.endsWith(".local"));
        return EXIT_SUCCESS;
    }

    {
        auto backend = resolvedBackend();
        FakeBackend *observed = backend.get();
        ScanMdnsResolver resolver(7, {}, std::move(backend));
        const MdnsLookupResult first = resolver.resolve("192.0.2.10", 500);
        const MdnsLookupResult cached = resolver.resolve("192.0.2.10", 500);
        REQUIRE(first.status == MdnsLookupStatus::Resolved);
        REQUIRE(first.hostname == "fixture.local");
        REQUIRE(cached.status == MdnsLookupStatus::Resolved);
        REQUIRE(observed->requestCount.load() == 1);
        REQUIRE(observed->receivedTimeoutMs.load() == 500);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::Resolved);
        REQUIRE(observed->requestCount.load() == 2);
    }

    {
        MdnsBackendReply noRecord;
        noRecord.status = MdnsLookupStatus::NoRecord;
        auto backend = std::make_unique<FakeBackend>(noRecord);
        FakeBackend *observed = backend.get();
        ScanMdnsResolver resolver(7, {}, std::move(backend));
        REQUIRE(resolver.resolve("192.0.2.20", 500).status ==
                MdnsLookupStatus::NoRecord);
        REQUIRE(resolver.resolve("192.0.2.20", 500).status ==
                MdnsLookupStatus::NoRecord);
        REQUIRE(observed->requestCount.load() == 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        REQUIRE(resolver.resolve("192.0.2.20", 500).status ==
                MdnsLookupStatus::NoRecord);
        REQUIRE(observed->requestCount.load() == 2);
    }

    {
        const QDBusError avahiNoAnswer(QDBusMessage::createError(
            "org.freedesktop.Avahi.TimeoutError", "Timeout reached"));
        const QDBusError transportTimeout(QDBusMessage::createError(
            "org.freedesktop.DBus.Error.NoReply", "D-Bus deadline reached"));
        const QDBusError backendFailure(QDBusMessage::createError(
            "org.freedesktop.DBus.Error.ServiceUnknown", "Avahi is unavailable"));
        const QDBusError noNetwork(QDBusMessage::createError(
            "org.freedesktop.Avahi.NoNetworkError", "No multicast interface"));
        const QDBusError noOwner(QDBusMessage::createError(
            "org.freedesktop.DBus.Error.NameHasNoOwner", "No daemon owner"));
        const QDBusError accessDenied(QDBusMessage::createError(
            "org.freedesktop.DBus.Error.AccessDenied", "Policy rejected request"));
        REQUIRE(mdnsStatusForDbusError(avahiNoAnswer) == MdnsLookupStatus::NoRecord);
        REQUIRE(mdnsStatusForDbusError(transportTimeout) == MdnsLookupStatus::TimedOut);
        REQUIRE(mdnsStatusForDbusError(backendFailure) ==
                MdnsLookupStatus::DaemonUnavailable);
        REQUIRE(mdnsStatusForDbusError(noNetwork) ==
                MdnsLookupStatus::MulticastUnavailable);
        REQUIRE(mdnsStatusForDbusError(noOwner) ==
                MdnsLookupStatus::DaemonUnavailable);
        REQUIRE(mdnsStatusForDbusError(accessDenied) ==
                MdnsLookupStatus::BackendUnavailable);
    }

    {
        auto backend = resolvedBackend(75);
        FakeBackend *observed = backend.get();
        ScanMdnsResolver resolver(7, {}, std::move(backend));
        MdnsLookupResult first;
        MdnsLookupResult second;
        std::thread firstCaller([&]() { first = resolver.resolve("192.0.2.10", 500); });
        std::thread secondCaller([&]() { second = resolver.resolve("192.0.2.10", 500); });
        firstCaller.join();
        secondCaller.join();
        REQUIRE(first.status == MdnsLookupStatus::Resolved);
        REQUIRE(second.status == MdnsLookupStatus::Resolved);
        REQUIRE(observed->requestCount.load() == 1);
    }

    {
        MdnsBackendReply wrongInterface;
        wrongInterface.status = MdnsLookupStatus::Resolved;
        wrongInterface.interfaceIndex = 8;
        wrongInterface.lookupProtocol = 0;
        wrongInterface.addressProtocol = 0;
        wrongInterface.address = "192.0.2.10";
        wrongInterface.hostname = "wrong.local";
        ScanMdnsResolver resolver(
            7, {}, std::make_unique<FakeBackend>(wrongInterface));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::InvalidResponse);
    }

    {
        MdnsBackendReply wrongProtocol;
        wrongProtocol.status = MdnsLookupStatus::Resolved;
        wrongProtocol.interfaceIndex = 7;
        wrongProtocol.lookupProtocol = -1;
        wrongProtocol.addressProtocol = 0;
        wrongProtocol.address = "192.0.2.10";
        wrongProtocol.hostname = "wrong.local";
        ScanMdnsResolver resolver(
            7, {}, std::make_unique<FakeBackend>(wrongProtocol));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::InvalidResponse);
    }

    {
        MdnsBackendReply wrongAddress;
        wrongAddress.status = MdnsLookupStatus::Resolved;
        wrongAddress.interfaceIndex = 7;
        wrongAddress.lookupProtocol = 0;
        wrongAddress.addressProtocol = 0;
        wrongAddress.address = "192.0.2.11";
        wrongAddress.hostname = "wrong.local";
        ScanMdnsResolver resolver(
            7, {}, std::make_unique<FakeBackend>(wrongAddress));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::InvalidResponse);
    }

    {
        MdnsBackendReply wrongAddressProtocol;
        wrongAddressProtocol.status = MdnsLookupStatus::Resolved;
        wrongAddressProtocol.interfaceIndex = 7;
        wrongAddressProtocol.lookupProtocol = 0;
        wrongAddressProtocol.addressProtocol = -1;
        wrongAddressProtocol.address = "192.0.2.10";
        wrongAddressProtocol.hostname = "wrong.local";
        ScanMdnsResolver resolver(
            7, {}, std::make_unique<FakeBackend>(wrongAddressProtocol));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::InvalidResponse);
    }

    for (const QString &malformed : QStringList({
             "", "bad name.local", "-bad.local", "bad..local", "192.0.2.10"})) {
        ScanMdnsResolver resolver(
            7, {}, resolvedBackendFor(7, "192.0.2.10", malformed));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::InvalidResponse);
    }

    {
        ScanMdnsResolver first(
            7, {}, resolvedBackendFor(7, "192.0.2.10", "first.local"));
        ScanMdnsResolver overlapping(
            8, {}, resolvedBackendFor(8, "192.0.2.10", "second.local"));
        REQUIRE(first.resolve("192.0.2.10", 500).hostname == "first.local");
        REQUIRE(overlapping.resolve("192.0.2.10", 500).hostname ==
                "second.local");
    }

    {
        MdnsBackendReply unavailable;
        unavailable.status = MdnsLookupStatus::DaemonUnavailable;
        MdnsBackendReply recovered;
        recovered.status = MdnsLookupStatus::Resolved;
        recovered.interfaceIndex = 7;
        recovered.lookupProtocol = 0;
        recovered.addressProtocol = 0;
        recovered.address = "192.0.2.10";
        recovered.hostname = "recovered.local";
        auto backend = std::make_unique<SequenceBackend>(
            QList<MdnsBackendReply>{unavailable, recovered});
        SequenceBackend *observed = backend.get();
        ScanMdnsResolver resolver(7, {}, std::move(backend));
        REQUIRE(resolver.resolve("192.0.2.10", 500).status ==
                MdnsLookupStatus::DaemonUnavailable);
        const MdnsLookupResult afterRestart =
            resolver.resolve("192.0.2.10", 500);
        REQUIRE(afterRestart.status == MdnsLookupStatus::Resolved);
        REQUIRE(afterRestart.hostname == "recovered.local");
        REQUIRE(observed->requestCount.load() == 2);
    }

    {
        auto backend = resolvedBackend(5000);
        auto cancellation = std::make_shared<std::atomic_bool>(false);
        ScanMdnsResolver resolver(7, cancellation, std::move(backend));
        MdnsLookupResult result;
        QElapsedTimer timer;
        timer.start();
        std::thread caller([&]() { result = resolver.resolve("192.0.2.10", 5000); });
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
        cancellation->store(true);
        caller.join();
        REQUIRE(result.status == MdnsLookupStatus::Cancelled);
        REQUIRE(timer.elapsed() < 500);
    }

    {
        auto backend = resolvedBackend(5000);
        FakeBackend *observed = backend.get();
        ScanMdnsResolver resolver(7, {}, std::move(backend));
        QElapsedTimer timer;
        timer.start();
        REQUIRE(resolver.resolve("192.0.2.10", 60).status ==
                MdnsLookupStatus::TimedOut);
        REQUIRE(timer.elapsed() < 500);
        REQUIRE(observed->receivedTimeoutMs.load() == 60);
    }

    REQUIRE(ScanMdnsResolver(0, {}, resolvedBackend())
                .resolve("192.0.2.10", 500)
                .status == MdnsLookupStatus::InvalidResponse);
    REQUIRE(ScanMdnsResolver(7, {}, resolvedBackend())
                .resolve("not-an-ip", 500)
                .status == MdnsLookupStatus::InvalidResponse);
    REQUIRE(ScanMdnsResolver(7, {}, {})
                .resolve("192.0.2.10", 500)
                .status == MdnsLookupStatus::BackendUnavailable);

    const HostnameEvidence preliminary{"gateway", HostnameSource::Preliminary};
    const HostnameEvidence system{"gateway.example", HostnameSource::SystemResolver};
    const HostnameEvidence mdns{"gateway.local", HostnameSource::AvahiMdns};
    const HostnameEvidence ptr{"gateway.ptr.example", HostnameSource::DnsPtr};
    const HostnameEvidence local{"gateway.localdomain", HostnameSource::LocalHost};
    REQUIRE(preferredHostname(preliminary, system).hostname == "gateway.example");
    REQUIRE(preferredHostname(system, mdns).hostname == "gateway.example");
    REQUIRE(preferredHostname(mdns, system).hostname == "gateway.example");
    REQUIRE(preferredHostname(system, ptr).hostname == "gateway.ptr.example");
    REQUIRE(preferredHostname(ptr, local).hostname == "gateway.localdomain");
    REQUIRE(preferredHostname(mdns,
                              {"other.local", HostnameSource::AvahiMdns})
                .hostname == "gateway.local");
    const QList<HostnameDisplayRow> retained = hostnameDisplayRows(
        {system, mdns, ptr, local});
    REQUIRE(retained.size() == 4);
    REQUIRE(retained.first().hostname == "gateway.localdomain");

    MdnsBackendReply fallbackNoRecord;
    fallbackNoRecord.status = MdnsLookupStatus::NoRecord;
    ScanMdnsResolver fallbackResolver(
        7, {}, std::make_unique<FakeBackend>(fallbackNoRecord));
    REQUIRE(fallbackResolver.resolve("192.0.2.10", 500).status ==
            MdnsLookupStatus::NoRecord);
    REQUIRE(preferredHostname({preliminary, system}).hostname ==
            "gateway.example");
    return EXIT_SUCCESS;
}
