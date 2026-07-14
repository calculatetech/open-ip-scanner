#include "scanengine.h"

#include <QCoreApplication>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace {
class FakeBackend final : public IHostScanBackend {
public:
    HostScanOutcome scan(
        const QHostAddress &host,
        const std::shared_ptr<std::atomic_bool> &cancellation) override
    {
        const int activeNow = active.fetch_add(1) + 1;
        int observed = maximumActive.load();
        while (activeNow > observed &&
               !maximumActive.compare_exchange_weak(observed, activeNow)) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        active.fetch_sub(1);
        calls.fetch_add(1);
        if (cancellation && cancellation->load()) {
            return {};
        }
        ScanResult result;
        result.ip = host.toString();
        result.interfaceName = "fixture0";
        result.mac = "Unknown";
        result.vendor = "Unknown";
        result.hostname = "Unknown";
        return {true, result};
    }

    std::atomic<int> active{0};
    std::atomic<int> maximumActive{0};
    std::atomic<int> calls{0};
};

class BlockingBackend final : public IHostScanBackend {
public:
    HostScanOutcome scan(
        const QHostAddress &host,
        const std::shared_ptr<std::atomic_bool> &) override
    {
        std::unique_lock<std::mutex> locker(mutex);
        ++entered;
        enteredCondition.notify_all();
        releaseCondition.wait(locker, [&]() { return released; });
        locker.unlock();
        calls.fetch_add(1);

        ScanResult result;
        result.ip = host.toString();
        result.interfaceName = "fixture0";
        result.mac = "Unknown";
        result.vendor = "Unknown";
        result.hostname = "Unknown";
        return {true, result};
    }

    void waitForEntered(int expected)
    {
        std::unique_lock<std::mutex> locker(mutex);
        enteredCondition.wait(locker, [&]() { return entered >= expected; });
    }

    void release()
    {
        const std::lock_guard<std::mutex> locker(mutex);
        released = true;
        releaseCondition.notify_all();
    }

    std::atomic<int> calls{0};

private:
    std::mutex mutex;
    std::condition_variable enteredCondition;
    std::condition_variable releaseCondition;
    int entered = 0;
    bool released = false;
};
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    FakeBackend backend;
    const auto cancellation = std::make_shared<std::atomic_bool>(false);
    QList<QHostAddress> hosts;
    for (int value = 12; value >= 1; --value) {
        hosts.append(QHostAddress(QString("192.0.2.%1").arg(value)));
    }
    std::atomic<int> progressCalls{0};
    std::atomic<int> published{0};
    const QList<ScanResult> results = ScanEngine::run(
        hosts,
        4,
        cancellation,
        backend,
        [&](int current, int total) {
            if (current >= 1 && current <= total && total == hosts.size()) {
                progressCalls.fetch_add(1);
            }
        },
        [&](const ScanResult &) { published.fetch_add(1); });
    if (results.size() != hosts.size() || results.first().ip != "192.0.2.1" ||
        results.last().ip != "192.0.2.12" || backend.calls.load() != hosts.size() ||
        backend.maximumActive.load() < 2 || backend.maximumActive.load() > 4 ||
        progressCalls.load() != hosts.size() || published.load() != hosts.size()) {
        std::cerr << "parallel scheduling or deterministic result contract failed\n";
        return 1;
    }

    int duplicateCall = 0;
    CallbackHostScanBackend mergingBackend(
        [&](const QHostAddress &host,
            const std::shared_ptr<std::atomic_bool> &) {
            ScanResult result;
            result.ip = host.toString();
            result.interfaceName = "fixture0";
            result.mac = duplicateCall == 0 ? "Unknown" : "00:11:22:33:44:55";
            result.vendor = duplicateCall == 0 ? "Unknown" : "Vendor";
            result.hostname = duplicateCall == 0 ? "Unknown" : "device.local";
            if (duplicateCall != 0) {
                result.hostnameEvidence.append(
                    {"device.local", HostnameSource::AvahiMdns});
                result.resolverEvents.append(
                    {ResolverKind::Mdns, ResolverOutcome::Resolved});
                result.services.append(
                    {"ssh", "SSH", 22, false,
                     ServiceEvidenceLevel::VerifiedProtocol});
            }
            ++duplicateCall;
            return HostScanOutcome{true, result};
        });
    int mergePublications = 0;
    const QList<ScanResult> merged = ScanEngine::run(
        {QHostAddress("198.51.100.7"), QHostAddress("198.51.100.7")},
        1,
        std::make_shared<std::atomic_bool>(false),
        mergingBackend,
        {},
        [&](const ScanResult &) { ++mergePublications; });
    if (merged.size() != 1 || merged.first().mac != "00:11:22:33:44:55" ||
        merged.first().vendor != "Vendor" ||
        merged.first().hostname != "device.local" ||
        merged.first().resolverEvents.size() != 1 ||
        merged.first().services.size() != 1 || mergePublications != 2) {
        std::cerr << "identity merge contract failed\n";
        return 1;
    }

    int interfaceCall = 0;
    CallbackHostScanBackend interfaceBackend(
        [&](const QHostAddress &host,
            const std::shared_ptr<std::atomic_bool> &) {
            ScanResult result;
            result.ip = host.toString();
            result.interfaceName = interfaceCall++ == 0 ? "zeta" : "alpha";
            result.mac = "Unknown";
            result.vendor = "Unknown";
            result.hostname = "Unknown";
            return HostScanOutcome{true, result};
        });
    const QList<ScanResult> interfaces = ScanEngine::run(
        {QHostAddress("198.51.100.8"), QHostAddress("198.51.100.8")},
        1,
        std::make_shared<std::atomic_bool>(false),
        interfaceBackend);
    if (interfaces.size() != 2 || interfaces.first().interfaceName != "alpha" ||
        interfaces.last().interfaceName != "zeta") {
        std::cerr << "interface identity or deterministic ordering contract failed\n";
        return 1;
    }

    BlockingBackend cancelBackend;
    const auto cancelToken = std::make_shared<std::atomic_bool>(false);
    QList<ScanResult> canceled;
    std::thread engineThread([&]() {
        canceled = ScanEngine::run(hosts, 2, cancelToken, cancelBackend);
    });
    cancelBackend.waitForEntered(2);
    cancelToken->store(true);
    cancelBackend.release();
    engineThread.join();
    if (cancelBackend.calls.load() != 2 || !canceled.isEmpty()) {
        std::cerr << "engine cancellation contract failed\n";
        return 1;
    }

    const auto failureToken = std::make_shared<std::atomic_bool>(false);
    CallbackHostScanBackend failingBackend(
        [](const QHostAddress &,
           const std::shared_ptr<std::atomic_bool> &) -> HostScanOutcome {
            throw std::runtime_error("injected backend failure");
        });
    const QList<ScanResult> failed = ScanEngine::run(
        {QHostAddress("203.0.113.9")}, 1, failureToken, failingBackend);
    if (!failureToken->load() || !failed.isEmpty()) {
        std::cerr << "backend failure containment contract failed\n";
        return 1;
    }

    const auto resultFailureToken = std::make_shared<std::atomic_bool>(false);
    FakeBackend resultCallbackBackend;
    ScanEngine::run(
        {QHostAddress("203.0.113.10")},
        1,
        resultFailureToken,
        resultCallbackBackend,
        {},
        [](const ScanResult &) { throw std::runtime_error("result callback"); });
    if (!resultFailureToken->load()) {
        std::cerr << "result callback failure containment contract failed\n";
        return 1;
    }

    const auto progressFailureToken = std::make_shared<std::atomic_bool>(false);
    FakeBackend progressCallbackBackend;
    ScanEngine::run(
        {QHostAddress("203.0.113.11")},
        1,
        progressFailureToken,
        progressCallbackBackend,
        [](int, int) { throw std::runtime_error("progress callback"); });
    if (!progressFailureToken->load()) {
        std::cerr << "progress callback failure containment contract failed\n";
        return 1;
    }
    return 0;
}
