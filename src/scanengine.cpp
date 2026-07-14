#include "scanengine.h"

#include "hostnameevidence.h"
#include "resolverdiagnostics.h"

#include <algorithm>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

CallbackHostScanBackend::CallbackHostScanBackend(Callback callback)
    : callback_(std::move(callback))
{
}

HostScanOutcome CallbackHostScanBackend::scan(
    const QHostAddress &host,
    const std::shared_ptr<std::atomic_bool> &cancellation)
{
    return callback_ ? callback_(host, cancellation) : HostScanOutcome{};
}

QList<ScanResult> ScanEngine::run(
    const QList<QHostAddress> &hosts,
    int maximumWorkers,
    const std::shared_ptr<std::atomic_bool> &cancellation,
    IHostScanBackend &backend,
    const ProgressCallback &progress,
    const ResultCallback &result)
{
    QList<ScanResult> results;
    std::mutex resultsMutex;
    std::atomic_bool stopRequested{false};
    const auto requestStop = [&]() {
        stopRequested.store(true);
        if (cancellation) {
            cancellation->store(true);
        }
    };
    const auto publish = [&](const ScanResult &candidate) {
        if (stopRequested.load() || (cancellation && cancellation->load())) {
            return false;
        }
        bool changed = false;
        ScanResult merged = candidate;
        {
            const std::lock_guard<std::mutex> locker(resultsMutex);
            auto existing = std::find_if(
                results.begin(), results.end(), [&](const ScanResult &value) {
                    return value.ip == candidate.ip &&
                           value.interfaceName == candidate.interfaceName;
                });
            if (existing == results.end()) {
                results.append(candidate);
                changed = true;
            } else {
                if (existing->mac == "Unknown" && candidate.mac != "Unknown") {
                    existing->mac = candidate.mac;
                    changed = true;
                }
                if (existing->vendor == "Unknown" && candidate.vendor != "Unknown") {
                    existing->vendor = candidate.vendor;
                    changed = true;
                }
                const HostnameEvidence previous{
                    existing->hostname, existing->hostnameSource};
                for (const HostnameEvidence &evidence : candidate.hostnameEvidence) {
                    existing->hostnameEvidence = mergeHostnameEvidence(
                        existing->hostnameEvidence, evidence);
                }
                const HostnameEvidence preferred = preferredHostname(
                    existing->hostnameEvidence);
                if (preferred.hostname != previous.hostname ||
                    preferred.source != previous.source) {
                    existing->hostname = preferred.hostname;
                    existing->hostnameSource = preferred.source;
                    changed = true;
                }
                for (const ResolverEvent &event : candidate.resolverEvents) {
                    const QList<ResolverEvent> events = mergeResolverEvents(
                        existing->resolverEvents, event);
                    if (events.size() != existing->resolverEvents.size()) {
                        existing->resolverEvents = events;
                        changed = true;
                    }
                }
                if (existing->services.isEmpty() && !candidate.services.isEmpty()) {
                    existing->services = candidate.services;
                    changed = true;
                }
                merged = *existing;
            }
        }
        if (changed && result) {
            if (stopRequested.load() || (cancellation && cancellation->load())) {
                return false;
            }
            try {
                result(merged);
            } catch (...) {
                requestStop();
                return false;
            }
        }
        return true;
    };

    const int total = static_cast<int>(hosts.size());
    std::atomic<int> nextIndex{0};
    std::atomic<int> completed{0};
    const int workerCount = std::clamp(maximumWorkers, 1, 16);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(workerCount));
    try {
        for (int worker = 0; worker < workerCount; ++worker) {
            workers.emplace_back([&]() {
                while (!stopRequested.load() &&
                       (!cancellation || !cancellation->load())) {
                    const int index = nextIndex.fetch_add(1);
                    if (index >= total) {
                        break;
                    }
                    HostScanOutcome outcome;
                    try {
                        outcome = backend.scan(hosts[index], cancellation);
                    } catch (...) {
                        requestStop();
                        break;
                    }
                    if (stopRequested.load() ||
                        (cancellation && cancellation->load())) {
                        break;
                    }
                    if (outcome.discovered && !publish(outcome.result)) {
                        break;
                    }
                    const int current = completed.fetch_add(1) + 1;
                    if (progress) {
                        if (stopRequested.load() ||
                            (cancellation && cancellation->load())) {
                            break;
                        }
                        try {
                            progress(current, total);
                        } catch (...) {
                            requestStop();
                            break;
                        }
                    }
                }
            });
        }
    } catch (const std::system_error &) {
        requestStop();
    }
    for (std::thread &worker : workers) {
        worker.join();
    }

    std::sort(results.begin(), results.end(), [](const ScanResult &left,
                                                  const ScanResult &right) {
        const quint32 leftAddress = QHostAddress(left.ip).toIPv4Address();
        const quint32 rightAddress = QHostAddress(right.ip).toIPv4Address();
        return leftAddress != rightAddress
                   ? leftAddress < rightAddress
                   : left.interfaceName < right.interfaceName;
    });
    return results;
}
