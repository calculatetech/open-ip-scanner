#pragma once

#include "scanresult.h"

#include <QHostAddress>
#include <QList>

#include <atomic>
#include <functional>
#include <memory>

struct HostScanOutcome {
    bool discovered = false;
    ScanResult result;
};

class IHostScanBackend {
public:
    virtual ~IHostScanBackend() = default;
    // ScanEngine may call one backend instance concurrently; implementations
    // must keep shared state thread-safe and cooperate with cancellation.
    virtual HostScanOutcome scan(
        const QHostAddress &host,
        const std::shared_ptr<std::atomic_bool> &cancellation) = 0;
};

class CallbackHostScanBackend final : public IHostScanBackend {
public:
    using Callback = std::function<HostScanOutcome(
        const QHostAddress &, const std::shared_ptr<std::atomic_bool> &)>;

    explicit CallbackHostScanBackend(Callback callback);
    HostScanOutcome scan(
        const QHostAddress &host,
        const std::shared_ptr<std::atomic_bool> &cancellation) override;

private:
    Callback callback_;
};

class ScanEngine {
public:
    using ProgressCallback = std::function<void(int, int)>;
    using ResultCallback = std::function<void(const ScanResult &)>;

    static QList<ScanResult> run(
        const QList<QHostAddress> &hosts,
        int maximumWorkers,
        const std::shared_ptr<std::atomic_bool> &cancellation,
        IHostScanBackend &backend,
        const ProgressCallback &progress = {},
        const ResultCallback &result = {});
};
