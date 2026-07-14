#pragma once

#include "neighborentry.h"
#include "scanbudget.h"
#include "scanengine.h"
#include "scanoptions.h"

#include <functional>

struct ProductionHostScanDependencies {
    using Cancellation = std::shared_ptr<std::atomic_bool>;

    std::function<bool(const QHostAddress &,
                       const ScanOptions &,
                       const TargetBudget &,
                       const Cancellation &)> ping;
    std::function<QList<ServiceHit>(const QString &,
                                    const QString &,
                                    const TargetBudget &,
                                    const Cancellation &,
                                    const ScanOptions &)> services;
    std::function<NeighborObservation(const QString &,
                                      const QString &,
                                      const TargetBudget &,
                                      const Cancellation &)> neighbor;
    std::function<NeighborObservation(const NeighborObservation &,
                                      const QString &,
                                      const QString &,
                                      const ScanOptions &,
                                      const TargetBudget &,
                                      const Cancellation &)> confirmNeighbor;
    std::function<QString(const QString &, const ScanOptions &)> vendor;
    std::function<HostnameScanResolution(const QString &,
                                         const HostnameEvidence &,
                                         const QStringList &,
                                         int,
                                         const TargetBudget &,
                                         const Cancellation &)> hostname;
    std::function<QString(const ScanResult &, const ScanOptions &)> details;
};

class ProductionHostScanBackend final : public IHostScanBackend {
public:
    ProductionHostScanBackend(ScanOptions options,
                              QString gatewayIp,
                              ProductionHostScanDependencies dependencies);

    HostScanOutcome scan(
        const QHostAddress &host,
        const std::shared_ptr<std::atomic_bool> &cancellation) override;

private:
    static bool isCancelled(
        const std::shared_ptr<std::atomic_bool> &cancellation);

    ScanOptions options_;
    QString gatewayIp_;
    ProductionHostScanDependencies dependencies_;
};
