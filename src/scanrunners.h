#pragma once

#include "scanoptions.h"
#include "scanresult.h"
#include "productionhostscanbackend.h"

#include <QHostAddress>
#include <QList>

#include <atomic>
#include <functional>
#include <memory>

using ScanCancellation = std::shared_ptr<std::atomic_bool>;
using ScanProgressCallback = std::function<void(int, int)>;
using ScanResultCallback = std::function<void(const ScanResult &)>;
using ScanVendorResolver = std::function<QString(const QString &, const ScanOptions &)>;
using ScanDetailsFormatter = std::function<QString(const ScanResult &, const ScanOptions &)>;

struct ProductionRunnerEnvironment {
    std::function<QString(const QString &)> gatewayLookup;
    std::function<ProductionHostScanDependencies(
        const ScanOptions &, const ScanCancellation &)> dependencyFactory;
};

QString ipv4GatewayFromHex(const QString &hexGateway);
QString gatewayIpFromRouteTable(const QByteArray &routeTable,
                                const QString &interfaceName);
QString linuxGatewayIp(const QString &interfaceName);

QList<ScanResult> runProductionScan(
    const ScanOptions &options,
    const QList<QHostAddress> &hosts,
    const ScanCancellation &cancellation,
    const ScanProgressCallback &onProgress,
    const ScanResultCallback &onResult,
    const ScanVendorResolver &vendorResolver,
    const ScanDetailsFormatter &detailsFormatter,
    ProductionRunnerEnvironment environment = {});
