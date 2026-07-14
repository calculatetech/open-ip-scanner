#include "scanrunners.h"

#include "hostnameresolver.h"
#include "linuxneighborprobe.h"
#include "linuxpingprobe.h"
#include "mdnsresolver.h"
#include "productionhostscanbackend.h"
#include "scanengine.h"
#include "serviceprobe.h"

#include <QFile>
#include <QNetworkInterface>
#include <QRegularExpression>

#include <limits>
#include <utility>

QString ipv4GatewayFromHex(const QString &hexGateway)
{
    if (hexGateway.size() != 8) {
        return {};
    }
    bool ok = false;
    const quint32 value = hexGateway.toUInt(&ok, 16);
    if (!ok) {
        return {};
    }
    const quint32 b1 = value & 0x000000FFu;
    const quint32 b2 = (value & 0x0000FF00u) >> 8;
    const quint32 b3 = (value & 0x00FF0000u) >> 16;
    const quint32 b4 = (value & 0xFF000000u) >> 24;
    return QString("%1.%2.%3.%4").arg(b1).arg(b2).arg(b3).arg(b4);
}

QString gatewayIpFromRouteTable(const QByteArray &routeTable,
                                const QString &interfaceName)
{
    QString selectedGateway;
    int selectedMetric = std::numeric_limits<int>::max();
    for (const QByteArray &rawLine : routeTable.split('\n')) {
        const QString line = QString::fromUtf8(rawLine).trimmed();
        if (line.isEmpty() || line.startsWith("Iface")) {
            continue;
        }
        const QStringList fields = line.split(
            QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (fields.size() < 8 || fields[0] != interfaceName ||
            fields[1] != "00000000" || fields[7] != "00000000" ||
            fields[2].size() != 8 || fields[2] == "00000000") {
            continue;
        }
        bool flagsOk = false;
        const uint flags = fields[3].toUInt(&flagsOk, 16);
        bool metricOk = false;
        const int metric = fields[6].toInt(&metricOk, 10);
        const QString gateway = ipv4GatewayFromHex(fields[2]);
        if (!flagsOk || (flags & 0x3u) != 0x3u || !metricOk || metric < 0 ||
            gateway.isEmpty()) {
            continue;
        }
        if (metric < selectedMetric) {
            selectedMetric = metric;
            selectedGateway = gateway;
        }
    }
    return selectedGateway;
}

QString linuxGatewayIp(const QString &interfaceName)
{
#ifdef Q_OS_LINUX
    QFile routeFile("/proc/net/route");
    if (routeFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return gatewayIpFromRouteTable(routeFile.readAll(), interfaceName);
    }
#else
    Q_UNUSED(interfaceName)
#endif
    return {};
}

QList<ScanResult> runProductionScan(
    const ScanOptions &options,
    const QList<QHostAddress> &hosts,
    const ScanCancellation &cancellation,
    const ScanProgressCallback &onProgress,
    const ScanResultCallback &onResult,
    const ScanVendorResolver &vendorResolver,
    const ScanDetailsFormatter &detailsFormatter,
    ProductionRunnerEnvironment environment)
{
    if (!environment.gatewayLookup) {
        environment.gatewayLookup = linuxGatewayIp;
    }
    if (!environment.dependencyFactory) {
        environment.dependencyFactory = [](const ScanOptions &factoryOptions,
                                           const ScanCancellation &factoryCancellation) {
            const int interfaceIndex = QNetworkInterface::interfaceIndexFromName(
                factoryOptions.interfaceName);
            auto mdnsResolver = std::make_shared<ScanMdnsResolver>(
                interfaceIndex, factoryCancellation, createAvahiDbusBackend());
            auto hostnameResolver = std::make_shared<HostnameResolver>(mdnsResolver);
            auto neighborProbe = std::make_shared<LinuxNeighborProbe>();
            auto pingProbe = std::make_shared<LinuxPingProbe>();
            auto serviceProbe = std::make_shared<ServiceProbe>();
            ProductionHostScanDependencies dependencies;
            dependencies.ping = [pingProbe](const QHostAddress &host,
                                    const ScanOptions &scanOptions,
                                    const TargetBudget &budget,
                                    const auto &activeCancellation) {
        return pingProbe->ping(host,
                               scanOptions.interfaceName,
                               scanOptions.pingAttempts,
                               scanOptions.pingTimeoutSeconds,
                               budget,
                               activeCancellation);
    };
            dependencies.services = [serviceProbe](const QString &ip,
                                           const QString &localIp,
                                           const TargetBudget &budget,
                                           const auto &activeCancellation,
                                           const ScanOptions &scanOptions) {
        return serviceProbe->scan(ip,
                                  localIp,
                                  scanOptions.enabledServiceIds,
                                  scanOptions.serviceAttempts,
                                  scanOptions.serviceTimeoutMs,
                                  budget,
                                  activeCancellation);
    };
            dependencies.neighbor = [neighborProbe](const QString &ip,
                                            const QString &interfaceName,
                                            const TargetBudget &budget,
                                            const auto &activeCancellation) {
        return neighborProbe->lookup(
            ip, interfaceName, budget, activeCancellation);
    };
            dependencies.confirmNeighbor = [neighborProbe](
                                               const NeighborObservation &initial,
                                               const QString &ip,
                                               const QString &interfaceName,
                                               const ScanOptions &scanOptions,
                                               const TargetBudget &budget,
                                               const auto &activeCancellation) {
        return neighborProbe->confirmLiveness(initial,
                                              ip,
                                              interfaceName,
                                              scanOptions.neighborConfirmationMs,
                                              budget,
                                              activeCancellation);
    };
            dependencies.hostname = [hostnameResolver](
                                const QString &ip,
                                const HostnameEvidence &preliminary,
                                const QStringList &dnsSuffixes,
                                int accuracyLevel,
                                const TargetBudget &budget,
                                const auto &activeCancellation) {
        return hostnameResolver->resolve(ip,
                                         preliminary,
                                         dnsSuffixes,
                                         accuracyLevel,
                                         budget,
                                         activeCancellation);
    };
            return dependencies;
        };
    }
    ProductionHostScanDependencies dependencies =
        environment.dependencyFactory(options, cancellation);
    dependencies.vendor = vendorResolver;
    dependencies.details = detailsFormatter;
    ProductionHostScanBackend backend(
        options,
        environment.gatewayLookup(options.interfaceName),
        std::move(dependencies));
    return ScanEngine::run(hosts,
                           options.maxParallelProbes,
                           cancellation,
                           backend,
                           onProgress,
                           onResult);
}
