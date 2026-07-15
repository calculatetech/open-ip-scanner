#include "productionhostscanbackend.h"

#include "hostnameevidence.h"

#include <QHostInfo>

#include <utility>

ProductionHostScanBackend::ProductionHostScanBackend(
    ScanOptions options,
    QString gatewayIp,
    ProductionHostScanDependencies dependencies)
    : options_(std::move(options)),
      gatewayIp_(std::move(gatewayIp)),
      dependencies_(std::move(dependencies))
{
}

bool ProductionHostScanBackend::isCancelled(
    const std::shared_ptr<std::atomic_bool> &cancellation)
{
    return cancellation && cancellation->load();
}

HostScanOutcome ProductionHostScanBackend::scan(
    const QHostAddress &host,
    const std::shared_ptr<std::atomic_bool> &cancellation)
{
    if (isCancelled(cancellation)) {
        return {};
    }

    const QString ipString = host.toString();
    const TargetBudget budget(
        options_.targetDeadlineMs,
        dependencies_.now ? dependencies_.now
                          : TargetBudget::NowFunction([]() {
                                return TargetBudget::Clock::now();
                            }));
    bool alive = false;
    QString discoveredMac;
    NeighborObservation neighbor;
    QList<ServiceHit> discoveredServices;
    bool servicesProbed = false;

    if (ipString == options_.localIp) {
        alive = true;
        discoveredMac = options_.localMac;
    } else if (ipString == gatewayIp_) {
        alive = true;
    } else {
        alive = dependencies_.ping(host, options_, budget, cancellation);
        if (isCancelled(cancellation)) {
            return {};
        }
        if (shouldProbeServicesForDiscovery(
                alive, static_cast<int>(options_.enabledServiceIds.size())) &&
            !budget.expired()) {
            servicesProbed = true;
            discoveredServices = dependencies_.services(
                ipString, options_.localIp, budget, cancellation, options_);
            if (isCancelled(cancellation)) {
                return {};
            }
            alive = !discoveredServices.isEmpty();
        }
        if (!alive) {
            neighbor = dependencies_.neighbor(
                ipString, options_.interfaceName, budget, cancellation);
            if (isCancelled(cancellation)) {
                return {};
            }
            neighbor = dependencies_.confirmNeighbor(neighbor,
                                                     ipString,
                                                     options_.interfaceName,
                                                     options_,
                                                     budget,
                                                     cancellation);
            if (isCancelled(cancellation)) {
                return {};
            }
            if (neighbor.suppliesMacMetadata()) {
                discoveredMac = neighbor.mac;
            }
            alive = neighbor.establishesLiveness();
        }
    }
    if (!alive) {
        return {};
    }

    ScanResult result;
    result.ip = ipString;
    result.interfaceName = options_.interfaceName;
    for (const AliveHostStage stage : kAliveHostStageOrder) {
        if (isCancelled(cancellation)) {
            return {};
        }
        switch (stage) {
        case AliveHostStage::Services:
            result.services = servicesProbed
                                  ? discoveredServices
                                  : dependencies_.services(ipString,
                                                           options_.localIp,
                                                           budget,
                                                           cancellation,
                                                           options_);
            break;
        case AliveHostStage::MacAddress:
            if (discoveredMac.isEmpty()) {
                if (neighbor.ip.isEmpty()) {
                    neighbor = dependencies_.neighbor(
                        ipString, options_.interfaceName, budget, cancellation);
                }
                if (neighbor.suppliesMacMetadata()) {
                    discoveredMac = neighbor.mac;
                }
            }
            result.mac = discoveredMac;
            break;
        case AliveHostStage::Vendor:
            result.vendor = dependencies_.vendor(result.mac, options_);
            break;
        case AliveHostStage::Hostname: {
            HostnameEvidence preliminary;
            if (ipString == options_.localIp) {
                preliminary.hostname = qualifyHostname(
                    QHostInfo::localHostName(), options_.dnsSuffixes.value(0));
                preliminary.source = HostnameSource::LocalHost;
            }
            const HostnameScanResolution resolved = dependencies_.hostname(
                ipString,
                preliminary,
                options_.dnsSuffixes,
                options_.accuracyLevel,
                budget,
                cancellation);
            result.hostnameEvidence = resolved.evidence;
            result.resolverEvents = resolved.resolverEvents;
            const HostnameEvidence preferred = preferredHostname(
                result.hostnameEvidence);
            result.hostname = preferred.hostname;
            result.hostnameSource = preferred.source;
            break;
        }
        case AliveHostStage::NormalizeIdentity:
            if (result.mac.isEmpty()) {
                result.mac = "Unknown";
            }
            if (result.vendor.isEmpty()) {
                result.vendor = "Unknown";
            }
            if (result.hostname.isEmpty()) {
                result.hostname = "Unknown";
            }
            break;
        case AliveHostStage::Details:
            result.detailsText = dependencies_.details(result, options_);
            break;
        }
    }
    return isCancelled(cancellation) ? HostScanOutcome{}
                                     : HostScanOutcome{true, result};
}
