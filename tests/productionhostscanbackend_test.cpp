#include "productionhostscanbackend.h"

#include <QCoreApplication>

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

namespace {
struct Fixture {
    bool pingAlive = false;
    QList<ServiceHit> serviceHits;
    NeighborObservation neighbor;
    NeighborObservation confirmedNeighbor;
    QStringList calls;
    HostnameEvidence preliminary;
};

ProductionHostScanDependencies dependenciesFor(Fixture &fixture)
{
    ProductionHostScanDependencies dependencies;
    dependencies.ping = [&](const QHostAddress &,
                            const ScanOptions &,
                            const TargetBudget &,
                            const auto &) {
        fixture.calls.append("ping");
        return fixture.pingAlive;
    };
    dependencies.services = [&](const QString &,
                                const QString &,
                                const TargetBudget &,
                                const auto &,
                                const ScanOptions &) {
        fixture.calls.append("services");
        return fixture.serviceHits;
    };
    dependencies.neighbor = [&](const QString &,
                                const QString &,
                                const TargetBudget &,
                                const auto &) {
        fixture.calls.append("neighbor");
        return fixture.neighbor;
    };
    dependencies.confirmNeighbor = [&](const NeighborObservation &,
                                       const QString &,
                                       const QString &,
                                       const ScanOptions &,
                                       const TargetBudget &,
                                       const auto &) {
        fixture.calls.append("confirm");
        return fixture.confirmedNeighbor;
    };
    dependencies.vendor = [&](const QString &mac, const ScanOptions &) {
        fixture.calls.append("vendor");
        return mac == "00:11:22:33:44:55" ? QString("Fixture Vendor")
                                           : QString("Unknown");
    };
    dependencies.hostname = [&](const QString &,
                                const HostnameEvidence &preliminary,
                                const QStringList &,
                                int,
                                const TargetBudget &,
                                const auto &) {
        fixture.calls.append("hostname");
        fixture.preliminary = preliminary;
        HostnameScanResolution resolution;
        resolution.evidence.append(
            {"fixture.example.test", HostnameSource::DnsPtr});
        resolution.resolverEvents.append(
            {ResolverKind::DnsPtr, ResolverOutcome::Resolved});
        return resolution;
    };
    dependencies.details = [&](const ScanResult &, const ScanOptions &) {
        fixture.calls.append("details");
        return QString("fixture details");
    };
    return dependencies;
}

ScanOptions baseOptions()
{
    ScanOptions options;
    options.interfaceName = "fixture0";
    options.localIp = "192.0.2.10";
    options.localMac = "00:11:22:33:44:55";
    options.dnsSuffixes = {"example.test"};
    options.enabledServiceIds.insert("ssh");
    options.targetDeadlineMs = 5000;
    return options;
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const auto cancellation = std::make_shared<std::atomic_bool>(false);

    Fixture serviceFixture;
    serviceFixture.serviceHits.append(
        {"ssh", "SSH", 22, false, ServiceEvidenceLevel::VerifiedProtocol});
    serviceFixture.neighbor = {"192.0.2.20",
                               "fixture0",
                               "00:11:22:33:44:55",
                               NeighborState::Stale};
    ProductionHostScanBackend serviceBackend(
        baseOptions(), "192.0.2.1", dependenciesFor(serviceFixture));
    const HostScanOutcome serviceOutcome = serviceBackend.scan(
        QHostAddress("192.0.2.20"), cancellation);
    const QStringList expectedServiceCalls = {
        "ping", "services", "neighbor", "vendor", "hostname", "details"};
    if (!serviceOutcome.discovered || serviceOutcome.result.services.size() != 1 ||
        serviceOutcome.result.mac != "00:11:22:33:44:55" ||
        serviceOutcome.result.vendor != "Fixture Vendor" ||
        serviceOutcome.result.hostname != "fixture.example.test" ||
        serviceOutcome.result.discoveryMethod != DiscoveryMethod::Service ||
        serviceOutcome.result.resolverEvents.size() != 1 ||
        serviceOutcome.result.detailsText != "fixture details" ||
        serviceFixture.calls != expectedServiceCalls) {
        std::cerr << "service-first discovery and enrichment contract failed\n";
        return 1;
    }

    Fixture neighborFixture;
    neighborFixture.neighbor = {"192.0.2.21",
                                "fixture0",
                                "00:11:22:33:44:55",
                                NeighborState::Stale};
    neighborFixture.confirmedNeighbor = neighborFixture.neighbor;
    neighborFixture.confirmedNeighbor.state = NeighborState::Reachable;
    ProductionHostScanBackend neighborBackend(
        baseOptions(), "192.0.2.1", dependenciesFor(neighborFixture));
    const HostScanOutcome neighborOutcome = neighborBackend.scan(
        QHostAddress("192.0.2.21"), cancellation);
    const QStringList expectedNeighborCalls = {
        "ping", "services", "neighbor", "confirm", "vendor", "hostname", "details"};
    if (!neighborOutcome.discovered ||
        neighborOutcome.result.mac != "00:11:22:33:44:55" ||
        neighborOutcome.result.discoveryMethod != DiscoveryMethod::Neighbor ||
        neighborFixture.calls != expectedNeighborCalls) {
        std::cerr << "confirmed-neighbor discovery contract failed\n";
        return 1;
    }

    Fixture pingFixture;
    pingFixture.pingAlive = true;
    pingFixture.neighbor = {"192.0.2.24", "fixture0", {}, NeighborState::Stale};
    ProductionHostScanBackend pingBackend(
        baseOptions(), "192.0.2.1", dependenciesFor(pingFixture));
    const HostScanOutcome pingOutcome = pingBackend.scan(
        QHostAddress("192.0.2.24"), cancellation);
    if (!pingOutcome.discovered ||
        pingOutcome.result.discoveryMethod != DiscoveryMethod::Ping ||
        pingFixture.calls.contains("confirm") ||
        pingFixture.calls.first() != "ping" ||
        pingFixture.calls.indexOf("services") > pingFixture.calls.indexOf("neighbor")) {
        std::cerr << "ping-positive discovery contract failed\n";
        return 1;
    }

    Fixture gatewayFixture;
    ProductionHostScanDependencies gatewayDependencies = dependenciesFor(
        gatewayFixture);
    gatewayDependencies.hostname = [&](const QString &,
                                       const HostnameEvidence &,
                                       const QStringList &,
                                       int,
                                       const TargetBudget &,
                                       const auto &) {
        gatewayFixture.calls.append("hostname");
        return HostnameScanResolution{};
    };
    ProductionHostScanBackend gatewayBackend(
        baseOptions(), "192.0.2.1", std::move(gatewayDependencies));
    const HostScanOutcome gatewayOutcome = gatewayBackend.scan(
        QHostAddress("192.0.2.1"), cancellation);
    if (!gatewayOutcome.discovered || gatewayFixture.calls.contains("ping") ||
        gatewayOutcome.result.discoveryMethod != DiscoveryMethod::Gateway ||
        gatewayOutcome.result.mac != "Unknown" ||
        gatewayOutcome.result.vendor != "Unknown" ||
        gatewayOutcome.result.hostname != "Unknown" ||
        gatewayOutcome.result.detailsText != "fixture details") {
        std::cerr << "gateway and unknown normalization contract failed\n";
        return 1;
    }

    Fixture deadFixture;
    deadFixture.neighbor = {"192.0.2.22",
                            "fixture0",
                            "00:11:22:33:44:55",
                            NeighborState::Stale};
    deadFixture.confirmedNeighbor = deadFixture.neighbor;
    ProductionHostScanBackend deadBackend(
        baseOptions(), "192.0.2.1", dependenciesFor(deadFixture));
    const HostScanOutcome deadOutcome = deadBackend.scan(
        QHostAddress("192.0.2.22"), cancellation);
    if (deadOutcome.discovered ||
        deadFixture.calls != QStringList{"ping", "services", "neighbor", "confirm"}) {
        std::cerr << "non-evidentiary neighbor contract failed\n";
        return 1;
    }

    Fixture localFixture;
    ProductionHostScanBackend localBackend(
        baseOptions(), "192.0.2.1", dependenciesFor(localFixture));
    const HostScanOutcome localOutcome = localBackend.scan(
        QHostAddress("192.0.2.10"), cancellation);
    if (!localOutcome.discovered ||
        localOutcome.result.discoveryMethod != DiscoveryMethod::Local ||
        localOutcome.result.mac != "00:11:22:33:44:55" ||
        localFixture.calls.contains("ping") || localFixture.calls.contains("neighbor") ||
        localFixture.preliminary.hostname.isEmpty() ||
        localFixture.preliminary.source != HostnameSource::LocalHost) {
        std::cerr << "local identity and preliminary-name contract failed\n";
        return 1;
    }

    struct CancellationCase {
        QString cancelAt;
        bool pingAlive = false;
        QStringList expectedCalls;
    };
    const QList<CancellationCase> cancellationCases = {
        {"initial", false, {}},
        {"ping", false, {"ping"}},
        {"services", false, {"ping", "services"}},
        {"neighbor", false, {"ping", "services", "neighbor"}},
        {"confirm", false, {"ping", "services", "neighbor", "confirm"}},
        {"services", true, {"ping", "services"}},
        {"neighbor", true, {"ping", "services", "neighbor"}},
        {"vendor", true, {"ping", "services", "neighbor", "vendor"}},
        {"hostname", true,
         {"ping", "services", "neighbor", "vendor", "hostname"}},
        {"details", true,
         {"ping", "services", "neighbor", "vendor", "hostname", "details"}},
    };
    for (const CancellationCase &testCase : cancellationCases) {
        Fixture fixture;
        fixture.pingAlive = testCase.pingAlive;
        fixture.neighbor = {"192.0.2.23",
                            "fixture0",
                            "00:11:22:33:44:55",
                            NeighborState::Stale};
        fixture.confirmedNeighbor = fixture.neighbor;
        fixture.confirmedNeighbor.state = NeighborState::Reachable;
        const auto token = std::make_shared<std::atomic_bool>(
            testCase.cancelAt == "initial");
        ProductionHostScanDependencies dependencies = dependenciesFor(fixture);
        const auto cancelAfter = [&](const QString &stage) {
            if (testCase.cancelAt == stage) {
                token->store(true);
            }
        };
        dependencies.ping = [&](const QHostAddress &,
                                const ScanOptions &,
                                const TargetBudget &,
                                const auto &) {
            fixture.calls.append("ping");
            cancelAfter("ping");
            return fixture.pingAlive;
        };
        dependencies.services = [&](const QString &,
                                    const QString &,
                                    const TargetBudget &,
                                    const auto &,
                                    const ScanOptions &) {
            fixture.calls.append("services");
            cancelAfter("services");
            return QList<ServiceHit>{};
        };
        dependencies.neighbor = [&](const QString &,
                                    const QString &,
                                    const TargetBudget &,
                                    const auto &) {
            fixture.calls.append("neighbor");
            cancelAfter("neighbor");
            return fixture.neighbor;
        };
        dependencies.confirmNeighbor = [&](const NeighborObservation &,
                                           const QString &,
                                           const QString &,
                                           const ScanOptions &,
                                           const TargetBudget &,
                                           const auto &) {
            fixture.calls.append("confirm");
            cancelAfter("confirm");
            return fixture.confirmedNeighbor;
        };
        dependencies.vendor = [&](const QString &, const ScanOptions &) {
            fixture.calls.append("vendor");
            cancelAfter("vendor");
            return QString("Fixture Vendor");
        };
        dependencies.hostname = [&](const QString &,
                                    const HostnameEvidence &,
                                    const QStringList &,
                                    int,
                                    const TargetBudget &,
                                    const auto &) {
            fixture.calls.append("hostname");
            cancelAfter("hostname");
            return HostnameScanResolution{};
        };
        dependencies.details = [&](const ScanResult &, const ScanOptions &) {
            fixture.calls.append("details");
            cancelAfter("details");
            return QString("fixture details");
        };
        ProductionHostScanBackend backend(
            baseOptions(), "192.0.2.1", std::move(dependencies));
        const HostScanOutcome outcome = backend.scan(
            QHostAddress("192.0.2.23"), token);
        if (outcome.discovered || fixture.calls != testCase.expectedCalls) {
            std::cerr << "backend cancellation boundary contract failed\n";
            return 1;
        }
    }

    std::atomic<int> activePings{0};
    std::atomic<int> maximumActivePings{0};
    std::atomic<int> pingCalls{0};
    ProductionHostScanDependencies concurrentDependencies;
    concurrentDependencies.ping = [&](const QHostAddress &,
                                      const ScanOptions &,
                                      const TargetBudget &,
                                      const auto &) {
        const int active = activePings.fetch_add(1) + 1;
        int maximum = maximumActivePings.load();
        while (active > maximum &&
               !maximumActivePings.compare_exchange_weak(maximum, active)) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        activePings.fetch_sub(1);
        pingCalls.fetch_add(1);
        return true;
    };
    concurrentDependencies.services = [](const QString &,
                                         const QString &,
                                         const TargetBudget &,
                                         const auto &,
                                         const ScanOptions &) {
        return QList<ServiceHit>{};
    };
    concurrentDependencies.neighbor = [](const QString &ip,
                                         const QString &interfaceName,
                                         const TargetBudget &,
                                         const auto &) {
        return NeighborObservation{ip, interfaceName, {}, NeighborState::Stale};
    };
    concurrentDependencies.confirmNeighbor = [](const NeighborObservation &value,
                                                const QString &,
                                                const QString &,
                                                const ScanOptions &,
                                                const TargetBudget &,
                                                const auto &) { return value; };
    concurrentDependencies.vendor = [](const QString &, const ScanOptions &) {
        return QString("Unknown");
    };
    concurrentDependencies.hostname = [](const QString &,
                                         const HostnameEvidence &,
                                         const QStringList &,
                                         int,
                                         const TargetBudget &,
                                         const auto &) {
        return HostnameScanResolution{};
    };
    concurrentDependencies.details = [](const ScanResult &,
                                        const ScanOptions &) { return QString{}; };
    ScanOptions concurrentOptions = baseOptions();
    concurrentOptions.enabledServiceIds.clear();
    ProductionHostScanBackend concurrentBackend(
        concurrentOptions, "192.0.2.1", std::move(concurrentDependencies));
    QList<QHostAddress> concurrentHosts;
    for (int value = 30; value < 38; ++value) {
        concurrentHosts.append(QHostAddress(QString("192.0.2.%1").arg(value)));
    }
    const QList<ScanResult> concurrentResults = ScanEngine::run(
        concurrentHosts,
        4,
        std::make_shared<std::atomic_bool>(false),
        concurrentBackend);
    if (concurrentResults.size() != concurrentHosts.size() ||
        pingCalls.load() != concurrentHosts.size() ||
        maximumActivePings.load() < 2 || maximumActivePings.load() > 4) {
        std::cerr << "concurrent production backend contract failed\n";
        return 1;
    }

    return 0;
}
