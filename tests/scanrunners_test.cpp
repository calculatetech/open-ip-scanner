#include "scanrunners.h"

#include "debugscanfixture.h"

#include <QCoreApplication>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "scan runner requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);

    REQUIRE(ipv4GatewayFromHex("0102A8C0") == "192.168.2.1");
    REQUIRE(ipv4GatewayFromHex("not-hex").isEmpty());
    const QByteArray routes =
        "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
        "eth9 0002A8C0 00000000 0001 0 0 100 00FFFFFF\n"
        "eth0 00000000 00000000 0001 0 0 1 00000000\n"
        "eth0 00000000 0100000A 0001 0 0 2 00000000\n"
        "eth0 00000000 0100000A 0003 0 0 0 00FFFFFF\n"
        "eth0 00000000 0102A8C0 0003 0 0 100 00000000\n"
        "eth0 00000000 0101A8C0 0003 0 0 20 00000000\n"
        "eth1 00000000 0100000A 0003 0 0 200 00000000\n";
    REQUIRE(gatewayIpFromRouteTable(routes, "eth0") == "192.168.1.1");
    REQUIRE(gatewayIpFromRouteTable(routes, "eth1") == "10.0.0.1");
    REQUIRE(gatewayIpFromRouteTable(routes, "missing").isEmpty());
    REQUIRE(gatewayIpFromRouteTable("malformed\n", "eth0").isEmpty());

    {
        ScanOptions options;
        options.interfaceName = "fixture0";
        options.maxParallelProbes = 1;
        options.targetDeadlineMs = 1000;
        int pingCalls = 0;
        int serviceCalls = 0;
        int neighborCalls = 0;
        int vendorCalls = 0;
        int detailsCalls = 0;
        int resultCalls = 0;
        int progressCalls = 0;
        bool factoryCalled = false;
        ProductionRunnerEnvironment environment;
        environment.gatewayLookup = [](const QString &interfaceName) {
            REQUIRE(interfaceName == "fixture0");
            return QString("192.0.2.1");
        };
        environment.dependencyFactory = [&](const ScanOptions &captured,
                                            const ScanCancellation &) {
            factoryCalled = true;
            REQUIRE(captured.interfaceName == "fixture0");
            ProductionHostScanDependencies dependencies;
            dependencies.ping = [&](const QHostAddress &, const ScanOptions &,
                                    const TargetBudget &, const auto &) {
                ++pingCalls;
                return false;
            };
            dependencies.services = [&](const QString &, const QString &,
                                        const TargetBudget &, const auto &,
                                        const ScanOptions &) {
                ++serviceCalls;
                return QList<ServiceHit>{{"ssh", "SSH", 22, false,
                                          ServiceEvidenceLevel::VerifiedProtocol}};
            };
            dependencies.neighbor = [&](const QString &, const QString &,
                                        const TargetBudget &, const auto &) {
                ++neighborCalls;
                return NeighborObservation{};
            };
            dependencies.confirmNeighbor = [](const NeighborObservation &initial,
                                               const QString &, const QString &,
                                               const ScanOptions &,
                                               const TargetBudget &,
                                               const auto &) { return initial; };
            dependencies.hostname = [](const QString &, const HostnameEvidence &,
                                       const QStringList &, int,
                                       const TargetBudget &, const auto &) {
                HostnameScanResolution resolution;
                resolution.evidence.append(
                    {"gateway.example", HostnameSource::DnsPtr});
                return resolution;
            };
            return dependencies;
        };
        const QList<ScanResult> results = runProductionScan(
            options,
            {QHostAddress("192.0.2.1")},
            {},
            [&](int current, int total) {
                ++progressCalls;
                REQUIRE(current == 1 && total == 1);
            },
            [&](const ScanResult &) { ++resultCalls; },
            [&](const QString &, const ScanOptions &captured) {
                ++vendorCalls;
                REQUIRE(captured.interfaceName == "fixture0");
                return QString("Fixture Vendor");
            },
            [&](const ScanResult &result, const ScanOptions &captured) {
                ++detailsCalls;
                REQUIRE(result.hostname == "gateway.example");
                REQUIRE(captured.interfaceName == "fixture0");
                return QString("fixture details");
            },
            environment);
        REQUIRE(factoryCalled);
        REQUIRE(pingCalls == 0);
        REQUIRE(serviceCalls == 1);
        REQUIRE(neighborCalls == 1);
        REQUIRE(vendorCalls == 1);
        REQUIRE(detailsCalls == 1);
        REQUIRE(resultCalls == 1);
        REQUIRE(progressCalls == 1);
        REQUIRE(results.size() == 1);
        REQUIRE(results.first().vendor == "Fixture Vendor");
        REQUIRE(results.first().detailsText == "fixture details");
    }

    {
        const auto cancellation = std::make_shared<std::atomic_bool>(true);
        int progressCalls = 0;
        int resultCalls = 0;
        const QList<ScanResult> results = runDebugScanFixture(
            0,
            cancellation,
            [&progressCalls](int, int) { ++progressCalls; },
            [&resultCalls](const ScanResult &) { ++resultCalls; });
        REQUIRE(results.isEmpty());
        REQUIRE(progressCalls == 0);
        REQUIRE(resultCalls == 0);
    }

    {
        const auto cancellation = std::make_shared<std::atomic_bool>(false);
        int lastProgress = 0;
        int resultCalls = 0;
        const QList<ScanResult> results = runDebugScanFixture(
            0,
            cancellation,
            [&lastProgress](int current, int total) {
                REQUIRE(total == debugScanFixtureResultCount());
                lastProgress = current;
            },
            [cancellation, &resultCalls](const ScanResult &) {
                ++resultCalls;
                if (resultCalls == 5) {
                    cancellation->store(true);
                }
            });
        REQUIRE(results.size() == 5);
        REQUIRE(resultCalls == 5);
        REQUIRE(lastProgress == 5);
        REQUIRE(results.first().ip == debugScanFixtureResult(0).ip);
        REQUIRE(results.last().ip == debugScanFixtureResult(4).ip);
    }

    return EXIT_SUCCESS;
}
