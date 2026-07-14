#include "debugscanfixture.h"
#include "neighborentry.h"

#include <QHostAddress>
#include <QSet>

#include <cstdlib>

namespace {

void require(bool condition)
{
    if (!condition) {
        std::abort();
    }
}

} // namespace

int main()
{
    require(isDebugScanFixtureTarget("test"));
    require(!isDebugScanFixtureTarget("TEST"));
    require(!isDebugScanFixtureTarget("test "));
    require(!isDebugScanFixtureTarget("test,192.0.2.1"));
    require(!isDebugScanFixtureTarget("999.999.999.999/24"));
    const int count = debugScanFixtureResultCount();
    require(count >= 500);
    require(debugScanFixtureIntervalMs(0) < debugScanFixtureIntervalMs(1));
    require(debugScanFixtureIntervalMs(1) < debugScanFixtureIntervalMs(2));
    require(debugScanFixtureIntervalMs(2) < debugScanFixtureIntervalMs(3));
    require(debugScanFixtureIntervalMs(-1) == debugScanFixtureIntervalMs(0));
    require(debugScanFixtureIntervalMs(99) == debugScanFixtureIntervalMs(3));

    QSet<QString> identities;
    QSet<QString> verifiedServiceIds;
    QSet<QString> unknownServiceIds;
    bool hasKnownVendor = false;
    bool hasUnknownVendor = false;
    bool hasKnownHostname = false;
    bool hasUnknownHostname = false;
    for (int index = 0; index < count; ++index) {
        const ScanResult result = debugScanFixtureResult(index);
        QHostAddress address(result.ip);
        require(address.protocol() == QAbstractSocket::IPv4Protocol);
        const quint32 ipv4 = address.toIPv4Address();
        require(ipv4 >= QHostAddress("198.18.0.0").toIPv4Address());
        require(ipv4 <= QHostAddress("198.19.255.255").toIPv4Address());
        identities.insert(neighborIdentityKey(result.interfaceName, result.ip));
        hasKnownVendor = hasKnownVendor || result.vendor != "Unknown";
        hasUnknownVendor = hasUnknownVendor || result.vendor == "Unknown";
        hasKnownHostname = hasKnownHostname || result.hostname != "Unknown";
        hasUnknownHostname = hasUnknownHostname || result.hostname == "Unknown";
        for (const ServiceHit &service : result.services) {
            if (service.evidence == ServiceEvidenceLevel::VerifiedProtocol) {
                verifiedServiceIds.insert(service.id);
            } else {
                unknownServiceIds.insert(service.id);
            }
        }
        require(debugScanFixtureResult(index).ip == result.ip);
    }
    require(identities.size() == count);
    require(verifiedServiceIds.size() == 10);
    require(unknownServiceIds.size() == 10);
    require(hasKnownVendor && hasUnknownVendor);
    require(hasKnownHostname && hasUnknownHostname);
    return EXIT_SUCCESS;
}
