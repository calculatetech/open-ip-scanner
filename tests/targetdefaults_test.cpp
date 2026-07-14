#include "targetdefaults.h"

#include <QHostAddress>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "target default requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

quint32 address(const char *text)
{
    return QHostAddress(QString::fromLatin1(text)).toIPv4Address();
}

DefaultNetworkInput network(const char *local,
                            int prefix,
                            const char *interfaceName = "eth0",
                            const char *interfaceLabel = "Ethernet")
{
    return {address(local),
            prefix,
            QString::fromLatin1(interfaceName),
            QString::fromLatin1(interfaceLabel)};
}

} // namespace

int main()
{
    const DefaultTargetPlan slash8 = buildDefaultTargetPlan({network("10.2.3.4", 8)});
    REQUIRE(slash8.uniqueHostCount == 254);
    REQUIRE(slash8.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash16 = buildDefaultTargetPlan({network("10.2.3.4", 16)});
    REQUIRE(slash16.uniqueHostCount == 254);
    REQUIRE(slash16.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash19 = buildDefaultTargetPlan({network("10.2.3.4", 19)});
    REQUIRE(slash19.uniqueHostCount == 254);
    REQUIRE(slash19.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash20 = buildDefaultTargetPlan({network("10.2.3.4", 20)});
    REQUIRE(slash20.uniqueHostCount == 4094);
    REQUIRE(slash20.targetText == "10.2.0.1-10.2.15.254");

    const DefaultTargetPlan slash24 = buildDefaultTargetPlan({network("192.0.2.88", 24)});
    REQUIRE(slash24.uniqueHostCount == 254);
    REQUIRE(slash24.targetText == "192.0.2.1-192.0.2.254");

    const DefaultTargetPlan slash30 = buildDefaultTargetPlan({network("192.0.2.5", 30)});
    REQUIRE(slash30.uniqueHostCount == 2);
    REQUIRE(slash30.targetText == "192.0.2.5-192.0.2.6");

    const DefaultTargetPlan slash31 = buildDefaultTargetPlan({network("192.0.2.11", 31)});
    REQUIRE(slash31.uniqueHostCount == 2);
    REQUIRE(slash31.targetText == "192.0.2.10-192.0.2.11");

    const DefaultTargetPlan slash32 = buildDefaultTargetPlan({network("192.0.2.11", 32)});
    REQUIRE(slash32.uniqueHostCount == 1);
    REQUIRE(slash32.targetText == "192.0.2.11");

    const DefaultTargetPlan cumulative = buildDefaultTargetPlan(
        {network("10.0.1.20", 20, "eth0", "Primary"),
         network("192.168.1.20", 24, "wlan0", "Camera LAN")});
    REQUIRE(cumulative.uniqueHostCount == 4096);
    REQUIRE(cumulative.targetText ==
            "10.0.0.1-10.0.15.254, 192.168.1.1-192.168.1.2");
    REQUIRE(cumulative.omittedInterfaces == QStringList({"Camera LAN"}));

    const DefaultTargetPlan overlap = buildDefaultTargetPlan(
        {network("198.51.100.10", 24, "eth0", "Primary"),
         network("198.51.100.20", 24, "vpn0", "Overlapping VPN")});
    REQUIRE(overlap.uniqueHostCount == 254);
    REQUIRE(overlap.omittedInterfaces.isEmpty());

    QList<DefaultNetworkInput> disjointHosts;
    const quint32 firstDisjointAddress = address("10.10.0.1");
    for (int index = 0; index < 4096; ++index) {
        disjointHosts.append({firstDisjointAddress + static_cast<quint32>(index * 2),
                              32,
                              "virtual",
                              "Virtual adapters"});
    }
    const DefaultTargetPlan textBounded = buildDefaultTargetPlan(disjointHosts);
    REQUIRE(textBounded.targetText.size() <= 2048);
    REQUIRE(textBounded.uniqueHostCount < 4096);
    REQUIRE(textBounded.omittedInterfaces == QStringList({"Virtual adapters"}));

    const DefaultTargetPlan none = buildDefaultTargetPlan({network("10.0.0.1", 24)}, 0);
    REQUIRE(none.uniqueHostCount == 0);
    REQUIRE(none.targetText.isEmpty());
    const DefaultTargetPlan noText =
        buildDefaultTargetPlan({network("10.0.0.1", 24)}, 4096, 0);
    REQUIRE(noText.uniqueHostCount == 0);
    REQUIRE(noText.targetText.isEmpty());
    return EXIT_SUCCESS;
}
