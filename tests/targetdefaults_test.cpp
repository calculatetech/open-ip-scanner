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

DefaultTargetPlan rangePlan(const QList<DefaultNetworkInput> &networks,
                            int maxHosts = 4096,
                            int maxTextCharacters = 2048)
{
    return buildDefaultTargetPlan(networks,
                                  maxHosts,
                                  maxTextCharacters,
                                  TargetTextFormat::Range);
}

} // namespace

int main()
{
    const DefaultTargetPlan slash8 = rangePlan({network("10.2.3.4", 8)});
    REQUIRE(slash8.uniqueHostCount == 254);
    REQUIRE(slash8.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash16 = rangePlan({network("10.2.3.4", 16)});
    REQUIRE(slash16.uniqueHostCount == 254);
    REQUIRE(slash16.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash19 = rangePlan({network("10.2.3.4", 19)});
    REQUIRE(slash19.uniqueHostCount == 254);
    REQUIRE(slash19.targetText == "10.2.3.1-10.2.3.254");

    const DefaultTargetPlan slash20 = rangePlan({network("10.2.3.4", 20)});
    REQUIRE(slash20.uniqueHostCount == 4094);
    REQUIRE(slash20.targetText == "10.2.0.1-10.2.15.254");

    const DefaultTargetPlan slash24 = rangePlan({network("192.0.2.88", 24)});
    REQUIRE(slash24.uniqueHostCount == 254);
    REQUIRE(slash24.targetText == "192.0.2.1-192.0.2.254");

    const DefaultTargetPlan slash30 = rangePlan({network("192.0.2.5", 30)});
    REQUIRE(slash30.uniqueHostCount == 2);
    REQUIRE(slash30.targetText == "192.0.2.5-192.0.2.6");

    const DefaultTargetPlan slash31 = rangePlan({network("192.0.2.11", 31)});
    REQUIRE(slash31.uniqueHostCount == 2);
    REQUIRE(slash31.targetText == "192.0.2.10-192.0.2.11");

    const DefaultTargetPlan slash32 = rangePlan({network("192.0.2.11", 32)});
    REQUIRE(slash32.uniqueHostCount == 1);
    REQUIRE(slash32.targetText == "192.0.2.11");

    const DefaultTargetPlan cumulative = rangePlan(
        {network("10.0.1.20", 20, "eth0", "Primary"),
         network("192.168.1.20", 24, "wlan0", "Camera LAN")});
    REQUIRE(cumulative.uniqueHostCount == 4096);
    REQUIRE(cumulative.targetText ==
            "10.0.0.1-10.0.15.254, 192.168.1.1-192.168.1.2");
    REQUIRE(cumulative.omittedInterfaces == QStringList({"Camera LAN"}));

    const DefaultTargetPlan overlap = rangePlan(
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
    const DefaultTargetPlan textBounded = rangePlan(disjointHosts);
    REQUIRE(textBounded.targetText.size() <= 2048);
    REQUIRE(textBounded.uniqueHostCount < 4096);
    REQUIRE(textBounded.omittedInterfaces == QStringList({"Virtual adapters"}));
    const DefaultTargetPlan cidrTextBounded =
        buildDefaultTargetPlan(disjointHosts);
    REQUIRE(cidrTextBounded.targetText.size() <= 2048);
    REQUIRE(cidrTextBounded.uniqueHostCount == textBounded.uniqueHostCount);
    REQUIRE(cidrTextBounded.omittedInterfaces == textBounded.omittedInterfaces);

    const DefaultTargetPlan none = rangePlan({network("10.0.0.1", 24)}, 0);
    REQUIRE(none.uniqueHostCount == 0);
    REQUIRE(none.targetText.isEmpty());
    const DefaultTargetPlan noText =
        rangePlan({network("10.0.0.1", 24)}, 4096, 0);
    REQUIRE(noText.uniqueHostCount == 0);
    REQUIRE(noText.targetText.isEmpty());

    const DefaultTargetPlan cidrSlash24 =
        buildDefaultTargetPlan({network("192.0.2.88", 24)});
    REQUIRE(cidrSlash24.targetText == "192.0.2.0/24");
    REQUIRE(cidrSlash24.uniqueHostCount == slash24.uniqueHostCount);
    const DefaultTargetPlan cidrSlash31 =
        buildDefaultTargetPlan({network("192.0.2.11", 31)});
    REQUIRE(cidrSlash31.targetText == "192.0.2.10/31");
    const DefaultTargetPlan cidrSlash32 =
        buildDefaultTargetPlan({network("192.0.2.11", 32)});
    REQUIRE(cidrSlash32.targetText == "192.0.2.11/32");
    const DefaultTargetPlan cidrCumulative = buildDefaultTargetPlan(
        {network("10.0.1.20", 20, "eth0", "Primary"),
         network("192.168.1.20", 24, "wlan0", "Camera LAN")});
    REQUIRE(cidrCumulative.targetText ==
            "10.0.0.0/20, 192.168.1.0/30");
    REQUIRE(cidrCumulative.uniqueHostCount == cumulative.uniqueHostCount);
    REQUIRE(cidrCumulative.omittedInterfaces == cumulative.omittedInterfaces);
    REQUIRE(cidrCumulative.targetText.size() <= 2048);
    return EXIT_SUCCESS;
}
