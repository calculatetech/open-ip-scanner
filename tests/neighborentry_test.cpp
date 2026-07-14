#include "neighborentry.h"

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "neighbor entry requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

NeighborObservation parseOne(const char *state,
                             const char *mac = "02:00:00:00:00:01",
                             const char *interfaceName = "eth0")
{
    const QByteArray json =
        QByteArray("[{\"dst\":\"192.0.2.10\",\"dev\":\"") + interfaceName +
        "\",\"lladdr\":\"" + mac + "\",\"state\":[\"" + state + "\"]}]";
    QString error;
    const QList<NeighborObservation> observations =
        parseLinuxNeighborJson(json, QString::fromLatin1(interfaceName), &error);
    REQUIRE(error.isEmpty());
    REQUIRE(observations.size() == 1);
    return observations.first();
}

} // namespace

int main()
{
    const NeighborObservation reachable = parseOne("REACHABLE");
    REQUIRE(reachable.establishesLiveness());
    REQUIRE(reachable.suppliesMacMetadata());
    REQUIRE(reachable.mac == "02:00:00:00:00:01");

    for (const char *state : {"STALE", "DELAY", "PROBE", "PERMANENT"}) {
        const NeighborObservation observation = parseOne(state);
        REQUIRE(!observation.establishesLiveness());
        REQUIRE(observation.suppliesMacMetadata());
    }

    for (const char *state : {"INCOMPLETE", "FAILED", "NONE", "NOARP"}) {
        const NeighborObservation observation = parseOne(state);
        REQUIRE(!observation.establishesLiveness());
        REQUIRE(!observation.suppliesMacMetadata());
        REQUIRE(observation.mac.isEmpty());
    }

    for (const char *mac : {"00:00:00:00:00:00",
                            "FF:FF:FF:FF:FF:FF",
                            "01:00:5E:00:00:01",
                            "33:33:00:00:00:01",
                            "02:00:00:00:00",
                            "not-a-mac"}) {
        const NeighborObservation observation = parseOne("REACHABLE", mac);
        REQUIRE(!observation.establishesLiveness());
        REQUIRE(!observation.suppliesMacMetadata());
    }

    const QByteArray overlapping =
        "[{\"dst\":\"10.0.0.2\",\"dev\":\"eth0\",\"lladdr\":"
        "\"02:00:00:00:00:01\",\"state\":[\"REACHABLE\"]},"
        "{\"dst\":\"10.0.0.2\",\"dev\":\"vpn0\",\"lladdr\":"
        "\"02:00:00:00:00:02\",\"state\":[\"REACHABLE\"]}]";
    const QList<NeighborObservation> observations =
        parseLinuxNeighborJson(overlapping, QString());
    REQUIRE(observations.size() == 2);
    REQUIRE(observations[0].identityKey() != observations[1].identityKey());
    REQUIRE(neighborIdentityKey("eth0", "10.0.0.2") !=
            neighborIdentityKey("vpn0", "10.0.0.2"));

    const QList<NeighborObservation> filtered =
        parseLinuxNeighborJson(overlapping, "vpn0");
    REQUIRE(filtered.size() == 1);
    REQUIRE(filtered.first().interfaceName == "vpn0");

    const QByteArray scopedOutputWithoutDev =
        "[{\"dst\":\"10.0.0.3\",\"lladdr\":\"02:00:00:00:00:03\","
        "\"state\":[\"REACHABLE\"]}]";
    const QList<NeighborObservation> scoped =
        parseLinuxNeighborJson(scopedOutputWithoutDev, "eth0");
    REQUIRE(scoped.size() == 1);
    REQUIRE(scoped.first().interfaceName == "eth0");
    REQUIRE(scoped.first().establishesLiveness());
    REQUIRE(parseLinuxNeighborJson(scopedOutputWithoutDev, QString()).isEmpty());

    QString error;
    REQUIRE(parseLinuxNeighborJson("not json", "eth0", &error).isEmpty());
    REQUIRE(!error.isEmpty());
    return EXIT_SUCCESS;
}
