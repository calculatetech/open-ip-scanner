#include "neighborentry.h"
#include "resulttablemodel.h"

#include <QCoreApplication>
#include <QAbstractItemModel>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "result search requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);

    ResultTableModel model;
    ScanResult result;
    result.ip = "192.0.2.44";
    result.interfaceName = "fixture0";
    result.mac = "00:90:7F:12:34:56";
    result.vendor = "Example Devices";
    result.hostname = "primary.corp.example";
    result.hostnameSource = HostnameSource::LocalHost;
    result.hostnameEvidence = {
        {"primary.corp.example", HostnameSource::LocalHost},
        {"alternate.hidden.example.", HostnameSource::DnsPtr},
        {"printer.local", HostnameSource::AvahiMdns},
    };
    result.services = {
        {"ssh", "Secure Shell", 22, false,
         ServiceEvidenceLevel::VerifiedProtocol},
        {"camera", "Probable Camera", 9000, false,
         ServiceEvidenceLevel::OpenPort},
    };
    model.upsertResult(result);

    REQUIRE(model.matchesSearch(0, "192.0.2", "ip"));
    REQUIRE(model.matchesSearch(0, "example devices", "vendor"));
    REQUIRE(model.matchesSearch(0, "00-90-7f", "mac"));
    REQUIRE(model.matchesSearch(0, "00907f1234", "mac"));
    REQUIRE(model.matchesSearch(0, "00:90:7F", "oui"));
    REQUIRE(model.matchesSearch(0, "00-9", "oui"));
    REQUIRE(model.matchesSearch(0, "00907F1", "oui"));
    REQUIRE(model.matchesSearch(0, "00:90:7F:12:3", "oui"));
    REQUIRE(model.matchesSearch(0, "alternate.hidden.example", "hostname"));
    REQUIRE(model.matchesSearch(0, "printer.local", "all"));
    REQUIRE(model.matchesSearch(0, "secure shell", "services"));
    REQUIRE(model.matchesSearch(0, "ssh", "services"));
    REQUIRE(model.matchesSearch(0, "22", "services"));
    REQUIRE(model.matchesSearch(0, "9000", "services"));
    REQUIRE(!model.matchesSearch(0, "probable camera", "services"));
    REQUIRE(!model.matchesSearch(0, "Unknown", "all"));
    REQUIRE(!model.matchesSearch(0, "PTR", "all"));
    REQUIRE(!model.matchesSearch(0, "daemon unavailable", "all"));
    REQUIRE(!model.matchesSearch(-1, "example", "all"));

    ScanResult progressive;
    progressive.ip = "192.0.2.45";
    progressive.interfaceName = "fixture0";
    model.upsertResult(progressive);
    const QString progressiveIdentity = neighborIdentityKey(
        progressive.interfaceName, progressive.ip);
    const int progressiveRow = model.rowForIdentity(progressiveIdentity);
    REQUIRE(!model.matchesSearch(progressiveRow, "late.alias.example", "all"));
    progressive.hostnameEvidence = {
        {"late.alias.example", HostnameSource::DnsPtr},
    };
    model.upsertResult(progressive);
    REQUIRE(model.matchesSearch(model.rowForIdentity(progressiveIdentity),
                                "LATE.ALIAS.EXAMPLE", "all"));
    progressive.hostnameEvidence.clear();
    progressive.hostname.clear();
    progressive.hostnameSource = HostnameSource::Unknown;
    model.upsertResult(progressive);
    REQUIRE(!model.matchesSearch(model.rowForIdentity(progressiveIdentity),
                                 "late.alias.example", "all"));
    progressive.hostname = "late.alias.example";
    progressive.hostnameSource = HostnameSource::DnsPtr;
    progressive.hostnameEvidence = {
        {progressive.hostname, progressive.hostnameSource},
    };
    model.upsertResult(progressive);
    REQUIRE(model.matchesSearch(model.rowForIdentity(progressiveIdentity),
                                "late.alias.example", "all"));

    progressive.services = {
        {"ssh", "Secure Shell", 22, false,
         ServiceEvidenceLevel::VerifiedProtocol},
    };
    model.upsertResult(progressive);
    REQUIRE(model.matchesSearch(model.rowForIdentity(progressiveIdentity),
                                "secure shell", "services"));
    progressive.services.clear();
    model.upsertResult(progressive);
    REQUIRE(!model.matchesSearch(model.rowForIdentity(progressiveIdentity),
                                 "secure shell", "services"));

    int dataChangeCount = 0;
    QObject::connect(&model, &QAbstractItemModel::dataChanged,
                     [&dataChangeCount]() { ++dataChangeCount; });
    REQUIRE(!model.upsertResult(progressive));
    REQUIRE(dataChangeCount == 0);

    ScanResult sibling = result;
    sibling.ip = "192.0.2.46";
    sibling.mac = "00:90:7F:22:34:56";
    model.upsertResult(sibling);
    REQUIRE(model.matchesSearch(model.rowForIdentity(
                                    neighborIdentityKey("fixture0", "192.0.2.44")),
                                "00907F1", "oui"));
    REQUIRE(!model.matchesSearch(model.rowForIdentity(
                                     neighborIdentityKey("fixture0", "192.0.2.46")),
                                 "00907F1", "oui"));

    ScanResult unknowns;
    unknowns.ip = "192.0.2.47";
    unknowns.interfaceName = "fixture0";
    unknowns.mac = "Unknown";
    unknowns.vendor = "Unknown";
    unknowns.hostname = "Unknown";
    model.upsertResult(unknowns);
    const int unknownRow = model.rowForIdentity(
        neighborIdentityKey(unknowns.interfaceName, unknowns.ip));
    REQUIRE(!model.matchesSearch(unknownRow, "Unknown", "all"));
    REQUIRE(model.matchesSearch(0, "alternate.hidden.example.", "hostname"));

    return EXIT_SUCCESS;
}
