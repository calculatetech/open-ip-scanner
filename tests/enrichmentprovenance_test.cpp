#include "hostnameevidence.h"
#include "resolverdiagnostics.h"

#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "enrichment provenance requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

} // namespace

int main()
{
    QList<HostnameEvidence> evidence;
    evidence = mergeHostnameEvidence(
        evidence, {"nas.local.", HostnameSource::AvahiMdns});
    evidence = mergeHostnameEvidence(
        evidence, {"nas-system", HostnameSource::SystemResolver});
    evidence = mergeHostnameEvidence(
        evidence, {"nas.example.test.", HostnameSource::DnsPtr});
    evidence = mergeHostnameEvidence(
        evidence, {"nas-os", HostnameSource::LocalHost});
    evidence = mergeHostnameEvidence(
        evidence, {"NAS.LOCAL", HostnameSource::SystemResolver});
    evidence = mergeHostnameEvidence(
        evidence, {"nas.local", HostnameSource::AvahiMdns});

    REQUIRE(evidence.size() == 5);
    REQUIRE(preferredHostname(evidence).hostname == "nas-os");
    REQUIRE(preferredHostname(evidence).source == HostnameSource::LocalHost);
    REQUIRE(ipv4PtrQueryName("192.0.2.10") == "10.2.0.192.in-addr.arpa");
    REQUIRE(ipv4PtrQueryName("not-an-ip").isEmpty());

    const QList<HostnameDisplayRow> rows = hostnameDisplayRows(evidence);
    REQUIRE(rows.size() == 4);
    REQUIRE(rows.first().hostname == "nas-os");
    REQUIRE(rows.first().preferred);
    bool combinedSources = false;
    for (const HostnameDisplayRow &row : rows) {
        if (normalizedHostnameKey(row.hostname) == "nas.local") {
            combinedSources = row.sourceLabels == QStringList({"System", "mDNS"});
        }
    }
    REQUIRE(combinedSources);

    const QList<HostnameDisplayRow> sameNameRows = hostnameDisplayRows({
        {"LOWER.local", HostnameSource::AvahiMdns},
        {"lower.LOCAL.", HostnameSource::DnsPtr}});
    REQUIRE(sameNameRows.size() == 1);
    REQUIRE(sameNameRows.first().hostname == "lower.LOCAL.");
    REQUIRE(sameNameRows.first().preferred);

    QList<HostnameEvidence> inheritedSuffix;
    inheritedSuffix = mergeHostnameEvidence(
        inheritedSuffix, {"workstation", HostnameSource::LocalHost});
    inheritedSuffix = mergeHostnameEvidence(
        inheritedSuffix, {"workstation", HostnameSource::SystemResolver});
    inheritedSuffix = mergeHostnameEvidence(
        inheritedSuffix, {"workstation.local", HostnameSource::DnsPtr});
    inheritedSuffix = mergeHostnameEvidence(
        inheritedSuffix, {"workstation.local", HostnameSource::AvahiMdns});
    REQUIRE(inheritedSuffix.size() == 4);
    REQUIRE(canonicalHostnameEvidence(inheritedSuffix).size() == 4);
    const QList<HostnameDisplayRow> inheritedRows = hostnameDisplayRows(
        inheritedSuffix);
    REQUIRE(inheritedRows.size() == 1);
    REQUIRE(inheritedRows.first().hostname == "workstation.local");
    REQUIRE(inheritedRows.first().sourceLabels ==
            QStringList({"Local", "PTR", "System", "mDNS"}));

    QList<HostnameEvidence> dnsSuffixWins;
    dnsSuffixWins = mergeHostnameEvidence(
        dnsSuffixWins, {"camera", HostnameSource::LocalHost});
    dnsSuffixWins = mergeHostnameEvidence(
        dnsSuffixWins, {"camera.local", HostnameSource::AvahiMdns});
    dnsSuffixWins = mergeHostnameEvidence(
        dnsSuffixWins, {"camera.example.test", HostnameSource::DnsPtr});
    const QList<HostnameDisplayRow> dnsSuffixRows = hostnameDisplayRows(
        dnsSuffixWins);
    REQUIRE(dnsSuffixRows.size() == 2);
    REQUIRE(dnsSuffixRows.first().hostname == "camera.example.test");

    REQUIRE(preferredPtrHostname(
                {"workstation.local.", "workstation"},
                {"example.test"}) == "workstation.example.test");
    REQUIRE(preferredPtrHostname(
                {"workstation.local.", "workstation.example.test."},
                {"example.test"}) == "workstation.example.test");
    REQUIRE(preferredPtrHostname(
                {"workstation.lab.example.test.", "workstation"},
                {"example.test"}) == "workstation.lab.example.test");
    REQUIRE(preferredPtrHostname(
                {"example.test.", "example"},
                {"example.test"}) == "example.test");
    REQUIRE(preferredPtrHostname(
                {"workstation.example.test.", "workstation.local."},
                {"local"}) == "workstation.local");
    REQUIRE(preferredPtrHostname(
                {"workstation", "workstation.local."}, {}) ==
            "workstation.local");

    QList<HostnameEvidence> unscopedShortPtr;
    unscopedShortPtr = mergeHostnameEvidence(
        unscopedShortPtr, {"printer", HostnameSource::DnsPtr});
    unscopedShortPtr = mergeHostnameEvidence(
        unscopedShortPtr, {"printer.local", HostnameSource::AvahiMdns});
    const QList<HostnameDisplayRow> unscopedRows = hostnameDisplayRows(
        unscopedShortPtr);
    REQUIRE(unscopedRows.size() == 2);
    REQUIRE(unscopedRows.first().hostname == "printer");
    REQUIRE(unscopedRows.first().sourceLabels == QStringList({"PTR"}));

    const QList<HostnameDisplayRow> mdnsOnlySuffixRows = hostnameDisplayRows({
        {"scanner", HostnameSource::LocalHost},
        {"scanner", HostnameSource::SystemResolver},
        {"scanner.local", HostnameSource::AvahiMdns}});
    REQUIRE(mdnsOnlySuffixRows.size() == 2);
    REQUIRE(mdnsOnlySuffixRows.first().hostname == "scanner");
    REQUIRE(mdnsOnlySuffixRows.first().sourceLabels ==
            QStringList({"Local", "System"}));

    const QList<ResolverEvent> events = {
        {ResolverKind::Mdns, ResolverOutcome::Resolved},
        {ResolverKind::Mdns, ResolverOutcome::NoRecord},
        {ResolverKind::Mdns, ResolverOutcome::DaemonUnavailable},
        {ResolverKind::Mdns, ResolverOutcome::MulticastUnavailable},
        {ResolverKind::Mdns, ResolverOutcome::TimedOut},
        {ResolverKind::Mdns, ResolverOutcome::Cancelled},
        {ResolverKind::Mdns, ResolverOutcome::InvalidResponse},
        {ResolverKind::DnsPtr, ResolverOutcome::Resolved},
        {ResolverKind::System, ResolverOutcome::BackendUnavailable}};
    const QString diagnosticText = resolverDiagnosticsText(events);
    REQUIRE(diagnosticText.contains("mDNS Daemon unavailable: 1"));
    REQUIRE(diagnosticText.contains("mDNS Multicast unavailable: 1"));
    REQUIRE(diagnosticText.contains("mDNS No record: 1"));
    REQUIRE(diagnosticText.contains("PTR Resolved: 1"));
    REQUIRE(diagnosticText.contains("System Backend unavailable: 1"));

    const QByteArray support = resolverSupportBundleJson(
        events, "0.5.1", "Fixture Linux");
    REQUIRE(!support.contains("192.0.2.10"));
    REQUIRE(!support.contains("nas.local"));
    const QJsonDocument document = QJsonDocument::fromJson(support);
    REQUIRE(document.isObject());
    REQUIRE(document.object().value("version").toString() == "0.5.1");
    REQUIRE(document.object()
                .value("hostname_enrichment")
                .toObject()
                .value("counts")
                .toObject()
                .value("mdns.resolved")
                .toInt() == 1);

    const QString cancelledHealth = resolverDiagnosticsText({
        {ResolverKind::Mdns, ResolverOutcome::Cancelled}});
    REQUIRE(cancelledHealth.contains("mDNS backend: Not observed"));
    const QJsonObject timedOutEnrichment = QJsonDocument::fromJson(
        resolverSupportBundleJson(
            {{ResolverKind::Mdns, ResolverOutcome::TimedOut}},
            "0.5.1",
            "Fixture Linux"))
                                              .object()
                                              .value("hostname_enrichment")
                                              .toObject();
    REQUIRE(timedOutEnrichment.value("mdns_backend").toString() ==
            "Unresponsive");
    const QString invalidResponseHealth = resolverDiagnosticsText({
        {ResolverKind::Mdns, ResolverOutcome::InvalidResponse}});
    REQUIRE(invalidResponseHealth.contains("mDNS backend: Available"));
    return EXIT_SUCCESS;
}
