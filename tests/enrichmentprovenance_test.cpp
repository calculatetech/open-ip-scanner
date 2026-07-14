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
