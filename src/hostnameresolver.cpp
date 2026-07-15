#include "hostnameresolver.h"
#include "diagnostics.h"

#include <QDnsLookup>

#include <utility>

HostnameResolver::HostnameResolver(std::shared_ptr<ScanMdnsResolver> mdnsResolver,
                                   PtrLookup ptrLookup,
                                   SystemLookup systemLookup,
                                   MdnsLookup mdnsLookup)
    : mdnsResolver_(std::move(mdnsResolver)),
      ptrLookup_(std::move(ptrLookup)),
      systemLookup_(std::move(systemLookup)),
      mdnsLookup_(std::move(mdnsLookup))
{
    if (!ptrLookup_) {
        ptrLookup_ = [](const QString &ip,
                        int timeoutMs,
                        const Cancellation &cancellation) {
            return cancellable::lookupPtr(ip, timeoutMs, cancellation);
        };
    }
    if (!systemLookup_) {
        systemLookup_ = [](const QString &ip,
                           int timeoutMs,
                           const Cancellation &cancellation) {
            SystemHostnameLookupResult result;
            result.hostInfo = cancellable::lookupHost(
                ip, timeoutMs, cancellation, &result.waitResult);
            return result;
        };
    }
    if (!mdnsLookup_) {
        const std::shared_ptr<ScanMdnsResolver> resolver = mdnsResolver_;
        mdnsLookup_ = [resolver](const QString &ip, int timeoutMs) {
            return resolver ? resolver->resolve(ip, timeoutMs) : MdnsLookupResult{};
        };
    }
}

HostnameScanResolution HostnameResolver::resolve(
    const QString &ip,
    const HostnameEvidence &preliminary,
    const QStringList &adapterDnsSuffixes,
    int accuracyLevel,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    HostnameScanResolution resolution;
    resolution.evidence = mergeHostnameEvidence(resolution.evidence, preliminary);
    const HostnameTimeoutProfile timeouts = hostnameTimeoutProfile(accuracyLevel);
    const auto addEvent = [&resolution](ResolverKind resolver,
                                        ResolverOutcome outcome) {
        resolution.resolverEvents = mergeResolverEvents(
            resolution.resolverEvents, {resolver, outcome});
        if (outcome == ResolverOutcome::Resolved ||
            outcome == ResolverOutcome::NoRecord ||
            outcome == ResolverOutcome::Cancelled) {
            return;
        }
        QString resolverName;
        QString remediation;
        switch (resolver) {
        case ResolverKind::Mdns:
            resolverName = "mdns";
            remediation = outcome == ResolverOutcome::DaemonUnavailable
                              ? "Start or install avahi-daemon."
                              : "Check Avahi, adapter multicast support, and firewall rules.";
            break;
        case ResolverKind::DnsPtr:
            resolverName = "dns_ptr";
            remediation = "Check DNS configuration and try again.";
            break;
        case ResolverKind::System:
            resolverName = "system_resolver";
            remediation = "Check the system name-service configuration.";
            break;
        }
        QString outcomeName;
        switch (outcome) {
        case ResolverOutcome::TimedOut: outcomeName = "timeout"; break;
        case ResolverOutcome::BackendUnavailable: outcomeName = "backend_unavailable"; break;
        case ResolverOutcome::DaemonUnavailable: outcomeName = "daemon_unavailable"; break;
        case ResolverOutcome::MulticastUnavailable: outcomeName = "multicast_unavailable"; break;
        case ResolverOutcome::InvalidResponse: outcomeName = "invalid_response"; break;
        case ResolverOutcome::Resolved:
        case ResolverOutcome::NoRecord:
        case ResolverOutcome::Cancelled: return;
        }
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Warning,
            resolverName + "." + outcomeName,
            "hostname",
            remediation));
    };

    const cancellable::DnsPtrLookupResult ptr = ptrLookup_(
        ip, budget.clampTimeout(timeouts.ptrMs), cancellation);
    if (ptr.waitResult == cancellable::WaitResult::Cancelled) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::Cancelled);
        return resolution;
    }
    if (ptr.waitResult == cancellable::WaitResult::TimedOut ||
        cancellable::isDnsLookupTimeoutError(ptr.error)) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::TimedOut);
    } else if (ptr.error == QDnsLookup::NoError && !ptr.hostnames.isEmpty()) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::Resolved);
        const QString hostname = preferredPtrHostname(
            ptr.hostnames, adapterDnsSuffixes);
        if (!hostname.isEmpty()) {
            resolution.evidence = mergeHostnameEvidence(
                resolution.evidence, {hostname, HostnameSource::DnsPtr});
        }
    } else if (ptr.error == QDnsLookup::NotFoundError ||
               (ptr.error == QDnsLookup::NoError && ptr.hostnames.isEmpty())) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::NoRecord);
    } else if (ptr.error == QDnsLookup::InvalidRequestError ||
               ptr.error == QDnsLookup::InvalidReplyError) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::InvalidResponse);
    } else {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::BackendUnavailable);
    }

    if (cancellable::isCancelled(cancellation) || budget.expired()) {
        return resolution;
    }
    const SystemHostnameLookupResult system = systemLookup_(
        ip, budget.clampTimeout(timeouts.systemMs), cancellation);
    if (system.waitResult == cancellable::WaitResult::Cancelled) {
        addEvent(ResolverKind::System, ResolverOutcome::Cancelled);
        return resolution;
    }
    const QHostInfo &info = system.hostInfo;
    if (system.waitResult == cancellable::WaitResult::TimedOut) {
        addEvent(ResolverKind::System, ResolverOutcome::TimedOut);
    } else if (info.error() == QHostInfo::NoError &&
               !normalizedHostnameKey(info.hostName()).isEmpty() &&
               info.hostName() != ip) {
        addEvent(ResolverKind::System, ResolverOutcome::Resolved);
        resolution.evidence = mergeHostnameEvidence(
            resolution.evidence,
            {qualifyHostname(info.hostName(), adapterDnsSuffixes.value(0)),
             HostnameSource::SystemResolver});
    } else if (info.error() == QHostInfo::HostNotFound ||
               (info.error() == QHostInfo::NoError &&
                normalizedHostnameKey(info.hostName()).isEmpty())) {
        addEvent(ResolverKind::System, ResolverOutcome::NoRecord);
    } else {
        addEvent(ResolverKind::System, ResolverOutcome::BackendUnavailable);
    }

    if (cancellable::isCancelled(cancellation) || budget.expired()) {
        return resolution;
    }
    const MdnsLookupResult mdns = mdnsLookup_(
        ip, budget.clampTimeout(timeouts.mdnsMs));
    switch (mdns.status) {
    case MdnsLookupStatus::Resolved:
        addEvent(ResolverKind::Mdns, ResolverOutcome::Resolved);
        resolution.evidence = mergeHostnameEvidence(
            resolution.evidence, {mdns.hostname, HostnameSource::AvahiMdns});
        break;
    case MdnsLookupStatus::NoRecord:
        addEvent(ResolverKind::Mdns, ResolverOutcome::NoRecord);
        break;
    case MdnsLookupStatus::TimedOut:
        addEvent(ResolverKind::Mdns, ResolverOutcome::TimedOut);
        break;
    case MdnsLookupStatus::Cancelled:
        addEvent(ResolverKind::Mdns, ResolverOutcome::Cancelled);
        break;
    case MdnsLookupStatus::BackendUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::BackendUnavailable);
        break;
    case MdnsLookupStatus::DaemonUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::DaemonUnavailable);
        break;
    case MdnsLookupStatus::MulticastUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::MulticastUnavailable);
        break;
    case MdnsLookupStatus::InvalidResponse:
        addEvent(ResolverKind::Mdns, ResolverOutcome::InvalidResponse);
        break;
    }
    return resolution;
}
