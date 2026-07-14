#include "hostnameresolver.h"

#include <QCoreApplication>
#include <QDnsLookup>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "hostname resolver requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

cancellable::DnsPtrLookupResult ptrResult(
    cancellable::WaitResult waitResult,
    QDnsLookup::Error error,
    QStringList hostnames = {})
{
    return {waitResult, error, std::move(hostnames)};
}

SystemHostnameLookupResult systemResult(cancellable::WaitResult waitResult,
                                        QHostInfo::HostInfoError error,
                                        const QString &hostname = {})
{
    SystemHostnameLookupResult result;
    result.waitResult = waitResult;
    result.hostInfo.setError(error);
    result.hostInfo.setHostName(hostname);
    return result;
}

ResolverOutcome requiredOutcomeFor(const HostnameScanResolution &resolution,
                                   ResolverKind kind)
{
    for (const ResolverEvent &event : resolution.resolverEvents) {
        if (event.resolver == kind) {
            return event.outcome;
        }
    }
    requireAt(false, __LINE__);
    return ResolverOutcome::BackendUnavailable;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const auto noRecordSystem = [](const QString &, int, const auto &) {
        return systemResult(cancellable::WaitResult::Completed,
                            QHostInfo::HostNotFound);
    };
    const auto noRecordMdns = [](const QString &, int) {
        return MdnsLookupResult{MdnsLookupStatus::NoRecord, {}};
    };

    {
        QList<int> timeouts;
        HostnameResolver resolver(
            {},
            [&timeouts](const QString &, int timeout, const auto &) {
                timeouts.append(timeout);
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NoError,
                                 {"fixture.local.", "fixture.corp.example."});
            },
            [&timeouts](const QString &, int timeout, const auto &) {
                timeouts.append(timeout);
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::NoError,
                                    "fixture");
            },
            [&timeouts](const QString &, int timeout) {
                timeouts.append(timeout);
                return MdnsLookupResult{MdnsLookupStatus::Resolved,
                                        "fixture.local."};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.20",
            {"gateway", HostnameSource::Preliminary},
            {"corp.example"},
            2,
            TargetBudget(10000),
            {});
        REQUIRE(timeouts == QList<int>({1250, 1000, 1750}));
        REQUIRE(result.resolverEvents == QList<ResolverEvent>({
            {ResolverKind::DnsPtr, ResolverOutcome::Resolved},
            {ResolverKind::System, ResolverOutcome::Resolved},
            {ResolverKind::Mdns, ResolverOutcome::Resolved}}));
        REQUIRE(result.evidence.size() == 4);
        REQUIRE(result.evidence.at(0).hostname == "gateway");
        REQUIRE(result.evidence.at(1).hostname == "fixture.corp.example");
        REQUIRE(result.evidence.at(1).source == HostnameSource::DnsPtr);
        REQUIRE(result.evidence.at(2).hostname == "fixture.corp.example");
        REQUIRE(result.evidence.at(2).source == HostnameSource::SystemResolver);
        REQUIRE(result.evidence.at(3).hostname == "fixture.local");
        REQUIRE(result.evidence.at(3).source == HostnameSource::AvahiMdns);
    }

    struct PtrCase {
        cancellable::WaitResult wait;
        QDnsLookup::Error error;
        QStringList hostnames;
        ResolverOutcome expected;
    };
    const QList<PtrCase> ptrCases = {
        {cancellable::WaitResult::Cancelled, QDnsLookup::ResolverError, {},
         ResolverOutcome::Cancelled},
        {cancellable::WaitResult::TimedOut, QDnsLookup::ResolverError, {},
         ResolverOutcome::TimedOut},
        {cancellable::WaitResult::Completed, QDnsLookup::NotFoundError, {},
         ResolverOutcome::NoRecord},
        {cancellable::WaitResult::Completed, QDnsLookup::NoError, {},
         ResolverOutcome::NoRecord},
        {cancellable::WaitResult::Completed, QDnsLookup::InvalidReplyError, {},
         ResolverOutcome::InvalidResponse},
        {cancellable::WaitResult::Failed, QDnsLookup::ResolverError, {},
         ResolverOutcome::BackendUnavailable},
    };
    for (const PtrCase &test : ptrCases) {
        HostnameResolver resolver(
            {},
            [test](const QString &, int, const auto &) {
                return ptrResult(test.wait, test.error, test.hostnames);
            },
            noRecordSystem,
            noRecordMdns);
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.30", {}, {}, 1, TargetBudget(5000), {});
        REQUIRE(requiredOutcomeFor(result, ResolverKind::DnsPtr) == test.expected);
    }

    struct SystemCase {
        cancellable::WaitResult wait;
        QHostInfo::HostInfoError error;
        QString hostname;
        ResolverOutcome expected;
    };
    const QList<SystemCase> systemCases = {
        {cancellable::WaitResult::Cancelled, QHostInfo::UnknownError, {},
         ResolverOutcome::Cancelled},
        {cancellable::WaitResult::TimedOut, QHostInfo::UnknownError, {},
         ResolverOutcome::TimedOut},
        {cancellable::WaitResult::Completed, QHostInfo::HostNotFound, {},
         ResolverOutcome::NoRecord},
        {cancellable::WaitResult::Completed, QHostInfo::NoError, {},
         ResolverOutcome::NoRecord},
        {cancellable::WaitResult::Failed, QHostInfo::UnknownError, {},
         ResolverOutcome::BackendUnavailable},
    };
    for (const SystemCase &test : systemCases) {
        HostnameResolver resolver(
            {},
            [](const QString &, int, const auto &) {
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [test](const QString &, int, const auto &) {
                return systemResult(test.wait, test.error, test.hostname);
            },
            noRecordMdns);
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.40", {}, {}, 1, TargetBudget(5000), {});
        REQUIRE(requiredOutcomeFor(result, ResolverKind::System) == test.expected);
    }

    const QList<QPair<MdnsLookupStatus, ResolverOutcome>> mdnsCases = {
        {MdnsLookupStatus::Resolved, ResolverOutcome::Resolved},
        {MdnsLookupStatus::NoRecord, ResolverOutcome::NoRecord},
        {MdnsLookupStatus::TimedOut, ResolverOutcome::TimedOut},
        {MdnsLookupStatus::Cancelled, ResolverOutcome::Cancelled},
        {MdnsLookupStatus::BackendUnavailable, ResolverOutcome::BackendUnavailable},
        {MdnsLookupStatus::DaemonUnavailable, ResolverOutcome::DaemonUnavailable},
        {MdnsLookupStatus::MulticastUnavailable, ResolverOutcome::MulticastUnavailable},
        {MdnsLookupStatus::InvalidResponse, ResolverOutcome::InvalidResponse},
    };
    for (const auto &test : mdnsCases) {
        HostnameResolver resolver(
            {},
            [](const QString &, int, const auto &) {
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            noRecordSystem,
            [test](const QString &, int) {
                return MdnsLookupResult{test.first,
                                        test.first == MdnsLookupStatus::Resolved
                                            ? "fixture.local" : QString{}};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.50", {}, {}, 1, TargetBudget(5000), {});
        REQUIRE(requiredOutcomeFor(result, ResolverKind::Mdns) == test.second);
    }

    {
        const QList<HostnameTimeoutProfile> expectedProfiles = {
            {400, 400, 700},
            {750, 750, 1250},
            {1250, 1000, 1750},
            {1500, 1500, 2000},
        };
        for (int accuracy = 0; accuracy < expectedProfiles.size(); ++accuracy) {
            QList<int> timeouts;
            HostnameResolver resolver(
                {},
                [&timeouts](const QString &, int timeout, const auto &) {
                    timeouts.append(timeout);
                    return ptrResult(cancellable::WaitResult::Completed,
                                     QDnsLookup::NotFoundError);
                },
                [&timeouts](const QString &, int timeout, const auto &) {
                    timeouts.append(timeout);
                    return systemResult(cancellable::WaitResult::Completed,
                                        QHostInfo::HostNotFound);
                },
                [&timeouts](const QString &, int timeout) {
                    timeouts.append(timeout);
                    return MdnsLookupResult{MdnsLookupStatus::NoRecord, {}};
                });
            resolver.resolve("192.0.2.55", {}, {}, accuracy,
                             TargetBudget(10000), {});
            const HostnameTimeoutProfile expected = expectedProfiles.at(accuracy);
            REQUIRE(timeouts == QList<int>({expected.ptrMs,
                                            expected.systemMs,
                                            expected.mdnsMs}));
        }
    }

    {
        const auto cancellation = std::make_shared<std::atomic_bool>(true);
        int ptrCalls = 0;
        int laterCalls = 0;
        HostnameResolver resolver(
            {},
            [&ptrCalls](const QString &, int, const auto &) {
                ++ptrCalls;
                return ptrResult(cancellable::WaitResult::Cancelled,
                                 QDnsLookup::ResolverError);
            },
            [&laterCalls](const QString &, int, const auto &) {
                ++laterCalls;
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::HostNotFound);
            },
            [&laterCalls](const QString &, int) {
                ++laterCalls;
                return MdnsLookupResult{};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.56", {}, {}, 1, TargetBudget(5000), cancellation);
        REQUIRE(ptrCalls == 1);
        REQUIRE(laterCalls == 0);
        REQUIRE(result.resolverEvents == QList<ResolverEvent>({
            {ResolverKind::DnsPtr, ResolverOutcome::Cancelled}}));
    }

    {
        const auto cancellation = std::make_shared<std::atomic_bool>(false);
        int laterCalls = 0;
        HostnameResolver resolver(
            {},
            [cancellation](const QString &, int, const auto &) {
                cancellation->store(true);
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [&laterCalls](const QString &, int, const auto &) {
                ++laterCalls;
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::HostNotFound);
            },
            [&laterCalls](const QString &, int) {
                ++laterCalls;
                return MdnsLookupResult{};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.60", {}, {}, 1, TargetBudget(5000), cancellation);
        REQUIRE(laterCalls == 0);
        REQUIRE(result.resolverEvents.size() == 1);
    }

    {
        using Clock = TargetBudget::Clock;
        auto now = Clock::now();
        int laterCalls = 0;
        TargetBudget budget(100, [&now]() { return now; });
        HostnameResolver resolver(
            {},
            [&now](const QString &, int timeout, const auto &) {
                REQUIRE(timeout == 100);
                now += std::chrono::milliseconds(100);
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [&laterCalls](const QString &, int, const auto &) {
                ++laterCalls;
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::HostNotFound);
            },
            noRecordMdns);
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.70", {}, {}, 3, budget, {});
        REQUIRE(laterCalls == 0);
        REQUIRE(result.resolverEvents.size() == 1);
    }

    {
        int mdnsCalls = 0;
        HostnameResolver resolver(
            {},
            [](const QString &, int, const auto &) {
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [](const QString &, int, const auto &) {
                return systemResult(cancellable::WaitResult::Cancelled,
                                    QHostInfo::UnknownError);
            },
            [&mdnsCalls](const QString &, int) {
                ++mdnsCalls;
                return MdnsLookupResult{};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.80", {}, {}, 1, TargetBudget(5000), {});
        REQUIRE(mdnsCalls == 0);
        REQUIRE(result.resolverEvents == QList<ResolverEvent>({
            {ResolverKind::DnsPtr, ResolverOutcome::NoRecord},
            {ResolverKind::System, ResolverOutcome::Cancelled}}));
    }

    {
        const auto cancellation = std::make_shared<std::atomic_bool>(false);
        int mdnsCalls = 0;
        HostnameResolver resolver(
            {},
            [](const QString &, int, const auto &) {
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [cancellation](const QString &, int, const auto &) {
                cancellation->store(true);
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::HostNotFound);
            },
            [&mdnsCalls](const QString &, int) {
                ++mdnsCalls;
                return MdnsLookupResult{};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.90", {}, {}, 1, TargetBudget(5000), cancellation);
        REQUIRE(mdnsCalls == 0);
        REQUIRE(result.resolverEvents.size() == 2);
    }

    {
        using Clock = TargetBudget::Clock;
        auto now = Clock::now();
        int mdnsCalls = 0;
        TargetBudget budget(200, [&now]() { return now; });
        HostnameResolver resolver(
            {},
            [](const QString &, int timeout, const auto &) {
                REQUIRE(timeout == 200);
                return ptrResult(cancellable::WaitResult::Completed,
                                 QDnsLookup::NotFoundError);
            },
            [&now](const QString &, int timeout, const auto &) {
                REQUIRE(timeout == 200);
                now += std::chrono::milliseconds(200);
                return systemResult(cancellable::WaitResult::Completed,
                                    QHostInfo::HostNotFound);
            },
            [&mdnsCalls](const QString &, int) {
                ++mdnsCalls;
                return MdnsLookupResult{};
            });
        const HostnameScanResolution result = resolver.resolve(
            "192.0.2.100", {}, {}, 1, budget, {});
        REQUIRE(mdnsCalls == 0);
        REQUIRE(result.resolverEvents.size() == 2);
    }

    return EXIT_SUCCESS;
}
