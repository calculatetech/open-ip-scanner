#pragma once

#include "cancellablewait.h"
#include "hostnameevidence.h"
#include "mdnsresolver.h"
#include "scanbudget.h"

#include <QHostInfo>

#include <functional>
#include <memory>

struct SystemHostnameLookupResult {
    cancellable::WaitResult waitResult = cancellable::WaitResult::Failed;
    QHostInfo hostInfo;
};

class HostnameResolver {
public:
    using Cancellation = cancellable::Flag;
    using PtrLookup = std::function<cancellable::DnsPtrLookupResult(
        const QString &, int, const Cancellation &)>;
    using SystemLookup = std::function<SystemHostnameLookupResult(
        const QString &, int, const Cancellation &)>;
    using MdnsLookup = std::function<MdnsLookupResult(const QString &, int)>;

    explicit HostnameResolver(std::shared_ptr<ScanMdnsResolver> mdnsResolver,
                              PtrLookup ptrLookup = {},
                              SystemLookup systemLookup = {},
                              MdnsLookup mdnsLookup = {});

    // One resolver may serve concurrent scan workers. Injected functions must
    // synchronize any mutable fixture state they share.
    HostnameScanResolution resolve(
        const QString &ip,
        const HostnameEvidence &preliminary,
        const QStringList &adapterDnsSuffixes,
        int accuracyLevel,
        const TargetBudget &budget,
        const Cancellation &cancellation) const;

private:
    std::shared_ptr<ScanMdnsResolver> mdnsResolver_;
    PtrLookup ptrLookup_;
    SystemLookup systemLookup_;
    MdnsLookup mdnsLookup_;
};
