#pragma once

#include "neighborentry.h"
#include "scanbudget.h"

#include <atomic>
#include <functional>
#include <memory>

class LinuxNeighborProbe {
public:
    using Cancellation = std::shared_ptr<std::atomic_bool>;
    using LookupOverride = std::function<NeighborObservation(
        const QString &,
        const QString &,
        const TargetBudget &,
        const Cancellation &)>;

    explicit LinuxNeighborProbe(LookupOverride lookupOverride = {});

    // One probe instance may serve concurrent scan workers. Injected lookup
    // functions must therefore keep any shared fixture state synchronized.
    NeighborObservation lookup(
        const QString &ip,
        const QString &interfaceName,
        const TargetBudget &budget,
        const Cancellation &cancellation) const;
    NeighborObservation confirmLiveness(
        const NeighborObservation &initial,
        const QString &ip,
        const QString &interfaceName,
        int confirmationTimeoutMs,
        const TargetBudget &budget,
        const Cancellation &cancellation) const;

private:
    NeighborObservation lookupProduction(
        const QString &ip,
        const QString &interfaceName,
        const TargetBudget &budget,
        const Cancellation &cancellation) const;

    LookupOverride lookupOverride_;
};
