#include "hostnameevidence.h"

namespace {

bool isUsable(const HostnameEvidence &evidence)
{
    const QString hostname = evidence.hostname.trimmed();
    return !hostname.isEmpty() && hostname != "Unknown";
}

} // namespace

HostnameEvidence preferredHostname(const HostnameEvidence &current,
                                   const HostnameEvidence &candidate)
{
    if (!isUsable(candidate)) {
        return current;
    }
    if (!isUsable(current) || static_cast<int>(candidate.quality) >
                                  static_cast<int>(current.quality)) {
        HostnameEvidence normalized = candidate;
        normalized.hostname = normalized.hostname.trimmed();
        return normalized;
    }
    return current;
}
