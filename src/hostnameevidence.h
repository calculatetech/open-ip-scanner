#pragma once

#include <QString>

enum class HostnameQuality : int {
    Unknown = 0,
    Preliminary = 100,
    SystemResolver = 300,
    AvahiMdns = 400
};

struct HostnameEvidence {
    QString hostname;
    HostnameQuality quality = HostnameQuality::Unknown;
};

HostnameEvidence preferredHostname(const HostnameEvidence &current,
                                   const HostnameEvidence &candidate);
