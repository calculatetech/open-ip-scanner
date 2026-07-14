#pragma once

#include "scanbudget.h"

#include <QHostAddress>

#include <atomic>
#include <memory>

class LinuxPingProbe {
public:
    using Cancellation = std::shared_ptr<std::atomic_bool>;

    bool ping(const QHostAddress &address,
              const QString &interfaceName,
              int attempts,
              int timeoutSeconds,
              const TargetBudget &budget,
              const Cancellation &cancellation) const;
};
