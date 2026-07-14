#pragma once

#include "scanbudget.h"
#include "serviceevidence.h"

#include <QList>
#include <QSet>
#include <QString>

#include <atomic>
#include <memory>

class QTcpSocket;

struct ServiceDefinition {
    QString id;
    QString label;
    int port = 0;
    bool defaultEnabled = false;
    bool isWeb = false;
};

struct ServiceProbeResult {
    bool open = false;
    ServiceEvidenceLevel evidence = ServiceEvidenceLevel::OpenPort;
};

class ServiceProbe {
public:
    using Cancellation = std::shared_ptr<std::atomic_bool>;

    static QList<ServiceDefinition> definitions();
    explicit ServiceProbe(QList<ServiceDefinition> catalog = definitions());

    QList<ServiceHit> scan(const QString &ip,
                           const QString &localBindIp,
                           const QSet<QString> &enabledServiceIds,
                           int attempts,
                           int timeoutMs,
                           const TargetBudget &budget,
                           const Cancellation &cancellation) const;

    ServiceProbeResult probe(const ServiceDefinition &definition,
                             const QString &ip,
                             const QString &localBindIp,
                             int attempts,
                             int timeoutMs,
                             const TargetBudget &budget,
                             const Cancellation &cancellation) const;

private:
    ServiceProbeResult probePlain(const ServiceDefinition &definition,
                                  const QString &ip,
                                  const QString &localBindIp,
                                  int attempts,
                                  int timeoutMs,
                                  const TargetBudget &budget,
                                  const Cancellation &cancellation) const;
    ServiceProbeResult probeTls(const ServiceDefinition &definition,
                                const QString &ip,
                                const QString &localBindIp,
                                int attempts,
                                int timeoutMs,
                                const TargetBudget &budget,
                                const Cancellation &cancellation) const;
    QByteArray readResponse(QTcpSocket &socket,
                            const TargetBudget &budget,
                            const Cancellation &cancellation,
                            int timeoutMs,
                            bool smtpMultiline = false) const;

    QList<ServiceDefinition> definitions_;
};
