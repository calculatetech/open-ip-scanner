#pragma once

#include <QByteArray>
#include <QString>

enum class ServiceEvidenceLevel {
    OpenPort,
    VerifiedProtocol
};

struct ServiceHit {
    QString id;
    QString label;
    int port = 0;
    bool isWeb = false;
    ServiceEvidenceLevel evidence = ServiceEvidenceLevel::OpenPort;
};

bool responseVerifiesService(const QString &serviceId, const QByteArray &response);
int serviceProbeWaitUnits(const QString &serviceId);
QString serviceEvidenceText(const QString &label,
                            int port,
                            ServiceEvidenceLevel evidence);
