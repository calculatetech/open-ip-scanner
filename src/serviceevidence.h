#pragma once

#include <QByteArray>
#include <QString>

enum class ServiceEvidenceLevel {
    OpenPort,
    VerifiedProtocol
};

bool responseVerifiesService(const QString &serviceId, const QByteArray &response);
int serviceProbeWaitUnits(const QString &serviceId);
QString serviceEvidenceText(const QString &label,
                            int port,
                            ServiceEvidenceLevel evidence);
