#pragma once

#include <QByteArray>
#include <QString>

enum class ServiceEvidenceLevel {
    OpenPort,
    VerifiedProtocol
};

bool responseVerifiesService(const QString &serviceId, const QByteArray &response);
QString serviceEvidenceText(const QString &label,
                            int port,
                            ServiceEvidenceLevel evidence);
