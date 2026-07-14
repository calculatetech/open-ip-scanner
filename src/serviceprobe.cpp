#include "serviceprobe.h"

#include "cancellablewait.h"

#include <QElapsedTimer>
#include <QHostAddress>
#include <QSslError>
#include <QSslSocket>
#include <QTcpSocket>

#include <algorithm>
#include <utility>

ServiceProbe::ServiceProbe(QList<ServiceDefinition> catalog)
    : definitions_(std::move(catalog))
{
}

QList<ServiceDefinition> ServiceProbe::definitions()
{
    return {
        {"http", "HTTP", 80, true, true},
        {"https", "HTTPS", 443, true, true},
        {"ssh", "SSH", 22, true, false},
        {"rdp", "RDP", 3389, true, false},
        {"ftp", "FTP", 21, false, false},
        {"telnet", "Telnet", 23, false, false},
        {"smb", "SMB", 445, false, false},
        {"smtp25", "SMTP", 25, false, false},
        {"smtps465", "SMTPS", 465, false, false},
        {"smtp587", "SMTP-STARTTLS", 587, false, false}
    };
}

QList<ServiceHit> ServiceProbe::scan(
    const QString &ip,
    const QString &localBindIp,
    const QSet<QString> &enabledServiceIds,
    int attempts,
    int timeoutMs,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    QList<ServiceHit> hits;
    for (const ServiceDefinition &definition : definitions_) {
        if (!enabledServiceIds.contains(definition.id)) {
            continue;
        }
        if (cancellable::isCancelled(cancellation) || budget.expired()) {
            break;
        }
        const ServiceProbeResult result = probe(
            definition, ip, localBindIp, attempts, timeoutMs, budget, cancellation);
        if (result.open) {
            hits.append({definition.id,
                         definition.label,
                         definition.port,
                         definition.isWeb,
                         result.evidence});
        }
    }
    return hits;
}

ServiceProbeResult ServiceProbe::probe(
    const ServiceDefinition &definition,
    const QString &ip,
    const QString &localBindIp,
    int attempts,
    int timeoutMs,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    if (definition.id == "https" || definition.id == "smtps465") {
        return probeTls(
            definition, ip, localBindIp, attempts, timeoutMs, budget, cancellation);
    }
    return probePlain(
        definition, ip, localBindIp, attempts, timeoutMs, budget, cancellation);
}

ServiceProbeResult ServiceProbe::probePlain(
    const ServiceDefinition &definition,
    const QString &ip,
    const QString &localBindIp,
    int attempts,
    int timeoutMs,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    bool sawOpenPort = false;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (cancellable::isCancelled(cancellation) || budget.expired()) {
            break;
        }
        QTcpSocket socket;
        if (!localBindIp.isEmpty()) {
            QHostAddress bindAddress;
            if (!bindAddress.setAddress(localBindIp) ||
                bindAddress.protocol() != QAbstractSocket::IPv4Protocol ||
                !socket.bind(bindAddress, 0)) {
                return {};
            }
        }
        socket.connectToHost(ip, static_cast<quint16>(definition.port));
        if (cancellable::waitForConnected(
                socket, budget.clampTimeout(timeoutMs), cancellation) !=
            cancellable::WaitResult::Completed) {
            continue;
        }
        sawOpenPort = true;

        const bool expectsResponse = definition.id == "http" ||
                                     definition.id == "ssh" ||
                                     definition.id == "ftp" ||
                                     definition.id == "smtp25" ||
                                     definition.id == "smtp587";
        if (!expectsResponse) {
            socket.abort();
            return {true, ServiceEvidenceLevel::OpenPort};
        }
        QByteArray request;
        if (definition.id == "http") {
            request = "HEAD / HTTP/1.0\r\nHost: " + ip.toUtf8() + "\r\n\r\n";
        }
        if (!request.isEmpty()) {
            socket.write(request);
            if (cancellable::waitForBytesWritten(
                    socket, budget.clampTimeout(timeoutMs), cancellation) !=
                cancellable::WaitResult::Completed) {
                socket.abort();
                continue;
            }
        }
        QByteArray response = readResponse(socket, budget, cancellation, timeoutMs);
        bool verified = false;
        if (definition.id == "smtp587") {
            if (responseVerifiesService("smtp25", response)) {
                socket.write("EHLO open-ip-scanner\r\n");
                if (cancellable::waitForBytesWritten(
                        socket, budget.clampTimeout(timeoutMs), cancellation) ==
                    cancellable::WaitResult::Completed) {
                    response = readResponse(
                        socket, budget, cancellation, timeoutMs, true);
                    verified = responseVerifiesService(definition.id, response);
                }
            }
        } else {
            verified = responseVerifiesService(definition.id, response);
        }
        socket.abort();
        if (verified) {
            return {true, ServiceEvidenceLevel::VerifiedProtocol};
        }
    }
    return {sawOpenPort, ServiceEvidenceLevel::OpenPort};
}

ServiceProbeResult ServiceProbe::probeTls(
    const ServiceDefinition &definition,
    const QString &ip,
    const QString &localBindIp,
    int attempts,
    int timeoutMs,
    const TargetBudget &budget,
    const Cancellation &cancellation) const
{
    bool sawOpenPort = false;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (cancellable::isCancelled(cancellation) || budget.expired()) {
            break;
        }
        QSslSocket socket;
        bool tcpConnected = false;
        QObject::connect(&socket, &QSslSocket::connected, &socket, [&tcpConnected]() {
            tcpConnected = true;
        });
        QObject::connect(&socket,
                         &QSslSocket::sslErrors,
                         &socket,
                         [&socket](const QList<QSslError> &) { socket.ignoreSslErrors(); });
        if (!localBindIp.isEmpty()) {
            QHostAddress bindAddress;
            if (!bindAddress.setAddress(localBindIp) ||
                bindAddress.protocol() != QAbstractSocket::IPv4Protocol ||
                !socket.bind(bindAddress, 0)) {
                return {};
            }
        }
        socket.connectToHostEncrypted(ip, static_cast<quint16>(definition.port));
        const int boundedTimeoutMs = budget.clampTimeout(timeoutMs);
        QElapsedTimer elapsed;
        elapsed.start();
        while (!socket.isEncrypted() && elapsed.elapsed() < boundedTimeoutMs &&
               !cancellable::isCancelled(cancellation) && !budget.expired()) {
            const int remaining = boundedTimeoutMs -
                                  static_cast<int>(elapsed.elapsed());
            socket.waitForEncrypted(std::min(25, remaining));
            if (socket.state() == QAbstractSocket::UnconnectedState &&
                socket.error() != QAbstractSocket::UnknownSocketError) {
                break;
            }
        }
        sawOpenPort = sawOpenPort || tcpConnected;
        if (socket.isEncrypted()) {
            bool verified = false;
            if (definition.id == "https") {
                socket.write("HEAD / HTTP/1.0\r\nHost: " + ip.toUtf8() + "\r\n\r\n");
                if (cancellable::waitForBytesWritten(
                        socket, budget.clampTimeout(timeoutMs), cancellation) ==
                    cancellable::WaitResult::Completed) {
                    verified = responseVerifiesService(
                        definition.id,
                        readResponse(socket, budget, cancellation, timeoutMs));
                }
            } else if (definition.id == "smtps465") {
                verified = responseVerifiesService(
                    definition.id,
                    readResponse(socket, budget, cancellation, timeoutMs));
            }
            if (verified) {
                socket.abort();
                return {true, ServiceEvidenceLevel::VerifiedProtocol};
            }
        }
        socket.abort();
    }
    return {sawOpenPort, ServiceEvidenceLevel::OpenPort};
}

QByteArray ServiceProbe::readResponse(
    QTcpSocket &socket,
    const TargetBudget &budget,
    const Cancellation &cancellation,
    int timeoutMs,
    bool smtpMultiline) const
{
    constexpr int kMaxResponseBytes = 4096;
    QByteArray response;
    QElapsedTimer elapsed;
    elapsed.start();
    while (response.size() < kMaxResponseBytes && elapsed.elapsed() < timeoutMs &&
           !cancellable::isCancelled(cancellation) && !budget.expired()) {
        if (socket.bytesAvailable() > 0) {
            response.append(socket.read(kMaxResponseBytes - response.size()));
            const QList<QByteArray> lines = response.split('\n');
            const bool hasCompleteLine = lines.size() > 1;
            const QByteArray first = hasCompleteLine ? lines.first().trimmed()
                                                     : QByteArray();
            bool responseComplete = hasCompleteLine && !smtpMultiline;
            if (smtpMultiline && hasCompleteLine) {
                if (!first.startsWith("250-") && !first.startsWith("250 ")) {
                    responseComplete = true;
                } else {
                    for (int lineIndex = 0; lineIndex + 1 < lines.size(); ++lineIndex) {
                        if (lines.at(lineIndex).trimmed().startsWith("250 ")) {
                            responseComplete = true;
                            break;
                        }
                    }
                }
            }
            if (responseComplete) {
                break;
            }
            continue;
        }
        const int remaining = timeoutMs - static_cast<int>(elapsed.elapsed());
        if (cancellable::waitForReadyRead(
                socket, budget.clampTimeout(remaining), cancellation) !=
            cancellable::WaitResult::Completed) {
            if (socket.bytesAvailable() > 0) {
                response.append(socket.read(kMaxResponseBytes - response.size()));
            }
            break;
        }
    }
    return response;
}
