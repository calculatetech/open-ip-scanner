#include "serviceprobe.h"
#include "diagnostics.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QHostAddress>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>
#include <QTimer>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

#ifdef Q_OS_LINUX
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

constexpr char kCertificate[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUbgv9ST5xFwllWuQUe5KMr4U35d0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcxNDIxNTgzMFoXDTI2MDcx
NjIxNTgzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAoNuvphRU+QvwirEg9K+NEfX561yPVT07i8NPlSwt8hfN
vQFmE8HDOSw/4PMSAjtbXneGefBMyRv1c2j4b3u2hdhdUw9p1u4Z01a3bwhhP3Zm
MgSAYhm2bj8O2bv/JdjSCdmsHSqt76x8yRItnk5+zY8sKzr78iEplgKS89+UOlhx
kRVKJb9n0zH1FZ+W7tUCwUh/DfsSi4ayymKzUtKm8xaggLll2vKjaZeZPlj0fk3y
2fC4STQh8P2W76xbwL7qL0K4620k9CPUyL+2l/GTwgm1EXUpGdycw4zqmafvnTtP
ugeXvsQk4Q45F3AG5Vb2EuzqI7y4YYZLXIXMCraqPwIDAQABo1MwUTAdBgNVHQ4E
FgQUSPON9kJ3yTb+ql+mbz4KqhYsEXYwHwYDVR0jBBgwFoAUSPON9kJ3yTb+ql+m
bz4KqhYsEXYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdBoo
0dhNrLu/HrQNox3UlD+ch/EcRxPmc6qL9J+O9okL9Yqv0WYsK5zEQzEEURCKqqCk
STHrWgR3ijqepZrVjHopCuDoIr+wRFPfJ8o/5u7OssdQsp0DBW9gfag4Ec2CAtGf
cNTWqOB9v/h6M2HSabhNkqbiGstaOcwPY9KfeNkMJKxrIP43FLzTU8tHUDt9WIHE
2dj7HGFmuGMFRp7F/AJ49wUbs08W8N4sTJpHi/jQFQAaW8dhsZ6wx/AnQtrWWgpt
1ywnctLRt6CBRfUHdEXBpRr3OD6KKNYLW/2brWeaynHSPZ0C9135XN/0D9LgsM9t
gpIgjsnF+ZDwXeDX0g==
-----END CERTIFICATE-----)PEM";

constexpr char kPrivateKey[] = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCg26+mFFT5C/CK
sSD0r40R9fnrXI9VPTuLw0+VLC3yF829AWYTwcM5LD/g8xICO1ted4Z58EzJG/Vz
aPhve7aF2F1TD2nW7hnTVrdvCGE/dmYyBIBiGbZuPw7Zu/8l2NIJ2awdKq3vrHzJ
Ei2eTn7NjywrOvvyISmWApLz35Q6WHGRFUolv2fTMfUVn5bu1QLBSH8N+xKLhrLK
YrNS0qbzFqCAuWXa8qNpl5k+WPR+TfLZ8LhJNCHw/ZbvrFvAvuovQrjrbST0I9TI
v7aX8ZPCCbURdSkZ3JzDjOqZp++dO0+6B5e+xCThDjkXcAblVvYS7OojvLhhhktc
hcwKtqo/AgMBAAECggEAN3dI+9Vq721Ehi5JlNWrqRPOF3AVJGk2zRyNpnxTY3T9
xjxjPFDFxkMRy7lE7mwVN1+ziPxpHbd8TU1WzOo1p7VRiMB52FjFou/11F1pWv6y
gnC27By9oQoxTrbaZex7kFX0WSJMU6aAaLzR6hJa+vpxWn6+PWFd+5Hrphfj/rHP
+UGYc8IfyeQs6RidbXUqOAr1qgdWr9MrTcXvJFQHpBEuJXPEHHmr0X89b6zEQDeT
g6FK7i2wKbijV6oPhwUZYXcWACjqiMLMWta/7SZEMJfYSJAslyNypZqe3U9OBxpL
5u5XcYEOblR5ZyWT5JQqsM8mgWHsZT8qNhHDlEiWMQKBgQDevfb0475nRAx9JeVN
L0cq27vgdLPWt4abMA/HR+bLrc+yZWZjUHyJBAI36SpamqCVTJ+Kvlgmse3yc9As
nEgF/ToqcQhO+D7RJCSBISdnq0e3Tf1MRHeNgqFl44oZ6xG86Da7uI0Q3b9EFWW2
l4yLtlEFlmxHhGyBk9HPGC4z0wKBgQC44El5m1Vb3b5TSS6xcqwvP3YIsI7jqDTN
TN5jK2XjBKZ+j05HktjLCgmq2Au7qNynQ4mE6c6nwy/ZOcEM5Uo662gbTJJBSmKz
sOV995eE2UoO+mfr+eUBYCwQAbKs3RfvYbT28UB7RGn9X2XtIgoih0YNvHVUKrSb
2DNedkfoZQKBgHX0v508Jg7luH9l3CKd0OBfcQUSiFJC6mOwdgqghxaBuyXMEQaz
DuA4YTxem/FTRYsLAsoktuX2//2PW0TkljelvHHRXgcD67AxpatEdWuvBtGJ2YPU
FkO4U+RzNSU4mTIi/yk2OG4gIDPb6PtjEijCqfF9kWXmONf+AfPb6EvFAoGBALbW
4vPI4xeS6ztVYj+OqKmluqeHbhnK7kWoYzxy3DY0EDGUqxdwLMZJbBwxxRDYRTmL
OsNftMkH6heM3ddSISK6VGDDTtYRqiIKrjzxlEGH4I2FqyefIpREt+8wrrP1iUlv
OVkMafg/Rg+WvKhUhO93F5pYKzWNcse6f7tJgX5dAoGAUGQ0lKn6rGiwAnw1QeaS
ui3LU/TqDMsNdEhaMEP99DWT6xJE1krPDGpYZGDOI0lbD6WQ/VZ59Kc4eLO+mDbb
Zh4TUWAd/VZ3p7Iy+kJXu9smO8FpxHXlAYOe6yrx8j1VK2uuZtDC53USlUJyEfD9
6XrCt/xPpFNQmcTpai9yabM=
-----END PRIVATE KEY-----)PEM";

#ifdef Q_OS_LINUX
std::pair<int, int> createListener()
{
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return {-1, 0};
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener,
               reinterpret_cast<const sockaddr *>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener, 1) != 0) {
        ::close(listener);
        return {-1, 0};
    }
    socklen_t length = sizeof(address);
    if (::getsockname(listener,
                      reinterpret_cast<sockaddr *>(&address),
                      &length) != 0) {
        ::close(listener);
        return {-1, 0};
    }
    return {listener, ntohs(address.sin_port)};
}

ServiceProbeResult probeEndpoint(const QString &serviceId,
                                 const QByteArray &response)
{
    const auto [listener, port] = createListener();
    if (listener < 0) {
        return {};
    }
    std::thread server([listener, response]() {
        pollfd descriptor{listener, POLLIN, 0};
        if (::poll(&descriptor, 1, 2000) > 0) {
            const int client = ::accept(listener, nullptr, nullptr);
            if (client >= 0) {
                if (!response.isEmpty()) {
                    ::send(client,
                           response.constData(),
                           static_cast<size_t>(response.size()),
                           MSG_NOSIGNAL);
                }
                ::shutdown(client, SHUT_RDWR);
                ::close(client);
            }
        }
        ::close(listener);
    });
    ServiceDefinition definition{serviceId, serviceId, port, false, false};
    const ServiceProbeResult result = ServiceProbe().probe(
        definition, "127.0.0.1", {}, 1, 500, TargetBudget(1500), {});
    server.join();
    return result;
}

ServiceProbeResult probeTlsEndpoint(const QString &serviceId,
                                    const QByteArray &response)
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
    const QSslCertificate certificate(QByteArray(kCertificate), QSsl::Pem);
    const QSslKey privateKey(QByteArray(kPrivateKey), QSsl::Rsa, QSsl::Pem);
    if (certificate.isNull() || privateKey.isNull()) {
        return {};
    }
    configuration.setLocalCertificate(certificate);
    configuration.setPrivateKey(privateKey);
    configuration.setPeerVerifyMode(QSslSocket::VerifyNone);

    QSslServer server;
    server.setSslConfiguration(configuration);
    server.setHandshakeTimeout(1500);
    if (!server.listen(QHostAddress::LocalHost, 0)) {
        return {};
    }
    QObject::connect(&server,
                     &QTcpServer::pendingConnectionAvailable,
                     &server,
                     [&](auto) {
        auto *socket = server.nextPendingConnection();
        if (socket == nullptr) {
            return;
        }
        if (serviceId == "https") {
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket, response]() {
                socket->readAll();
                socket->write(response);
                socket->flush();
            });
        } else {
            socket->write(response);
            socket->flush();
        }
    });

    const ServiceDefinition definition{
        serviceId,
        serviceId,
        static_cast<int>(server.serverPort()),
        false,
        serviceId == "https"};
    const ServiceProbe probe;
    std::promise<ServiceProbeResult> resultPromise;
    std::future<ServiceProbeResult> resultFuture = resultPromise.get_future();
    std::thread client([&]() {
        resultPromise.set_value(probe.probe(
            definition, "127.0.0.1", "127.0.0.1", 1, 1000, TargetBudget(2000), {}));
    });
    QEventLoop loop;
    QTimer poll;
    poll.setInterval(5);
    QObject::connect(&poll, &QTimer::timeout, &loop, [&]() {
        if (resultFuture.wait_for(std::chrono::milliseconds(0)) ==
            std::future_status::ready) {
            loop.quit();
        }
    });
    QTimer::singleShot(2500, &loop, &QEventLoop::quit);
    poll.start();
    loop.exec();
    client.join();
    server.close();
    return resultFuture.get();
}

struct PlainEndpoint {
    int listener = -1;
    int port = 0;
    std::thread server;
};

PlainEndpoint startPlainEndpoint(
    const QByteArray &response,
    int holdMs = 0,
    const std::shared_ptr<std::atomic_bool> &cancelOnAccept = {})
{
    const auto [listener, port] = createListener();
    PlainEndpoint endpoint;
    endpoint.listener = listener;
    endpoint.port = port;
    if (listener < 0) {
        return endpoint;
    }
    endpoint.server = std::thread([listener, response, holdMs, cancelOnAccept]() {
        pollfd descriptor{listener, POLLIN, 0};
        if (::poll(&descriptor, 1, 2000) > 0) {
            const int client = ::accept(listener, nullptr, nullptr);
            if (client >= 0) {
                if (cancelOnAccept) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(30));
                    cancelOnAccept->store(true);
                }
                if (holdMs > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(holdMs));
                }
                if (!response.isEmpty()) {
                    ::send(client,
                           response.constData(),
                           static_cast<size_t>(response.size()),
                           MSG_NOSIGNAL);
                }
                ::shutdown(client, SHUT_RDWR);
                ::close(client);
            }
        }
        ::close(listener);
    });
    return endpoint;
}

void joinEndpoint(PlainEndpoint &endpoint)
{
    if (endpoint.server.joinable()) {
        endpoint.server.join();
    }
}
#endif

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const bool runTlsFixtures = !application.arguments().contains("--skip-tls");
    const QList<ServiceDefinition> definitions = ServiceProbe::definitions();
    const QStringList expectedIds = {
        "http", "https", "ssh", "rdp", "ftp",
        "telnet", "smb", "smtp25", "smtps465", "smtp587"};
    QStringList actualIds;
    for (const ServiceDefinition &definition : definitions) {
        actualIds.append(definition.id);
    }
    if (actualIds != expectedIds || definitions.at(0).port != 80 ||
        definitions.at(1).port != 443 || definitions.at(2).port != 22 ||
        !definitions.at(0).defaultEnabled || !definitions.at(0).isWeb ||
        definitions.at(4).defaultEnabled) {
        std::cerr << "service catalog contract failed\n";
        return 1;
    }

#ifdef Q_OS_LINUX
    const ServiceProbeResult verifiedSsh = probeEndpoint(
        "ssh", "SSH-2.0-window-free-fixture\r\n");
    const ServiceProbeResult openTelnet = probeEndpoint("telnet", {});
    if (!verifiedSsh.open ||
        verifiedSsh.evidence != ServiceEvidenceLevel::VerifiedProtocol ||
        !openTelnet.open ||
        openTelnet.evidence != ServiceEvidenceLevel::OpenPort) {
        std::cerr << "service evidence contract failed\n";
        return 1;
    }

    if (runTlsFixtures) {
        const ServiceProbeResult verifiedHttps = probeTlsEndpoint(
            "https", "HTTP/1.1 204 No Content\r\n\r\n");
        const ServiceProbeResult verifiedSmtps = probeTlsEndpoint(
            "smtps465", "220 fixture ESMTP ready\r\n");
        if (!verifiedHttps.open ||
            verifiedHttps.evidence != ServiceEvidenceLevel::VerifiedProtocol ||
            !verifiedSmtps.open ||
            verifiedSmtps.evidence != ServiceEvidenceLevel::VerifiedProtocol) {
            std::cerr << "TLS verification contract failed: https="
                      << verifiedHttps.open << "/"
                      << static_cast<int>(verifiedHttps.evidence) << " smtps="
                      << verifiedSmtps.open << "/"
                      << static_cast<int>(verifiedSmtps.evidence) << "\n";
            return 1;
        }

        PlainEndpoint failedHandshake = startPlainEndpoint({}, 300);
        const ServiceDefinition https{
            "https", "HTTPS", failedHandshake.port, false, true};
        const ServiceProbeResult tlsOpenOnly = ServiceProbe().probe(
            https, "127.0.0.1", {}, 1, 150, TargetBudget(800), {});
        joinEndpoint(failedHandshake);
        if (!tlsOpenOnly.open ||
            tlsOpenOnly.evidence != ServiceEvidenceLevel::OpenPort) {
            std::cerr << "failed TLS handshake evidence contract failed\n";
            return 1;
        }

        PlainEndpoint interruptedHandshake = startPlainEndpoint({}, 500);
        const ServiceDefinition interruptedHttps{
            "https", "HTTPS", interruptedHandshake.port, false, true};
        const auto liveCancellation = std::make_shared<std::atomic_bool>(false);
        std::thread canceler([liveCancellation]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            liveCancellation->store(true);
        });
        const auto cancellationStarted = std::chrono::steady_clock::now();
        const ServiceProbeResult interrupted = ServiceProbe().probe(
            interruptedHttps,
            "127.0.0.1",
            {},
            1,
            1000,
            TargetBudget(1500),
            liveCancellation);
        const auto cancellationElapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - cancellationStarted).count();
        canceler.join();
        joinEndpoint(interruptedHandshake);
        if (!interrupted.open ||
            interrupted.evidence != ServiceEvidenceLevel::OpenPort ||
            cancellationElapsed >= 400) {
            std::cerr << "interrupted TLS handshake contract failed\n";
            return 1;
        }
    }

    PlainEndpoint orderedTelnet = startPlainEndpoint({});
    PlainEndpoint orderedSsh = startPlainEndpoint("SSH-2.0-ordered-fixture\r\n");
    const QList<ServiceDefinition> scanDefinitions = {
        {"telnet", "Telnet", orderedTelnet.port, false, false},
        {"http", "HTTP", 9, false, true},
        {"ssh", "SSH", orderedSsh.port, false, false}};
    const QList<ServiceHit> orderedHits = ServiceProbe(scanDefinitions).scan(
        "127.0.0.1",
        {},
        QSet<QString>{"telnet", "ssh"},
        1,
        500,
        TargetBudget(1800),
        {});
    joinEndpoint(orderedTelnet);
    joinEndpoint(orderedSsh);
    if (orderedHits.size() != 2 || orderedHits.at(0).id != "telnet" ||
        orderedHits.at(0).label != "Telnet" ||
        orderedHits.at(0).port != orderedTelnet.port || orderedHits.at(0).isWeb ||
        orderedHits.at(0).evidence != ServiceEvidenceLevel::OpenPort ||
        orderedHits.at(1).id != "ssh" ||
        orderedHits.at(1).evidence != ServiceEvidenceLevel::VerifiedProtocol) {
        std::cerr << "scan filtering, ordering, or propagation contract failed\n";
        return 1;
    }

    const auto stopBetweenServices = std::make_shared<std::atomic_bool>(false);
    PlainEndpoint firstOnly = startPlainEndpoint(
        "SSH-2.0-stop-fixture\r\n", 0, stopBetweenServices);
    const QList<ServiceDefinition> stoppingDefinitions = {
        {"ssh", "SSH", firstOnly.port, false, false},
        {"telnet", "Telnet", 9, false, false}};
    const ServiceProbe stoppingProbe(stoppingDefinitions);
    const QList<ServiceHit> stoppedHits = stoppingProbe.scan(
        "127.0.0.1",
        {},
        QSet<QString>{"ssh", "telnet"},
        1,
        500,
        TargetBudget(1500),
        stopBetweenServices);
    joinEndpoint(firstOnly);
    const QList<ServiceHit> expiredScan = stoppingProbe.scan(
        "127.0.0.1",
        {},
        QSet<QString>{"ssh"},
        1,
        500,
        TargetBudget(0),
        {});
    if (stoppedHits.size() != 1 || stoppedHits.first().id != "ssh" ||
        !expiredScan.isEmpty()) {
        std::cerr << "scan cancellation or budget stop contract failed\n";
        return 1;
    }
#endif

    const ServiceDefinition unreachable{"ssh", "SSH", 9, false, false};
    const auto canceled = std::make_shared<std::atomic_bool>(true);
    const ServiceProbe probe;
    DiagnosticsStore::instance().clear();
    if (probe.probe(unreachable,
                    "127.0.0.1",
                    {},
                    2,
                    500,
                    TargetBudget(1500),
                    canceled).open ||
        probe.probe(unreachable,
                    "127.0.0.1",
                    {},
                    2,
                    500,
                    TargetBudget(0),
                    {}).open ||
        probe.probe(unreachable,
                    "127.0.0.1",
                    "not-an-ip",
                    1,
                    500,
                    TargetBudget(1500),
                    {}).open) {
        std::cerr << "service cutoff or bind contract failed\n";
        return 1;
    }
    if (DiagnosticsStore::instance().counts().value("socket.bind_failed") != 1) {
        std::cerr << "service bind diagnostics contract failed\n";
        return 1;
    }
    return 0;
}
