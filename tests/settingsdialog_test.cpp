#include "settingslayout.h"
#include "scannerwindow.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QListWidget>
#include <QMetaObject>
#include <QPoint>
#include <QSlider>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTimer>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <utility>

struct ScannerWindowTestAccess {
    static QList<QHostAddress> parseTargets(const ScannerWindow &window,
                                            const QString &text,
                                            QString *error)
    {
        return window.parseTargetsInput(text, error);
    }

    static bool preservesInterfaceIdentity(ScannerWindow &window)
    {
        ScanResult ethernet;
        ethernet.ip = "192.0.2.10";
        ethernet.interfaceName = "eth0";
        ethernet.mac = "02:00:00:00:00:01";
        ethernet.vendor = "Ethernet device";
        ethernet.hostname = "ethernet-host";
        ethernet.services.append({"ssh", "SSH", 22, false});
        ethernet.detailsText = "Ethernet details";

        ScanResult vpn = ethernet;
        vpn.interfaceName = "vpn0";
        vpn.mac = "02:00:00:00:00:02";
        vpn.vendor = "VPN device";
        vpn.hostname = "vpn-host";
        vpn.services = {{"https", "HTTPS", 443, true}};
        vpn.detailsText = "VPN details";

        window.addOrUpdateResultRow(ethernet);
        window.addOrUpdateResultRow(vpn);
        const QString ethernetKey = neighborIdentityKey(ethernet.interfaceName, ethernet.ip);
        const QString vpnKey = neighborIdentityKey(vpn.interfaceName, vpn.ip);
        return window.table_->rowCount() == 2 &&
               window.findRowByIdentity(ethernetKey) >= 0 &&
               window.findRowByIdentity(vpnKey) >= 0 &&
               window.servicesByIdentity_.value(ethernetKey).size() == 1 &&
               window.servicesByIdentity_.value(vpnKey).size() == 1 &&
               window.servicesByIdentity_.value(ethernetKey).first().id == "ssh" &&
               window.servicesByIdentity_.value(vpnKey).first().id == "https" &&
               window.detailsByIdentity_.value(ethernetKey) == "Ethernet details" &&
               window.detailsByIdentity_.value(vpnKey) == "VPN details";
    }

    static bool capturesAllScanOptions(ScannerWindow &window)
    {
        const int originalAccuracy = window.accuracyLevel_;
        const int originalWorkers = window.maxParallelProbes_;
        const int originalMacFormat = window.macDisplayFormat_;
        const QSet<QString> originalServices = window.enabledServiceIds_;
        const QHash<QString, QString> originalBuiltInVendors = window.builtInOuiVendors_;
        const QHash<QString, QString> originalCustomVendors = window.customOuiVendors_;

        window.accuracyLevel_ = 1;
        window.maxParallelProbes_ = 7;
        window.macDisplayFormat_ = ScannerWindow::MacPlainLower;
        window.enabledServiceIds_ = {"http", "smtp587", "rdp"};
        window.builtInOuiVendors_ = {{"AABBCC", "Built in fixture"}};
        window.customOuiVendors_ = {{"DDEEFF", "Custom fixture"}};

        ScannerWindow::AdapterInfo adapter;
        adapter.interfaceName = "fixture0";
        adapter.interfaceLabel = "Fixture adapter";
        adapter.localIp = "192.0.2.10";
        adapter.localMac = "02:00:00:00:00:10";
        const ScanOptions options = window.captureScanOptions(adapter);

        window.accuracyLevel_ = originalAccuracy;
        window.maxParallelProbes_ = originalWorkers;
        window.macDisplayFormat_ = originalMacFormat;
        window.enabledServiceIds_ = originalServices;
        window.builtInOuiVendors_ = originalBuiltInVendors;
        window.customOuiVendors_ = originalCustomVendors;

        return options.accuracyLevel == 1 && options.maxParallelProbes == 7 &&
               options.interfaceName == "fixture0" &&
               options.interfaceLabel == "Fixture adapter" &&
               options.localIp == "192.0.2.10" &&
               options.localMac == "02:00:00:00:00:10" && options.pingAttempts == 2 &&
               options.pingTimeoutSeconds == 1 && options.serviceAttempts == 2 &&
               options.serviceTimeoutMs == 750 && options.macDisplayFormat == 6 &&
               options.enabledServiceIds == QSet<QString>({"http", "smtp587", "rdp"}) &&
               options.targetDeadlineMs == 17000 &&
               options.builtInOuiVendors.value("AABBCC") == "Built in fixture" &&
               options.customOuiVendors.value("DDEEFF") == "Custom fixture";
    }

    static std::pair<bool, ServiceEvidenceLevel> probePlainService(
        const ScannerWindow &window,
        const QString &serviceId,
        const QString &label,
        int port,
        int attempts = 1)
    {
        ScannerWindow::ServiceDefinition definition;
        definition.id = serviceId;
        definition.label = label;
        definition.port = port;
        ScanOptions options;
        options.serviceAttempts = attempts;
        options.serviceTimeoutMs = 500;
        TargetBudget budget(2000);
        auto cancellation = std::make_shared<std::atomic_bool>(false);
        ServiceEvidenceLevel evidence = ServiceEvidenceLevel::OpenPort;
        const bool open = window.probePlainService(definition,
                                                   "127.0.0.1",
                                                   QString(),
                                                   budget,
                                                   cancellation,
                                                   options,
                                                   &evidence);
        return {open, evidence};
    }
};

namespace {

bool requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "settings dialog requirement failed at line %d\n", line);
    }
    return condition;
}

#define REQUIRE(condition) ok = requireAt((condition), __LINE__) && ok

std::pair<int, int> createMockListener()
{
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return {-1, 0};
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(listener, 1) != 0) {
        ::close(listener);
        return {-1, 0};
    }
    socklen_t length = sizeof(address);
    if (::getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) != 0) {
        ::close(listener);
        return {-1, 0};
    }
    return {listener, ntohs(address.sin_port)};
}

std::pair<bool, ServiceEvidenceLevel> probeMockEndpoint(ScannerWindow &window,
                                                        const QString &serviceId,
                                                        const QByteArray &response,
                                                        bool fragmented = false)
{
    const auto [listener, port] = createMockListener();
    if (listener < 0) {
        return {false, ServiceEvidenceLevel::OpenPort};
    }
    std::thread server([listener, response, serviceId, fragmented]() {
        pollfd descriptor{listener, POLLIN, 0};
        if (::poll(&descriptor, 1, 2000) > 0) {
            const int client = ::accept(listener, nullptr, nullptr);
            if (client >= 0) {
                if (serviceId == "http") {
                    char request[512];
                    ::recv(client, request, sizeof(request), 0);
                }
                if (!response.isEmpty()) {
                    const qsizetype split = fragmented ? std::min<qsizetype>(2, response.size())
                                                       : response.size();
                    ::send(client,
                           response.constData(),
                           static_cast<size_t>(split),
                           MSG_NOSIGNAL);
                    if (split < response.size()) {
                        ::usleep(20000);
                        ::send(client,
                               response.constData() + split,
                               static_cast<size_t>(response.size() - split),
                               MSG_NOSIGNAL);
                    }
                }
                ::shutdown(client, SHUT_RDWR);
                ::close(client);
            }
        }
        ::close(listener);
    });
    const auto result =
        ScannerWindowTestAccess::probePlainService(window, serviceId, serviceId, port);
    server.join();
    return result;
}

std::pair<bool, ServiceEvidenceLevel> probeMockSequence(
    ScannerWindow &window,
    const QString &serviceId,
    const QList<QByteArray> &responses)
{
    const auto [listener, port] = createMockListener();
    if (listener < 0) {
        return {false, ServiceEvidenceLevel::OpenPort};
    }
    std::thread server([listener, responses]() {
        for (const QByteArray &response : responses) {
            pollfd descriptor{listener, POLLIN, 0};
            if (::poll(&descriptor, 1, 2000) <= 0) {
                break;
            }
            const int client = ::accept(listener, nullptr, nullptr);
            if (client < 0) {
                break;
            }
            ::send(client,
                   response.constData(),
                   static_cast<size_t>(response.size()),
                   MSG_NOSIGNAL);
            ::shutdown(client, SHUT_RDWR);
            ::close(client);
        }
        ::close(listener);
    });
    const auto result = ScannerWindowTestAccess::probePlainService(
        window, serviceId, serviceId, port, static_cast<int>(responses.size()));
    server.join();
    return result;
}

std::pair<bool, ServiceEvidenceLevel> probeMockStartTls(ScannerWindow &window)
{
    const auto [listener, port] = createMockListener();
    if (listener < 0) {
        return {false, ServiceEvidenceLevel::OpenPort};
    }
    std::thread server([listener]() {
        pollfd descriptor{listener, POLLIN, 0};
        if (::poll(&descriptor, 1, 2000) > 0) {
            const int client = ::accept(listener, nullptr, nullptr);
            if (client >= 0) {
                const QByteArray greeting = "220 fixture ESMTP ready\r\n";
                ::send(client,
                       greeting.constData(),
                       static_cast<size_t>(greeting.size()),
                       MSG_NOSIGNAL);
                char request[512];
                const ssize_t count = ::recv(client, request, sizeof(request), 0);
                if (count > 0 && QByteArray(request, count).startsWith("EHLO ")) {
                    const QByteArray firstCapabilities =
                        "250-fixture\r\n250-PIPELINING\r\n";
                    const QByteArray finalCapability = "250 STARTTLS\r\n";
                    ::send(client,
                           firstCapabilities.constData(),
                           static_cast<size_t>(firstCapabilities.size()),
                           MSG_NOSIGNAL);
                    ::usleep(20000);
                    ::send(client,
                           finalCapability.constData(),
                           static_cast<size_t>(finalCapability.size()),
                           MSG_NOSIGNAL);
                }
                ::shutdown(client, SHUT_RDWR);
                ::close(client);
            }
        }
        ::close(listener);
    });
    const auto result = ScannerWindowTestAccess::probePlainService(
        window, "smtp587", "SMTP-STARTTLS", port);
    server.join();
    return result;
}

} // namespace

int main(int argc, char **argv)
{
    QStandardPaths::setTestModeEnabled(true);
    QApplication app(argc, argv);
    ScannerWindow window;
    bool ok = true;

    const DefaultTargetPlan parserPlan =
        buildDefaultTargetPlan({{QHostAddress("10.2.3.4").toIPv4Address(),
                                 20,
                                 "eth0",
                                 "Ethernet"}});
    QString parserError;
    const QList<QHostAddress> parsedTargets =
        ScannerWindowTestAccess::parseTargets(window, parserPlan.targetText, &parserError);
    REQUIRE(parserError.isEmpty());
    REQUIRE(parsedTargets.size() == parserPlan.uniqueHostCount);
    REQUIRE(parserPlan.targetText.size() <= 2048);
    REQUIRE(ScannerWindowTestAccess::preservesInterfaceIdentity(window));
    REQUIRE(ScannerWindowTestAccess::capturesAllScanOptions(window));

    const auto verifiedSsh = probeMockEndpoint(window, "ssh", "SSH-2.0-fixture\r\n");
    REQUIRE(verifiedSsh.first);
    REQUIRE(verifiedSsh.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto verifiedHttp =
        probeMockEndpoint(window, "http", "HTTP/1.1 204 No Content\r\n\r\n");
    REQUIRE(verifiedHttp.first);
    REQUIRE(verifiedHttp.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto fragmentedHttp = probeMockEndpoint(
        window, "http", "HTTP/1.1 200 OK\r\n\r\n", true);
    REQUIRE(fragmentedHttp.first);
    REQUIRE(fragmentedHttp.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto wrongProtocol =
        probeMockEndpoint(window, "http", "SSH-2.0-not-http\r\n");
    REQUIRE(wrongProtocol.first);
    REQUIRE(wrongProtocol.second == ServiceEvidenceLevel::OpenPort);
    const auto retriedSsh = probeMockSequence(
        window, "ssh", {"not ssh\r\n", "SSH-2.0-second-attempt\r\n"});
    REQUIRE(retriedSsh.first);
    REQUIRE(retriedSsh.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto verifiedFtp =
        probeMockEndpoint(window, "ftp", "220 fixture FTP server ready\r\n");
    REQUIRE(verifiedFtp.first);
    REQUIRE(verifiedFtp.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto verifiedSmtp =
        probeMockEndpoint(window, "smtp25", "220 fixture ESMTP ready\r\n");
    REQUIRE(verifiedSmtp.first);
    REQUIRE(verifiedSmtp.second == ServiceEvidenceLevel::VerifiedProtocol);
    const auto verifiedStartTls = probeMockStartTls(window);
    REQUIRE(verifiedStartTls.first);
    REQUIRE(verifiedStartTls.second == ServiceEvidenceLevel::VerifiedProtocol);

    QTimer::singleShot(0, &window, [&window]() {
        QMetaObject::invokeMethod(&window, "showSettingsDialog", Qt::DirectConnection);
    });
    QTimer::singleShot(100, &app, [&]() {
        auto *dialog = window.findChild<QDialog *>("settingsDialog");
        REQUIRE(dialog != nullptr);
        if (dialog == nullptr) {
            app.exit(EXIT_FAILURE);
            return;
        }

        auto *categories = dialog->findChild<QListWidget *>("settingsCategories");
        auto *workerSlider = dialog->findChild<QSlider *>("settingsWorkerSlider");
        auto *accuracySlider = dialog->findChild<QSlider *>("settingsAccuracySlider");
        auto *workerValue = dialog->findChild<QLabel *>("settingsWorkerValue");
        auto *accuracyValue = dialog->findChild<QLabel *>("settingsAccuracyValue");
        auto *workerRowLabel = dialog->findChild<QLabel *>("settingsWorkerRowLabel");
        auto *accuracyRowLabel = dialog->findChild<QLabel *>("settingsAccuracyRowLabel");
        auto *details = dialog->findChild<QLabel *>("settingsAccuracyDetails");
        auto *help = dialog->findChild<QLabel *>("settingsAccuracyHelp");
        auto *buttons = dialog->findChild<QDialogButtonBox *>("settingsButtons");
        REQUIRE(categories != nullptr);
        REQUIRE(workerSlider != nullptr);
        REQUIRE(accuracySlider != nullptr);
        REQUIRE(workerValue != nullptr);
        REQUIRE(accuracyValue != nullptr);
        REQUIRE(workerRowLabel != nullptr);
        REQUIRE(accuracyRowLabel != nullptr);
        REQUIRE(details != nullptr);
        REQUIRE(help != nullptr);
        REQUIRE(buttons != nullptr);
        if (categories == nullptr || workerSlider == nullptr || accuracySlider == nullptr ||
            workerValue == nullptr || accuracyValue == nullptr || workerRowLabel == nullptr ||
            accuracyRowLabel == nullptr || details == nullptr || help == nullptr ||
            buttons == nullptr) {
            dialog->reject();
            app.exit(EXIT_FAILURE);
            return;
        }

        categories->setCurrentRow(2);
        QApplication::processEvents();
        REQUIRE(dialog->size() == QSize(settingslayout::kDialogWidth,
                                        settingslayout::kDialogHeight));
        REQUIRE(workerSlider->width() == settingslayout::kSliderWidth);
        REQUIRE(accuracySlider->width() == settingslayout::kSliderWidth);
        REQUIRE(workerSlider->mapTo(dialog, QPoint(0, 0)).x() ==
                accuracySlider->mapTo(dialog, QPoint(0, 0)).x());
        REQUIRE(details->height() == settingslayout::kDynamicDescriptionHeight);

        const QRect workerGeometry = workerSlider->geometry();
        const QRect accuracyGeometry = accuracySlider->geometry();
        const QRect workerValueGeometry = workerValue->geometry();
        const QRect accuracyValueGeometry = accuracyValue->geometry();
        const QRect workerRowLabelGeometry = workerRowLabel->geometry();
        const QRect accuracyRowLabelGeometry = accuracyRowLabel->geometry();
        const QRect detailsGeometry = details->geometry();
        const QRect helpGeometry = help->geometry();
        const QRect buttonsGeometry = buttons->geometry();
        for (int value = 0; value <= 3; ++value) {
            accuracySlider->setValue(value);
            QApplication::processEvents();
            REQUIRE(workerSlider->geometry() == workerGeometry);
            REQUIRE(accuracySlider->geometry() == accuracyGeometry);
            REQUIRE(workerValue->geometry() == workerValueGeometry);
            REQUIRE(accuracyValue->geometry() == accuracyValueGeometry);
            REQUIRE(workerRowLabel->geometry() == workerRowLabelGeometry);
            REQUIRE(accuracyRowLabel->geometry() == accuracyRowLabelGeometry);
            REQUIRE(details->geometry() == detailsGeometry);
            REQUIRE(help->geometry() == helpGeometry);
            REQUIRE(buttons->geometry() == buttonsGeometry);
        }

        dialog->reject();
        app.exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
    });

    return app.exec();
}
