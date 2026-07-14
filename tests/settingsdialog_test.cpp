#include "debugscanfixture.h"
#include "mdnsresolver.h"
#include "settingslayout.h"
#include "scannerwindow.h"
#include "resulttablemodel.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMetaObject>
#include <QPoint>
#include <QPushButton>
#include <QSlider>
#include <QStandardPaths>
#include <QTableView>
#include <QTemporaryDir>
#include <QTimer>
#include <QValidator>

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
        const ScanResult storedEthernet = window.resultModel_->resultForIdentity(ethernetKey);
        const ScanResult storedVpn = window.resultModel_->resultForIdentity(vpnKey);
        return window.resultModel_->rowCount() == 2 &&
               window.findRowByIdentity(ethernetKey) >= 0 &&
               window.findRowByIdentity(vpnKey) >= 0 &&
               storedEthernet.services.size() == 1 && storedVpn.services.size() == 1 &&
               storedEthernet.services.first().id == "ssh" &&
               storedVpn.services.first().id == "https" &&
               storedEthernet.detailsText == "Ethernet details" &&
               storedVpn.detailsText == "VPN details";
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
        adapter.dnsSuffixes = {"example.test"};
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
               options.dnsSuffixes == QStringList({"example.test"}) &&
               options.pingTimeoutSeconds == 1 && options.serviceAttempts == 2 &&
               options.serviceTimeoutMs == 750 && options.neighborConfirmationMs == 5500 &&
               options.macDisplayFormat == 6 &&
               options.enabledServiceIds == QSet<QString>({"http", "smtp587", "rdp"}) &&
               options.targetDeadlineMs == 23750 &&
               options.builtInOuiVendors.value("AABBCC") == "Built in fixture" &&
               options.customOuiVendors.value("DDEEFF") == "Custom fixture";
    }

    static bool parsesAdapterDnsDomains()
    {
        const QByteArray fixture = R"json([
            {"ifname":"eth0","searchDomains":[
                {"name":"example.test","routeOnly":false,"ifindex":2},
                {"name":"~internal.test","routeOnly":true,"ifindex":2}]},
            {"ifname":"wlan0","searchDomains":[
                {"name":"local.","routeOnly":false,"ifindex":3}]},
            {"ifname":"empty0","searchDomains":null}
        ])json";
        const QHash<QString, QStringList> parsed =
            ScannerWindow::parseAdapterDnsDomains(fixture);
        return parsed.size() == 2 &&
               parsed.value("eth0") == QStringList({"example.test"}) &&
               parsed.value("wlan0") == QStringList({"local"}) &&
               ScannerWindow::parseAdapterDnsDomains("not json").isEmpty();
    }

    static bool rendersConciseHostnameProvenance(ScannerWindow &window)
    {
        ScanResult result;
        result.ip = "192.0.2.10";
        result.interfaceName = "fixture0";
        result.hostnameEvidence = {
            {"fixture.local", HostnameSource::AvahiMdns},
            {"fixture.example", HostnameSource::DnsPtr},
            {"FIXTURE.LOCAL.", HostnameSource::SystemResolver}};
        const HostnameEvidence preferred = preferredHostname(result.hostnameEvidence);
        result.hostname = preferred.hostname;
        result.hostnameSource = preferred.source;
        result.mac = "02:00:00:00:00:10";
        result.vendor = "Fixture vendor";
        result.services = {{"ssh",
                            "SSH",
                            22,
                            false,
                            ServiceEvidenceLevel::VerifiedProtocol},
                           {"smb",
                            "SMB",
                            445,
                            false,
                            ServiceEvidenceLevel::OpenPort}};
        ScanOptions options;
        result.detailsText = window.collectDeviceDetails(result, options);
        window.resultModel_->clear();
        window.resultModel_->upsertResult(result);
        const QString tableHostname = window.resultModel_
                                          ->data(window.resultModel_->index(
                                              0, ScannerWindow::ColHostname),
                                                 Qt::DisplayRole)
                                          .toString();
        const QString html = result.detailsText;
        return tableHostname == "fixture.example" &&
               !tableHostname.contains("PTR") &&
               html.count("Hostname(s):") == 1 &&
               html.contains("fixture.example (PTR)") &&
               html.contains("fixture.local") &&
               html.contains("fixture.local (System, mDNS)") &&
               !html.contains("</td><td>(PTR)") &&
               html.contains("SSH:22") && html.contains("(Verified)") &&
               html.contains("Unknown:445") && html.contains("(Open)") &&
               html.contains("<table");
    }

    static bool rendersMergedHostnameEvidence(ScannerWindow &window)
    {
        ScanResult mdns;
        mdns.ip = "192.0.2.20";
        mdns.interfaceName = "fixture0";
        mdns.hostname = "fixture.local";
        mdns.hostnameSource = HostnameSource::AvahiMdns;
        mdns.hostnameEvidence = {
            {mdns.hostname, mdns.hostnameSource}};
        mdns.detailsText = "<p>stale mDNS-only details</p>";

        ScanResult ptr = mdns;
        ptr.hostname = "fixture.example";
        ptr.hostnameSource = HostnameSource::DnsPtr;
        ptr.hostnameEvidence = {
            {ptr.hostname, ptr.hostnameSource}};
        ptr.detailsText = "<p>stale PTR-only details</p>";

        window.resultModel_->clear();
        window.resultModel_->upsertResult(mdns);
        window.resultModel_->upsertResult(ptr);
        const ScanResult merged = window.resultModel_->resultAt(0);
        ScanOptions options;
        const QString html = window.collectDeviceDetails(merged, options);
        return merged.hostname == "fixture.example" &&
               merged.hostnameEvidence.size() == 2 &&
               html.contains("fixture.example") && html.contains("(PTR)") &&
               html.contains("fixture.local") && html.contains("(mDNS)");
    }

    static bool resolverSupportBundleIsRedacted(ScannerWindow &window)
    {
        ScanResult result;
        result.ip = "192.0.2.44";
        result.interfaceName = "fixture0";
        result.hostname = "private-device.local";
        result.resolverEvents = {
            {ResolverKind::Mdns, ResolverOutcome::Resolved},
            {ResolverKind::DnsPtr, ResolverOutcome::NoRecord}};
        window.resultModel_->clear();
        window.resultModel_->upsertResult(result);
        const QByteArray bundle = window.resolverSupportBundle();
        return !bundle.contains("192.0.2.44") &&
               !bundle.contains("private-device.local") &&
               bundle.contains("mdns.resolved") &&
               bundle.contains("ptr.no_record");
    }

    static bool resultScalingContract(ScannerWindow &window)
    {
        window.resultModel_->clear();
        window.pendingDisplayResults_.clear();
        int modelResetCount = 0;
        const QMetaObject::Connection resetConnection = QObject::connect(
            window.resultModel_, &QAbstractItemModel::modelReset, &window,
            [&modelResetCount]() { ++modelResetCount; });

        window.resize(1000, 600);
        window.show();
        QApplication::processEvents();

        qint64 maximumHeartbeatGapMs = 0;
        qint64 previousHeartbeatMs = 0;
        QElapsedTimer elapsed;
        elapsed.start();
        QTimer heartbeat;
        heartbeat.setInterval(10);
        QObject::connect(&heartbeat, &QTimer::timeout, &window, [&]() {
            const qint64 now = elapsed.elapsed();
            if (previousHeartbeatMs > 0) {
                maximumHeartbeatGapMs = std::max(maximumHeartbeatGapMs,
                                                 now - previousHeartbeatMs);
            }
            previousHeartbeatMs = now;
        });
        heartbeat.start();

        for (int arrival = 0; arrival < 4096; ++arrival) {
            const int i = (arrival * 4051) % 4096;
            ScanResult result;
            result.ip = QString("10.20.%1.%2").arg(i / 256).arg(i % 256);
            result.interfaceName = "fixture0";
            result.hostname = QString("host-%1").arg(i, 4, 10, QChar('0'));
            result.mac = QString("02:00:%1:%2:%3:%4")
                             .arg((i >> 24) & 0xff, 2, 16, QChar('0'))
                             .arg((i >> 16) & 0xff, 2, 16, QChar('0'))
                             .arg((i >> 8) & 0xff, 2, 16, QChar('0'))
                             .arg(i & 0xff, 2, 16, QChar('0'));
            result.vendor = (i % 2 == 0) ? "Even vendor" : "Odd vendor";
            result.services.append({i % 2 == 0 ? "ssh" : "rdp",
                                    i % 2 == 0 ? "SSH" : "RDP",
                                    i % 2 == 0 ? 22 : 3389,
                                    false,
                                    i % 2 == 0 ? ServiceEvidenceLevel::VerifiedProtocol
                                               : ServiceEvidenceLevel::OpenPort});
            result.detailsText = QString("Details %1").arg(i);
            window.queueResultForDisplay(result);
        }
        while (!window.pendingDisplayResults_.isEmpty() ||
               window.resultFlushTimer_->isActive()) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        bool ordered = window.resultModel_->rowCount() == 4096;
        qulonglong previousIp = 0;
        for (int row = 0; row < window.resultModel_->rowCount(); ++row) {
            const qulonglong current = QHostAddress(
                window.resultModel_->resultAt(row).ip).toIPv4Address();
            if (row > 0 && current <= previousIp) {
                ordered = false;
                break;
            }
            previousIp = current;
        }

        window.searchInput_->setText("host-20");
        window.applyTableFilters();
        int visibleRows = 0;
        QSet<QString> filteredIdentitiesBeforeSort;
        for (int row = 0; row < window.resultModel_->rowCount(); ++row) {
            if (!window.table_->isRowHidden(row)) {
                ++visibleRows;
                filteredIdentitiesBeforeSort.insert(window.resultModel_->identityAt(row));
            }
        }

        window.table_->sortByColumn(ScannerWindow::ColServices, Qt::AscendingOrder);
        QApplication::processEvents();
        bool servicesOrdered = true;
        QSet<QString> filteredIdentitiesAfterSort;
        QString previousService;
        for (int row = 0; row < window.resultModel_->rowCount(); ++row) {
            const QString current = window.cellText(row, ScannerWindow::ColServices);
            if (row > 0 && QString::compare(previousService, current,
                                             Qt::CaseInsensitive) > 0) {
                servicesOrdered = false;
                break;
            }
            previousService = current;
            if (!window.table_->isRowHidden(row)) {
                filteredIdentitiesAfterSort.insert(window.resultModel_->identityAt(row));
            }
        }

        window.searchInput_->clear();
        window.applyTableFilters();
        window.table_->sortByColumn(ScannerWindow::ColIp, Qt::AscendingOrder);
        window.table_->scrollTo(window.resultModel_->index(2000, 0),
                                QAbstractItemView::PositionAtTop);
        window.table_->setCurrentIndex(window.resultModel_->index(2200, 0));
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor before = window.captureViewportAnchor();
        const QString selectedBefore = window.rowIdentityKey(
            window.table_->currentIndex().row());

        ScanResult preceding;
        preceding.ip = "1.1.1.1";
        preceding.interfaceName = "fixture0";
        preceding.hostname = "preceding";
        window.addOrUpdateResultRow(preceding);
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor after = window.captureViewportAnchor();
        const QString selectedAfter = window.rowIdentityKey(
            window.table_->currentIndex().row());

        QList<ScanResult> finalSnapshot;
        QStringList orderBeforeCompletion;
        finalSnapshot.reserve(window.resultModel_->rowCount());
        orderBeforeCompletion.reserve(window.resultModel_->rowCount());
        for (int row = 0; row < window.resultModel_->rowCount(); ++row) {
            finalSnapshot.append(window.resultModel_->resultAt(row));
            orderBeforeCompletion.append(window.resultModel_->identityAt(row));
        }
        ScanResult completionOnly;
        completionOnly.ip = "1.0.0.1";
        completionOnly.interfaceName = "fixture0";
        completionOnly.hostname = "completion-only";
        finalSnapshot.append(completionOnly);
        const ScannerWindow::ViewportAnchor completionAnchorBefore =
            window.captureViewportAnchor();
        const QString completionSelectionBefore = window.rowIdentityKey(
            window.table_->currentIndex().row());
        window.beginScanCompletionPresentation(finalSnapshot, false);
        const bool scanActionDisabledDuringCompletion = !window.scanButton_->isEnabled();
        while (window.scanCompletionPending_ || window.resultFlushTimer_->isActive()) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const ScannerWindow::ViewportAnchor completionAnchorAfter =
            window.captureViewportAnchor();
        const QString completionSelectionAfter = window.rowIdentityKey(
            window.table_->currentIndex().row());
        QStringList orderAfterCompletion;
        orderAfterCompletion.reserve(window.resultModel_->rowCount());
        for (int row = 0; row < window.resultModel_->rowCount(); ++row) {
            orderAfterCompletion.append(window.resultModel_->identityAt(row));
        }
        orderAfterCompletion.removeAll(neighborIdentityKey(
            completionOnly.interfaceName, completionOnly.ip));

        bool hasIndexWidget = false;
        for (int row = 0; row < std::min(20, window.resultModel_->rowCount()); ++row) {
            hasIndexWidget = hasIndexWidget ||
                             window.table_->indexWidget(
                                 window.resultModel_->index(row, ScannerWindow::ColServices)) !=
                                 nullptr;
        }
        QApplication::processEvents();
        heartbeat.stop();
        window.hide();
        QObject::disconnect(resetConnection);
        return ordered && servicesOrdered && visibleRows > 0 && visibleRows < 4096 &&
               filteredIdentitiesBeforeSort == filteredIdentitiesAfterSort &&
               elapsed.elapsed() < 5000 && maximumHeartbeatGapMs < 250 &&
               modelResetCount == 0 && before.identity == after.identity &&
               before.pixelOffset == after.pixelOffset &&
               selectedBefore == selectedAfter && !hasIndexWidget &&
               completionAnchorBefore.identity == completionAnchorAfter.identity &&
               completionAnchorBefore.pixelOffset == completionAnchorAfter.pixelOffset &&
               completionSelectionBefore == completionSelectionAfter &&
               scanActionDisabledDuringCompletion &&
               orderBeforeCompletion == orderAfterCompletion &&
               window.resultModel_->rowCount() == 4098;
    }

    static bool debugScanContract(ScannerWindow &window)
    {
        const QString originalTarget = window.targetInput_->text();
        const int originalAccuracy = window.accuracyLevel_;
        const QList<ScannerWindow::AdapterInfo> originalAdapters = window.adapters_;
        QString validatedTarget = "test";
        int validatorPosition = validatedTarget.size();
        if (window.targetInput_->validator()->validate(validatedTarget, validatorPosition) !=
            QValidator::Acceptable) {
            return false;
        }
        QString parserError;
        const QList<QHostAddress> parsedTestTarget =
            window.parseTargetsInput("test", &parserError);
        if (!parsedTestTarget.isEmpty() || parserError.isEmpty()) {
            return false;
        }

        window.adapters_.clear();
        window.targetInput_->setText("test");
        const bool availableWithoutAdapter = window.scanButton_->isEnabled();
        window.accuracyLevel_ = 0;
        window.startScan();
        QElapsedTimer fastTimer;
        fastTimer.start();
        bool observedIncrementalPublication = false;
        while ((window.scanInProgress_ || window.scanCompletionPending_ ||
                window.scanWatcher_.isRunning()) && fastTimer.elapsed() < 6000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
            const int rows = window.resultModel_->rowCount();
            observedIncrementalPublication = observedIncrementalPublication ||
                                             (rows > 0 &&
                                              rows < debugScanFixtureResultCount());
        }
        const bool completedFixture = !window.scanInProgress_ &&
                                      !window.scanCompletionPending_ &&
                                      !window.scanWatcher_.isRunning() &&
                                      window.resultModel_->rowCount() ==
                                          debugScanFixtureResultCount();
        const bool endpointsPresent =
            window.resultModel_->resultForIdentity(
                neighborIdentityKey("debug-fixture", "198.18.0.1")).ip ==
                "198.18.0.1" &&
            window.resultModel_->resultForIdentity(
                neighborIdentityKey("debug-fixture", "198.18.3.0")).ip ==
                "198.18.3.0";

        window.accuracyLevel_ = 3;
        window.startScan();
        QElapsedTimer publicationTimer;
        publicationTimer.start();
        while (window.resultModel_->rowCount() < 3 &&
               window.scanWatcher_.isRunning() && publicationTimer.elapsed() < 2000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const int rowsBeforeCancellation = window.resultModel_->rowCount();
        QElapsedTimer cancellationTimer;
        cancellationTimer.start();
        window.startScan();
        while ((window.scanInProgress_ || window.scanCompletionPending_ ||
                window.scanWatcher_.isRunning()) && cancellationTimer.elapsed() < 2000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const bool canceledPromptly = !window.scanInProgress_ &&
                                      !window.scanCompletionPending_ &&
                                      !window.scanWatcher_.isRunning() &&
                                      cancellationTimer.elapsed() < 1000 &&
                                      rowsBeforeCancellation > 0 &&
                                      window.resultModel_->rowCount() <
                                          debugScanFixtureResultCount();

        window.targetInput_->setText(originalTarget);
        window.accuracyLevel_ = originalAccuracy;
        window.adapters_ = originalAdapters;
        window.scanButton_->setEnabled(!window.adapters_.isEmpty());
        return availableWithoutAdapter && observedIncrementalPublication &&
               completedFixture && endpointsPresent && canceledPromptly;
    }

    static bool confirmsDelayedNeighbor(ScannerWindow &window)
    {
        QTemporaryDir tools;
        if (!tools.isValid()) {
            return false;
        }
        QFile fakeIp(tools.filePath("ip"));
        if (!fakeIp.open(QIODevice::WriteOnly | QIODevice::Text)) {
            return false;
        }
        fakeIp.write(
            "#!/bin/sh\n"
            "printf '%s\\n' '[{\"dst\":\"192.0.2.55\",\"dev\":\"fixture0\","
            "\"lladdr\":\"02:00:00:00:00:55\",\"state\":[\"REACHABLE\"]}]'\n");
        fakeIp.close();
        if (!fakeIp.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                   QFileDevice::ExeOwner)) {
            return false;
        }

        const QByteArray previousPath = qgetenv("PATH");
        qputenv("PATH", tools.path().toUtf8() + ':' + previousPath);
        NeighborObservation initial;
        initial.ip = "192.0.2.55";
        initial.interfaceName = "fixture0";
        initial.mac = "02:00:00:00:00:55";
        initial.state = NeighborState::Delay;
        ScanOptions options;
        options.neighborConfirmationMs = 1000;
        const TargetBudget budget(2000);
        const NeighborObservation confirmed = window.confirmNeighborLiveness(
            initial, initial.ip, initial.interfaceName, options, budget, {});
        qputenv("PATH", previousPath);
        return confirmed.establishesLiveness() && confirmed.mac == initial.mac;
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
    REQUIRE(ScannerWindowTestAccess::parsesAdapterDnsDomains());
    REQUIRE(ScannerWindowTestAccess::rendersConciseHostnameProvenance(window));
    REQUIRE(ScannerWindowTestAccess::rendersMergedHostnameEvidence(window));
    REQUIRE(ScannerWindowTestAccess::resolverSupportBundleIsRedacted(window));
    REQUIRE(ScannerWindowTestAccess::resultScalingContract(window));
    REQUIRE(ScannerWindowTestAccess::debugScanContract(window));
    REQUIRE(ScannerWindowTestAccess::confirmsDelayedNeighbor(window));

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
