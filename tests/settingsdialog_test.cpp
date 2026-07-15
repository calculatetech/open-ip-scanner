#include "debugscanfixture.h"
#include "csvexporter.h"
#include "mdnsresolver.h"
#include "settingslayout.h"
#include "scannerwindow.h"
#include "linuxneighborprobe.h"
#include "scansession.h"
#include "serviceprobe.h"
#include "resulttablemodel.h"

#include <QApplication>
#include <QAccessible>
#include <QAbstractButton>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDebug>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMetaObject>
#include <QPoint>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QShortcut>
#include <QSlider>
#include <QStandardPaths>
#include <QSplitter>
#include <QSysInfo>
#include <QTableView>
#include <QTemporaryDir>
#include <QTextEdit>
#include <QTextBrowser>
#include <QTimer>
#include <QUrl>
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

namespace {
bool readFailingSettings(QIODevice &, QSettings::SettingsMap &map)
{
    map.insert("targets/history", QStringList{"10.66.0.0/24"});
    map.insert("targets/last_input", "10.66.0.0/24");
    map.insert("targets/save_history", false);
    map.insert("targets/remember_last", false);
    map.insert("settings/schema_version", 2);
    return true;
}

bool writeFailingSettings(QIODevice &, const QSettings::SettingsMap &)
{
    return false;
}
} // namespace

struct ScannerWindowTestAccess {
    static bool accessibilityContract(ScannerWindow &window)
    {
        const auto fail = [](const char *message) {
            std::fprintf(stderr, "accessibility contract: %s\n", message);
            return false;
        };
        window.toolbarDisplayMode_ = 0;
        window.applyToolbarDisplayMode();
        const QList<QWidget *> controls = {
            window.targetInput_,
            window.defaultsButton_,
            window.adapterCombo_,
            window.refreshAdaptersButton_,
            window.terminalButton_,
            window.findButton_,
            window.scanButton_,
            window.table_,
            window.searchScopeCombo_,
            window.searchInput_,
            window.findChild<QPushButton *>("searchClearButton"),
            window.detailsPane_,
        };
        for (QWidget *control : controls) {
            if (control == nullptr || control->focusPolicy() == Qt::NoFocus) {
                return fail("missing or unfocusable primary control");
            }
            QAccessibleInterface *interface =
                QAccessible::queryAccessibleInterface(control);
            if (interface == nullptr ||
                interface->text(QAccessible::Name).trimmed().isEmpty() ||
                interface->role() == QAccessible::NoRole ||
                control->accessibleDescription().trimmed().isEmpty()) {
                if (control != nullptr) {
                    std::fprintf(stderr,
                                 "accessibility contract control=%s name=%s role=%d\n",
                                 control->objectName().toUtf8().constData(),
                                 interface == nullptr
                                     ? "<null>"
                                     : interface->text(QAccessible::Name)
                                           .toUtf8().constData(),
                                 interface == nullptr
                                     ? -1
                                     : static_cast<int>(interface->role()));
                }
                return false;
            }
        }
        for (int mode = 0; mode <= 2; ++mode) {
            window.toolbarDisplayMode_ = mode;
            window.applyToolbarDisplayMode();
            if (window.scanButton_->accessibleName() != "Scan" ||
                window.defaultsButton_->accessibleName() != "Auto" ||
                window.findButton_->accessibleName() != "Find" ||
                window.terminalButton_->accessibleName() != "Terminal" ||
                window.refreshAdaptersButton_->accessibleName() != "Refresh") {
                return fail("toolbar mode changed an accessible name");
            }
        }
        window.toolbarDisplayMode_ = 0;
        window.applyToolbarDisplayMode();
        if (!window.scanButton_->text().isEmpty() ||
            !window.findButton_->text().isEmpty() ||
            !window.refreshAdaptersButton_->text().isEmpty()) {
            return fail("icon-only toolbar retained visible button text");
        }

        const QList<QKeySequence> primaryShortcuts = {
            window.scanButton_->shortcut(),
            window.defaultsButton_->shortcut(),
            window.findButton_->shortcut(),
            window.terminalButton_->shortcut(),
            window.refreshAdaptersButton_->shortcut(),
            QKeySequence("Ctrl+L"),
        };
        for (int left = 0; left < primaryShortcuts.size(); ++left) {
            if (primaryShortcuts.at(left).isEmpty()) {
                return fail("primary shortcut missing");
            }
            for (int right = left + 1; right < primaryShortcuts.size(); ++right) {
                if (primaryShortcuts.at(left) == primaryShortcuts.at(right)) {
                    return fail("primary shortcut conflict");
                }
            }
        }
        if (window.scanButton_->shortcut() != QKeySequence(Qt::Key_F5) ||
            window.findButton_->shortcut() != QKeySequence("Ctrl+F") ||
            window.refreshAdaptersButton_->shortcut() != QKeySequence("Ctrl+R")) {
            return fail("documented primary shortcut mismatch");
        }
        if (window.targetsLabel_->buddy() != window.targetInput_ ||
            window.adapterLabel_->buddy() != window.adapterCombo_) {
            return fail("primary label buddy mismatch");
        }

        window.scanInProgress_ = true;
        window.scanCompletionPending_ = false;
        window.scanButton_->setToolTip("Stop scan");
        window.applyToolbarDisplayMode();
        if (window.scanButton_->accessibleName() != "Stop" ||
            window.scanButton_->accessibleDescription() != "Stop scan") {
            return fail("Stop accessibility state mismatch");
        }
        window.scanCompletionPending_ = true;
        window.scanButton_->setToolTip("Finalizing results");
        window.applyToolbarDisplayMode();
        if (window.scanButton_->accessibleName() != "Finalizing results" ||
            window.scanButton_->accessibleDescription() != "Finalizing results") {
            return fail("Finalizing accessibility state mismatch");
        }
        window.scanInProgress_ = false;
        window.scanCompletionPending_ = false;
        window.scanButton_->setToolTip("Start scan");
        window.applyToolbarDisplayMode();

        window.showStatusMessage("Accessibility status fixture");
        window.updateProbeSummary();
        for (QLabel *label : {window.statusTextLabel_, window.probeSummaryLabel_}) {
            QAccessibleInterface *interface =
                QAccessible::queryAccessibleInterface(label);
            if (interface == nullptr || label->text().trimmed().isEmpty() ||
                interface->text(QAccessible::Name) != label->text() ||
                label->accessibleDescription().trimmed().isEmpty()) {
                return fail("dynamic status accessibility mismatch");
            }
        }

        window.show();
        window.activateWindow();
        window.raise();
        QApplication::processEvents();
        window.findButton_->click();
        QApplication::processEvents();
        if (!window.searchBar_->isVisible() || !window.searchInput_->hasFocus()) {
            return fail("Find action did not expose and focus search");
        }
        QShortcut *focusTargets =
            window.findChild<QShortcut *>("focusTargetsShortcut");
        if (focusTargets == nullptr ||
            focusTargets->key() != QKeySequence("Ctrl+L")) {
            return fail("target focus shortcut missing");
        }
        QMetaObject::invokeMethod(focusTargets, "activated", Qt::DirectConnection);
        QApplication::processEvents();
        return window.targetInput_->hasFocus()
                   ? true
                   : fail("Ctrl+L did not focus targets");
    }

    static bool externalDiagnosticsContract(ScannerWindow &window)
    {
        DiagnosticsStore &store = DiagnosticsStore::instance();
        store.setLoggingEnabled(false);
        store.clear();

        const QByteArray previousPath = qgetenv("PATH");
        const QByteArray previousTerminal = qgetenv("TERMINAL");
        const QByteArray previousKdeTerminal = qgetenv("KDE_TERMINAL_APPLICATION");
        qputenv("PATH", QByteArray());
        qputenv("TERMINAL", "missing-terminal-fixture");
        qputenv("KDE_TERMINAL_APPLICATION", "missing-kde-terminal-fixture");
        window.buildAdapters();
        QString terminalError;
        const bool terminalOpened = window.openPreferredTerminal({}, &terminalError);
        qputenv("PATH", previousPath);
        if (previousTerminal.isNull()) {
            qunsetenv("TERMINAL");
        } else {
            qputenv("TERMINAL", previousTerminal);
        }
        if (previousKdeTerminal.isNull()) {
            qunsetenv("KDE_TERMINAL_APPLICATION");
        } else {
            qputenv("KDE_TERMINAL_APPLICATION", previousKdeTerminal);
        }
        if (terminalOpened || terminalError.isEmpty() ||
            store.counts().value("dns_suffix.query_failed") != 1 ||
            store.counts().value("launcher.terminal_failed") != 1) {
            return false;
        }

        ScannerWindow::AdapterInfo unavailableAdapter;
        unavailableAdapter.interfaceName = "fixture-missing";
        unavailableAdapter.interfaceLabel = "Unavailable fixture";
        unavailableAdapter.localIp = "192.0.2.123";
        unavailableAdapter.localMac = "02:00:00:00:00:7B";
        window.adapters_ = {unavailableAdapter};
        window.adapterCombo_->clear();
        window.adapterCombo_->addItem(unavailableAdapter.interfaceLabel, 0);
        window.adapterCombo_->setCurrentIndex(0);
        window.targetInput_->setText("192.0.2.124");
        window.startScan();
        if (window.scanInProgress_ ||
            store.counts().value("socket.bind_failed") != 1 ||
            store.counts().value("dns_suffix.query_failed") != 1) {
            return false;
        }

        CsvExportData exportData;
        exportData.headers = {"IP Address"};
        exportData.rows = {{"192.0.2.124"}};
        if (window.exportCsvToPath("/dev/null/scan.csv", exportData) ||
            window.saveSupportBundleToPath("/dev/null/support.json") ||
            store.counts().value("export.csv_failed") != 1 ||
            store.counts().value("export.support_bundle_failed") != 1) {
            return false;
        }

        const auto dismissNextDialog = []() {
            QTimer::singleShot(0, []() {
                if (auto *dialog = qobject_cast<QDialog *>(
                        QApplication::activeModalWidget())) {
                    dialog->reject();
                }
            });
        };
        const auto previousUrlLauncher = window.urlLauncher_;
        const auto previousDetachedLauncher = window.detachedLauncher_;
        window.urlLauncher_ = [](const QUrl &) { return false; };
        ServiceHit webService;
        webService.id = "http";
        webService.label = "HTTP";
        webService.port = 80;
        webService.isWeb = true;
        dismissNextDialog();
        window.openService("192.0.2.124", webService);

        ServiceHit commandService;
        commandService.id = "fixture-command";
        commandService.label = "Fixture";
        commandService.port = 22;
        window.customCommands_[commandService.id] =
            "definitely-missing-executable {host}";
        dismissNextDialog();
        window.openService("192.0.2.124", commandService);
        window.customCommands_[commandService.id] = "/bin/true";
        window.detachedLauncher_ = [](const QString &, const QStringList &) {
            return false;
        };
        dismissNextDialog();
        window.openService("192.0.2.124", commandService);
        window.urlLauncher_ = previousUrlLauncher;
        window.detachedLauncher_ = previousDetachedLauncher;
        if (store.counts().value("launcher.url_failed") != 1 ||
            store.counts().value("launcher.executable_missing") != 1 ||
            store.counts().value("launcher.start_failed") != 1) {
            return false;
        }

        store.clear();
        for (int index = 0; index < 700; ++index) {
            store.record(diagnosticEvent(DiagnosticSeverity::Error,
                                         "export.csv_failed",
                                         "export",
                                         "Choose a writable destination."));
        }
        ScanResult result;
        result.ip = "192.0.2.124";
        result.discoveryMethod = DiscoveryMethod::Ping;
        window.resultModel_->clear();
        window.resultModel_->upsertResult(result);
        window.completedScanWasCanceled_ = false;
        window.completeScanPresentation();
        const bool summaryIsComplete =
            window.statusTextLabel_->text() ==
                "Scan complete. 1 host detected." &&
            store.failureCountsByStage().value("export") == 700;
        window.refreshAdapters();
        return summaryIsComplete;
    }

    static QList<QHostAddress> parseTargets(const ScannerWindow &window,
                                            const QString &text,
                                            QString *error)
    {
        return window.parseTargetsInput(text, error);
    }

    static bool targetFormatRoundTrips(ScannerWindow &window)
    {
        const TargetTextFormat original = window.targetTextFormat_;
        window.targetTextFormat_ = TargetTextFormat::Range;
        window.saveSettings();
        window.targetTextFormat_ = TargetTextFormat::Cidr;
        window.loadSettings();
        const bool restored =
            window.targetTextFormat_ == TargetTextFormat::Range;
        window.targetTextFormat_ = original;
        window.saveSettings();
        return restored;
    }

    static bool usesTargetFormat(const ScannerWindow &window,
                                 TargetTextFormat format)
    {
        return window.targetTextFormat_ == format;
    }

    static bool settingsMigrationContract(ScannerWindow &window)
    {
        QSettings settings("OpenIPScanner", "OpenIPScanner");
        for (int schema : {0, 1, 2}) {
            for (int globalMode = 0; globalMode <= 2; ++globalMode) {
                for (int explicitMode = 0; explicitMode <= 2; ++explicitMode) {
                    settings.clear();
                    settings.setValue("settings/schema_version", schema);
                    settings.setValue("unrelated/keep", "preserved");
                    settings.setValue("targets/remember_last", false);
                    settings.setValue("targets/history", QStringList{"10.0.0.0/24"});
                    settings.setValue("targets/last_input", "10.0.0.0/24");
                    settings.setValue("services/enabled_ids", QStringList{});
                    settings.setValue("toolbar/display_mode", globalMode);
                    settings.setValue("toolbar/item_mode_scan", -1);
                    settings.setValue("toolbar/item_mode_auto", explicitMode);
                    settings.sync();

                    window.applyDefaultSettings();
                    window.loadSettings();
                    if (settings.value("settings/schema_version").toInt() != 3 ||
                        settings.value("unrelated/keep").toString() != "preserved" ||
                        settings.contains("targets/history") ||
                        settings.contains("targets/last_input") ||
                        !settings.contains("services/enabled_ids") ||
                        !window.enabledServiceIds_.isEmpty() ||
                        window.toolbarDisplayMode_ != globalMode ||
                        window.toolbarItemDisplayModes_.value("scan") != -1 ||
                        window.toolbarItemDisplayModes_.value("auto") != explicitMode) {
                        return false;
                    }
                    window.applyToolbarDisplayMode();
                    const bool scanHasText = !window.scanButton_->text().isEmpty();
                    const bool scanHasIcon = !window.scanButton_->icon().isNull();
                    const bool autoHasText = !window.defaultsButton_->text().isEmpty();
                    const bool autoHasIcon = !window.defaultsButton_->icon().isNull();
                    if (scanHasText != (globalMode != 0) ||
                        scanHasIcon != (globalMode != 2) ||
                        autoHasText != (explicitMode != 0) ||
                        autoHasIcon != (explicitMode != 2)) {
                        return false;
                    }

                    window.saveSettings();
                    window.enabledServiceIds_ << "ssh";
                    window.loadSettings();
                    if (!window.enabledServiceIds_.isEmpty()) {
                        return false;
                    }
                }
            }
        }

        settings.clear();
        settings.setValue("settings/schema_version", 1);
        settings.setValue("unrelated/keep", "preserved");
        settings.setValue("targets/remember_last", true);
        settings.setValue("targets/history", QStringList{"10.0.0.0/24"});
        settings.setValue("targets/last_input", "10.0.0.0/24");
        window.applyDefaultSettings();
        window.loadSettings();
        if (settings.value("targets/history").toStringList() !=
                QStringList{"10.0.0.0/24"} ||
            settings.value("targets/last_input").toString() != "10.0.0.0/24" ||
            !settings.value("targets/save_history").toBool()) {
            return false;
        }

        window.applyDefaultSettings();
        window.saveSettings();
        settings.sync();
        const bool resetPreservedUnrelated =
            settings.value("unrelated/keep").toString() == "preserved";
        settings.clear();
        window.applyDefaultSettings();
        window.saveSettings();
        return resetPreservedUnrelated;
    }

    static bool scanPrivacyContract(ScannerWindow &window)
    {
        QSettings settings("OpenIPScanner", "OpenIPScanner");
        settings.clear();
        window.applyDefaultSettings();
        window.targetHistory_.clear();
        window.targetInput_->setText("10.44.0.0/24");
        window.saveSettings();
        settings.sync();
        if (settings.contains("targets/history") ||
            settings.contains("targets/last_input") ||
            settings.value("targets/save_history", true).toBool()) {
            return false;
        }

        window.setTargetHistoryRetention(true);
        window.rememberLastTargetOnLaunch_ = true;
        if (!window.recordTargetHistory("10.44.0.0/24")) {
            return false;
        }
        settings.sync();
        if (settings.value("targets/history").toStringList() !=
                QStringList{"10.44.0.0/24"} ||
            settings.value("targets/last_input").toString() != "10.44.0.0/24") {
            return false;
        }

        window.clearTargetHistory();
        settings.sync();
        if (settings.contains("targets/history") ||
            settings.contains("targets/last_input") ||
            window.rememberLastTargetOnLaunch_ || !window.saveTargetHistory_) {
            return false;
        }

        window.recordTargetHistory("10.55.0.0/24");
        window.setTargetHistoryRetention(false);
        settings.sync();
        if (settings.contains("targets/history") ||
            settings.contains("targets/last_input") ||
            settings.value("targets/save_history", true).toBool() ||
            !window.targetHistory_.isEmpty()) {
            return false;
        }

        window.accuracyLevel_ = 0;
        window.enabledServiceIds_ = {"http", "ssh", "smtp587"};
        const QString concise = window.activeProbeSummary(false);
        const QString detailed = window.activeProbeSummary(true);
        if (concise != "Mode: Fast" ||
            !detailed.contains("1 echo attempt") ||
            !detailed.contains("80, 22, 587") ||
            !detailed.contains("HTTP HEAD") ||
            !detailed.contains("SMTP EHLO") ||
            !detailed.contains("PTR") || detailed.contains("443")) {
            return false;
        }
        ScanOptions captured;
        captured.accuracyLevel = 0;
        captured.pingAttempts = 1;
        captured.pingTimeoutSeconds = 1;
        captured.serviceAttempts = 1;
        captured.enabledServiceIds = {"http"};
        window.activeScanOptions_ = captured;
        window.hasActiveScanOptions_ = true;
        window.activeScanTargetRetained_ = false;
        window.scanInProgress_ = true;
        window.accuracyLevel_ = 3;
        window.enabledServiceIds_ = {"ssh"};
        window.saveTargetHistory_ = true;
        const QString pinned = window.activeProbeSummary(false);
        window.scanInProgress_ = false;
        window.hasActiveScanOptions_ = false;
        const QString nextScan = window.activeProbeSummary(false);
        if (pinned != "Mode: Fast" || nextScan != "Mode: Maximum") {
            return false;
        }

        const QSettings::Format failingFormat = QSettings::registerFormat(
            "ois-failing-settings", readFailingSettings, writeFailingSettings);
        QTemporaryDir failingDirectory;
        if (!failingDirectory.isValid()) {
            return false;
        }
        const QString failingPath = failingDirectory.filePath("privacy.ois-failing-settings");
        {
            QFile seed(failingPath);
            if (!seed.open(QIODevice::WriteOnly) || seed.write("seed") != 4) {
                return false;
            }
        }
        QSettings failingSettings(failingPath, failingFormat);
        QString deletionError;
        if (ScannerWindow::clearRetainedTargetSettings(
                failingSettings, true, &deletionError) || deletionError.isEmpty() ||
            failingSettings.status() == QSettings::NoError) {
            return false;
        }
        const QString persistencePath =
            failingDirectory.filePath("persistence.ois-failing-settings");
        {
            QFile seed(persistencePath);
            if (!seed.open(QIODevice::WriteOnly) || seed.write("seed") != 4) {
                return false;
            }
        }
        QSettings failingPersistence(persistencePath, failingFormat);
        QString persistenceError;
        if (ScannerWindow::persistTargetHistorySettings(
                failingPersistence,
                QStringList{"10.77.0.0/24"},
                "10.77.0.0/24",
                true,
                &persistenceError) || persistenceError.isEmpty()) {
            return false;
        }

        const QString migrationPath =
            failingDirectory.filePath("migration.ois-failing-settings");
        {
            QFile seed(migrationPath);
            if (!seed.open(QIODevice::WriteOnly) || seed.write("seed") != 4) {
                return false;
            }
        }
        QSettings failingMigration(migrationPath, failingFormat);
        QString migrationError;
        if (ScannerWindow::migrateSettings(failingMigration, &migrationError) ||
            migrationError.isEmpty() ||
            failingMigration.value("settings/schema_version").toInt() == 3) {
            return false;
        }

        settings.setValue("safety/authorization_ack_version", 1);
        const bool acknowledged = window.confirmScanAuthorization(captured);
        window.applyDefaultSettings();
        return acknowledged;
    }

    static bool customOuiValidationContract()
    {
        QHash<QString, QString> vendors;
        QString error;
        if (!ScannerWindow::parseCustomOuiOverrides(
                "00:16:3E=Lab vendor\n# comment\nAABBCC1=Camera range\n"
                "AABBCC112=Camera device",
                &vendors,
                &error) ||
            !error.isEmpty() || vendors.size() != 3 ||
            vendors.value("00163E") != "Lab vendor" ||
            vendors.value("AABBCC1") != "Camera range" ||
            vendors.value("AABBCC112") != "Camera device") {
            return false;
        }
        if (ScannerWindow::parseCustomOuiOverrides(
                "00163E=Valid\nGG1122=Invalid", &vendors, &error) ||
            vendors.size() != 3 || vendors.value("00163E") != "Lab vendor" ||
            !error.startsWith("Line 2")) {
            return false;
        }
        if (ScannerWindow::parseCustomOuiOverrides(
                "00163E Missing separator", &vendors, &error) ||
            !error.startsWith("Line 1")) {
            return false;
        }
        return ScannerWindow::normalizeOuiPrefix("GG:11:22:33:44:55").isEmpty();
    }

    static bool debouncedTargetSaveContract(ScannerWindow &window)
    {
        QSettings settings("OpenIPScanner", "OpenIPScanner");
        settings.remove("targets/last_input");
        settings.sync();
        window.saveTargetHistory_ = true;
        window.rememberLastTargetOnLaunch_ = true;
        window.targetInput_->setText("192.0.2.1");
        window.targetInput_->setText("192.0.2.2");
        window.targetInput_->setText("192.0.2.3");
        if (!window.settingsSaveTimer_->isActive() ||
            settings.contains("targets/last_input")) {
            return false;
        }
        QEventLoop wait;
        QTimer::singleShot(500, &wait, &QEventLoop::quit);
        wait.exec();
        settings.sync();
        const bool savedLastValue =
            settings.value("targets/last_input").toString() == "192.0.2.3" &&
            !window.settingsSaveTimer_->isActive();
        window.rememberLastTargetOnLaunch_ = false;
        window.saveTargetHistory_ = false;
        window.saveSettings();
        return savedLastValue;
    }

    static void installTargetFormatFixture(ScannerWindow &window)
    {
        window.networkTargets_ = {
            {QHostAddress("10.50.0.0"),
             24,
             "eth-fixture",
             "Primary fixture",
             "10.50.0.9",
             "02:00:00:00:00:01"},
            {QHostAddress("192.0.2.4"),
             30,
             "camera-fixture",
             "Camera fixture",
             "192.0.2.5",
             "02:00:00:00:00:02"}};
        window.adapters_ = {
            {"eth-fixture",
             "Primary fixture",
             "10.50.0.9",
             "02:00:00:00:00:01",
             {},
             true,
             true,
             true},
            {"camera-fixture",
             "Camera fixture",
             "192.0.2.5",
             "02:00:00:00:00:02",
             {},
             true,
             true,
             false}};
        window.adapterCombo_->clear();
        window.adapterCombo_->addItem("Auto Select", -1);
        window.adapterCombo_->addItem("Primary fixture", 0);
        window.adapterCombo_->addItem("Camera fixture", 1);
        window.adapterCombo_->setCurrentIndex(0);
        window.targetTextFormat_ = TargetTextFormat::Cidr;
        window.defaultTargetText_ =
            window.buildDefaultTargetPlanForAdapter("eth-fixture").targetText;
        window.userCustomizedTargets_ = false;
        window.applyDefaultTargets();
    }

    static int selectedAdapter(const ScannerWindow &window)
    {
        return window.adapterCombo_->currentData().toInt();
    }

    static QString targetText(const ScannerWindow &window)
    {
        return window.targetInput_->text();
    }

    static void selectAdapterAndApply(ScannerWindow &window, int adapterData)
    {
        const int index = window.adapterCombo_->findData(adapterData);
        window.adapterCombo_->setCurrentIndex(index);
        window.userCustomizedTargets_ = false;
        window.applyDefaultTargets();
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
        window.macDisplayFormat_ = MacPlainLower;
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

    static bool consecutiveProductionScanOptions(ScannerWindow &window)
    {
        const int originalAccuracy = window.accuracyLevel_;
        const int originalWorkers = window.maxParallelProbes_;
        const int originalMacFormat = window.macDisplayFormat_;
        const bool originalSaveHistory = window.saveTargetHistory_;
        const QSet<QString> originalServices = window.enabledServiceIds_;
        const QHash<QString, QString> originalBuiltInVendors =
            window.builtInOuiVendors_;
        const QHash<QString, QString> originalCustomVendors =
            window.customOuiVendors_;
        const QList<ScannerWindow::AdapterInfo> originalAdapters = window.adapters_;
        const QString originalTarget = window.targetInput_->text();
        const ScannerWindow::ProductionScanRunner originalRunner =
            window.productionScanRunner_;
        QList<QPair<QString, QVariant>> originalAdapterItems;
        for (int index = 0; index < window.adapterCombo_->count(); ++index) {
            originalAdapterItems.append(
                {window.adapterCombo_->itemText(index),
                 window.adapterCombo_->itemData(index)});
        }
        const int originalAdapterIndex = window.adapterCombo_->currentIndex();

        QSettings settings("OpenIPScanner", "OpenIPScanner");
        const bool hadAuthorization =
            settings.contains("safety/authorization_ack_version");
        const QVariant originalAuthorization =
            settings.value("safety/authorization_ack_version");
        settings.setValue("safety/authorization_ack_version", 1);
        settings.sync();

        QList<ScanOptions> capturedScans;
        window.productionScanRunner_ = [&capturedScans](
                                           const ScanOptions &options,
                                           const QList<QHostAddress> &hosts,
                                           const std::shared_ptr<std::atomic_bool> &,
                                           const std::function<void(int, int)> &progress,
                                           const std::function<void(const ScanResult &)> &) {
            capturedScans.append(options);
            progress(static_cast<int>(hosts.size()), static_cast<int>(hosts.size()));
            return QList<ScanResult>{};
        };
        ScannerWindow::AdapterInfo adapter;
        adapter.interfaceName = "lo";
        adapter.interfaceLabel = "Loopback fixture";
        adapter.localIp = "127.0.0.1";
        adapter.localMac = "02:00:00:00:00:01";
        adapter.dnsSuffixes = {"first.example"};
        window.adapters_ = {adapter};
        window.adapterCombo_->clear();
        window.adapterCombo_->addItem(adapter.interfaceLabel, 0);
        window.adapterCombo_->setCurrentIndex(0);
        window.targetInput_->setText("127.0.0.2");
        window.saveTargetHistory_ = false;

        const auto runAndWait = [&window]() {
            window.startScan();
            QElapsedTimer timer;
            timer.start();
            while ((window.scanInProgress_ || window.scanCompletionPending_ ||
                    window.scanSession_->isRunning()) && timer.elapsed() < 2000) {
                QApplication::processEvents(QEventLoop::AllEvents, 20);
            }
            return !window.scanInProgress_ && !window.scanCompletionPending_ &&
                   !window.scanSession_->isRunning();
        };

        window.accuracyLevel_ = 0;
        window.maxParallelProbes_ = 2;
        window.macDisplayFormat_ = MacColonUpper;
        window.enabledServiceIds_ = {"ssh"};
        window.builtInOuiVendors_ = {{"020000", "First built in"}};
        window.customOuiVendors_ = {{"020001", "First custom"}};
        const bool firstCompleted = runAndWait();

        window.accuracyLevel_ = 3;
        window.maxParallelProbes_ = 9;
        window.macDisplayFormat_ = MacPlainLower;
        window.enabledServiceIds_ = {"http", "rdp"};
        window.builtInOuiVendors_ = {{"020002", "Second built in"}};
        window.customOuiVendors_ = {{"020003", "Second custom"}};
        window.adapters_[0].interfaceName = "loopback-second";
        window.adapters_[0].interfaceLabel = "Second loopback fixture";
        window.adapters_[0].localIp = "127.0.0.2";
        window.adapters_[0].localMac = "02:00:00:00:00:02";
        window.adapters_[0].dnsSuffixes = {"second.example"};
        window.targetInput_->setText("127.0.0.3");
        const bool secondCompleted = runAndWait();

        const bool passed = firstCompleted && secondCompleted &&
                            capturedScans.size() == 2 &&
                            capturedScans[0].accuracyLevel == 0 &&
                            capturedScans[0].maxParallelProbes == 2 &&
                            capturedScans[0].interfaceName == "lo" &&
                            capturedScans[0].interfaceLabel == "Loopback fixture" &&
                            capturedScans[0].localIp == "127.0.0.1" &&
                            capturedScans[0].macDisplayFormat == MacColonUpper &&
                            capturedScans[0].enabledServiceIds ==
                                QSet<QString>{"ssh"} &&
                            capturedScans[0].localMac == "02:00:00:00:00:01" &&
                            capturedScans[0].dnsSuffixes ==
                                QStringList{"first.example"} &&
                            capturedScans[0].pingAttempts == 1 &&
                            capturedScans[0].pingTimeoutSeconds == 1 &&
                            capturedScans[0].serviceAttempts == 1 &&
                            capturedScans[0].serviceTimeoutMs == 350 &&
                            capturedScans[0].neighborConfirmationMs == 0 &&
                            capturedScans[0].targetDeadlineMs == 5000 &&
                            capturedScans[0].builtInOuiVendors ==
                                QHash<QString, QString>{
                                    {"020000", "First built in"}} &&
                            capturedScans[0].customOuiVendors ==
                                QHash<QString, QString>{
                                    {"020001", "First custom"}} &&
                            capturedScans[1].accuracyLevel == 3 &&
                            capturedScans[1].maxParallelProbes == 9 &&
                            capturedScans[1].interfaceName == "loopback-second" &&
                            capturedScans[1].interfaceLabel ==
                                "Second loopback fixture" &&
                            capturedScans[1].localIp == "127.0.0.2" &&
                            capturedScans[1].macDisplayFormat == MacPlainLower &&
                            capturedScans[1].enabledServiceIds ==
                                QSet<QString>({"http", "rdp"}) &&
                            capturedScans[1].localMac == "02:00:00:00:00:02" &&
                            capturedScans[1].dnsSuffixes ==
                                QStringList{"second.example"} &&
                            capturedScans[1].pingAttempts == 4 &&
                            capturedScans[1].pingTimeoutSeconds == 3 &&
                            capturedScans[1].serviceAttempts == 4 &&
                            capturedScans[1].serviceTimeoutMs == 2000 &&
                            capturedScans[1].neighborConfirmationMs == 8000 &&
                            capturedScans[1].targetDeadlineMs == 59500 &&
                            capturedScans[1].builtInOuiVendors ==
                                QHash<QString, QString>{
                                    {"020002", "Second built in"}} &&
                            capturedScans[1].customOuiVendors ==
                                QHash<QString, QString>{
                                    {"020003", "Second custom"}};

        window.productionScanRunner_ = originalRunner;
        window.accuracyLevel_ = originalAccuracy;
        window.maxParallelProbes_ = originalWorkers;
        window.macDisplayFormat_ = originalMacFormat;
        window.saveTargetHistory_ = originalSaveHistory;
        window.enabledServiceIds_ = originalServices;
        window.builtInOuiVendors_ = originalBuiltInVendors;
        window.customOuiVendors_ = originalCustomVendors;
        window.adapters_ = originalAdapters;
        window.targetInput_->setText(originalTarget);
        window.adapterCombo_->clear();
        for (const auto &item : originalAdapterItems) {
            window.adapterCombo_->addItem(item.first, item.second);
        }
        window.adapterCombo_->setCurrentIndex(originalAdapterIndex);
        if (hadAuthorization) {
            settings.setValue("safety/authorization_ack_version",
                              originalAuthorization);
        } else {
            settings.remove("safety/authorization_ack_version");
        }
        settings.sync();
        return passed;
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

    static bool aboutReportsRuntimeAndVendorSource(const ScannerWindow &window)
    {
        const QString text = window.aboutText();
        return text.contains(QString("Qt runtime: %1").arg(qVersion())) &&
               text.contains(QString("Running architecture: %1")
                                 .arg(QSysInfo::currentCpuArchitecture())) &&
               !text.contains("Application scope") &&
               text.contains("github.com/calculatetech/open-ip-scanner/tree/main/docs") &&
               text.contains("IEEE Registration Authority public listings") &&
               text.contains("standards.ieee.org/products-programs/regauth/") &&
               text.contains("53315 assignments") &&
               !text.contains("Unavailable") &&
               window.builtInOuiVendors_.size() == 53315 &&
               window.builtInOuiVendors_.value("000000") ==
                   "XEROX CORPORATION" &&
               window.builtInOuiVendors_.value("0055DA0") ==
                   "Shinko Technos co.,ltd." &&
               window.builtInOuiVendors_.value("001BC5000") ==
                   "Converging Systems Inc." &&
               !text.contains("Supported for 1.0") &&
               !text.contains("Tested on");
    }

    static bool externalLinkContract(ScannerWindow &window)
    {
        QList<QUrl> launched;
        const auto previousLauncher = window.urlLauncher_;
        window.urlLauncher_ = [&launched](const QUrl &url) {
            launched.append(url);
            return true;
        };
        QTextBrowser browser;
        browser.setHtml(window.aboutText());
        window.configureExternalLinks(&browser);
        const QList<QUrl> expected = {
            QUrl("https://github.com/calculatetech/open-ip-scanner/tree/main/docs"),
            QUrl("https://standards.ieee.org/products-programs/regauth/"),
        };
        bool invoked = !browser.openLinks() && !browser.openExternalLinks();
        for (const QUrl &url : expected) {
            invoked = QMetaObject::invokeMethod(
                          &browser,
                          "anchorClicked",
                          Qt::DirectConnection,
                          Q_ARG(QUrl, url)) &&
                      invoked;
        }
        window.urlLauncher_ = previousLauncher;
        return invoked && launched == expected;
    }

    static bool statusPresentationContract(ScannerWindow &window)
    {
        const int originalAccuracy = window.accuracyLevel_;
        window.accuracyLevel_ = 0;
        window.scanInProgress_ = false;
        window.hasActiveScanOptions_ = false;
        window.updateProbeSummary();
        if (window.probeSummaryLabel_->text() != "Mode: Fast" ||
            !window.probeSummaryLabel_->toolTip().isEmpty()) {
            return false;
        }

        window.resultModel_->clear();
        window.completedScanWasCanceled_ = false;
        window.completeScanPresentation();
        if (window.statusTextLabel_->text() !=
            "Scan complete. 0 hosts detected.") {
            return false;
        }
        ScanResult result;
        result.ip = "192.0.2.200";
        window.resultModel_->upsertResult(result);
        window.completeScanPresentation();
        if (window.statusTextLabel_->text() !=
            "Scan complete. 1 host detected.") {
            return false;
        }
        window.completedScanWasCanceled_ = true;
        window.completeScanPresentation();
        const bool stopped = window.statusTextLabel_->text() ==
                             "Scan stopped. 1 host detected.";
        window.accuracyLevel_ = originalAccuracy;
        window.updateProbeSummary();
        return stopped;
    }

    static bool detailsPanePersistenceContract(ScannerWindow &window)
    {
        QSettings settings("OpenIPScanner", "OpenIPScanner");
        settings.remove("appearance/details_pane_height");
        settings.remove("appearance/show_details_pane");
        settings.sync();

        window.resize(900, 650);
        window.show();
        ScanResult result;
        result.ip = "192.0.2.210";
        result.hostnameEvidence = {
            {"fixture.example", HostnameSource::DnsPtr}};
        result.mac = "02:00:00:00:00:D2";
        result.vendor = "Fixture vendor";
        result.services = {{"ssh", "SSH", 22, false,
                            ServiceEvidenceLevel::VerifiedProtocol}};
        window.resultModel_->clear();
        window.resultModel_->upsertResult(result);
        window.table_->setCurrentIndex(window.resultModel_->index(0, 0));
        window.detailsPaneHeight_ = 0;
        window.setDetailsPaneVisible(true);
        QApplication::processEvents();
        QApplication::processEvents();
        const QList<int> defaultSizes = window.resultsSplitter_->sizes();
        const bool usefulDefault = defaultSizes.size() == 2 &&
                                   defaultSizes.at(1) >=
                                       window.defaultDetailsPaneHeight() &&
                                   window.detailsPane_->verticalScrollBar()->maximum() == 0;

        const int total = defaultSizes.at(0) + defaultSizes.at(1);
        const int requestedHeight = std::min(190, total / 2);
        window.resultsSplitter_->setSizes(
            {total - requestedHeight, requestedHeight});
        QApplication::processEvents();
        const int savedHeight = window.resultsSplitter_->sizes().at(1);
        window.saveSettings();
        window.setDetailsPaneVisible(false);
        window.detailsPaneHeight_ = 0;
        window.loadSettings();
        QApplication::processEvents();
        QApplication::processEvents();
        const QList<int> restoredSizes = window.resultsSplitter_->sizes();
        const bool restored = window.detailsPane_->isVisible() &&
                              window.detailsPaneHeight_ == savedHeight &&
                              restoredSizes.size() == 2 &&
                              std::abs(restoredSizes.at(1) - savedHeight) <= 2;

        if (!usefulDefault || !restored) {
            qWarning() << "details persistence"
                       << "default sizes" << defaultSizes
                       << "default required" << window.defaultDetailsPaneHeight()
                       << "scroll maximum"
                       << window.detailsPane_->verticalScrollBar()->maximum()
                       << "saved" << savedHeight
                       << "member" << window.detailsPaneHeight_
                       << "restored sizes" << restoredSizes
                       << "visible" << window.detailsPane_->isVisible();
        }

        window.setDetailsPaneVisible(false);
        window.detailsPaneHeight_ = 0;
        settings.setValue("appearance/show_details_pane", false);
        settings.remove("appearance/details_pane_height");
        settings.sync();
        return usefulDefault && restored;
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
        result.detailsText = deviceDetailsHtml(result, options.macDisplayFormat);
        window.resultModel_->clear();
        window.resultModel_->upsertResult(result);
        const QString tableHostname = window.resultModel_
                                          ->data(window.resultModel_->index(
                                              0, ScannerWindow::ColHostname),
                                                 Qt::DisplayRole)
                                          .toString();
        const QString html = result.detailsText;
        return tableHostname == "fixture" &&
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
            {ptr.hostname, ptr.hostnameSource},
            {mdns.hostname, mdns.hostnameSource}};
        ptr.detailsText = "<p>stale PTR-only details</p>";

        window.resultModel_->clear();
        window.resultModel_->upsertResult(mdns);
        window.resultModel_->upsertResult(ptr);
        const ScanResult merged = window.resultModel_->resultAt(0);
        ScanOptions options;
        const QString html = deviceDetailsHtml(merged, options.macDisplayFormat);
        return merged.hostname == "fixture.example" &&
               merged.hostnameEvidence.size() == 2 &&
               html.contains("fixture.example") && html.contains("(PTR)") &&
               html.contains("fixture.local") && html.contains("(mDNS)");
    }

    static bool tableHostnamePresentation(ScannerWindow &window)
    {
        ScanResult dns;
        dns.ip = "192.0.2.30";
        dns.interfaceName = "fixture0";
        dns.hostname = "long-device-name.example.test";
        dns.hostnameSource = HostnameSource::DnsPtr;
        dns.hostnameEvidence = {{dns.hostname, dns.hostnameSource}};

        ScanResult mdns;
        mdns.ip = "192.0.2.31";
        mdns.interfaceName = "fixture0";
        mdns.hostname = "mdns-device.local";
        mdns.hostnameSource = HostnameSource::AvahiMdns;
        mdns.hostnameEvidence = {{mdns.hostname, mdns.hostnameSource}};

        window.resultModel_->clear();
        window.resultModel_->upsertResult(dns);
        window.resultModel_->upsertResult(mdns);
        const QString first = window.resultModel_->data(
            window.resultModel_->index(0, ScannerWindow::ColHostname),
            Qt::DisplayRole).toString();
        const QString second = window.resultModel_->data(
            window.resultModel_->index(1, ScannerWindow::ColHostname),
            Qt::DisplayRole).toString();
        return first == "long-device-name" && second == "mdns-device.local" &&
               !window.table_->wordWrap() &&
               window.table_->textElideMode() == Qt::ElideRight;
    }

    static bool resolverSupportBundleIsRedacted(ScannerWindow &window)
    {
        DiagnosticsStore::instance().clear();
        DiagnosticsStore::instance().record(diagnosticEvent(
            DiagnosticSeverity::Warning,
            "mdns.daemon_unavailable",
            "hostname",
            "Start avahi-daemon.",
            "192.0.2.44 private-device.local SSH-2.0-secret"));
        const QByteArray bundle = window.resolverSupportBundle();
        return !bundle.contains("192.0.2.44") &&
               !bundle.contains("private-device.local") &&
               !bundle.contains("SSH-2.0-secret") &&
               bundle.contains("mdns.daemon_unavailable") &&
               bundle.contains("Start avahi-daemon");
    }

    static bool resultScalingContract(ScannerWindow &window)
    {
        window.resultModel_->clear();
        window.pendingDisplayResults_.clear();
        window.pendingDisplayIdentityRows_.clear();
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

        ScanResult olderSnapshot;
        olderSnapshot.ip = "198.51.100.20";
        olderSnapshot.interfaceName = "queue-fixture";
        olderSnapshot.hostname = "stale.queue.example";
        olderSnapshot.hostnameEvidence = {
            {olderSnapshot.hostname, HostnameSource::DnsPtr},
        };
        ScanResult newerSnapshot = olderSnapshot;
        newerSnapshot.hostname = "current.queue.example";
        newerSnapshot.hostnameEvidence = {
            {newerSnapshot.hostname, HostnameSource::DnsPtr},
        };
        window.queueResultForDisplay(olderSnapshot);
        window.queueResultForDisplay(newerSnapshot);
        while (!window.pendingDisplayResults_.isEmpty() ||
               window.resultFlushTimer_->isActive()) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const bool queueKeepsNewestSnapshot =
            window.resultModel_->resultForIdentity(neighborIdentityKey(
                newerSnapshot.interfaceName, newerSnapshot.ip)).hostname ==
            newerSnapshot.hostname;
        window.resultModel_->clear();

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
        window.searchScopeCombo_->setCurrentIndex(0);
        window.searchInput_->setText("host-");
        window.applyTableFilters();
        const int filterCountBeforeCompletion =
            window.tableFilterApplicationCount_;
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
        const bool completionFilteringBounded =
            window.tableFilterApplicationCount_ - filterCountBeforeCompletion == 1;
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
        const qint64 benchmarkElapsedMs = elapsed.elapsed();

        for (int row = 1000; row < 1020; ++row) {
            ScanResult enriched = window.resultModel_->resultAt(row);
            enriched.hostnameEvidence = {
                {QString("match-%1.corp.search.example").arg(row),
                 HostnameSource::DnsPtr},
            };
            window.resultModel_->upsertResult(enriched);
        }
        window.searchScopeCombo_->setCurrentIndex(
            window.searchScopeCombo_->findData("hostname"));
        window.searchInput_->setText("corp.search.example");
        window.applyTableFilters();
        window.table_->scrollTo(window.resultModel_->index(1005, 0),
                                QAbstractItemView::PositionAtTop);
        window.table_->setCurrentIndex(window.resultModel_->index(1010, 0));
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor enrichmentAnchorBefore =
            window.captureViewportAnchor();
        const QString enrichmentSelectionBefore = window.rowIdentityKey(
            window.table_->currentIndex().row());
        ScanResult newlyMatching = window.resultModel_->resultAt(500);
        newlyMatching.hostnameEvidence = {
            {"newly-visible.corp.search.example", HostnameSource::DnsPtr},
        };
        const QString newlyMatchingIdentity = neighborIdentityKey(
            newlyMatching.interfaceName, newlyMatching.ip);
        window.addOrUpdateResultRow(newlyMatching);
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor enrichmentAnchorAfter =
            window.captureViewportAnchor();
        const QString enrichmentSelectionAfter = window.rowIdentityKey(
            window.table_->currentIndex().row());
        const bool enrichmentAddedStable =
            !window.table_->isRowHidden(
                window.resultModel_->rowForIdentity(newlyMatchingIdentity)) &&
            enrichmentAnchorBefore.identity == enrichmentAnchorAfter.identity &&
            enrichmentAnchorBefore.pixelOffset == enrichmentAnchorAfter.pixelOffset &&
            enrichmentSelectionBefore == enrichmentSelectionAfter;

        ScanResult noLongerMatching = newlyMatching;
        noLongerMatching.hostnameEvidence.clear();
        const ScannerWindow::ViewportAnchor removalAnchorBefore =
            window.captureViewportAnchor();
        window.addOrUpdateResultRow(noLongerMatching);
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor removalAnchorAfter =
            window.captureViewportAnchor();
        const bool enrichmentRemovedStable =
            window.table_->isRowHidden(
                window.resultModel_->rowForIdentity(newlyMatchingIdentity)) &&
            removalAnchorBefore.identity == removalAnchorAfter.identity &&
            removalAnchorBefore.pixelOffset == removalAnchorAfter.pixelOffset &&
            enrichmentSelectionAfter == window.rowIdentityKey(
                window.table_->currentIndex().row());

        const ScannerWindow::ViewportAnchor restorationAnchorBefore =
            window.captureViewportAnchor();
        window.addOrUpdateResultRow(newlyMatching);
        QApplication::processEvents();
        const ScannerWindow::ViewportAnchor restorationAnchorAfter =
            window.captureViewportAnchor();
        const bool enrichmentRestoredStable =
            !window.table_->isRowHidden(
                window.resultModel_->rowForIdentity(newlyMatchingIdentity)) &&
            restorationAnchorBefore.identity == restorationAnchorAfter.identity &&
            restorationAnchorBefore.pixelOffset == restorationAnchorAfter.pixelOffset &&
            enrichmentSelectionAfter == window.rowIdentityKey(
                window.table_->currentIndex().row());
        const bool enrichmentFilterStable = enrichmentAddedStable &&
                                            enrichmentRemovedStable &&
                                            enrichmentRestoredStable;
        window.searchInput_->clear();
        window.searchScopeCombo_->setCurrentIndex(0);
        window.applyTableFilters();

        window.hide();
        QObject::disconnect(resetConnection);
        const bool enforceTiming =
            qEnvironmentVariableIsEmpty("OIS_SKIP_HARDWARE_TIMING_ASSERTIONS");
        const bool passed =
               queueKeepsNewestSnapshot && ordered && servicesOrdered &&
               visibleRows > 0 && visibleRows < 4096 &&
               filteredIdentitiesBeforeSort == filteredIdentitiesAfterSort &&
               enrichmentFilterStable &&
               (!enforceTiming ||
                (benchmarkElapsedMs < 5000 && maximumHeartbeatGapMs < 250)) &&
               modelResetCount == 0 && before.identity == after.identity &&
               before.pixelOffset == after.pixelOffset &&
               selectedBefore == selectedAfter && !hasIndexWidget &&
               completionAnchorBefore.identity == completionAnchorAfter.identity &&
               completionAnchorBefore.pixelOffset == completionAnchorAfter.pixelOffset &&
               completionSelectionBefore == completionSelectionAfter &&
               completionFilteringBounded &&
               scanActionDisabledDuringCompletion &&
               orderBeforeCompletion == orderAfterCompletion &&
               window.resultModel_->rowCount() == 4098;
        qInfo() << "result scaling diagnostics"
                << "elapsedMs" << benchmarkElapsedMs
                << "maximumHeartbeatGapMs" << maximumHeartbeatGapMs
                << "rows" << window.resultModel_->rowCount()
                << "visibleRows" << visibleRows
                << "ordered" << ordered
                << "servicesOrdered" << servicesOrdered
                << "enrichmentFilterStable" << enrichmentFilterStable
                << "enrichmentAnchorBefore" << enrichmentAnchorBefore.identity
                << enrichmentAnchorBefore.pixelOffset
                << "enrichmentAnchorAfter" << enrichmentAnchorAfter.identity
                << enrichmentAnchorAfter.pixelOffset
                << "enrichmentSelectionStable"
                << (enrichmentSelectionBefore == enrichmentSelectionAfter)
                << "modelResetCount" << modelResetCount
                << "timingEnforced" << enforceTiming;
        return passed;
    }

    static bool debugScanContract(ScannerWindow &window)
    {
        const QString originalTarget = window.targetInput_->text();
        const int originalAccuracy = window.accuracyLevel_;
        const QList<ScannerWindow::AdapterInfo> originalAdapters = window.adapters_;
        QString validatedTarget = "test";
        int validatorPosition = static_cast<int>(validatedTarget.size());
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
                window.scanSession_->isRunning()) && fastTimer.elapsed() < 6000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
            const int rows = window.resultModel_->rowCount();
            observedIncrementalPublication = observedIncrementalPublication ||
                                             (rows > 0 &&
                                              rows < debugScanFixtureResultCount());
        }
        const bool completedFixture = !window.scanInProgress_ &&
                                      !window.scanCompletionPending_ &&
                                      !window.scanSession_->isRunning() &&
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
        const bool fixtureStartedInMaximumMode =
            window.probeSummaryLabel_->text() == "Mode: Maximum";
        window.accuracyLevel_ = 0;
        window.updateProbeSummary();
        const bool fixtureModePinned =
            window.probeSummaryLabel_->text() == "Mode: Maximum";
        QElapsedTimer publicationTimer;
        publicationTimer.start();
        while (window.resultModel_->rowCount() < 3 &&
               window.scanSession_->isRunning() && publicationTimer.elapsed() < 2000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const int rowsBeforeCancellation = window.resultModel_->rowCount();
        QElapsedTimer cancellationTimer;
        cancellationTimer.start();
        window.startScan();
        while ((window.scanInProgress_ || window.scanCompletionPending_ ||
                window.scanSession_->isRunning()) && cancellationTimer.elapsed() < 2000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        const bool canceledPromptly = !window.scanInProgress_ &&
                                      !window.scanCompletionPending_ &&
                                      !window.scanSession_->isRunning() &&
                                      cancellationTimer.elapsed() < 1000 &&
                                      rowsBeforeCancellation > 0 &&
                                      window.resultModel_->rowCount() <
                                          debugScanFixtureResultCount();

        window.targetInput_->setText(originalTarget);
        window.accuracyLevel_ = originalAccuracy;
        window.adapters_ = originalAdapters;
        window.scanButton_->setEnabled(!window.adapters_.isEmpty());
        return availableWithoutAdapter && observedIncrementalPublication &&
               completedFixture && endpointsPresent &&
               fixtureStartedInMaximumMode && fixtureModePinned &&
               canceledPromptly;
    }

    static bool confirmsDelayedNeighbor(ScannerWindow &window)
    {
        Q_UNUSED(window)
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
        const LinuxNeighborProbe probe;
        const NeighborObservation confirmed = probe.confirmLiveness(
            initial,
            initial.ip,
            initial.interfaceName,
            options.neighborConfirmationMs,
            budget,
            {});
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
        Q_UNUSED(window)
        ServiceDefinition definition;
        definition.id = serviceId;
        definition.label = label;
        definition.port = port;
        TargetBudget budget(2000);
        auto cancellation = std::make_shared<std::atomic_bool>(false);
        const ServiceProbeResult result = ServiceProbe().probe(
            definition,
            "127.0.0.1",
            QString(),
            attempts,
            500,
            budget,
            cancellation);
        return {result.open, result.evidence};
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
    QSettings("OpenIPScanner", "OpenIPScanner").clear();
    ScannerWindow window;
    bool ok = true;
    REQUIRE(ScannerWindowTestAccess::settingsMigrationContract(window));
    REQUIRE(ScannerWindowTestAccess::scanPrivacyContract(window));
    REQUIRE(ScannerWindowTestAccess::customOuiValidationContract());
    REQUIRE(ScannerWindowTestAccess::debouncedTargetSaveContract(window));
    REQUIRE(ScannerWindowTestAccess::accessibilityContract(window));

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
    const DefaultTargetPlan rangeParserPlan = buildDefaultTargetPlan(
        {{QHostAddress("10.2.3.4").toIPv4Address(),
          20,
          "eth0",
          "Ethernet"}},
        4096,
        2048,
        TargetTextFormat::Range);
    QString rangeParserError;
    const QList<QHostAddress> rangeParsedTargets =
        ScannerWindowTestAccess::parseTargets(
            window, rangeParserPlan.targetText, &rangeParserError);
    REQUIRE(rangeParserError.isEmpty());
    REQUIRE(rangeParsedTargets == parsedTargets);
    REQUIRE(rangeParserPlan.uniqueHostCount == parserPlan.uniqueHostCount);
    REQUIRE(ScannerWindowTestAccess::targetFormatRoundTrips(window));
    REQUIRE(ScannerWindowTestAccess::preservesInterfaceIdentity(window));
    REQUIRE(ScannerWindowTestAccess::capturesAllScanOptions(window));
    REQUIRE(ScannerWindowTestAccess::consecutiveProductionScanOptions(window));
    REQUIRE(ScannerWindowTestAccess::parsesAdapterDnsDomains());
    REQUIRE(ScannerWindowTestAccess::aboutReportsRuntimeAndVendorSource(window));
    REQUIRE(ScannerWindowTestAccess::externalLinkContract(window));
    REQUIRE(ScannerWindowTestAccess::statusPresentationContract(window));
    REQUIRE(ScannerWindowTestAccess::rendersConciseHostnameProvenance(window));
    REQUIRE(ScannerWindowTestAccess::rendersMergedHostnameEvidence(window));
    REQUIRE(ScannerWindowTestAccess::tableHostnamePresentation(window));
    REQUIRE(ScannerWindowTestAccess::resolverSupportBundleIsRedacted(window));
    REQUIRE(ScannerWindowTestAccess::resultScalingContract(window));
    REQUIRE(ScannerWindowTestAccess::debugScanContract(window));
    REQUIRE(ScannerWindowTestAccess::confirmsDelayedNeighbor(window));
    REQUIRE(ScannerWindowTestAccess::externalDiagnosticsContract(window));
    REQUIRE(ScannerWindowTestAccess::detailsPanePersistenceContract(window));

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

    ScannerWindowTestAccess::installTargetFormatFixture(window);
    const QString autoCidrText = ScannerWindowTestAccess::targetText(window);
    QString autoCidrError;
    const QList<QHostAddress> autoCidrHosts =
        ScannerWindowTestAccess::parseTargets(
            window, autoCidrText, &autoCidrError);
    REQUIRE(autoCidrError.isEmpty());
    REQUIRE(ScannerWindowTestAccess::selectedAdapter(window) == -1);

    QList<QHostAddress> explicitRangeHosts;
    QString explicitRangeText;

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
        auto *targetFormat = dialog->findChild<QComboBox *>("settingsTargetFormat");
        auto *diagnosticLog = dialog->findChild<QCheckBox *>("settingsDiagnosticLog");
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
        REQUIRE(targetFormat != nullptr);
        REQUIRE(diagnosticLog != nullptr);
        REQUIRE(workerValue != nullptr);
        REQUIRE(accuracyValue != nullptr);
        REQUIRE(workerRowLabel != nullptr);
        REQUIRE(accuracyRowLabel != nullptr);
        REQUIRE(details != nullptr);
        REQUIRE(help != nullptr);
        REQUIRE(buttons != nullptr);
        if (categories == nullptr || workerSlider == nullptr || accuracySlider == nullptr ||
            targetFormat == nullptr || diagnosticLog == nullptr ||
            workerValue == nullptr || accuracyValue == nullptr || workerRowLabel == nullptr ||
            accuracyRowLabel == nullptr || details == nullptr || help == nullptr ||
            buttons == nullptr) {
            dialog->reject();
            app.exit(EXIT_FAILURE);
            return;
        }

        for (QWidget *control : QList<QWidget *>{categories,
                                                 workerSlider,
                                                 accuracySlider,
                                                 targetFormat,
                                                 diagnosticLog}) {
            QAccessibleInterface *interface =
                QAccessible::queryAccessibleInterface(control);
            REQUIRE(interface != nullptr);
            REQUIRE(interface != nullptr &&
                    !interface->text(QAccessible::Name).trimmed().isEmpty());
            REQUIRE(interface != nullptr &&
                    interface->role() != QAccessible::NoRole);
            REQUIRE(!control->accessibleDescription().trimmed().isEmpty());
        }
        REQUIRE(workerRowLabel->buddy() == workerSlider);
        REQUIRE(accuracyRowLabel->buddy() == accuracySlider);
        for (QAbstractButton *button : buttons->buttons()) {
            QAccessibleInterface *interface =
                QAccessible::queryAccessibleInterface(button);
            REQUIRE(interface != nullptr);
            REQUIRE(interface != nullptr &&
                    !interface->text(QAccessible::Name).trimmed().isEmpty());
        }

        categories->setCurrentRow(2);
        QApplication::processEvents();
        REQUIRE(dialog->minimumSize() ==
                QSize(settingslayout::kMinimumDialogWidth,
                      settingslayout::kMinimumDialogHeight));
        REQUIRE(dialog->width() >= settingslayout::kMinimumDialogWidth);
        REQUIRE(dialog->height() >= settingslayout::kMinimumDialogHeight);
        REQUIRE(dialog->width() <= settingslayout::kPreferredDialogWidth);
        REQUIRE(dialog->height() <= settingslayout::kPreferredDialogHeight);
        dialog->resize(settingslayout::kMinimumDialogWidth,
                       settingslayout::kMinimumDialogHeight);
        QApplication::processEvents();
        REQUIRE(dialog->size() ==
                QSize(settingslayout::kMinimumDialogWidth,
                      settingslayout::kMinimumDialogHeight));
        for (int category = 0; category < categories->count(); ++category) {
            categories->setCurrentRow(category);
            QApplication::processEvents();
            QScrollArea *visiblePage = nullptr;
            for (QScrollArea *scroll :
                 dialog->findChildren<QScrollArea *>("settingsPageScroll")) {
                if (scroll->isVisibleTo(dialog)) {
                    visiblePage = scroll;
                    break;
                }
            }
            REQUIRE(visiblePage != nullptr);
            REQUIRE(visiblePage != nullptr &&
                    visiblePage->horizontalScrollBarPolicy() ==
                        Qt::ScrollBarAlwaysOff);
            REQUIRE(visiblePage != nullptr &&
                    visiblePage->horizontalScrollBar()->maximum() == 0);
        }
        categories->setCurrentRow(2);
        QApplication::processEvents();
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

        REQUIRE(targetFormat->currentData().toString() == "cidr");
        diagnosticLog->setChecked(true);
        targetFormat->setCurrentIndex(
            targetFormat->findData(QStringLiteral("range")));
        QPushButton *okButton = buttons->button(QDialogButtonBox::Ok);
        REQUIRE(okButton != nullptr);
        if (okButton != nullptr) {
            okButton->click();
            QTimer::singleShot(0, &app, [&]() {
                REQUIRE(ScannerWindowTestAccess::usesTargetFormat(
                    window, TargetTextFormat::Range));
                REQUIRE(ScannerWindowTestAccess::selectedAdapter(window) == -1);
                const QString autoRangeText =
                    ScannerWindowTestAccess::targetText(window);
                QString autoRangeError;
                const QList<QHostAddress> autoRangeHosts =
                    ScannerWindowTestAccess::parseTargets(
                        window, autoRangeText, &autoRangeError);
                REQUIRE(autoRangeError.isEmpty());
                REQUIRE(autoRangeHosts == autoCidrHosts);
                REQUIRE(autoRangeText != autoCidrText);

                ScannerWindowTestAccess::selectAdapterAndApply(window, 1);
                REQUIRE(ScannerWindowTestAccess::selectedAdapter(window) == 1);
                explicitRangeText = ScannerWindowTestAccess::targetText(window);
                QString explicitRangeError;
                explicitRangeHosts = ScannerWindowTestAccess::parseTargets(
                    window, explicitRangeText, &explicitRangeError);
                REQUIRE(explicitRangeError.isEmpty());

                QTimer::singleShot(0, &window, [&window]() {
                    QMetaObject::invokeMethod(
                        &window, "showSettingsDialog", Qt::DirectConnection);
                });
                QTimer::singleShot(100, &app, [&]() {
                    auto *secondDialog =
                        window.findChild<QDialog *>("settingsDialog");
                    REQUIRE(secondDialog != nullptr);
                    if (secondDialog == nullptr) {
                        app.exit(EXIT_FAILURE);
                        return;
                    }
                    auto *secondFormat = secondDialog->findChild<QComboBox *>(
                        "settingsTargetFormat");
                    auto *secondButtons =
                        secondDialog->findChild<QDialogButtonBox *>(
                            "settingsButtons");
                    REQUIRE(secondFormat != nullptr);
                    REQUIRE(secondButtons != nullptr);
                    if (secondFormat == nullptr || secondButtons == nullptr) {
                        secondDialog->reject();
                        app.exit(EXIT_FAILURE);
                        return;
                    }
                    REQUIRE(secondFormat->currentData().toString() == "range");
                    secondFormat->setCurrentIndex(
                        secondFormat->findData(QStringLiteral("cidr")));
                    QPushButton *secondOk =
                        secondButtons->button(QDialogButtonBox::Ok);
                    REQUIRE(secondOk != nullptr);
                    if (secondOk == nullptr) {
                        secondDialog->reject();
                        app.exit(EXIT_FAILURE);
                        return;
                    }
                    secondOk->click();
                    QTimer::singleShot(0, &app, [&]() {
                        REQUIRE(ScannerWindowTestAccess::usesTargetFormat(
                            window, TargetTextFormat::Cidr));
                        REQUIRE(ScannerWindowTestAccess::selectedAdapter(window) == 1);
                        const QString explicitCidrText =
                            ScannerWindowTestAccess::targetText(window);
                        QString explicitCidrError;
                        const QList<QHostAddress> explicitCidrHosts =
                            ScannerWindowTestAccess::parseTargets(
                                window, explicitCidrText, &explicitCidrError);
                        REQUIRE(explicitCidrError.isEmpty());
                        REQUIRE(explicitCidrHosts == explicitRangeHosts);
                        REQUIRE(explicitCidrText != explicitRangeText);
                        QSettings diagnosticSettings(
                            "OpenIPScanner", "OpenIPScanner");
                        REQUIRE(DiagnosticsStore::instance().loggingEnabled());
                        REQUIRE(diagnosticSettings.value(
                            "diagnostics/log_enabled", false).toBool());
                        app.exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
                    });
                });
            });
        } else {
            dialog->reject();
            app.exit(EXIT_FAILURE);
        }
    });

    return app.exec();
}
