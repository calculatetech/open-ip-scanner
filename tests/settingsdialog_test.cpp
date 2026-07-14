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

#include <cstdio>
#include <cstdlib>

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
