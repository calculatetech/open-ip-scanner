#include "debugscanfixture.h"
#include "resulttablemodel.h"
#include "scansession.h"
#include "scannerwindow.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QImageWriter>
#include <QLineEdit>
#include <QPixmap>
#include <QThread>
#include <QTemporaryDir>

struct ScannerWindowTestAccess {
    static bool prepareFixture(ScannerWindow &window)
    {
        window.adapters_.clear();
        window.adapterCombo_->clear();
        window.adapterCombo_->addItem("Deterministic test fixture", -1);
        window.targetInput_->setText("test");
        window.accuracyLevel_ = 0;
        window.startScan();
        return window.scanInProgress_;
    }

    static bool fixtureComplete(const ScannerWindow &window)
    {
        return !window.scanInProgress_ && !window.scanCompletionPending_ &&
               !window.scanSession_->isRunning() &&
               window.resultModel_->rowCount() == debugScanFixtureResultCount();
    }

    static void stopFixture(ScannerWindow &window)
    {
        if (window.scanInProgress_ || window.scanSession_->isRunning()) {
            window.startScan();
        }
    }
};

int main(int argc, char *argv[])
{
    QTemporaryDir settingsDirectory;
    if (!settingsDirectory.isValid()) {
        return 3;
    }
    qputenv("XDG_CONFIG_HOME", settingsDirectory.path().toUtf8());
    QApplication application(argc, argv);
    application.setStyle("Fusion");
    QApplication::setApplicationName("Open IP Scanner");
    QApplication::setOrganizationName("OpenIpScanner");

    if (argc != 2) {
        return 2;
    }

    const QString outputPath = QString::fromLocal8Bit(argv[1]);
    ScannerWindow window;
    window.resize(1200, 700);
    window.show();
    QApplication::processEvents(QEventLoop::AllEvents, 100);

    if (!ScannerWindowTestAccess::prepareFixture(window)) {
        return 4;
    }

    QElapsedTimer timer;
    timer.start();
    while (!ScannerWindowTestAccess::fixtureComplete(window) && timer.elapsed() < 10000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    if (!ScannerWindowTestAccess::fixtureComplete(window)) {
        ScannerWindowTestAccess::stopFixture(window);
        return 5;
    }

    QApplication::processEvents(QEventLoop::AllEvents, 100);
    QImage screenshot = window.grab().toImage();
    screenshot.setText("Fixture", "Open IP Scanner hidden test");
    screenshot.setText("FixtureRows", QString::number(debugScanFixtureResultCount()));
    screenshot.setText("FixtureAccuracy", "Fast");
    QImageWriter writer(outputPath, "png");
    const bool saved = screenshot.size() == QSize(1200, 700) && writer.write(screenshot);
    ScannerWindowTestAccess::stopFixture(window);
    QApplication::processEvents(QEventLoop::AllEvents, 100);
    return saved && QFileInfo::exists(outputPath) ? 0 : 6;
}
