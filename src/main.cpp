#include <QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QTimer>

#include "scannerwindow.h"

int main(int argc, char *argv[])
{
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
    QCoreApplication::setOrganizationName("OpenIPScanner");
    QCoreApplication::setApplicationName("open-ip-scanner");
    QCoreApplication::setApplicationVersion(OPEN_IP_SCANNER_VERSION);
    // Must match the installed desktop file basename for Wayland app-id/icon mapping.
    QGuiApplication::setDesktopFileName(OPEN_IP_SCANNER_APP_ID);

    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(true);
    app.setOrganizationName("OpenIPScanner");
    app.setApplicationName("open-ip-scanner");
    QObject::connect(&app, &QGuiApplication::lastWindowClosed, &app, &QCoreApplication::quit, Qt::QueuedConnection);

    // Use embedded icon for window/titlebar; launcher/taskbar icon comes from .desktop integration.
    const QIcon appIcon(":/icons/app.svg");
    app.setWindowIcon(appIcon);

    ScannerWindow window;
    window.setWindowIcon(appIcon);
    window.show();

    if (app.arguments().contains("--startup-smoke")) {
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    }

    return app.exec();
}
