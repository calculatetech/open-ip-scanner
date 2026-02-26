#include <QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QByteArray>

#include "scannerwindow.h"

int main(int argc, char *argv[])
{
    // Set HiDPI rounding policy before creating the Qt application object.
    if (qEnvironmentVariableIsEmpty("QT_SCALE_FACTOR_ROUNDING_POLICY")) {
        qputenv("QT_SCALE_FACTOR_ROUNDING_POLICY", QByteArray("PassThrough"));
    }
    QCoreApplication::setOrganizationName("OpenIPScanner");
    QCoreApplication::setApplicationName("open-ip-scanner");
    // Must match the installed desktop file basename for Wayland app-id/icon mapping.
    QGuiApplication::setDesktopFileName("open-ip-scanner");

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

    return app.exec();
}
