#include <QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QByteArray>

#include "scannerwindow.h"

int main(int argc, char *argv[])
{
    if (qEnvironmentVariableIsEmpty("QT_SCALE_FACTOR_ROUNDING_POLICY")) {
        qputenv("QT_SCALE_FACTOR_ROUNDING_POLICY", QByteArray("PassThrough"));
    }
    QCoreApplication::setOrganizationName("OpenIPScanner");
    QCoreApplication::setApplicationName("open_ip_scanner");
    QGuiApplication::setDesktopFileName("open_ip_scanner");

    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(true);
    app.setOrganizationName("OpenIPScanner");
    app.setApplicationName("open_ip_scanner");
    QObject::connect(&app, &QGuiApplication::lastWindowClosed, &app, &QCoreApplication::quit, Qt::QueuedConnection);
    app.setWindowIcon(QIcon(":/icons/app.svg"));

    ScannerWindow window;
    window.setWindowIcon(QIcon(":/icons/app.svg"));
    window.show();

    return app.exec();
}
