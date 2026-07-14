#include "mdnsresolver.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QNetworkInterface>
#include <QTextStream>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "controlled mDNS requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

QString argumentValue(const QStringList &arguments, const QString &name)
{
    const int index = arguments.indexOf(name);
    return index >= 0 && index + 1 < arguments.size()
               ? arguments.at(index + 1)
               : QString();
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QStringList arguments = app.arguments();
    const QString interfaceName = argumentValue(arguments, "--interface");
    const QString address = argumentValue(arguments, "--address");
    const QString expectedHostname = argumentValue(arguments, "--hostname");
    const int interfaceIndex = QNetworkInterface::interfaceIndexFromName(interfaceName);
    REQUIRE(!interfaceName.isEmpty());
    REQUIRE(!address.isEmpty());
    REQUIRE(!expectedHostname.isEmpty());
    REQUIRE(interfaceIndex > 0);

    {
        ScanMdnsResolver resolver(interfaceIndex, {}, createAvahiDbusBackend());
        const MdnsLookupResult result = resolver.resolve(address, 2000);
        REQUIRE(result.status == MdnsLookupStatus::Resolved);
        REQUIRE(result.hostname == expectedHostname);
        QTextStream(stdout) << "mdns positive: " << result.hostname
                            << " source=AvahiMdns interface=" << interfaceName << '\n';
    }

    {
        const int wrongInterface = QNetworkInterface::interfaceIndexFromName("lo");
        REQUIRE(wrongInterface > 0 && wrongInterface != interfaceIndex);
        ScanMdnsResolver resolver(wrongInterface, {}, createAvahiDbusBackend());
        const MdnsLookupResult result = resolver.resolve(address, 500);
        REQUIRE(result.status != MdnsLookupStatus::Resolved);
        QTextStream(stdout) << "mdns wrong-interface: rejected\n";
    }

    {
        auto cancellation = std::make_shared<std::atomic_bool>(false);
        ScanMdnsResolver resolver(interfaceIndex,
                                  cancellation,
                                  createAvahiDbusBackend());
        MdnsLookupResult result;
        QElapsedTimer elapsed;
        elapsed.start();
        std::thread caller([&]() {
            result = resolver.resolve("10.77.0.99", 2000);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
        cancellation->store(true);
        caller.join();
        REQUIRE(result.status == MdnsLookupStatus::Cancelled);
        REQUIRE(elapsed.elapsed() < 500);
        QTextStream(stdout) << "mdns cancellation: Cancelled\n";
    }

    return EXIT_SUCCESS;
}
