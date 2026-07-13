#include "scanoptions.h"

#include <atomic>
#include <cstdlib>
#include <thread>

namespace {

[[noreturn]] void fail()
{
    std::abort();
}

void require(bool condition)
{
    if (!condition) {
        fail();
    }
}

} // namespace

int main()
{
    ScanOptions preferences;
    preferences.accuracyLevel = 1;
    preferences.maxParallelProbes = 4;
    preferences.interfaceName = "eth0";
    preferences.interfaceLabel = "Ethernet before";
    preferences.localIp = "192.0.2.10";
    preferences.localMac = "AA:BB:CC:00:00:01";
    preferences.pingAttempts = 2;
    preferences.pingTimeoutSeconds = 1;
    preferences.serviceAttempts = 1;
    preferences.serviceTimeoutMs = 280;
    preferences.macDisplayFormat = 0;
    preferences.enabledServiceIds = {"http", "ssh"};
    preferences.builtInOuiVendors.insert("AABBCC", "Built in before");
    preferences.customOuiVendors.insert("AABBCC", "Before");

    const ScanOptions activeScan = preferences;
    std::atomic_int reads{0};
    std::atomic_int readsDuringMutation{0};
    std::atomic_bool mutationInProgress{false};
    std::atomic_bool stop{false};

    std::thread worker([&]() {
        while (!stop.load()) {
            require(activeScan.accuracyLevel == 1);
            require(activeScan.maxParallelProbes == 4);
            require(activeScan.interfaceName == "eth0");
            require(activeScan.interfaceLabel == "Ethernet before");
            require(activeScan.localIp == "192.0.2.10");
            require(activeScan.localMac == "AA:BB:CC:00:00:01");
            require(activeScan.pingAttempts == 2);
            require(activeScan.pingTimeoutSeconds == 1);
            require(activeScan.serviceAttempts == 1);
            require(activeScan.serviceTimeoutMs == 280);
            require(activeScan.macDisplayFormat == 0);
            require(activeScan.enabledServiceIds == QSet<QString>({"http", "ssh"}));
            require(activeScan.builtInOuiVendors.value("AABBCC") == "Built in before");
            require(activeScan.customOuiVendors.value("AABBCC") == "Before");
            reads.fetch_add(1);
            if (mutationInProgress.load()) {
                readsDuringMutation.fetch_add(1);
            }
        }
    });

    while (reads.load() < 100) {
        std::this_thread::yield();
    }

    // Model accepting preferences while the active scan reads its snapshot.
    mutationInProgress.store(true);
    while (readsDuringMutation.load() < 50) {
        std::this_thread::yield();
    }
    preferences.accuracyLevel = 3;
    preferences.maxParallelProbes = 12;
    preferences.interfaceName = "wlan0";
    preferences.interfaceLabel = "Wi-Fi after";
    preferences.localIp = "198.51.100.20";
    preferences.localMac = "AA:BB:CC:00:00:02";
    preferences.pingAttempts = 4;
    preferences.pingTimeoutSeconds = 3;
    preferences.serviceAttempts = 3;
    preferences.serviceTimeoutMs = 700;
    preferences.macDisplayFormat = 6;
    preferences.enabledServiceIds = {"rdp"};
    preferences.builtInOuiVendors["AABBCC"] = "Built in after";
    preferences.customOuiVendors["AABBCC"] = "After";

    const ScanOptions nextScan = preferences;
    mutationInProgress.store(false);
    while (reads.load() < 200) {
        std::this_thread::yield();
    }
    stop.store(true);
    worker.join();

    require(activeScan.accuracyLevel == 1);
    require(activeScan.enabledServiceIds.contains("http"));
    require(activeScan.customOuiVendors.value("AABBCC") == "Before");

    require(nextScan.accuracyLevel == 3);
    require(nextScan.maxParallelProbes == 12);
    require(nextScan.interfaceName == "wlan0");
    require(nextScan.interfaceLabel == "Wi-Fi after");
    require(nextScan.localIp == "198.51.100.20");
    require(nextScan.localMac == "AA:BB:CC:00:00:02");
    require(nextScan.pingAttempts == 4);
    require(nextScan.pingTimeoutSeconds == 3);
    require(nextScan.serviceAttempts == 3);
    require(nextScan.serviceTimeoutMs == 700);
    require(nextScan.macDisplayFormat == 6);
    require(nextScan.enabledServiceIds == QSet<QString>({"rdp"}));
    require(nextScan.builtInOuiVendors.value("AABBCC") == "Built in after");
    require(nextScan.customOuiVendors.value("AABBCC") == "After");
    return EXIT_SUCCESS;
}
