#include "debugscanfixture.h"

#include <QHostAddress>

#include <algorithm>
#include <array>

namespace {

struct FixtureService {
    const char *id;
    const char *label;
    int port;
    bool isWeb;
};

struct FixtureVendor {
    const char *prefix;
    const char *name;
};

constexpr int kFixtureResultCount = 768;
constexpr std::array<FixtureService, 10> kServices = {{
    {"http", "HTTP", 80, true},
    {"https", "HTTPS", 443, true},
    {"ssh", "SSH", 22, false},
    {"rdp", "RDP", 3389, false},
    {"ftp", "FTP", 21, false},
    {"telnet", "Telnet", 23, false},
    {"smb", "SMB", 445, false},
    {"smtp25", "SMTP", 25, false},
    {"smtps465", "SMTPS", 465, false},
    {"smtp587", "SMTP-STARTTLS", 587, false},
}};
constexpr std::array<FixtureVendor, 4> kKnownVendors = {{
    {"00:00:0C", "Cisco Systems"},
    {"00:1B:21", "Intel Corporate"},
    {"00:50:56", "VMware"},
    {"00:15:5D", "Microsoft"},
}};

QString suffixFor(int index)
{
    return QString("%1:%2:%3")
        .arg((index >> 16) & 0xff, 2, 16, QChar('0'))
        .arg((index >> 8) & 0xff, 2, 16, QChar('0'))
        .arg(index & 0xff, 2, 16, QChar('0'))
        .toUpper();
}

} // namespace

bool isDebugScanFixtureTarget(const QString &targetText)
{
    return targetText == "test";
}

int debugScanFixtureResultCount()
{
    return kFixtureResultCount;
}

int debugScanFixtureIntervalMs(int accuracyLevel)
{
    constexpr std::array<int, 4> intervals = {2, 8, 18, 35};
    return intervals.at(static_cast<std::size_t>(std::clamp(accuracyLevel, 0, 3)));
}

ScanResult debugScanFixtureResult(int index)
{
    const int boundedIndex = std::clamp(index, 0, kFixtureResultCount - 1);
    const quint32 address = QHostAddress("198.18.0.1").toIPv4Address() +
                            static_cast<quint32>(boundedIndex);
    const FixtureService &service = kServices.at(
        static_cast<std::size_t>(boundedIndex % static_cast<int>(kServices.size())));

    ScanResult result;
    result.ip = QHostAddress(address).toString();
    result.interfaceName = "debug-fixture";
    result.hostname = boundedIndex % 7 == 0
                          ? QString("Unknown")
                          : QString("fixture-%1.test").arg(boundedIndex + 1, 3, 10, QChar('0'));

    if (boundedIndex % 2 == 0) {
        const FixtureVendor &vendor = kKnownVendors.at(
            static_cast<std::size_t>((boundedIndex / 2) % static_cast<int>(kKnownVendors.size())));
        result.mac = QString("%1:%2").arg(vendor.prefix, suffixFor(boundedIndex));
        result.vendor = vendor.name;
    } else {
        result.mac = QString("02:FE:ED:%1").arg(suffixFor(boundedIndex));
        result.vendor = "Unknown";
    }

    result.services.append({service.id,
                            service.label,
                            service.port,
                            service.isWeb,
                            ServiceEvidenceLevel::VerifiedProtocol});
    result.services.append({service.id,
                            service.label,
                            10000 + boundedIndex,
                            service.isWeb,
                            ServiceEvidenceLevel::OpenPort});
    if (boundedIndex % 5 == 0) {
        const FixtureService &extra = kServices.at(
            static_cast<std::size_t>((boundedIndex + 3) % static_cast<int>(kServices.size())));
        result.services.append({extra.id,
                                extra.label,
                                extra.port,
                                extra.isWeb,
                                ServiceEvidenceLevel::VerifiedProtocol});
    }
    result.detailsText = QString("Debug fixture device %1\nEvidence: synthetic\nNetwork traffic: none")
                             .arg(boundedIndex + 1);
    return result;
}
