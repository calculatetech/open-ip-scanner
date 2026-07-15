#include "devicepresentation.h"

#include <QCoreApplication>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "device presentation requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);

    const QString mac = "14:75:5B:37:CC:24";
    REQUIRE(normalizeMacHex12(mac) == "14755B37CC24");
    REQUIRE(normalizeMacHex12("not-a-mac").isEmpty());
    REQUIRE(formatMacAddress(mac, MacColonUpper) == "14:75:5B:37:CC:24");
    REQUIRE(formatMacAddress(mac, MacColonLower) == "14:75:5b:37:cc:24");
    REQUIRE(formatMacAddress(mac, MacHyphenUpper) == "14-75-5B-37-CC-24");
    REQUIRE(formatMacAddress(mac, MacHyphenLower) == "14-75-5b-37-cc-24");
    REQUIRE(formatMacAddress(mac, MacCiscoDot) == "1475.5b37.cc24");
    REQUIRE(formatMacAddress(mac, MacPlainUpper) == "14755B37CC24");
    REQUIRE(formatMacAddress(mac, MacPlainLower) == "14755b37cc24");
    REQUIRE(formatMacAddress("Unknown", MacPlainLower) == "Unknown");
    REQUIRE(formatMacAddress("fixture", MacPlainLower) == "fixture");

    ScanResult result;
    result.ip = "192.0.2.1<script>";
    result.mac = mac;
    result.vendor = "Vendor & Sons";
    result.hostname = "short";
    result.hostnameSource = HostnameSource::SystemResolver;
    result.hostnameEvidence = {
        {"device.corp.example", HostnameSource::DnsPtr},
        {"device.local", HostnameSource::AvahiMdns},
    };
    result.services = {
        {"ssh", "SSH", 22, false, ServiceEvidenceLevel::VerifiedProtocol},
        {"custom", "Custom", 9000, false, ServiceEvidenceLevel::OpenPort},
    };
    const QString html = deviceDetailsHtml(result, MacPlainLower);
    REQUIRE(html.contains("192.0.2.1&lt;script&gt;"));
    REQUIRE(!html.contains("192.0.2.1<script>"));
    REQUIRE(html.contains("device.corp.example (PTR)"));
    REQUIRE(html.contains("device.local (mDNS)"));
    REQUIRE(html.contains("14755b37cc24"));
    REQUIRE(html.contains("Vendor &amp; Sons"));
    REQUIRE(html.contains("SSH:22"));
    REQUIRE(html.contains("(Verified)"));
    REQUIRE(html.contains("Unknown:9000"));
    REQUIRE(html.contains("(Open)"));
    REQUIRE(html.contains("SSH:22 (Verified)"));
    REQUIRE(html.contains("Unknown:9000 (Open)"));
    REQUIRE(!html.contains("</td><td>(Verified)"));
    REQUIRE(!html.contains("</td><td>(Open)"));

    ScanResult hostile;
    hostile.ip = "<ip&>";
    hostile.mac = "<mac&>";
    hostile.vendor = "<vendor&>";
    hostile.hostnameEvidence = {
        {"<host&>.example", HostnameSource::DnsPtr},
    };
    hostile.services = {
        {"fixture", "<service&>", 1234, false,
         ServiceEvidenceLevel::VerifiedProtocol},
    };
    const QString hostileHtml = deviceDetailsHtml(hostile, MacColonUpper);
    for (const QString raw : {"<ip&>", "<mac&>", "<vendor&>",
                              "<host&>.example", "<service&>:1234"}) {
        REQUIRE(!hostileHtml.contains(raw));
    }
    REQUIRE(hostileHtml.contains("&lt;ip&amp;&gt;"));
    REQUIRE(hostileHtml.contains("&lt;mac&amp;&gt;"));
    REQUIRE(hostileHtml.contains("&lt;vendor&amp;&gt;"));
    REQUIRE(hostileHtml.contains("&lt;host&amp;&gt;.example"));
    REQUIRE(hostileHtml.contains("&lt;service&amp;&gt;:1234"));

    const ScanResult empty;
    const QString emptyHtml = deviceDetailsHtml(empty, MacColonUpper);
    REQUIRE(emptyHtml.contains("<b>IP:</b></td><td></td>"));
    REQUIRE(emptyHtml.contains("<b>Hostname(s):</b></td><td>Unknown"));
    REQUIRE(emptyHtml.contains("<b>MAC:</b></td><td>Unknown"));
    REQUIRE(emptyHtml.contains("<b>Vendor:</b></td><td></td>"));
    REQUIRE(emptyHtml.contains("<b>Services:</b></td><td>None"));

    return EXIT_SUCCESS;
}
