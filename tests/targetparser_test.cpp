#include "targetparser.h"

#include <QCoreApplication>

#include <iostream>

namespace {
bool equals(const TargetParseResult &result, const QStringList &expected)
{
    if (!result.isValid() || result.hosts.size() != expected.size()) {
        return false;
    }
    for (int index = 0; index < expected.size(); ++index) {
        if (result.hosts[index].toString() != expected[index]) {
            return false;
        }
    }
    return true;
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    if (!equals(TargetParser::parse("192.0.2.9"), {"192.0.2.9"}) ||
        !equals(TargetParser::parse("192.0.2.8/30"),
                {"192.0.2.9", "192.0.2.10"}) ||
        !equals(TargetParser::parse("192.0.2.8/31"),
                {"192.0.2.8", "192.0.2.9"}) ||
        !equals(TargetParser::parse("192.0.2.8/32"), {"192.0.2.8"}) ||
        !equals(TargetParser::parse("192.0.2.3-5"),
                {"192.0.2.3", "192.0.2.4", "192.0.2.5"}) ||
        !equals(TargetParser::parse("192.0.2.5-192.0.2.3"),
                {"192.0.2.3", "192.0.2.4", "192.0.2.5"}) ||
        !equals(TargetParser::parse("192.0.2.2,192.0.2.0/30,192.0.2.1"),
                {"192.0.2.1", "192.0.2.2"})) {
        std::cerr << "valid target parsing contract failed\n";
        return 1;
    }

    const TargetParseResult invalid = TargetParser::parse("192.0.2.1/33");
    const TargetParseResult whitespace = TargetParser::parse(" , ");
    const TargetParseResult cumulative =
        TargetParser::parse("192.0.2.0/24,198.51.100.0/24", 300);
    const TargetParseResult exactLimit = TargetParser::parse("192.0.2.1-10", 10);
    if (invalid.isValid() || invalid.error != "Invalid CIDR: 192.0.2.1/33" ||
        whitespace.isValid() ||
        whitespace.error != "Enter at least one target (CIDR, range, or IP)." ||
        cumulative.isValid() ||
        cumulative.error != "Too many targets (300 max). Narrow the range." ||
        !equals(exactLimit,
                {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
                 "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8",
                 "192.0.2.9", "192.0.2.10"})) {
        std::cerr << "target validation or host-limit contract failed\n";
        return 1;
    }
    return 0;
}
