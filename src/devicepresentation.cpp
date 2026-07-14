#include "devicepresentation.h"

#include "hostnameevidence.h"
#include "serviceevidence.h"

#include <QStringList>

QString normalizeMacHex12(const QString &mac)
{
    QString hex = mac.toUpper();
    hex.remove(':');
    hex.remove('-');
    hex.remove('.');
    if (hex.size() != 12) {
        return {};
    }
    for (const QChar ch : hex) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'))) {
            return {};
        }
    }
    return hex;
}

QString formatMacAddress(const QString &mac, int displayFormat)
{
    if (mac.isEmpty() || mac == "Unknown") {
        return "Unknown";
    }
    const QString hex = normalizeMacHex12(mac);
    if (hex.isEmpty()) {
        return mac;
    }
    const auto pairJoin = [](const QString &input, const QString &separator) {
        QStringList parts;
        for (int index = 0; index < 12; index += 2) {
            parts.append(input.mid(index, 2));
        }
        return parts.join(separator);
    };
    switch (displayFormat) {
    case MacColonLower: return pairJoin(hex.toLower(), ":");
    case MacHyphenUpper: return pairJoin(hex, "-");
    case MacHyphenLower: return pairJoin(hex.toLower(), "-");
    case MacCiscoDot:
        return QString("%1.%2.%3")
            .arg(hex.mid(0, 4), hex.mid(4, 4), hex.mid(8, 4))
            .toLower();
    case MacPlainUpper: return hex;
    case MacPlainLower: return hex.toLower();
    case MacColonUpper:
    default: return pairJoin(hex, ":");
    }
}

QString deviceDetailsHtml(const ScanResult &result, int macDisplayFormat)
{
    const auto escaped = [](const QString &text) { return text.toHtmlEscaped(); };
    QString html = "<table cellspacing='2' cellpadding='2'>";
    html += QString("<tr><td><b>IP:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(result.ip));
    QList<HostnameDisplayRow> hostnameRows = hostnameDisplayRows(
        result.hostnameEvidence);
    if (hostnameRows.isEmpty() && !normalizedHostnameKey(result.hostname).isEmpty()) {
        hostnameRows.append({result.hostname,
                             {hostnameSourceLabel(result.hostnameSource)},
                             true});
    }
    if (hostnameRows.isEmpty()) {
        html += "<tr><td><b>Hostname(s):</b></td><td>Unknown</td><td></td></tr>";
    } else {
        for (int index = 0; index < hostnameRows.size(); ++index) {
            const HostnameDisplayRow &row = hostnameRows.at(index);
            const QString heading = index == 0 ? "<b>Hostname(s):</b>" : QString();
            const QString sources = row.sourceLabels.isEmpty()
                                        ? QString()
                                        : QString("(%1)").arg(
                                              escaped(row.sourceLabels.join(", ")));
            const QString hostnameWithSources = sources.isEmpty()
                                                    ? escaped(row.hostname)
                                                    : QString("%1 %2").arg(
                                                          escaped(row.hostname), sources);
            html += QString("<tr><td>%1</td><td>%2</td><td></td></tr>")
                        .arg(heading, hostnameWithSources);
        }
    }
    html += QString("<tr><td><b>MAC:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(formatMacAddress(result.mac, macDisplayFormat)));
    html += QString("<tr><td><b>Vendor:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(result.vendor));
    if (result.services.isEmpty()) {
        html += "<tr><td><b>Services:</b></td><td>None</td><td></td></tr>";
    } else {
        for (int index = 0; index < result.services.size(); ++index) {
            const ServiceHit &service = result.services.at(index);
            const QString heading = index == 0 ? "<b>Services:</b>" : QString();
            const QString evidence = service.evidence ==
                                             ServiceEvidenceLevel::VerifiedProtocol
                                         ? "Verified"
                                         : "Open";
            html += QString("<tr><td>%1</td><td>%2</td><td>(%3)</td></tr>")
                        .arg(heading,
                             escaped(serviceEvidenceText(service.label,
                                                         service.port,
                                                         service.evidence)),
                             evidence);
        }
    }
    html += "</table>";
    return html;
}
