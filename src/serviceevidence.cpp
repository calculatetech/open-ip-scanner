#include "serviceevidence.h"

#include <QRegularExpression>

namespace {

QByteArray firstLine(const QByteArray &response)
{
    const qsizetype newline = response.indexOf('\n');
    return response.left(newline >= 0 ? newline : response.size()).trimmed();
}

bool is220GreetingWithToken(const QByteArray &response, const QByteArray &token)
{
    const QByteArray greeting = firstLine(response).toUpper();
    if (!greeting.startsWith("220 ") && !greeting.startsWith("220-")) {
        return false;
    }
    const QRegularExpression tokenPattern(
        QString("(?:^|[^A-Z0-9])%1(?:[^A-Z0-9]|$)")
            .arg(QRegularExpression::escape(QString::fromLatin1(token))));
    return tokenPattern.match(QString::fromLatin1(greeting)).hasMatch();
}

bool isStartTlsEhloReply(const QByteArray &response)
{
    const QList<QByteArray> rawLines = response.toUpper().split('\n');
    bool sawReplyLine = false;
    bool sawStartTls = false;
    bool sawTerminalLine = false;
    for (QByteArray line : rawLines) {
        line = line.trimmed();
        if (line.isEmpty()) {
            continue;
        }
        if (!line.startsWith("250-") && !line.startsWith("250 ")) {
            return false;
        }
        sawReplyLine = true;
        sawTerminalLine = line.startsWith("250 ");
        if (line.mid(4).trimmed() == "STARTTLS") {
            sawStartTls = true;
        }
    }
    return sawReplyLine && sawStartTls && sawTerminalLine;
}

} // namespace

bool responseVerifiesService(const QString &serviceId, const QByteArray &response)
{
    const QByteArray line = firstLine(response);
    if (serviceId == "http" || serviceId == "https") {
        static const QRegularExpression statusLine(
            "^HTTP/[0-9]+(?:\\.[0-9]+)? [1-5][0-9]{2}(?: |$)",
            QRegularExpression::CaseInsensitiveOption);
        return statusLine.match(QString::fromLatin1(line)).hasMatch();
    }
    if (serviceId == "ssh") {
        return line.startsWith("SSH-");
    }
    if (serviceId == "ftp") {
        return is220GreetingWithToken(response, "FTP");
    }
    if (serviceId == "smtp25" || serviceId == "smtps465") {
        return is220GreetingWithToken(response, "SMTP") ||
               is220GreetingWithToken(response, "ESMTP");
    }
    if (serviceId == "smtp587") {
        return isStartTlsEhloReply(response);
    }
    return false;
}

QString serviceEvidenceText(const QString &label, int port, ServiceEvidenceLevel evidence)
{
    if (evidence == ServiceEvidenceLevel::VerifiedProtocol) {
        return QString("%1:%2").arg(label).arg(port);
    }
    return QString("Port %1 open (probable %2)").arg(port).arg(label);
}
