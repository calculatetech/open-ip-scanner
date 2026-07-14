#include "serviceevidence.h"

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "service evidence requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

} // namespace

int main()
{
    REQUIRE(responseVerifiesService("http", "HTTP/1.1 200 OK\r\nServer: fixture\r\n"));
    REQUIRE(!responseVerifiesService("http", "SSH-2.0-fixture\r\n"));
    REQUIRE(responseVerifiesService("ssh", "SSH-2.0-OpenSSH_fixture\r\n"));
    REQUIRE(!responseVerifiesService("ssh", "220 fixture ESMTP\r\n"));
    REQUIRE(responseVerifiesService("ftp", "220 fixture FTP server ready\r\n"));
    REQUIRE(!responseVerifiesService("ftp", "220 fixture ESMTP ready\r\n"));
    REQUIRE(!responseVerifiesService("ftp", "2200 fixture FTP ready\r\n"));
    REQUIRE(!responseVerifiesService("ftp", "220 fixture NOTFTP ready\r\n"));
    REQUIRE(responseVerifiesService("smtp25", "220 fixture ESMTP ready\r\n"));
    REQUIRE(responseVerifiesService("smtps465", "220 fixture ESMTP ready\r\n"));
    REQUIRE(responseVerifiesService("smtp587", "250-fixture\r\n250 STARTTLS\r\n"));
    REQUIRE(!responseVerifiesService("smtp587", "220 fixture SMTP ready\r\n"));
    REQUIRE(!responseVerifiesService("smtp587", "250 AUTH PLAIN\r\n"));
    REQUIRE(!responseVerifiesService("smtp587", "250 NOSTARTTLS\r\n"));
    REQUIRE(!responseVerifiesService("smtp587", "250 STARTTLS disabled\r\n"));
    REQUIRE(!responseVerifiesService("smtp587", "250-fixture\r\n250-STARTTLS\r\n"));
    REQUIRE(!responseVerifiesService("rdp", "HTTP/1.1 200 OK\r\n"));

    REQUIRE(serviceProbeWaitUnits("rdp") == 1);
    REQUIRE(serviceProbeWaitUnits("ssh") == 2);
    REQUIRE(serviceProbeWaitUnits("ftp") == 2);
    REQUIRE(serviceProbeWaitUnits("smtp25") == 2);
    REQUIRE(serviceProbeWaitUnits("smtps465") == 2);
    REQUIRE(serviceProbeWaitUnits("http") == 3);
    REQUIRE(serviceProbeWaitUnits("https") == 3);
    REQUIRE(serviceProbeWaitUnits("smtp587") == 4);

    REQUIRE(serviceEvidenceText("SSH", 2222, ServiceEvidenceLevel::VerifiedProtocol) ==
            "SSH:2222");
    REQUIRE(serviceEvidenceText("SSH", 22, ServiceEvidenceLevel::OpenPort) ==
            "Unknown:22");
    REQUIRE(serviceEvidenceText("HTTP", 8080, ServiceEvidenceLevel::OpenPort) ==
            "Unknown:8080");
    return EXIT_SUCCESS;
}
