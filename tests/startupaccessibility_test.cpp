#include <QCoreApplication>
#include <QProcess>
#include <QProcessEnvironment>

#include <cstdio>
#include <cstdlib>

namespace {

void requireAt(bool condition, int line, const QByteArray &evidence = {})
{
    if (!condition) {
        std::fprintf(stderr,
                     "startup accessibility requirement failed at line %d: %s\n",
                     line,
                     evidence.constData());
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

void verifyStartup(const QString &program, const QByteArray &scaleFactor)
{
    QProcess process;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert("QT_QPA_PLATFORM", "offscreen");
    environment.insert("QT_SCALE_FACTOR", QString::fromLatin1(scaleFactor));
    environment.remove("QT_SCALE_FACTOR_ROUNDING_POLICY");
    process.setProcessEnvironment(environment);
    process.start(program, {"--startup-smoke"});
    requireAt(process.waitForStarted(5000), __LINE__, process.errorString().toUtf8());
    requireAt(process.waitForFinished(10000), __LINE__, process.errorString().toUtf8());
    const QByteArray stderrOutput = process.readAllStandardError();
    requireAt(process.exitStatus() == QProcess::NormalExit, __LINE__, stderrOutput);
    requireAt(process.exitCode() == EXIT_SUCCESS, __LINE__, stderrOutput);
    requireAt(!stderrOutput.contains("setHighDpiScaleFactorRoundingPolicy"),
              __LINE__,
              stderrOutput);
    requireAt(!stderrOutput.contains("must be called before creating"),
              __LINE__,
              stderrOutput);
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    REQUIRE(application.arguments().size() == 2);
    const QString program = application.arguments().at(1);
    verifyStartup(program, "1");
    verifyStartup(program, "2");
    return EXIT_SUCCESS;
}
