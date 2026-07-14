#include "ouidatabase.h"
#include "settingsstore.h"

#include <QCoreApplication>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

#include <iostream>

namespace {
bool readFailingSettings(QIODevice &, QSettings::SettingsMap &map)
{
    map.insert("targets/history", QStringList{"10.66.0.0/24"});
    map.insert("targets/last_input", "10.66.0.0/24");
    map.insert("targets/save_history", false);
    map.insert("targets/remember_last", false);
    map.insert("settings/schema_version", 2);
    return true;
}

bool writeFailingSettings(QIODevice &, const QSettings::SettingsMap &)
{
    return false;
}

bool ouiContract()
{
    QHash<QString, QString> overrides;
    QString error;
    if (!OuiDatabase::parseOverrides(
            "00:16:3E=Lab vendor\n# comment\nAABBCC=Camera vendor",
            &overrides,
            &error) ||
        !error.isEmpty() || overrides.value("00163E") != "Lab vendor" ||
        overrides.value("AABBCC") != "Camera vendor" ||
        OuiDatabase::lookup("00:16:3e:11:22:33", overrides,
                            {{"00163E", "Built-in collision"}}) != "Lab vendor" ||
        OuiDatabase::lookup("DE:AD:BE:EF:00:01", overrides,
                            {{"DEADBE", "Built in"}}) != "Built in" ||
        OuiDatabase::lookup("invalid", overrides, {}) != "Unknown") {
        return false;
    }
    if (OuiDatabase::parseOverrides("00163E=Valid\nGG1122=Invalid",
                                    &overrides,
                                    &error) ||
        overrides.size() != 2 || overrides.value("00163E") != "Lab vendor" ||
        !error.startsWith("Line 2")) {
        return false;
    }
    return OuiDatabase::normalizePrefix("0016.3e11.2233") == "00163E";
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    if (!ouiContract()) {
        std::cerr << "OUI policy contract failed\n";
        return 1;
    }

    QTemporaryDir directory;
    if (!directory.isValid()) {
        return 1;
    }
    QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
    settings.setValue("settings/schema_version", 1);
    settings.setValue("unrelated/keep", "preserved");
    settings.setValue("targets/remember_last", false);
    settings.setValue("targets/history", QStringList{"10.0.0.0/24"});
    settings.setValue("targets/last_input", "10.0.0.0/24");
    QString error;
    if (!SettingsStore::migrate(settings, &error) || !error.isEmpty() ||
        settings.value("settings/schema_version").toInt() != 3 ||
        settings.value("unrelated/keep").toString() != "preserved" ||
        settings.contains("targets/history") || settings.contains("targets/last_input")) {
        std::cerr << "settings migration contract failed\n";
        return 1;
    }

    const QStringList history{"192.0.2.0/24", "198.51.100.1"};
    if (!SettingsStore::persistTargetHistory(
            settings, history, history.first(), true, &error) ||
        settings.value("targets/history").toStringList() != history ||
        !SettingsStore::clearRetainedTargets(settings, true, &error) ||
        settings.contains("targets/history") || settings.contains("targets/last_input") ||
        settings.value("targets/save_history", true).toBool()) {
        std::cerr << "target-retention persistence contract failed\n";
        return 1;
    }

    const QSettings::Format failingFormat = QSettings::registerFormat(
        "ois-core-failing", readFailingSettings, writeFailingSettings);
    const auto seedFailingPath = [&directory](const QString &name) {
        const QString path = directory.filePath(name + ".ois-core-failing");
        QFile seed(path);
        return seed.open(QIODevice::WriteOnly) && seed.write("seed") == 4
                   ? path
                   : QString{};
    };
    const QString migrationPath = seedFailingPath("migration");
    const QString persistencePath = seedFailingPath("persistence");
    const QString clearingPath = seedFailingPath("clearing");
    if (migrationPath.isEmpty() || persistencePath.isEmpty() || clearingPath.isEmpty()) {
        return 1;
    }
    QSettings failingMigration(migrationPath, failingFormat);
    QSettings failingPersistence(persistencePath, failingFormat);
    QSettings failingClearing(clearingPath, failingFormat);
    if (SettingsStore::migrate(failingMigration, &error) || error.isEmpty() ||
        failingMigration.status() == QSettings::NoError ||
        SettingsStore::persistTargetHistory(
            failingPersistence, history, history.first(), true, &error) ||
        error.isEmpty() || failingPersistence.status() == QSettings::NoError ||
        SettingsStore::clearRetainedTargets(failingClearing, true, &error) ||
        error.isEmpty() || failingClearing.status() == QSettings::NoError) {
        std::cerr << "settings write-failure contracts failed\n";
        return 1;
    }
    return 0;
}
