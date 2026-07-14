#include "settingsstore.h"

#include <QSettings>

bool SettingsStore::migrate(QSettings &settings, QString *error)
{
    const int schema = settings.value("settings/schema_version", 0).toInt();
    if (schema >= CurrentSchemaVersion) {
        if (error != nullptr) {
            error->clear();
        }
        return true;
    }
    const bool legacyRetention = settings.value("targets/remember_last", false).toBool();
    if (schema < 3 && !settings.contains("targets/save_history")) {
        settings.setValue("targets/save_history", legacyRetention);
    }
    if (!settings.value("targets/save_history", false).toBool() &&
        !clearRetainedTargets(settings, true, error)) {
        return false;
    }
    settings.setValue("settings/schema_version", CurrentSchemaVersion);
    settings.sync();
    if (settings.status() != QSettings::NoError ||
        settings.value("settings/schema_version", 0).toInt() != CurrentSchemaVersion) {
        if (error != nullptr) {
            *error = "Could not complete the settings privacy migration. Check settings-file permissions and restart.";
        }
        return false;
    }
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool SettingsStore::clearRetainedTargets(QSettings &settings,
                                         bool disableRetention,
                                         QString *error)
{
    settings.remove("targets/history");
    settings.remove("targets/last_input");
    settings.setValue("targets/remember_last", false);
    if (disableRetention) {
        settings.setValue("targets/save_history", false);
    }
    settings.sync();
    const bool failed = settings.status() != QSettings::NoError ||
                        settings.contains("targets/history") ||
                        settings.contains("targets/last_input") ||
                        (disableRetention &&
                         settings.value("targets/save_history", true).toBool());
    if (!failed) {
        if (error != nullptr) {
            error->clear();
        }
        return true;
    }
    if (error != nullptr) {
        *error = "Could not remove saved target data. Check settings-file permissions and try again.";
    }
    return false;
}

bool SettingsStore::persistTargetHistory(QSettings &settings,
                                         const QStringList &history,
                                         const QString &lastInput,
                                         bool rememberLast,
                                         QString *error)
{
    settings.setValue("targets/save_history", true);
    settings.setValue("targets/remember_last", rememberLast);
    if (history.isEmpty()) {
        settings.remove("targets/history");
    } else {
        settings.setValue("targets/history", history);
    }
    if (rememberLast && !lastInput.isEmpty()) {
        settings.setValue("targets/last_input", lastInput);
    } else {
        settings.remove("targets/last_input");
    }
    settings.sync();
    const bool failed = settings.status() != QSettings::NoError ||
                        !settings.value("targets/save_history", false).toBool() ||
                        settings.value("targets/history").toStringList() != history ||
                        (rememberLast &&
                         settings.value("targets/last_input").toString() != lastInput) ||
                        (!rememberLast && settings.contains("targets/last_input"));
    if (!failed) {
        if (error != nullptr) {
            error->clear();
        }
        return true;
    }
    if (error != nullptr) {
        *error = "Could not save target history. Check settings-file permissions; this scan target was not retained.";
    }
    return false;
}
